#!/usr/bin/env python3
"""
TUN Bridge - Handles TUN device I/O and communicates with Node.js via Unix socket
"""

import os
import sys
import socket
import select
import struct
import fcntl
import threading
from typing import Optional

# TUN device constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

class TunBridge:
    def __init__(self, tun_name: str = 'vpn0', socket_path: str = '/tmp/vpn-tun.sock'):
        self.tun_name = tun_name
        self.socket_path = socket_path
        self.tun_fd: Optional[int] = None
        self.unix_socket: Optional[socket.socket] = None
        self.running = False
        self.clients: list = []

    def open_tun(self) -> int:
        """Open and configure TUN device"""
        # Open /dev/net/tun
        tun_fd = os.open('/dev/net/tun', os.O_RDWR)

        # Configure TUN interface
        ifr = struct.pack('16sH', self.tun_name.encode(), IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

        # Set non-blocking
        flags = fcntl.fcntl(tun_fd, fcntl.F_GETFL)
        fcntl.fcntl(tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        print(f"[TUN Bridge] Opened TUN device {self.tun_name}")
        return tun_fd

    def setup_unix_socket(self):
        """Create Unix socket for Node.js communication"""
        # Remove existing socket file
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        self.unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.unix_socket.bind(self.socket_path)
        self.unix_socket.listen(5)
        self.unix_socket.setblocking(False)

        # Make socket accessible
        os.chmod(self.socket_path, 0o777)

        print(f"[TUN Bridge] Listening on {self.socket_path}")

    def handle_client(self, client_sock: socket.socket):
        """Handle incoming data from Node.js client"""
        try:
            # Read length prefix (4 bytes, big-endian)
            length_data = client_sock.recv(4)
            if not length_data or len(length_data) < 4:
                return False

            length = struct.unpack('>I', length_data)[0]
            if length > 65535:
                return False

            # Read packet data
            packet = b''
            while len(packet) < length:
                chunk = client_sock.recv(length - len(packet))
                if not chunk:
                    return False
                packet += chunk

            # Write to TUN
            if self.tun_fd and len(packet) > 0:
                os.write(self.tun_fd, packet)
                print(f"[TUN Bridge] Wrote {len(packet)} bytes to TUN")

            return True
        except BlockingIOError:
            return True
        except Exception as e:
            print(f"[TUN Bridge] Client error: {e}")
            return False

    def broadcast_to_clients(self, packet: bytes):
        """Send packet from TUN to all connected Node.js clients"""
        # Length-prefix the packet
        data = struct.pack('>I', len(packet)) + packet

        for client in self.clients[:]:
            try:
                client.sendall(data)
            except Exception as e:
                print(f"[TUN Bridge] Failed to send to client: {e}")
                self.clients.remove(client)
                client.close()

    def run(self):
        """Main event loop"""
        self.tun_fd = self.open_tun()
        self.setup_unix_socket()
        self.running = True

        print("[TUN Bridge] Running...")

        while self.running:
            # Build list of file descriptors to monitor
            read_fds = [self.tun_fd, self.unix_socket]
            read_fds.extend(self.clients)

            try:
                readable, _, _ = select.select(read_fds, [], [], 0.1)
            except select.error:
                continue

            for fd in readable:
                if fd == self.unix_socket:
                    # New client connection
                    try:
                        client, _ = self.unix_socket.accept()
                        client.setblocking(False)
                        self.clients.append(client)
                        print(f"[TUN Bridge] New client connected ({len(self.clients)} total)")
                    except BlockingIOError:
                        pass

                elif fd == self.tun_fd:
                    # Data from TUN device
                    try:
                        packet = os.read(self.tun_fd, 2048)
                        if packet:
                            print(f"[TUN Bridge] Read {len(packet)} bytes from TUN")
                            self.broadcast_to_clients(packet)
                    except BlockingIOError:
                        pass

                elif fd in self.clients:
                    # Data from Node.js client
                    if not self.handle_client(fd):
                        self.clients.remove(fd)
                        fd.close()
                        print(f"[TUN Bridge] Client disconnected ({len(self.clients)} remaining)")

    def stop(self):
        """Clean shutdown"""
        self.running = False

        if self.tun_fd:
            os.close(self.tun_fd)

        for client in self.clients:
            client.close()

        if self.unix_socket:
            self.unix_socket.close()

        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        print("[TUN Bridge] Stopped")


if __name__ == '__main__':
    tun_name = sys.argv[1] if len(sys.argv) > 1 else 'vpn0'

    bridge = TunBridge(tun_name=tun_name)

    try:
        bridge.run()
    except KeyboardInterrupt:
        print("\n[TUN Bridge] Shutting down...")
        bridge.stop()
