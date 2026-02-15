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
from typing import Optional

# TUN device constants
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Buffer sizes
TUN_READ_SIZE = 65536
SOCKET_BUFFER_SIZE = 1048576  # 1MB

class TunBridge:
    def __init__(self, tun_name: str = 'vpn0', socket_path: str = '/tmp/vpn-tun.sock'):
        self.tun_name = tun_name
        self.socket_path = socket_path
        self.tun_fd: Optional[int] = None
        self.unix_socket: Optional[socket.socket] = None
        self.running = False
        self.clients: list = []
        self.packet_count = 0

    def open_tun(self) -> int:
        """Open and configure TUN device"""
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
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        self.unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.unix_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Increase socket buffer sizes
        try:
            self.unix_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
            self.unix_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
        except:
            pass

        self.unix_socket.bind(self.socket_path)
        self.unix_socket.listen(5)
        self.unix_socket.setblocking(False)

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
                chunk = client_sock.recv(min(length - len(packet), 65536))
                if not chunk:
                    return False
                packet += chunk

            # Write to TUN
            if self.tun_fd and len(packet) > 0:
                os.write(self.tun_fd, packet)

            return True
        except BlockingIOError:
            return True
        except Exception as e:
            print(f"[TUN Bridge] Client error: {e}")
            return False

    def broadcast_to_clients(self, packet: bytes):
        """Send packet from TUN to all connected Node.js clients"""
        data = struct.pack('>I', len(packet)) + packet

        for client in self.clients[:]:
            try:
                client.sendall(data)
            except BlockingIOError:
                # Socket buffer full, skip this packet
                pass
            except Exception:
                self.clients.remove(client)
                try:
                    client.close()
                except:
                    pass

    def run(self):
        """Main event loop"""
        self.tun_fd = self.open_tun()
        self.setup_unix_socket()
        self.running = True

        print("[TUN Bridge] Running...")

        while self.running:
            read_fds = [self.tun_fd, self.unix_socket]
            read_fds.extend(self.clients)

            try:
                readable, _, _ = select.select(read_fds, [], [], 0.01)
            except select.error:
                continue

            for fd in readable:
                if fd == self.unix_socket:
                    # New client connection
                    try:
                        client, _ = self.unix_socket.accept()
                        client.setblocking(False)
                        # Set client socket buffers
                        try:
                            client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
                            client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
                        except:
                            pass
                        self.clients.append(client)
                        print(f"[TUN Bridge] Client connected ({len(self.clients)} total)")
                    except BlockingIOError:
                        pass

                elif fd == self.tun_fd:
                    # Data from TUN device - read multiple packets
                    try:
                        while True:
                            packet = os.read(self.tun_fd, TUN_READ_SIZE)
                            if packet:
                                self.broadcast_to_clients(packet)
                                self.packet_count += 1
                            else:
                                break
                    except BlockingIOError:
                        pass

                elif fd in self.clients:
                    # Data from Node.js client
                    if not self.handle_client(fd):
                        self.clients.remove(fd)
                        try:
                            fd.close()
                        except:
                            pass
                        print(f"[TUN Bridge] Client disconnected ({len(self.clients)} remaining)")

    def stop(self):
        """Clean shutdown"""
        self.running = False

        if self.tun_fd:
            os.close(self.tun_fd)

        for client in self.clients:
            try:
                client.close()
            except:
                pass

        if self.unix_socket:
            self.unix_socket.close()

        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        print(f"[TUN Bridge] Stopped (processed {self.packet_count} packets)")


if __name__ == '__main__':
    tun_name = sys.argv[1] if len(sys.argv) > 1 else 'vpn0'

    bridge = TunBridge(tun_name=tun_name)

    try:
        bridge.run()
    except KeyboardInterrupt:
        print("\n[TUN Bridge] Shutting down...")
        bridge.stop()
