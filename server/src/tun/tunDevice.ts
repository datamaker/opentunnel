import { EventEmitter } from 'events';
import { spawn, execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import { logger } from '../utils/logger';

export interface TunDeviceOptions {
  name?: string;
  mtu?: number;
}

// Abstract TUN device interface
export abstract class TunDevice extends EventEmitter {
  protected name: string;
  protected mtu: number;
  protected fd: number = -1;
  protected running: boolean = false;

  constructor(options: TunDeviceOptions = {}) {
    super();
    this.name = options.name || 'vpn0';
    this.mtu = options.mtu || 1400;
  }

  abstract create(): Promise<void>;
  abstract destroy(): Promise<void>;
  abstract assignIP(ip: string, netmask: string): Promise<void>;
  abstract read(): Promise<Buffer>;
  abstract write(packet: Buffer): Promise<void>;

  getName(): string {
    return this.name;
  }

  isRunning(): boolean {
    return this.running;
  }

  protected exec(cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
      try {
        const output = execSync(cmd, { encoding: 'utf-8' });
        resolve(output);
      } catch (error: unknown) {
        const err = error as Error;
        reject(err);
      }
    });
  }

  // Factory method to create platform-specific TUN device
  static create(options?: TunDeviceOptions): TunDevice {
    const platform = os.platform();

    switch (platform) {
      case 'linux':
        return new LinuxTunDevice(options);
      case 'darwin':
        return new MacOSTunDevice(options);
      default:
        throw new Error(`Unsupported platform: ${platform}`);
    }
  }
}

// Linux TUN device implementation using Python bridge via Unix socket
class LinuxTunDevice extends TunDevice {
  private socket: any = null;
  private socketPath: string = '/tmp/vpn-tun.sock';
  private bridgeProcess: any = null;
  private receiveBuffer: Buffer = Buffer.alloc(0);

  async create(): Promise<void> {
    try {
      // Create TUN device using ip command (will be used by Python bridge)
      try {
        await this.exec(`ip tuntap add dev ${this.name} mode tun`);
      } catch (e) {
        logger.warn(`TUN device ${this.name} may already exist`);
      }
      await this.exec(`ip link set ${this.name} mtu ${this.mtu}`);

      // Start Python TUN bridge
      const bridgePath = '/app/tun-bridge.py';
      if (!fs.existsSync(bridgePath)) {
        throw new Error(`TUN bridge not found at ${bridgePath}`);
      }

      this.bridgeProcess = spawn('python3', [bridgePath, this.name], {
        stdio: ['ignore', 'inherit', 'inherit']
      });

      this.bridgeProcess.on('error', (err: Error) => {
        logger.error('TUN bridge process error', err);
      });

      this.bridgeProcess.on('exit', (code: number) => {
        logger.warn(`TUN bridge exited with code ${code}`);
      });

      // Wait for socket to be available
      await new Promise(resolve => setTimeout(resolve, 1500));

      // Connect to Unix socket
      const net = require('net');
      this.socket = net.createConnection(this.socketPath);

      this.socket.on('data', (data: Buffer) => {
        this.handleIncomingData(data);
      });

      this.socket.on('error', (err: Error) => {
        logger.error('TUN socket error', err);
      });

      // Wait for connection
      await new Promise<void>((resolve, reject) => {
        this.socket.once('connect', () => {
          logger.info('Connected to TUN bridge');
          resolve();
        });
        this.socket.once('error', reject);
        setTimeout(() => reject(new Error('Socket connection timeout')), 5000);
      });

      this.running = true;
      logger.info(`Linux TUN device ${this.name} created with Python bridge`);
    } catch (error) {
      logger.error('Failed to create TUN device', error);
      throw error;
    }
  }

  private handleIncomingData(data: Buffer): void {
    this.receiveBuffer = Buffer.concat([this.receiveBuffer, data]);

    while (this.receiveBuffer.length >= 4) {
      const length = this.receiveBuffer.readUInt32BE(0);
      if (this.receiveBuffer.length < 4 + length) {
        break;
      }

      const packet = this.receiveBuffer.slice(4, 4 + length);
      this.receiveBuffer = this.receiveBuffer.slice(4 + length);

      this.emit('packet', packet);
    }
  }

  async destroy(): Promise<void> {
    this.running = false;

    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }

    if (this.bridgeProcess) {
      this.bridgeProcess.kill();
      this.bridgeProcess = null;
    }

    try {
      await this.exec(`ip link delete ${this.name}`);
      logger.info(`Linux TUN device ${this.name} destroyed`);
    } catch (error) {
      logger.warn(`Failed to destroy TUN device ${this.name}`, error);
    }
  }

  async assignIP(ip: string, netmask: string): Promise<void> {
    const prefix = this.netmaskToCIDR(netmask);

    try {
      await this.exec(`ip addr add ${ip}/${prefix} dev ${this.name}`);
    } catch (e) {
      logger.warn('IP may already be assigned');
    }
    await this.exec(`ip link set ${this.name} up`);

    // Enable IP forwarding (may fail in container, that's OK - host should have it enabled)
    try {
      await this.exec('echo 1 > /proc/sys/net/ipv4/ip_forward');
    } catch (e) {
      logger.info('IP forwarding should be enabled on host: sysctl -w net.ipv4.ip_forward=1');
    }

    // Set up NAT rules
    const subnet = ip.replace(/\.\d+$/, '.0') + '/24';
    try {
      await this.exec(`iptables -t nat -C POSTROUTING -s ${subnet} -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s ${subnet} -o eth0 -j MASQUERADE`);
      await this.exec(`iptables -C FORWARD -i ${this.name} -j ACCEPT 2>/dev/null || iptables -A FORWARD -i ${this.name} -j ACCEPT`);
      await this.exec(`iptables -C FORWARD -o ${this.name} -j ACCEPT 2>/dev/null || iptables -A FORWARD -o ${this.name} -j ACCEPT`);
      logger.info('NAT configured for VPN subnet');
    } catch (e) {
      logger.warn('NAT setup warning', e);
    }

    logger.info(`Assigned IP ${ip}/${prefix} to ${this.name}`);
  }

  async read(): Promise<Buffer> {
    return Buffer.alloc(0);
  }

  async write(packet: Buffer): Promise<void> {
    if (!this.socket || !this.running) {
      return;
    }

    try {
      const header = Buffer.alloc(4);
      header.writeUInt32BE(packet.length, 0);
      this.socket.write(Buffer.concat([header, packet]));
      logger.debug(`Wrote ${packet.length} bytes to TUN via bridge`);
    } catch (error) {
      logger.error('Error writing to TUN', error);
    }
  }

  private netmaskToCIDR(netmask: string): number {
    const octets = netmask.split('.').map(Number);
    let bits = 0;
    for (const octet of octets) {
      bits += (octet >>> 0).toString(2).split('1').length - 1;
    }
    return bits;
  }
}

// macOS TUN device implementation (using utun)
class MacOSTunDevice extends TunDevice {
  private utunNumber: number = 0;

  async create(): Promise<void> {
    // On macOS, we use utun devices
    // Find an available utun device number
    for (let i = 0; i < 256; i++) {
      try {
        // Check if utun device exists
        await this.exec(`ifconfig utun${i} 2>/dev/null`);
      } catch {
        // Device doesn't exist, we can try to create it
        this.utunNumber = i;
        this.name = `utun${i}`;
        break;
      }
    }

    // On macOS, utun devices are created automatically when opened via system socket
    // For a full implementation, we'd need native code to open a PF_SYSTEM socket
    // Here we'll use a simplified approach

    logger.info(`macOS TUN device ${this.name} prepared (utun${this.utunNumber})`);
    this.running = true;
  }

  async destroy(): Promise<void> {
    this.running = false;
    // utun devices are automatically destroyed when the socket is closed
    logger.info(`macOS TUN device ${this.name} destroyed`);
  }

  async assignIP(ip: string, netmask: string): Promise<void> {
    // Calculate peer IP (gateway)
    const parts = ip.split('.').map(Number);
    parts[3] = 1; // Gateway is .1
    const gateway = parts.join('.');

    await this.exec(`ifconfig ${this.name} ${ip} ${gateway} netmask ${netmask} mtu ${this.mtu} up`);

    logger.info(`Assigned IP ${ip} to ${this.name} (gateway: ${gateway})`);
  }

  async read(): Promise<Buffer> {
    // In production, this would read from the utun socket
    return Buffer.alloc(0);
  }

  async write(packet: Buffer): Promise<void> {
    // In production, this would write to the utun socket
    logger.debug(`Writing ${packet.length} bytes to utun`);
  }
}

// Mock TUN device for testing without root privileges
export class MockTunDevice extends TunDevice {
  private packetQueue: Buffer[] = [];

  async create(): Promise<void> {
    logger.info(`Mock TUN device ${this.name} created`);
    this.running = true;
  }

  async destroy(): Promise<void> {
    this.running = false;
    this.packetQueue = [];
    logger.info(`Mock TUN device ${this.name} destroyed`);
  }

  async assignIP(ip: string, netmask: string): Promise<void> {
    logger.info(`Mock: Assigned IP ${ip}/${netmask} to ${this.name}`);
  }

  async read(): Promise<Buffer> {
    if (this.packetQueue.length > 0) {
      return this.packetQueue.shift()!;
    }
    return Buffer.alloc(0);
  }

  async write(packet: Buffer): Promise<void> {
    logger.debug(`Mock: Writing ${packet.length} bytes`);
    // Emit packet for handling
    this.emit('packet', packet);
  }

  // For testing: inject a packet as if it came from the network
  injectPacket(packet: Buffer): void {
    this.packetQueue.push(packet);
    this.emit('readable');
  }
}
