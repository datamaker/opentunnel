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

// Linux TUN device implementation
class LinuxTunDevice extends TunDevice {
  private readStream?: fs.ReadStream;
  private writeStream?: fs.WriteStream;

  async create(): Promise<void> {
    // On Linux, we need to use /dev/net/tun with ioctl
    // For simplicity, we'll use the ip command to create a tun device
    try {
      // Create TUN device using ip command
      await this.exec(`ip tuntap add dev ${this.name} mode tun`);
      await this.exec(`ip link set ${this.name} mtu ${this.mtu}`);

      // Open the device
      const devicePath = `/dev/net/tun`;
      if (!fs.existsSync(devicePath)) {
        throw new Error('TUN device not available. Is the tun module loaded?');
      }

      this.running = true;
      logger.info(`Linux TUN device ${this.name} created`);
    } catch (error) {
      logger.error('Failed to create TUN device', error);
      throw error;
    }
  }

  async destroy(): Promise<void> {
    this.running = false;

    if (this.readStream) {
      this.readStream.destroy();
    }
    if (this.writeStream) {
      this.writeStream.destroy();
    }

    try {
      await this.exec(`ip link delete ${this.name}`);
      logger.info(`Linux TUN device ${this.name} destroyed`);
    } catch (error) {
      logger.warn(`Failed to destroy TUN device ${this.name}`, error);
    }
  }

  async assignIP(ip: string, netmask: string): Promise<void> {
    // Convert netmask to CIDR prefix
    const prefix = this.netmaskToCIDR(netmask);

    await this.exec(`ip addr add ${ip}/${prefix} dev ${this.name}`);
    await this.exec(`ip link set ${this.name} up`);

    logger.info(`Assigned IP ${ip}/${prefix} to ${this.name}`);
  }

  async read(): Promise<Buffer> {
    // In production, this would read from the TUN device file descriptor
    // Using a simplified approach here
    return Buffer.alloc(0);
  }

  async write(packet: Buffer): Promise<void> {
    // In production, this would write to the TUN device file descriptor
    logger.debug(`Writing ${packet.length} bytes to TUN`);
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
