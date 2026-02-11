import { EventEmitter } from 'events';
import { execSync } from 'child_process';
import * as os from 'os';
import { TunDevice, MockTunDevice } from '../tun/tunDevice';
import { SessionManager } from '../session/sessionManager';
import { IPPool } from './ipPool';
import { config } from '../config/config';
import { logger } from '../utils/logger';

export class PacketRouter extends EventEmitter {
  private tunDevice: TunDevice;
  private sessionManager: SessionManager;
  private ipPool: IPPool;
  private running: boolean = false;
  private readInterval?: NodeJS.Timeout;
  private useMock: boolean;

  constructor(
    sessionManager: SessionManager,
    ipPool: IPPool,
    useMock: boolean = false
  ) {
    super();
    this.sessionManager = sessionManager;
    this.ipPool = ipPool;
    this.useMock = useMock;

    // Create TUN device (mock in development/testing)
    if (useMock) {
      this.tunDevice = new MockTunDevice({ name: 'vpn0', mtu: config.vpn.mtu });
    } else {
      this.tunDevice = TunDevice.create({ name: 'vpn0', mtu: config.vpn.mtu });
    }

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    // Handle packets from sessions (client -> internet)
    this.sessionManager.on('packet', (sourceIP: string, packet: Buffer) => {
      this.routeFromClient(sourceIP, packet);
    });

    // Handle packets from TUN device (internet -> client)
    this.tunDevice.on('packet', (packet: Buffer) => {
      this.routeToClient(packet);
    });
  }

  async initialize(): Promise<void> {
    try {
      // Create TUN device
      await this.tunDevice.create();

      // Assign gateway IP
      const gateway = this.ipPool.getGateway();
      const subnetMask = this.ipPool.getSubnetMask();
      await this.tunDevice.assignIP(gateway, subnetMask);

      // Setup NAT (if not using mock)
      if (!this.useMock) {
        await this.setupNAT();
      }

      this.running = true;

      // Start reading from TUN device
      this.startReadLoop();

      logger.info('Packet router initialized');
    } catch (error) {
      logger.error('Failed to initialize packet router', error);
      throw error;
    }
  }

  // Route packet from client to internet
  private async routeFromClient(sourceIP: string, packet: Buffer): Promise<void> {
    if (!this.running) return;

    try {
      // Write packet to TUN device (will be routed by kernel)
      await this.tunDevice.write(packet);
    } catch (error) {
      logger.error('Error routing packet from client', error);
    }
  }

  // Route packet from internet to client
  private routeToClient(packet: Buffer): void {
    if (!this.running || packet.length < 20) return;

    try {
      // Extract destination IP from IPv4 header (offset 16-19)
      const destIP = this.extractDestIP(packet);

      // Find session by destination IP and forward packet
      const forwarded = this.sessionManager.routePacket(destIP, packet);

      if (forwarded) {
        logger.debug(`Routed packet to ${destIP} (${packet.length} bytes)`);
      }
    } catch (error) {
      logger.error('Error routing packet to client', error);
    }
  }

  private extractDestIP(packet: Buffer): string {
    // IPv4 header: destination IP at offset 16-19
    return `${packet[16]}.${packet[17]}.${packet[18]}.${packet[19]}`;
  }

  private extractSourceIP(packet: Buffer): string {
    // IPv4 header: source IP at offset 12-15
    return `${packet[12]}.${packet[13]}.${packet[14]}.${packet[15]}`;
  }

  private startReadLoop(): void {
    // Poll TUN device for incoming packets
    this.readInterval = setInterval(async () => {
      if (!this.running) return;

      try {
        const packet = await this.tunDevice.read();
        if (packet.length > 0) {
          this.routeToClient(packet);
        }
      } catch (error) {
        logger.error('Error reading from TUN device', error);
      }
    }, 1); // 1ms polling (in production, use epoll/kqueue)
  }

  private async setupNAT(): Promise<void> {
    const platform = os.platform();

    try {
      if (platform === 'linux') {
        await this.setupLinuxNAT();
      } else if (platform === 'darwin') {
        await this.setupMacOSNAT();
      }
    } catch (error) {
      logger.warn('NAT setup failed (may require root privileges)', error);
    }
  }

  private async setupLinuxNAT(): Promise<void> {
    // NAT is already configured in tunDevice.assignIP()
    // Just log that we're using the existing configuration
    logger.info('NAT configured by TUN device');
  }

  private async setupMacOSNAT(): Promise<void> {
    const subnet = `${config.vpn.subnet}/24`;

    // Enable IP forwarding
    execSync('sysctl -w net.inet.ip.forwarding=1');

    // Get default interface
    const defaultIface = this.getDefaultInterface();

    // Create pf.conf rules
    const pfRules = `
nat on ${defaultIface} from ${subnet} to any -> (${defaultIface})
pass in on ${this.tunDevice.getName()} from ${subnet} to any
pass out on ${defaultIface} from ${subnet} to any
`;

    // Write to temporary file and load
    const fs = require('fs');
    fs.writeFileSync('/tmp/vpn-nat.conf', pfRules);
    execSync('pfctl -f /tmp/vpn-nat.conf');
    execSync('pfctl -e');

    logger.info(`macOS NAT configured for ${subnet} via ${defaultIface}`);
  }

  private getDefaultInterface(): string {
    const platform = os.platform();

    try {
      if (platform === 'linux') {
        const output = execSync(
          "ip route | grep default | awk '{print $5}'"
        ).toString().trim();
        return output || 'eth0';
      } else if (platform === 'darwin') {
        const output = execSync(
          "route -n get default | grep interface | awk '{print $2}'"
        ).toString().trim();
        return output || 'en0';
      }
    } catch {
      // Fallback
    }

    return platform === 'darwin' ? 'en0' : 'eth0';
  }

  async shutdown(): Promise<void> {
    this.running = false;

    if (this.readInterval) {
      clearInterval(this.readInterval);
    }

    await this.tunDevice.destroy();

    logger.info('Packet router shut down');
  }

  getStats(): { packetsRouted: number } {
    // In production, track actual packet counts
    return { packetsRouted: 0 };
  }
}
