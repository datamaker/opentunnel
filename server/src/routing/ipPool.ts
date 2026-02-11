import { logger } from '../utils/logger';

// Simple IP address pool manager
export class IPPool {
  private subnet: string;
  private netmaskBits: number;
  private usedIPs: Set<string> = new Set();
  private baseIP: number;
  private maxHosts: number;

  constructor(cidr: string) {
    const [subnet, bits] = cidr.split('/');
    this.subnet = subnet;
    this.netmaskBits = parseInt(bits, 10);
    this.baseIP = this.ipToNumber(subnet);
    this.maxHosts = Math.pow(2, 32 - this.netmaskBits) - 2; // Exclude network and broadcast

    // Reserve gateway IP (first usable IP)
    this.usedIPs.add(this.numberToIP(this.baseIP + 1));

    logger.info(`IP Pool initialized: ${cidr} (${this.maxHosts} available hosts)`);
  }

  // Allocate an IP address
  allocate(): string | null {
    // Start from .2 (skip .0 network and .1 gateway)
    for (let i = 2; i <= this.maxHosts; i++) {
      const ip = this.numberToIP(this.baseIP + i);
      if (!this.usedIPs.has(ip)) {
        this.usedIPs.add(ip);
        logger.debug(`Allocated IP: ${ip}`);
        return ip;
      }
    }

    logger.warn('IP Pool exhausted');
    return null;
  }

  // Release an IP address back to the pool
  release(ip: string): void {
    if (this.usedIPs.has(ip)) {
      this.usedIPs.delete(ip);
      logger.debug(`Released IP: ${ip}`);
    }
  }

  // Check if an IP is in use
  isInUse(ip: string): boolean {
    return this.usedIPs.has(ip);
  }

  // Get pool statistics
  getStats(): { total: number; used: number; available: number } {
    return {
      total: this.maxHosts,
      used: this.usedIPs.size,
      available: this.maxHosts - this.usedIPs.size,
    };
  }

  // Get gateway IP
  getGateway(): string {
    return this.numberToIP(this.baseIP + 1);
  }

  // Get subnet mask in dotted decimal format
  getSubnetMask(): string {
    const mask = (0xffffffff << (32 - this.netmaskBits)) >>> 0;
    return this.numberToIP(mask);
  }

  private ipToNumber(ip: string): number {
    return ip
      .split('.')
      .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  }

  private numberToIP(num: number): string {
    return [
      (num >>> 24) & 0xff,
      (num >>> 16) & 0xff,
      (num >>> 8) & 0xff,
      num & 0xff,
    ].join('.');
  }
}
