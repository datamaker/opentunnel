import * as tls from 'tls';
import { EventEmitter } from 'events';
import { VpnSession, SessionInfo } from './vpnSession';
import { AuthService } from '../auth/authService';
import { IPPool } from '../routing/ipPool';
import { logger } from '../utils/logger';

export class SessionManager extends EventEmitter {
  private sessions: Map<string, VpnSession> = new Map();
  private sessionsByIP: Map<string, VpnSession> = new Map();
  private authService: AuthService;
  private ipPool: IPPool;

  constructor(authService: AuthService, ipPool: IPPool) {
    super();
    this.authService = authService;
    this.ipPool = ipPool;
  }

  // Create a new session for an incoming connection
  createSession(socket: tls.TLSSocket): VpnSession {
    const session = new VpnSession(socket, this.authService, this.ipPool);

    this.sessions.set(session.id, session);

    // Track by assigned IP once authenticated
    session.on('packet', (sourceIP: string, packet: Buffer) => {
      this.handlePacket(session, sourceIP, packet);
    });

    session.on('close', (id: string) => {
      this.removeSession(id);
    });

    session.on('error', (id: string) => {
      this.removeSession(id);
    });

    logger.info(`Session created: ${session.id} from ${session.clientIP}`);

    return session;
  }

  // Handle packet from a session
  private handlePacket(session: VpnSession, sourceIP: string, packet: Buffer): void {
    // Update IP mapping if needed
    if (!this.sessionsByIP.has(sourceIP)) {
      this.sessionsByIP.set(sourceIP, session);
    }

    // Emit for packet router to handle
    this.emit('packet', sourceIP, packet);
  }

  // Route a packet to the appropriate session
  routePacket(destIP: string, packet: Buffer): boolean {
    const session = this.sessionsByIP.get(destIP);
    if (session) {
      session.sendPacket(packet);
      return true;
    }
    return false;
  }

  // Remove a session
  private removeSession(id: string): void {
    const session = this.sessions.get(id);
    if (session) {
      const info = session.getInfo();

      // Remove from IP mapping
      if (info.assignedIP) {
        this.sessionsByIP.delete(info.assignedIP);
      }

      this.sessions.delete(id);
      logger.info(`Session removed: ${id}`);
    }
  }

  // Get session by ID
  getSession(id: string): VpnSession | undefined {
    return this.sessions.get(id);
  }

  // Get session by assigned IP
  getSessionByIP(ip: string): VpnSession | undefined {
    return this.sessionsByIP.get(ip);
  }

  // Get all session info
  getAllSessions(): SessionInfo[] {
    return Array.from(this.sessions.values()).map((s) => s.getInfo());
  }

  // Get active session count
  getActiveCount(): number {
    return this.sessions.size;
  }

  // Close all sessions
  closeAll(): void {
    for (const session of this.sessions.values()) {
      session.close();
    }
  }

  // Get statistics
  getStats(): {
    activeSessions: number;
    totalBytesSent: number;
    totalBytesReceived: number;
  } {
    let totalBytesSent = 0;
    let totalBytesReceived = 0;

    for (const session of this.sessions.values()) {
      const info = session.getInfo();
      totalBytesSent += info.bytesSent;
      totalBytesReceived += info.bytesReceived;
    }

    return {
      activeSessions: this.sessions.size,
      totalBytesSent,
      totalBytesReceived,
    };
  }
}
