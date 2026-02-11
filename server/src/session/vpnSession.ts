import * as tls from 'tls';
import { EventEmitter } from 'events';
import { v4 as uuidv4 } from 'uuid';
import { MessageHandler } from '../protocol/messageHandler';
import { ProtocolSerializer } from '../protocol/serializer';
import { AuthRequest, ClientPlatform, ConfigPush } from '../protocol/types';
import { AuthService } from '../auth/authService';
import { IPPool } from '../routing/ipPool';
import { config } from '../config/config';
import { logger } from '../utils/logger';

export enum SessionState {
  CONNECTED = 'connected',
  AUTHENTICATING = 'authenticating',
  AUTHENTICATED = 'authenticated',
  ACTIVE = 'active',
  DISCONNECTING = 'disconnecting',
  DISCONNECTED = 'disconnected',
}

export interface SessionInfo {
  id: string;
  sessionDbId?: string;
  userId?: string;
  username?: string;
  assignedIP?: string;
  platform?: ClientPlatform;
  clientVersion?: string;
  clientIP: string;
  state: SessionState;
  connectedAt: Date;
  lastActivity: Date;
  bytesSent: number;
  bytesReceived: number;
}

export class VpnSession extends EventEmitter {
  public readonly id: string;
  private socket: tls.TLSSocket;
  private messageHandler: MessageHandler;
  private authService: AuthService;
  private ipPool: IPPool;
  private keepaliveTimer?: NodeJS.Timeout;

  private state: SessionState = SessionState.CONNECTED;
  private sessionDbId?: string;
  private userId?: string;
  private username?: string;
  private assignedIP?: string;
  private platform?: ClientPlatform;
  private clientVersion?: string;
  private connectedAt: Date;
  private lastActivity: Date;
  private bytesSent: number = 0;
  private bytesReceived: number = 0;

  constructor(
    socket: tls.TLSSocket,
    authService: AuthService,
    ipPool: IPPool
  ) {
    super();
    this.id = uuidv4();
    this.socket = socket;
    this.authService = authService;
    this.ipPool = ipPool;
    this.messageHandler = new MessageHandler();
    this.connectedAt = new Date();
    this.lastActivity = new Date();

    this.setupEventHandlers();
  }

  get clientIP(): string {
    return this.socket.remoteAddress || 'unknown';
  }

  getInfo(): SessionInfo {
    return {
      id: this.id,
      sessionDbId: this.sessionDbId,
      userId: this.userId,
      username: this.username,
      assignedIP: this.assignedIP,
      platform: this.platform,
      clientVersion: this.clientVersion,
      clientIP: this.clientIP,
      state: this.state,
      connectedAt: this.connectedAt,
      lastActivity: this.lastActivity,
      bytesSent: this.bytesSent,
      bytesReceived: this.bytesReceived,
    };
  }

  private setupEventHandlers(): void {
    // Socket events
    this.socket.on('data', (data) => this.handleData(data));
    this.socket.on('close', () => this.handleClose());
    this.socket.on('error', (err) => this.handleError(err));

    // Message handler events
    this.messageHandler.on('auth', (request) => this.handleAuth(request));
    this.messageHandler.on('keepalive', () => this.handleKeepalive());
    this.messageHandler.on('disconnect', () => this.handleDisconnect());
    this.messageHandler.on('data', (packet) => this.handlePacket(packet));
  }

  private handleData(data: Buffer): void {
    this.bytesReceived += data.length;
    this.lastActivity = new Date();
    this.messageHandler.handleData(data);
  }

  private async handleAuth(request: AuthRequest): Promise<void> {
    if (this.state !== SessionState.CONNECTED) {
      logger.warn(`Session ${this.id}: Auth request in invalid state ${this.state}`);
      return;
    }

    this.state = SessionState.AUTHENTICATING;
    this.platform = request.platform;
    this.clientVersion = request.clientVersion;

    logger.info(`Session ${this.id}: Auth request from ${request.username}`);

    const result = await this.authService.authenticate(
      request.username,
      request.password,
      request.platform,
      this.clientIP
    );

    if (!result.success) {
      this.sendAuthResponse(false, result.errorMessage);
      this.close();
      return;
    }

    this.userId = result.userId;
    this.username = request.username;

    // Allocate IP address
    const ip = this.ipPool.allocate();
    if (!ip) {
      this.sendAuthResponse(false, 'No available IP addresses');
      this.close();
      return;
    }

    this.assignedIP = ip;

    // Create database session
    this.sessionDbId = await this.authService.createSession(
      this.userId!,
      this.assignedIP,
      this.platform,
      this.clientIP,
      this.clientVersion || 'unknown'
    );

    this.state = SessionState.AUTHENTICATED;

    // Send auth success
    this.sendAuthResponse(true, undefined, result.sessionToken);

    // Send VPN configuration
    this.sendConfig();

    this.state = SessionState.ACTIVE;

    // Start keepalive
    this.startKeepalive();

    logger.info(`Session ${this.id}: User ${this.username} authenticated, assigned IP ${this.assignedIP}`);
  }

  private handleKeepalive(): void {
    this.lastActivity = new Date();
    this.send(ProtocolSerializer.serializeKeepaliveAck());

    if (this.sessionDbId) {
      this.authService.updateSessionActivity(this.sessionDbId);
    }
  }

  private handleDisconnect(): void {
    logger.info(`Session ${this.id}: Client requested disconnect`);
    this.close();
  }

  private handlePacket(packet: Buffer): void {
    if (this.state !== SessionState.ACTIVE) return;

    // Emit packet for routing
    this.emit('packet', this.assignedIP, packet);
  }

  private handleClose(): void {
    this.cleanup();
    this.emit('close', this.id);
  }

  private handleError(error: Error): void {
    logger.error(`Session ${this.id}: Socket error`, error);
    this.cleanup();
    this.emit('error', this.id, error);
  }

  // Send data packet to client
  sendPacket(data: Buffer): void {
    if (this.state !== SessionState.ACTIVE) {
      return;
    }

    const message = ProtocolSerializer.serializeDataPacket(data);
    this.send(message);
  }

  private sendAuthResponse(
    success: boolean,
    errorMessage?: string,
    sessionToken?: string
  ): void {
    const response = ProtocolSerializer.serializeAuthResponse({
      success,
      errorMessage,
      sessionToken,
    });
    this.send(response);
  }

  private sendConfig(): void {
    const configPush: ConfigPush = {
      assignedIP: this.assignedIP!,
      subnetMask: this.ipPool.getSubnetMask(),
      gateway: this.ipPool.getGateway(),
      dns: config.vpn.dns,
      mtu: config.vpn.mtu,
      keepaliveInterval: 10,
    };

    const message = ProtocolSerializer.serializeConfigPush(configPush);
    this.send(message);
  }

  private send(data: Buffer): void {
    if (!this.socket.destroyed) {
      this.socket.write(data);
      this.bytesSent += data.length;
    }
  }

  private startKeepalive(): void {
    this.keepaliveTimer = setInterval(() => {
      const now = new Date();
      const idleTime = now.getTime() - this.lastActivity.getTime();

      // Send keepalive if idle for 30 seconds
      if (idleTime > 30000) {
        this.send(ProtocolSerializer.serializeKeepalive());
      }

      // Close if no activity for 2 minutes
      if (idleTime > 120000) {
        logger.info(`Session ${this.id}: Timeout, closing`);
        this.close();
      }
    }, 10000);
  }

  close(): void {
    if (this.state === SessionState.DISCONNECTED) {
      return;
    }

    this.state = SessionState.DISCONNECTING;

    // Send disconnect message
    if (!this.socket.destroyed) {
      this.send(ProtocolSerializer.serializeDisconnect());
      this.socket.end();
    }

    this.cleanup();
  }

  private async cleanup(): Promise<void> {
    if (this.state === SessionState.DISCONNECTED) {
      return;
    }

    this.state = SessionState.DISCONNECTED;

    // Stop keepalive
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
    }

    // Release IP
    if (this.assignedIP) {
      this.ipPool.release(this.assignedIP);
    }

    // End database session
    if (this.sessionDbId) {
      await this.authService.updateSessionStats(
        this.sessionDbId,
        this.bytesSent,
        this.bytesReceived
      );
      await this.authService.endSession(this.sessionDbId);
    }

    // Cleanup message handler
    this.messageHandler.reset();

    logger.info(`Session ${this.id}: Cleaned up`);
  }
}
