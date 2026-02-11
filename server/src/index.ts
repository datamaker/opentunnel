import * as tls from 'tls';
import { config } from './config/config';
import { pool, initDatabase, closeDatabase } from './db/connection';
import { TlsServer } from './crypto/tlsServer';
import { AuthService } from './auth/authService';
import { SessionManager } from './session/sessionManager';
import { IPPool } from './routing/ipPool';
import { PacketRouter } from './routing/packetRouter';
import { logger } from './utils/logger';

class VpnServer {
  private tlsServer: TlsServer;
  private authService: AuthService;
  private sessionManager: SessionManager;
  private ipPool: IPPool;
  private packetRouter: PacketRouter;
  private isShuttingDown: boolean = false;

  constructor() {
    // Initialize IP pool
    this.ipPool = new IPPool(`${config.vpn.subnet}/24`);

    // Initialize auth service
    this.authService = new AuthService(pool);

    // Initialize session manager
    this.sessionManager = new SessionManager(this.authService, this.ipPool);

    // Initialize packet router (use mock in development)
    const useMock = process.env.NODE_ENV !== 'production';
    this.packetRouter = new PacketRouter(this.sessionManager, this.ipPool, useMock);

    // Initialize TLS server
    this.tlsServer = new TlsServer();

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    // Handle new TLS connections
    this.tlsServer.on('connection', (socket: tls.TLSSocket) => {
      this.handleConnection(socket);
    });

    // Handle server errors
    this.tlsServer.on('error', (error: Error) => {
      logger.error('TLS Server error', error);
    });

    // Handle process signals
    process.on('SIGINT', () => this.shutdown('SIGINT'));
    process.on('SIGTERM', () => this.shutdown('SIGTERM'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', error);
      this.shutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', reason);
    });
  }

  private handleConnection(socket: tls.TLSSocket): void {
    // Create session for the connection
    const session = this.sessionManager.createSession(socket);

    logger.info(
      `New connection: ${session.id} from ${socket.remoteAddress}:${socket.remotePort}`
    );
  }

  async start(): Promise<void> {
    logger.info('Starting VPN Server...');
    logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);

    try {
      // Initialize database
      await initDatabase();
      logger.info('Database connected');

      // Initialize packet router
      await this.packetRouter.initialize();
      logger.info('Packet router initialized');

      // Start TLS server
      await this.tlsServer.start();
      logger.info(`TLS Server listening on ${config.server.host}:${config.server.port}`);

      // Start stale session cleanup
      this.startSessionCleanup();

      logger.info('VPN Server started successfully');
      this.printStatus();
    } catch (error) {
      logger.error('Failed to start VPN Server', error);
      throw error;
    }
  }

  private startSessionCleanup(): void {
    // Clean up stale sessions every 5 minutes
    setInterval(async () => {
      try {
        const cleaned = await this.authService.cleanupStaleSessions(5);
        if (cleaned > 0) {
          logger.info(`Cleaned up ${cleaned} stale sessions`);
        }
      } catch (error) {
        logger.error('Session cleanup error', error);
      }
    }, 5 * 60 * 1000);
  }

  private printStatus(): void {
    const ipStats = this.ipPool.getStats();
    const sessionStats = this.sessionManager.getStats();

    logger.info('=== VPN Server Status ===');
    logger.info(`  IP Pool: ${ipStats.used}/${ipStats.total} used`);
    logger.info(`  Active Sessions: ${sessionStats.activeSessions}`);
    logger.info(`  Gateway: ${this.ipPool.getGateway()}`);
    logger.info(`  DNS: ${config.vpn.dns.join(', ')}`);
    logger.info('========================');
  }

  async shutdown(signal: string): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }

    this.isShuttingDown = true;
    logger.info(`Shutting down VPN Server (${signal})...`);

    try {
      // Close all sessions
      this.sessionManager.closeAll();
      logger.info('All sessions closed');

      // Stop packet router
      await this.packetRouter.shutdown();
      logger.info('Packet router stopped');

      // Stop TLS server
      await this.tlsServer.stop();
      logger.info('TLS server stopped');

      // Close database
      await closeDatabase();
      logger.info('Database closed');

      logger.info('VPN Server shutdown complete');
      process.exit(0);
    } catch (error) {
      logger.error('Error during shutdown', error);
      process.exit(1);
    }
  }
}

// Main entry point
async function main(): Promise<void> {
  const server = new VpnServer();
  await server.start();
}

main().catch((error) => {
  logger.error('Fatal error', error);
  process.exit(1);
});
