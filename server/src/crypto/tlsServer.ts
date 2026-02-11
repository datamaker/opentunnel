import * as tls from 'tls';
import * as fs from 'fs';
import { EventEmitter } from 'events';
import { config } from '../config/config';
import { logger } from '../utils/logger';

export interface TlsServerOptions {
  port?: number;
  host?: string;
  certPath?: string;
  keyPath?: string;
  caPath?: string;
}

export class TlsServer extends EventEmitter {
  private server: tls.Server | null = null;
  private options: Required<TlsServerOptions>;

  constructor(options: TlsServerOptions = {}) {
    super();
    this.options = {
      port: options.port || config.server.port,
      host: options.host || config.server.host,
      certPath: options.certPath || config.server.tlsCertPath,
      keyPath: options.keyPath || config.server.tlsKeyPath,
      caPath: options.caPath || config.server.tlsCaPath,
    };
  }

  async start(): Promise<void> {
    // Load certificates
    let tlsOptions: tls.TlsOptions;

    try {
      tlsOptions = {
        key: fs.readFileSync(this.options.keyPath),
        cert: fs.readFileSync(this.options.certPath),
        // CA certificate is optional
        ...(fs.existsSync(this.options.caPath) && {
          ca: fs.readFileSync(this.options.caPath),
        }),

        // TLS configuration
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',

        // Prefer server cipher suites
        honorCipherOrder: true,

        // Strong ciphers
        ciphers: [
          'TLS_AES_256_GCM_SHA384',
          'TLS_CHACHA20_POLY1305_SHA256',
          'TLS_AES_128_GCM_SHA256',
          'ECDHE-RSA-AES256-GCM-SHA384',
          'ECDHE-RSA-CHACHA20-POLY1305',
          'ECDHE-RSA-AES128-GCM-SHA256',
        ].join(':'),

        // Don't require client certificates (we use user/password auth)
        requestCert: false,
        rejectUnauthorized: false,
      };
    } catch (error) {
      logger.error('Failed to load TLS certificates', error);
      throw new Error('TLS certificate loading failed. Please ensure certificates exist.');
    }

    return new Promise((resolve, reject) => {
      this.server = tls.createServer(tlsOptions, (socket) => {
        this.handleConnection(socket);
      });

      this.server.on('error', (err) => {
        logger.error('TLS Server error', err);
        this.emit('error', err);
      });

      this.server.on('tlsClientError', (err, socket) => {
        logger.warn('TLS client error', err);
        socket.destroy();
      });

      this.server.listen(this.options.port, this.options.host, () => {
        logger.info(`TLS Server listening on ${this.options.host}:${this.options.port}`);
        resolve();
      });

      this.server.on('error', (err) => {
        reject(err);
      });
    });
  }

  private handleConnection(socket: tls.TLSSocket): void {
    const clientAddr = `${socket.remoteAddress}:${socket.remotePort}`;
    logger.info(`New TLS connection from ${clientAddr}`);

    // Log TLS info
    const cipher = socket.getCipher();
    const protocol = socket.getProtocol();
    logger.debug(`TLS: ${protocol}, Cipher: ${cipher?.name}`);

    // Emit connection event for session manager
    this.emit('connection', socket);
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          logger.info('TLS Server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  getAddress(): { address: string; port: number } | null {
    if (this.server) {
      const addr = this.server.address();
      if (addr && typeof addr === 'object') {
        return { address: addr.address, port: addr.port };
      }
    }
    return null;
  }
}
