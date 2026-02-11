import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { v4 as uuidv4 } from 'uuid';
import { config } from '../config/config';
import { logger } from '../utils/logger';
import { ClientPlatform } from '../protocol/types';

export interface AuthResult {
  success: boolean;
  userId?: string;
  sessionToken?: string;
  errorMessage?: string;
}

export interface UserInfo {
  id: string;
  username: string;
  isActive: boolean;
  maxConnections: number;
}

export class AuthService {
  constructor(private db: Pool) {}

  async authenticate(
    username: string,
    password: string,
    platform: ClientPlatform,
    clientIP: string
  ): Promise<AuthResult> {
    try {
      // Query user from database
      const userResult = await this.db.query(
        `SELECT id, username, password_hash, is_active, max_connections
         FROM users WHERE username = $1`,
        [username]
      );

      if (userResult.rows.length === 0) {
        await this.logEvent(null, 'auth_fail', platform, clientIP, 'User not found');
        return { success: false, errorMessage: 'Invalid credentials' };
      }

      const user = userResult.rows[0];

      // Check if account is active
      if (!user.is_active) {
        await this.logEvent(user.id, 'auth_fail', platform, clientIP, 'Account disabled');
        return { success: false, errorMessage: 'Account is disabled' };
      }

      // Verify password
      const passwordValid = await bcrypt.compare(password, user.password_hash);
      if (!passwordValid) {
        await this.logEvent(user.id, 'auth_fail', platform, clientIP, 'Wrong password');
        return { success: false, errorMessage: 'Invalid credentials' };
      }

      // Check concurrent connection limit
      const sessionCountResult = await this.db.query(
        'SELECT COUNT(*) as count FROM sessions WHERE user_id = $1',
        [user.id]
      );

      const currentSessions = parseInt(sessionCountResult.rows[0].count, 10);
      if (currentSessions >= user.max_connections) {
        await this.logEvent(
          user.id,
          'auth_fail',
          platform,
          clientIP,
          'Max connections reached'
        );
        return { success: false, errorMessage: 'Maximum connections reached' };
      }

      // Generate session token
      const sessionToken = jwt.sign(
        {
          userId: user.id,
          username: user.username,
          platform,
        },
        config.jwtSecret,
        { expiresIn: '24h' }
      );

      logger.info(`User ${username} authenticated successfully from ${clientIP}`);

      return {
        success: true,
        userId: user.id,
        sessionToken,
      };
    } catch (error) {
      logger.error('Authentication error', error);
      return { success: false, errorMessage: 'Internal server error' };
    }
  }

  async createSession(
    userId: string,
    assignedIP: string,
    platform: ClientPlatform,
    clientIP: string,
    clientVersion: string
  ): Promise<string> {
    const sessionId = uuidv4();

    await this.db.query(
      `INSERT INTO sessions (id, user_id, assigned_ip, client_ip, client_platform, client_version)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sessionId, userId, assignedIP, clientIP, platform, clientVersion]
    );

    await this.logEvent(userId, 'connect', platform, clientIP);

    logger.info(`Session created for user ${userId}: ${assignedIP}`);

    return sessionId;
  }

  async endSession(sessionId: string): Promise<void> {
    // Get session info before deleting
    const sessionResult = await this.db.query(
      'SELECT user_id, client_platform, client_ip FROM sessions WHERE id = $1',
      [sessionId]
    );

    if (sessionResult.rows.length > 0) {
      const session = sessionResult.rows[0];
      await this.logEvent(
        session.user_id,
        'disconnect',
        session.client_platform,
        session.client_ip
      );
    }

    await this.db.query('DELETE FROM sessions WHERE id = $1', [sessionId]);

    logger.info(`Session ${sessionId} ended`);
  }

  async updateSessionActivity(sessionId: string): Promise<void> {
    await this.db.query(
      'UPDATE sessions SET last_activity = CURRENT_TIMESTAMP WHERE id = $1',
      [sessionId]
    );
  }

  async updateSessionStats(
    sessionId: string,
    bytesSent: number,
    bytesReceived: number
  ): Promise<void> {
    await this.db.query(
      `UPDATE sessions
       SET bytes_sent = bytes_sent + $2, bytes_received = bytes_received + $3, last_activity = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [sessionId, bytesSent, bytesReceived]
    );
  }

  async cleanupStaleSessions(maxIdleMinutes: number = 5): Promise<number> {
    const result = await this.db.query(
      `DELETE FROM sessions
       WHERE last_activity < CURRENT_TIMESTAMP - INTERVAL '${maxIdleMinutes} minutes'
       RETURNING id`
    );

    if (result.rowCount && result.rowCount > 0) {
      logger.info(`Cleaned up ${result.rowCount} stale sessions`);
    }

    return result.rowCount || 0;
  }

  async createUser(
    username: string,
    password: string,
    email?: string
  ): Promise<string> {
    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    await this.db.query(
      `INSERT INTO users (id, username, password_hash, email)
       VALUES ($1, $2, $3, $4)`,
      [userId, username, passwordHash, email]
    );

    logger.info(`User ${username} created`);

    return userId;
  }

  private async logEvent(
    userId: string | null,
    eventType: string,
    platform: ClientPlatform,
    clientIP: string,
    details?: string
  ): Promise<void> {
    await this.db.query(
      `INSERT INTO connection_logs (user_id, event_type, client_platform, client_ip, details)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, eventType, platform, clientIP, details]
    );
  }
}
