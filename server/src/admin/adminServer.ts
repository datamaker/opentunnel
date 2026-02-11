import express, { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcrypt';
import path from 'path';
import { pool } from '../db/connection';
import { logger } from '../utils/logger';

const app = express();
const ADMIN_PORT = process.env.ADMIN_PORT || 8080;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '../../public')));

// Simple session-based auth
const sessions = new Map<string, { expires: number }>();

function generateToken(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers['authorization']?.replace('Bearer ', '') ||
                req.query.token as string;

  if (!token || !sessions.has(token)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const session = sessions.get(token)!;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    res.status(401).json({ error: 'Session expired' });
    return;
  }

  next();
}

// Auth endpoints
app.post('/api/login', (req: Request, res: Response) => {
  const { password } = req.body;

  if (password !== ADMIN_PASSWORD) {
    res.status(401).json({ error: 'Invalid password' });
    return;
  }

  const token = generateToken();
  sessions.set(token, { expires: Date.now() + 24 * 60 * 60 * 1000 }); // 24h
  res.json({ token });
});

app.post('/api/logout', (req: Request, res: Response) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (token) sessions.delete(token);
  res.json({ success: true });
});

// User management API
app.get('/api/users', authMiddleware, async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT id, username, is_active, max_connections, created_at, updated_at
      FROM users ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    logger.error('Failed to fetch users', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/users', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { username, password, maxConnections = 3 } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password required' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(`
      INSERT INTO users (username, password_hash, is_active, max_connections)
      VALUES ($1, $2, true, $3)
      RETURNING id, username, is_active, max_connections, created_at
    `, [username, passwordHash, maxConnections]);

    logger.info(`User created: ${username}`);
    res.json(result.rows[0]);
  } catch (error: any) {
    if (error.code === '23505') {
      res.status(409).json({ error: 'Username already exists' });
      return;
    }
    logger.error('Failed to create user', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.put('/api/users/:id', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { username, password, isActive, maxConnections } = req.body;

    let query = 'UPDATE users SET updated_at = NOW()';
    const params: any[] = [];
    let paramCount = 0;

    if (username) {
      params.push(username);
      query += `, username = $${++paramCount}`;
    }
    if (password) {
      const passwordHash = await bcrypt.hash(password, 10);
      params.push(passwordHash);
      query += `, password_hash = $${++paramCount}`;
    }
    if (typeof isActive === 'boolean') {
      params.push(isActive);
      query += `, is_active = $${++paramCount}`;
    }
    if (maxConnections) {
      params.push(maxConnections);
      query += `, max_connections = $${++paramCount}`;
    }

    params.push(id);
    query += ` WHERE id = $${++paramCount} RETURNING id, username, is_active, max_connections, updated_at`;

    const result = await pool.query(query, params);

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    logger.info(`User updated: ${id}`);
    res.json(result.rows[0]);
  } catch (error) {
    logger.error('Failed to update user', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/users/:id', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING username', [id]);

    if (result.rows.length === 0) {
      res.status(404).json({ error: 'User not found' });
      return;
    }

    logger.info(`User deleted: ${result.rows[0].username}`);
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to delete user', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Session API
app.get('/api/sessions', authMiddleware, async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`
      SELECT s.id, s.assigned_ip, s.client_platform, s.connected_at, u.username
      FROM sessions s
      JOIN users u ON s.user_id = u.id
      WHERE s.disconnected_at IS NULL
      ORDER BY s.connected_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    logger.error('Failed to fetch sessions', error);
    res.status(500).json({ error: 'Database error' });
  }
});

app.delete('/api/sessions/:id', authMiddleware, async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    await pool.query(`
      UPDATE sessions SET disconnected_at = NOW() WHERE id = $1
    `, [id]);

    logger.info(`Session terminated: ${id}`);
    res.json({ success: true });
  } catch (error) {
    logger.error('Failed to terminate session', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Stats API
app.get('/api/stats', authMiddleware, async (req: Request, res: Response) => {
  try {
    const [usersResult, sessionsResult, logsResult] = await Promise.all([
      pool.query('SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE is_active) as active FROM users'),
      pool.query('SELECT COUNT(*) as active FROM sessions WHERE disconnected_at IS NULL'),
      pool.query(`
        SELECT event_type, COUNT(*) as count
        FROM connection_logs
        WHERE created_at > NOW() - INTERVAL '24 hours'
        GROUP BY event_type
      `)
    ]);

    res.json({
      users: {
        total: parseInt(usersResult.rows[0].total),
        active: parseInt(usersResult.rows[0].active)
      },
      activeSessions: parseInt(sessionsResult.rows[0].active),
      last24h: logsResult.rows.reduce((acc, row) => {
        acc[row.event_type] = parseInt(row.count);
        return acc;
      }, {} as Record<string, number>)
    });
  } catch (error) {
    logger.error('Failed to fetch stats', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Connection logs API
app.get('/api/logs', authMiddleware, async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;

    const result = await pool.query(`
      SELECT l.id, l.event_type, l.client_ip, l.created_at, u.username
      FROM connection_logs l
      LEFT JOIN users u ON l.user_id = u.id
      ORDER BY l.created_at DESC
      LIMIT $1
    `, [limit]);

    res.json(result.rows);
  } catch (error) {
    logger.error('Failed to fetch logs', error);
    res.status(500).json({ error: 'Database error' });
  }
});

// Serve index.html for all other routes
app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, '../../public/index.html'));
});

export function startAdminServer(): void {
  app.listen(ADMIN_PORT, () => {
    logger.info(`Admin panel running at http://localhost:${ADMIN_PORT}`);
  });
}

// Run standalone if executed directly
if (require.main === module) {
  startAdminServer();
}
