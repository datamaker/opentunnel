import { Pool, PoolConfig } from 'pg';
import { config } from '../config/config';
import { logger } from '../utils/logger';

const poolConfig: PoolConfig = {
  host: config.database.host,
  port: config.database.port,
  database: config.database.database,
  user: config.database.user,
  password: config.database.password,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
};

export const pool = new Pool(poolConfig);

pool.on('error', (err) => {
  logger.error('Unexpected error on idle client', err);
});

export async function initDatabase(): Promise<void> {
  try {
    const client = await pool.connect();
    logger.info('Database connected successfully');
    client.release();
  } catch (error) {
    logger.error('Failed to connect to database', error);
    throw error;
  }
}

export async function closeDatabase(): Promise<void> {
  await pool.end();
  logger.info('Database connection closed');
}
