import dotenv from 'dotenv';

dotenv.config();

export interface ServerConfig {
  port: number;
  host: string;
  tlsCertPath: string;
  tlsKeyPath: string;
  tlsCaPath: string;
}

export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
}

export interface VpnConfig {
  subnet: string;
  netmask: string;
  gateway: string;
  dns: string[];
  mtu: number;
}

export interface Config {
  server: ServerConfig;
  database: DatabaseConfig;
  vpn: VpnConfig;
  jwtSecret: string;
}

export const config: Config = {
  server: {
    port: parseInt(process.env.VPN_PORT || '1194', 10),
    host: process.env.VPN_HOST || '0.0.0.0',
    tlsCertPath: process.env.TLS_CERT_PATH || './certs/server.crt',
    tlsKeyPath: process.env.TLS_KEY_PATH || './certs/server.key',
    tlsCaPath: process.env.TLS_CA_PATH || './certs/ca.crt',
  },
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    database: process.env.DB_NAME || 'vpn',
    user: process.env.DB_USER || 'vpn',
    password: process.env.DB_PASSWORD || 'vpn_password',
  },
  vpn: {
    subnet: process.env.VPN_SUBNET || '10.8.0.0',
    netmask: process.env.VPN_NETMASK || '255.255.255.0',
    gateway: process.env.VPN_GATEWAY || '10.8.0.1',
    dns: (process.env.VPN_DNS || '8.8.8.8,8.8.4.4').split(','),
    mtu: parseInt(process.env.VPN_MTU || '1400', 10),
  },
  jwtSecret: process.env.JWT_SECRET || 'change-this-in-production',
};
