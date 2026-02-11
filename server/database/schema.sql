-- VPN Server Database Schema
-- PostgreSQL 14+

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    max_connections INT DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Active sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_ip VARCHAR(15) NOT NULL,
    client_ip VARCHAR(45),
    client_platform VARCHAR(20) NOT NULL,
    client_version VARCHAR(20),
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    UNIQUE(assigned_ip)
);

-- Connection logs table
CREATE TABLE connection_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID,
    event_type VARCHAR(20) NOT NULL CHECK (event_type IN ('connect', 'disconnect', 'auth_fail', 'error')),
    client_ip VARCHAR(45),
    client_platform VARCHAR(20),
    details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_assigned_ip ON sessions(assigned_ip);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity);
CREATE INDEX idx_connection_logs_user_id ON connection_logs(user_id);
CREATE INDEX idx_connection_logs_created_at ON connection_logs(created_at);
CREATE INDEX idx_connection_logs_event_type ON connection_logs(event_type);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for users table
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default admin user (password: admin123)
-- In production, change this password immediately!
INSERT INTO users (username, password_hash, email, max_connections)
VALUES ('admin', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin@example.com', 5);

-- Sample user for testing (password: test123)
INSERT INTO users (username, password_hash, email)
VALUES ('testuser', '$2b$10$K.0HwpsoPDGaB/atFBmmXOGTw4ceeg33.WrxJx/FeC9.gOMzlSzPa', 'test@example.com');
