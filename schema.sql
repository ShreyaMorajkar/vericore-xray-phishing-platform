-- ============================================================================
-- VERICORE // X-RAY — AI Phishing Detection Platform
-- PostgreSQL / Supabase Database Schema (PRD Section 11 Compliant + Extended)
-- ============================================================================

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(180) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    cyber_hygiene_score INTEGER DEFAULT 78,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. SCAN HISTORY TABLE
CREATE TABLE IF NOT EXISTS scan_history (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    scan_type VARCHAR(30) NOT NULL CHECK (scan_type IN ('url', 'email', 'qr', 'header')),
    content TEXT NOT NULL,
    result VARCHAR(60) NOT NULL,
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    naive_scanner_score INTEGER DEFAULT 0,
    forensic_layers JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. REPORTS TABLE
CREATE TABLE IF NOT EXISTS reports (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    scan_id VARCHAR(64) REFERENCES scan_history(id) ON DELETE SET NULL,
    report_type VARCHAR(50) NOT NULL,
    target_artifact TEXT NOT NULL,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'HIGH',
    status VARCHAR(30) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'BLOCKLISTED', 'FALSE_POSITIVE', 'RESOLVED')),
    details TEXT NOT NULL,
    analyst_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. SUSPICIOUS KEYWORDS & HEURISTIC RULES TABLE (Admin Managed)
CREATE TABLE IF NOT EXISTS suspicious_keywords (
    id VARCHAR(64) PRIMARY KEY,
    keyword VARCHAR(120) UNIQUE NOT NULL,
    category VARCHAR(40) NOT NULL CHECK (category IN ('URGENCY', 'AUTHORITY', 'FEAR', 'SCARCITY', 'CREDENTIAL', 'URL_TOKEN', 'SUSPICIOUS_TLD')),
    weight INTEGER NOT NULL DEFAULT 15,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    added_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast dashboard & SOC queries
CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON scan_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_risk_level ON scan_history(risk_level);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
