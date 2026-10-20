const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'vericore_db.json');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const INITIAL_KEYWORDS = [
  { id: 'kw-1', keyword: 'verify immediately', category: 'URGENCY', weight: 28, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-2', keyword: 'account suspended', category: 'FEAR', weight: 26, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-2b', keyword: 'suspended', category: 'FEAR', weight: 24, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-2c', keyword: 'bank account', category: 'CREDENTIAL', weight: 20, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-3', keyword: 'unauthorized login attempt', category: 'FEAR', weight: 22, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-4', keyword: 'within 24 hours', category: 'URGENCY', weight: 18, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-5', keyword: 'confirm your identity', category: 'CREDENTIAL', weight: 20, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-6', keyword: 'update payment method', category: 'CREDENTIAL', weight: 22, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-7', keyword: 'security alert', category: 'AUTHORITY', weight: 14, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-8', keyword: 'wire transfer', category: 'CREDENTIAL', weight: 24, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-9', keyword: 'seed phrase', category: 'CREDENTIAL', weight: 35, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-10', keyword: 'claim your reward', category: 'SCARCITY', weight: 18, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-11', keyword: 'otp', category: 'CREDENTIAL', weight: 18, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-12', keyword: 'password expired', category: 'FEAR', weight: 20, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-13', keyword: 'login-secure', category: 'URL_TOKEN', weight: 20, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-13b', keyword: 'secure-paypal', category: 'URL_TOKEN', weight: 26, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-13c', keyword: 'login-free', category: 'URL_TOKEN', weight: 22, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-14', keyword: 'verify-account', category: 'URL_TOKEN', weight: 22, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-15', keyword: 'webscr', category: 'URL_TOKEN', weight: 25, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-16', keyword: '.xyz', category: 'SUSPICIOUS_TLD', weight: 18, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-17', keyword: '.top', category: 'SUSPICIOUS_TLD', weight: 20, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-18', keyword: '.zip', category: 'SUSPICIOUS_TLD', weight: 24, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-19', keyword: '.tk', category: 'SUSPICIOUS_TLD', weight: 26, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' },
  { id: 'kw-20', keyword: '.ru', category: 'SUSPICIOUS_TLD', weight: 15, active: true, added_by: 'system', created_at: '2026-10-01T09:00:00Z' }
];

function createDefaultDb() {
  const passwordHash = bcrypt.hashSync('vericore123', 8);
  return {
    users: [
      {
        id: 'usr-analyst-01',
        name: 'Shreya (Security Analyst)',
        email: 'analyst@vericore.sec',
        password: passwordHash,
        role: 'user',
        status: 'active',
        cyber_hygiene_score: 92,
        created_at: '2026-10-05T10:15:00Z'
      },
      {
        id: 'usr-admin-01',
        name: 'Commander Vance (SOC Lead)',
        email: 'admin@vericore.sec',
        password: passwordHash,
        role: 'admin',
        status: 'active',
        cyber_hygiene_score: 99,
        created_at: '2026-10-01T08:00:00Z'
      },
      {
        id: 'usr-emp-02',
        name: 'Rohan Mehta (Finance Ops)',
        email: 'rohan.m@enterprise.org',
        password: passwordHash,
        role: 'user',
        status: 'active',
        cyber_hygiene_score: 74,
        created_at: '2026-10-11T14:22:00Z'
      },
      {
        id: 'usr-emp-03',
        name: 'Elena Rostova (DevSecOps)',
        email: 'elena@enterprise.org',
        password: passwordHash,
        role: 'user',
        status: 'active',
        cyber_hygiene_score: 88,
        created_at: '2026-10-14T11:05:00Z'
      }
    ],
    scan_history: [],
    reports: [
      {
        id: 'rep-2026-001',
        user_id: 'usr-analyst-01',
        scan_id: 'scan-seed-1',
        report_type: 'Brand Impersonation & Homograph Attack',
        target_artifact: 'https://pаypal.com.secure-session-auth.top/myaccount/verify',
        risk_level: 'CRITICAL',
        status: 'BLOCKLISTED',
        details: 'Uses Cyrillic small letter "а" (U+0430) inside paypal lookalike subdomain on a .top TLD to harvest banking credentials and 2FA OTP tokens.',
        analyst_notes: 'Confirmed active AitM reverse-proxy kit. Added domain & IP range to global firewall blocklist.',
        created_at: '2026-10-19T16:40:00Z'
      },
      {
        id: 'rep-2026-002',
        user_id: 'usr-emp-02',
        scan_id: 'scan-seed-2',
        report_type: 'Executive Wire Fraud (BEC) & SPF Spoofing',
        target_artifact: 'From: CEO Office <ceo@company-portal.com> (Return-Path: <bounce@mail-relay-88.xyz>)',
        risk_level: 'HIGH',
        status: 'INVESTIGATING',
        details: 'Urgent invoice wire request bypassing basic keyword filters using polite corporate language, caught by SPF/Return-Path mismatch and authority coercion score.',
        analyst_notes: 'Tracing mail relay ASN and notifying finance department.',
        created_at: '2026-10-19T18:12:00Z'
      },
      {
        id: 'rep-2026-003',
        user_id: 'usr-emp-03',
        scan_id: 'scan-seed-3',
        report_type: 'QR Code Quishing (Fake Microsoft 365 MFA Re-enrollment)',
        target_artifact: 'http://185.220.101.44:8080/m365-qr-sso/auth?token=9f8a7b6c5d4e',
        risk_level: 'CRITICAL',
        status: 'OPEN',
        details: 'Embedded QR code inside PDF attachment routes mobile browser directly to raw IPv4 host harvesting Microsoft 365 session cookies.',
        analyst_notes: 'Pending sinkhole takedown request.',
        created_at: '2026-10-20T06:30:00Z'
      }
    ],
    suspicious_keywords: INITIAL_KEYWORDS
  };
}

function readDb() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      const initial = createDefaultDb();
      fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), 'utf8');
      return initial;
    }
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed.suspicious_keywords)) {
      let updated = false;
      for (const initKw of INITIAL_KEYWORDS) {
        if (!parsed.suspicious_keywords.some((k) => k.id === initKw.id || k.keyword.toLowerCase() === initKw.keyword.toLowerCase())) {
          parsed.suspicious_keywords.push(initKw);
          updated = true;
        }
      }
      if (updated) {
        fs.writeFileSync(DB_PATH, JSON.stringify(parsed, null, 2), 'utf8');
      }
    }
    return parsed;
  } catch (err) {
    console.error('Error reading DB, initializing fresh DB:', err.message);
    const initial = createDefaultDb();
    return initial;
  }
}

function writeDb(data) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.error('Error writing DB:', err.message);
  }
}

module.exports = {
  readDb,
  writeDb
};
