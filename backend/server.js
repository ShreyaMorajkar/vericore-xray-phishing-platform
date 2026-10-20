require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { readDb, writeDb } = require('./db');
const { runXrayDissection } = require('./engine/xrayEngine');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'vericore-xray-super-secret-key-2026';

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// Seed initial realistic scans on first boot so the dashboard & history are rich immediately
async function ensureSeedScans() {
  const db = readDb();
  if (db.scan_history && db.scan_history.length > 0) return;

  const samples = [
    {
      id: 'scan-seed-1',
      user_id: 'usr-analyst-01',
      scanType: 'url',
      content: 'https://p\u0430ypal.com.secure-session-auth.top/myaccount/verify?session=99812',
      created_at: '2026-10-19T16:35:00Z'
    },
    {
      id: 'scan-seed-2',
      user_id: 'usr-emp-02',
      scanType: 'email',
      content: `From: PayPal Security <security@paypal.com>\nReturn-Path: <bounce-alert@mail-auth-relay.xyz>\nReply-To: <verify-now@support-desk-pp.top>\nAuthentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\nSubject: URGENT: Your account suspended due to unauthorized login attempt\n\nDear Customer,\nWe detected an unauthorized login attempt on your account. Your account suspended within 24 hours unless you verify immediately and update payment method.\n\nClick here to confirm your identity: http://login-secure-paypal-update.xyz/webscr`,
      created_at: '2026-10-19T18:05:00Z'
    },
    {
      id: 'scan-seed-3',
      user_id: 'usr-emp-03',
      scanType: 'qr',
      content: 'http://185.220.101.44:8080/m365-qr-sso/login-secure?otp=required',
      created_at: '2026-10-20T06:20:00Z'
    },
    {
      id: 'scan-seed-4',
      user_id: 'usr-analyst-01',
      scanType: 'url',
      content: 'https://github.com/security/advisories',
      created_at: '2026-10-20T07:45:00Z'
    }
  ];

  for (const s of samples) {
    const analysis = await runXrayDissection({
      scanType: s.scanType,
      content: s.content,
      customKeywords: db.suspicious_keywords
    });
    db.scan_history.push({
      id: s.id,
      user_id: s.user_id,
      scan_type: s.scanType,
      content: s.content,
      result: analysis.result,
      risk_level: analysis.riskLevel,
      risk_score: analysis.riskScore,
      naive_scanner_score: analysis.naiveScannerScore,
      recommendation: analysis.recommendation,
      forensic_layers: analysis.forensic_layers,
      created_at: s.created_at
    });
  }

  writeDb(db);
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ONLINE',
    service: 'VERICORE // X-RAY Forensics API',
    version: '2.4.0',
    timestamp: new Date().toISOString()
  });
});

// ============================================================================
// AUTHENTICATION ENDPOINTS (JWT + 1-Click Role Switcher)
// ============================================================================
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const db = readDb();
  const user = db.users.find((u) => u.email.toLowerCase() === (email || '').toLowerCase());
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials. User not found.' });
  }
  if (user.status === 'suspended') {
    return res.status(403).json({ error: 'Account is suspended by SOC Administrator.' });
  }
  const valid = bcrypt.compareSync(password || '', user.password);
  if (!valid) {
    return res.status(401).json({ error: 'Invalid password.' });
  }
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safeUser } = user;
  res.json({ token, user: safeUser });
});

app.post('/api/auth/register', (req, res) => {
  const { name, email, password, role } = req.body || {};
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }
  const db = readDb();
  if (db.users.some((u) => u.email.toLowerCase() === email.toLowerCase())) {
    return res.status(409).json({ error: 'Email is already registered.' });
  }
  const newUser = {
    id: `usr-${Date.now()}`,
    name,
    email,
    password: bcrypt.hashSync(password, 8),
    role: role === 'admin' ? 'admin' : 'user',
    status: 'active',
    cyber_hygiene_score: 80,
    created_at: new Date().toISOString()
  };
  db.users.push(newUser);
  writeDb(db);
  const token = jwt.sign({ id: newUser.id, email: newUser.email, role: newUser.role }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safeUser } = newUser;
  res.status(201).json({ token, user: safeUser });
});

app.post('/api/auth/demo-switch', (req, res) => {
  const { role } = req.body || {};
  const db = readDb();
  const targetUser = role === 'admin'
    ? db.users.find((u) => u.role === 'admin')
    : db.users.find((u) => u.role === 'user');
  if (!targetUser) {
    return res.status(404).json({ error: 'Demo user not found' });
  }
  const token = jwt.sign({ id: targetUser.id, email: targetUser.email, role: targetUser.role }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safeUser } = targetUser;
  res.json({ token, user: safeUser });
});

// ============================================================================
// CORE X-RAY SCANNING ENDPOINT
// ============================================================================
app.post('/api/scan', async (req, res) => {
  try {
    const { scanType = 'url', content = '', userId = 'usr-analyst-01' } = req.body || {};
    if (!content || !content.trim()) {
      return res.status(400).json({ error: 'Please provide a URL, email payload, header, or QR content to dissect.' });
    }

    const db = readDb();
    const dissection = await runXrayDissection({
      scanType,
      content,
      customKeywords: db.suspicious_keywords
    });

    const scanRecord = {
      id: `scan-${Date.now()}`,
      user_id: userId,
      scan_type: dissection.scanType,
      content: dissection.content,
      result: dissection.result,
      risk_level: dissection.riskLevel,
      risk_score: dissection.riskScore,
      naive_scanner_score: dissection.naiveScannerScore,
      recommendation: dissection.recommendation,
      forensic_layers: dissection.forensic_layers,
      created_at: new Date().toISOString()
    };

    db.scan_history.unshift(scanRecord);
    writeDb(db);

    res.json(scanRecord);
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({ error: 'Internal forensics engine error', details: err.message });
  }
});

// ============================================================================
// RED-TEAM VS. BLUE-TEAM EVASION MUTATOR ENDPOINT
// ============================================================================
app.post('/api/mutate-test', async (req, res) => {
  try {
    const { content = '', scanType = 'url', activeKeywords } = req.body || {};
    const db = readDb();
    const dissection = await runXrayDissection({
      scanType,
      content,
      customKeywords: Array.isArray(activeKeywords) ? activeKeywords : db.suspicious_keywords
    });
    res.json(dissection);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================================
// DASHBOARD STATS & SCAN HISTORY
// ============================================================================
app.get('/api/history', (req, res) => {
  const { scanType, riskLevel, search } = req.query;
  const db = readDb();
  let list = [...db.scan_history];

  if (scanType && scanType !== 'ALL') {
    list = list.filter((s) => s.scan_type === scanType.toLowerCase());
  }
  if (riskLevel && riskLevel !== 'ALL') {
    list = list.filter((s) => s.risk_level === riskLevel.toUpperCase());
  }
  if (search && search.trim()) {
    const q = search.toLowerCase();
    list = list.filter(
      (s) =>
        s.content.toLowerCase().includes(q) ||
        s.result.toLowerCase().includes(q) ||
        s.id.toLowerCase().includes(q)
    );
  }

  const totalScans = db.scan_history.length;
  const safeCount = db.scan_history.filter((s) => s.risk_level === 'LOW').length;
  const suspiciousCount = db.scan_history.filter((s) => ['MEDIUM', 'HIGH', 'CRITICAL'].includes(s.risk_level)).length;
  const criticalCount = db.scan_history.filter((s) => s.risk_level === 'CRITICAL').length;
  const avgRiskScore = totalScans > 0
    ? Math.round(db.scan_history.reduce((sum, s) => sum + (s.risk_score || 0), 0) / totalScans)
    : 0;
  const naiveBypassCount = db.scan_history.filter(
    (s) => (s.risk_score || 0) >= 60 && (s.naive_scanner_score || 0) < 45
  ).length;

  res.json({
    stats: {
      totalScans,
      safeCount,
      suspiciousCount,
      criticalCount,
      avgRiskScore,
      naiveBypassCount,
      activeRulesCount: db.suspicious_keywords.filter((k) => k.active).length,
      openReportsCount: db.reports.filter((r) => r.status === 'OPEN' || r.status === 'INVESTIGATING').length
    },
    history: list
  });
});

// ============================================================================
// THREAT REPORTS ENDPOINTS
// ============================================================================
app.get('/api/reports', (req, res) => {
  const db = readDb();
  res.json(db.reports);
});

app.post('/api/reports', (req, res) => {
  const { user_id, scan_id, report_type, target_artifact, risk_level, details } = req.body || {};
  if (!target_artifact || !details) {
    return res.status(400).json({ error: 'Target artifact and report details are required.' });
  }
  const db = readDb();
  const newReport = {
    id: `rep-2026-${String(db.reports.length + 1).padStart(3, '0')}`,
    user_id: user_id || 'usr-analyst-01',
    scan_id: scan_id || null,
    report_type: report_type || 'Suspicious Phishing Artifact',
    target_artifact,
    risk_level: risk_level || 'HIGH',
    status: 'OPEN',
    details,
    analyst_notes: 'Awaiting SOC triage.',
    created_at: new Date().toISOString()
  };
  db.reports.unshift(newReport);
  writeDb(db);
  res.status(201).json(newReport);
});

app.patch('/api/reports/:id', (req, res) => {
  const { id } = req.params;
  const { status, analyst_notes } = req.body || {};
  const db = readDb();
  const idx = db.reports.findIndex((r) => r.id === id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Report not found.' });
  }
  if (status) db.reports[idx].status = status;
  if (analyst_notes !== undefined) db.reports[idx].analyst_notes = analyst_notes;
  writeDb(db);
  res.json(db.reports[idx]);
});

// ============================================================================
// ADMIN ENDPOINTS (Keywords CRUD, Users Management, Analytics)
// ============================================================================
app.get('/api/admin/keywords', (req, res) => {
  const db = readDb();
  res.json(db.suspicious_keywords);
});

app.post('/api/admin/keywords', (req, res) => {
  const { keyword, category = 'URGENCY', weight = 18 } = req.body || {};
  if (!keyword || !keyword.trim()) {
    return res.status(400).json({ error: 'Keyword text is required.' });
  }
  const db = readDb();
  const cleanKw = keyword.trim().toLowerCase();
  if (db.suspicious_keywords.some((k) => k.keyword.toLowerCase() === cleanKw)) {
    return res.status(409).json({ error: 'Keyword rule already exists.' });
  }
  const newRule = {
    id: `kw-${Date.now()}`,
    keyword: keyword.trim(),
    category,
    weight: Number(weight) || 18,
    active: true,
    added_by: 'admin',
    created_at: new Date().toISOString()
  };
  db.suspicious_keywords.unshift(newRule);
  writeDb(db);
  res.status(201).json(newRule);
});

app.patch('/api/admin/keywords/:id', (req, res) => {
  const { id } = req.params;
  const { active, weight, category } = req.body || {};
  const db = readDb();
  const idx = db.suspicious_keywords.findIndex((k) => k.id === id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Keyword rule not found.' });
  }
  if (typeof active === 'boolean') db.suspicious_keywords[idx].active = active;
  if (weight !== undefined) db.suspicious_keywords[idx].weight = Number(weight);
  if (category) db.suspicious_keywords[idx].category = category;
  writeDb(db);
  res.json(db.suspicious_keywords[idx]);
});

app.delete('/api/admin/keywords/:id', (req, res) => {
  const { id } = req.params;
  const db = readDb();
  db.suspicious_keywords = db.suspicious_keywords.filter((k) => k.id !== id);
  writeDb(db);
  res.json({ deleted: id });
});

app.get('/api/admin/users', (req, res) => {
  const db = readDb();
  const usersWithCounts = db.users.map(({ password, ...u }) => ({
    ...u,
    scanCount: db.scan_history.filter((s) => s.user_id === u.id).length
  }));
  res.json(usersWithCounts);
});

app.patch('/api/admin/users/:id', (req, res) => {
  const { id } = req.params;
  const { role, status, cyber_hygiene_score } = req.body || {};
  const db = readDb();
  const idx = db.users.findIndex((u) => u.id === id);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found.' });
  }
  if (role) db.users[idx].role = role;
  if (status) db.users[idx].status = status;
  if (cyber_hygiene_score !== undefined) db.users[idx].cyber_hygiene_score = Number(cyber_hygiene_score);
  writeDb(db);
  const { password, ...safeUser } = db.users[idx];
  res.json(safeUser);
});

ensureSeedScans().then(() => {
  app.listen(PORT, () => {
    console.log(`[VERICORE // X-RAY] Forensics Backend API listening on http://localhost:${PORT}`);
  });
});
