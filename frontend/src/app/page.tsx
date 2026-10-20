'use client';

import React, { useState, useEffect, useCallback } from 'react';
import {
  ScanLine,
  ShieldAlert,
  ShieldCheck,
  Radar,
  Swords,
  Award,
  LayoutDashboard,
  Shield,
  Link2,
  Mail,
  QrCode,
  FileCode2,
  Sparkles,
  Search,
  UserCheck,
  LogIn,
  PlusCircle,
  CheckCircle2,
  X,
  ArrowUpRight,
  Activity
} from 'lucide-react';
import XrayDissectionStage, { ScanRecord } from '@/components/XrayDissectionStage';
import QrQuishingPanel from '@/components/QrQuishingModal';
import RedTeamEvasionLab from '@/components/RedTeamEvasionLab';
import CyberRangeSimulator from '@/components/CyberRangeSimulator';
import SocAdminPanel, { KeywordRule, ThreatReport, PlatformUser } from '@/components/SocAdminPanel';
import { THREAT_PRESETS, ThreatPreset } from '@/lib/presets';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export default function VericoreXrayPlatform() {
  // Primary navigation tabs
  const [activeNav, setActiveNav] = useState<
    'XRAY_SCANNER' | 'RED_VS_BLUE' | 'CYBER_RANGE' | 'DASHBOARD_HISTORY' | 'ADMIN_PANEL'
  >('XRAY_SCANNER');

  // Scanner input state
  const [scanMode, setScanMode] = useState<'url' | 'email' | 'qr' | 'header'>('url');
  const [inputContent, setInputContent] = useState<string>(THREAT_PRESETS[0].content);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);

  // User & Auth state
  const [currentUser, setCurrentUser] = useState<{
    id: string;
    name: string;
    email: string;
    role: 'user' | 'admin';
    cyber_hygiene_score?: number;
  }>({
    id: 'usr-analyst-01',
    name: 'Shreya (Security Analyst)',
    email: 'analyst@vericore.sec',
    role: 'user',
    cyber_hygiene_score: 92
  });
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authMode, setAuthMode] = useState<'LOGIN' | 'REGISTER'>('LOGIN');
  const [authForm, setAuthForm] = useState({ name: '', email: '', password: '', role: 'user' });
  const [authError, setAuthError] = useState('');

  // History, Stats, Reports & Admin state
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    safeCount: 0,
    suspiciousCount: 0,
    criticalCount: 0,
    avgRiskScore: 0,
    naiveBypassCount: 0,
    activeRulesCount: 20,
    openReportsCount: 3
  });
  const [keywords, setKeywords] = useState<KeywordRule[]>([]);
  const [reports, setReports] = useState<ThreatReport[]>([]);
  const [users, setUsers] = useState<PlatformUser[]>([]);

  // History Filters
  const [filterType, setFilterType] = useState('ALL');
  const [filterRisk, setFilterRisk] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Report Threat Modal
  const [reportModalScan, setReportModalScan] = useState<ScanRecord | null>(null);
  const [reportTypeInput, setReportTypeInput] = useState('Brand Impersonation & Credential Phishing');
  const [reportDetailsInput, setReportDetailsInput] = useState('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const fetchAllData = useCallback(async () => {
    try {
      const [histRes, kwRes, repRes, usrRes] = await Promise.all([
        fetch(
          `${API_BASE}/api/history?scanType=${filterType}&riskLevel=${filterRisk}&search=${encodeURIComponent(
            searchQuery
          )}`
        ),
        fetch(`${API_BASE}/api/admin/keywords`),
        fetch(`${API_BASE}/api/reports`),
        fetch(`${API_BASE}/api/admin/users`)
      ]);

      if (histRes.ok) {
        const data = await histRes.json();
        setHistory(data.history || []);
        if (data.stats) setStats(data.stats);
        if (!activeScan && data.history && data.history.length > 0) {
          setActiveScan(data.history[0]);
        }
      }
      if (kwRes.ok) setKeywords(await kwRes.json());
      if (repRes.ok) setReports(await repRes.json());
      if (usrRes.ok) setUsers(await usrRes.json());
    } catch (err) {
      console.error('Error syncing with backend:', err);
    }
  }, [filterType, filterRisk, searchQuery, activeScan]);

  useEffect(() => {
    fetchAllData();
  }, [fetchAllData]);

  const executeScan = async (overrideType?: 'url' | 'email' | 'qr' | 'header', overrideContent?: string) => {
    const targetType = overrideType || scanMode;
    const targetContent = overrideContent !== undefined ? overrideContent : inputContent;
    if (!targetContent.trim()) return;

    setIsScanning(true);
    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanType: targetType,
          content: targetContent,
          userId: currentUser.id
        })
      });
      if (res.ok) {
        const record: ScanRecord = await res.json();
        setActiveScan(record);
        setActiveNav('XRAY_SCANNER');
        await fetchAllData();
        showToast(`Dissection Complete: ${record.risk_level} RISK (${record.risk_score}%)`);
      }
    } catch (err) {
      console.error('Scan request failed:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectPreset = (preset: ThreatPreset) => {
    setScanMode(preset.scanType);
    setInputContent(preset.content);
    executeScan(preset.scanType, preset.content);
  };

  const handleRoleSwitch = async (targetRole: 'user' | 'admin') => {
    try {
      const res = await fetch(`${API_BASE}/api/auth/demo-switch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: targetRole })
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentUser(data.user);
        showToast(`Switched active role to ${data.user.name} [${data.user.role.toUpperCase()}]`);
        if (targetRole === 'admin') {
          setActiveNav('ADMIN_PANEL');
        }
      }
    } catch (_) {}
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    const endpoint = authMode === 'LOGIN' ? '/api/auth/login' : '/api/auth/register';
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(authForm)
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(data.error || 'Authentication failed');
        return;
      }
      setCurrentUser(data.user);
      setAuthModalOpen(false);
      showToast(`Authenticated as ${data.user.name}`);
      fetchAllData();
    } catch (err) {
      setAuthError('Could not connect to authentication server');
    }
  };

  const handleOpenReportModal = (scan: ScanRecord) => {
    setReportModalScan(scan);
    setReportTypeInput(
      scan.scan_type === 'email' || scan.scan_type === 'header'
        ? 'Spear-Phishing & Envelope Spoofing'
        : scan.scan_type === 'qr'
          ? 'QR Code Quishing Vector'
          : 'Brand Impersonation & Deceptive URL'
    );
    setReportDetailsInput(
      `X-Ray Risk Score: ${scan.risk_score}% (${scan.risk_level}). ${scan.result}. Recommended quarantine and DNS sinkhole.`
    );
  };

  const submitThreatReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportModalScan) return;
    const res = await fetch(`${API_BASE}/api/reports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: currentUser.id,
        scan_id: reportModalScan.id,
        report_type: reportTypeInput,
        target_artifact: reportModalScan.content.slice(0, 180),
        risk_level: reportModalScan.risk_level,
        details: reportDetailsInput
      })
    });
    if (res.ok) {
      setReportModalScan(null);
      await fetchAllData();
      showToast('Official Threat Report filed to SOC Queue!');
    }
  };

  // Admin handlers
  const handleAddKeyword = async (keyword: string, category: string, weight: number) => {
    const res = await fetch(`${API_BASE}/api/admin/keywords`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keyword, category, weight })
    });
    if (res.ok) {
      await fetchAllData();
      showToast(`Deployed live heuristic rule: "${keyword}" (+${weight} pts)`);
    }
  };

  const handleToggleKeyword = async (id: string, active: boolean) => {
    await fetch(`${API_BASE}/api/admin/keywords/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ active })
    });
    await fetchAllData();
  };

  const handleDeleteKeyword = async (id: string) => {
    await fetch(`${API_BASE}/api/admin/keywords/${id}`, { method: 'DELETE' });
    await fetchAllData();
    showToast('Removed heuristic rule');
  };

  const handleUpdateReportStatus = async (id: string, status: ThreatReport['status']) => {
    await fetch(`${API_BASE}/api/reports/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    });
    await fetchAllData();
    showToast(`Updated Incident Report ${id} -> ${status}`);
  };

  const handleUpdateUser = async (id: string, updates: Partial<PlatformUser>) => {
    await fetch(`${API_BASE}/api/admin/users/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    await fetchAllData();
    showToast(`Updated user ${id}`);
  };

  return (
    <div className="min-h-screen xray-grid-bg flex flex-col">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-[#0D121B] border-2 border-[#00F0FF] text-white px-4 py-3 rounded-xl shadow-[0_0_25px_rgba(0,240,255,0.3)] flex items-center gap-2.5 font-mono text-xs">
          <CheckCircle2 className="w-4 h-4 text-[#00F0FF] shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* TOP COMMAND HEADER */}
      <header className="sticky top-0 z-40 border-b border-slate-800/90 bg-[#070A0F]/95 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3.5 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          {/* Brand Logo */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#00F0FF]/15 border border-[#00F0FF] flex items-center justify-center shadow-[0_0_20px_rgba(0,240,255,0.25)]">
                <ScanLine className="w-5 h-5 text-[#00F0FF]" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-base font-bold tracking-wider text-white">
                    VERICORE <span className="text-[#00F0FF]">// X-RAY</span>
                  </span>
                  <span className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono bg-[#00E599]/15 text-[#00E599] border border-[#00E599]/40">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#00E599] animate-ping" />
                    4-LAYER ENGINE ONLINE
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 font-mono">
                  Multi-Layer Phishing Dissection &amp; Threat Intelligence Platform
                </p>
              </div>
            </div>
          </div>

          {/* Primary Navigation Bar */}
          <nav className="flex items-center gap-1.5 overflow-x-auto pb-1 lg:pb-0">
            {[
              { id: 'XRAY_SCANNER', label: 'X-Ray Dissector', icon: ScanLine },
              { id: 'RED_VS_BLUE', label: 'Red vs. Blue Lab', icon: Swords },
              { id: 'CYBER_RANGE', label: 'Spot-the-Phish Range', icon: Award },
              {
                id: 'DASHBOARD_HISTORY',
                label: `Telemetry & History (${stats.totalScans})`,
                icon: LayoutDashboard
              },
              {
                id: 'ADMIN_PANEL',
                label: 'SOC Admin',
                icon: Shield,
                badge: currentUser.role === 'admin' ? 'ACTIVE' : undefined
              }
            ].map((item) => {
              const Icon = item.icon;
              const active = activeNav === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveNav(item.id as typeof activeNav)}
                  className={`px-3 py-2 rounded-lg font-mono text-xs flex items-center gap-1.5 shrink-0 transition-all border ${
                    active
                      ? 'bg-[#00F0FF] text-slate-950 font-bold border-[#00F0FF] shadow-[0_0_16px_rgba(0,240,255,0.25)]'
                      : 'bg-[#0D121B] text-slate-300 border-slate-800 hover:border-slate-700 hover:text-white'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right User / 1-Click Role Switcher & Auth */}
          <div className="flex items-center gap-2 self-end lg:self-auto">
            <div className="flex items-center bg-[#0D121B] p-1 rounded-lg border border-slate-800 text-xs font-mono">
              <button
                onClick={() => handleRoleSwitch('user')}
                className={`px-2.5 py-1 rounded transition-all ${
                  currentUser.role === 'user'
                    ? 'bg-[#00F0FF]/20 text-[#00F0FF] font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Analyst User
              </button>
              <button
                onClick={() => handleRoleSwitch('admin')}
                className={`px-2.5 py-1 rounded transition-all ${
                  currentUser.role === 'admin'
                    ? 'bg-[#00F0FF]/20 text-[#00F0FF] font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                SOC Admin
              </button>
            </div>

            <button
              onClick={() => setAuthModalOpen(true)}
              className="px-3 py-1.5 rounded-lg bg-[#131B28] hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-200 flex items-center gap-1.5"
            >
              <LogIn className="w-3.5 h-3.5 text-[#00F0FF]" />
              <span className="hidden sm:inline">{currentUser.name.split(' ')[0]}</span>
            </button>
          </div>
        </div>
      </header>

      {/* MAIN WORKBENCH CONTENT */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* ===================================================================
            TAB 1: MULTI-MODAL X-RAY DISSECTION SCANNER + 4-LAYER STAGE
           =================================================================== */}
        {activeNav === 'XRAY_SCANNER' && (
          <div className="space-y-6">
            {/* Scanner Input Console */}
            <div className="rounded-xl border border-slate-800 bg-[#0D121B] p-5 shadow-xl space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div>
                  <h1 className="text-lg sm:text-xl font-bold text-white flex items-center gap-2">
                    <Sparkles className="w-5 h-5 text-[#00F0FF]" />
                    Anatomical Phishing X-Ray Probe
                  </h1>
                  <p className="text-xs text-slate-400">
                    Inspect URLs, spear-phishing emails, raw SMTP headers (SPF/DKIM/DMARC), or QR Quishing matrices across 4 forensic layers.
                  </p>
                </div>

                {/* 4 Modality Tabs */}
                <div className="flex flex-wrap gap-1.5">
                  {[
                    { id: 'url', label: 'URL Forensics Probe', icon: Link2 },
                    { id: 'email', label: 'Email Spectrometer', icon: Mail },
                    { id: 'header', label: 'Raw SMTP Headers', icon: FileCode2 },
                    { id: 'qr', label: 'QR "Quishing" Decoder', icon: QrCode }
                  ].map((m) => {
                    const Icon = m.icon;
                    const active = scanMode === m.id;
                    return (
                      <button
                        key={m.id}
                        onClick={() => setScanMode(m.id as typeof scanMode)}
                        className={`px-3 py-1.5 rounded-lg font-mono text-xs flex items-center gap-1.5 border transition-all ${
                          active
                            ? 'bg-[#00F0FF]/20 text-[#00F0FF] border-[#00F0FF] font-bold'
                            : 'bg-[#090D14] text-slate-400 border-slate-800 hover:text-white'
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5" />
                        {m.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* One-Click Curated Threat & Benign Presets */}
              <div className="space-y-1.5">
                <div className="text-[11px] font-mono text-slate-400 uppercase flex items-center gap-1.5">
                  <span>⚡ Instant Threat &amp; Benign Test Specimens (Click to Dissect):</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {THREAT_PRESETS.map((preset) => (
                    <button
                      key={preset.id}
                      onClick={() => handleSelectPreset(preset)}
                      className={`p-2.5 rounded-lg border text-left transition-all flex items-start justify-between gap-2 ${
                        inputContent === preset.content
                          ? 'bg-[#131B28] border-[#00F0FF] shadow-[0_0_12px_rgba(0,240,255,0.15)]'
                          : 'bg-[#090D14] border-slate-800/90 hover:border-slate-700'
                      }`}
                    >
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <span
                            className={`font-mono text-[9.5px] px-1.5 py-0.2 rounded font-bold ${
                              preset.badge.includes('BENIGN')
                                ? 'bg-[#00E599]/20 text-[#00E599]'
                                : 'bg-[#FF2E54]/20 text-[#FF2E54]'
                            }`}
                          >
                            {preset.badge}
                          </span>
                          <span className="text-xs font-semibold text-white truncate">
                            {preset.label}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 line-clamp-1">{preset.summary}</p>
                      </div>
                      <ArrowUpRight className="w-3.5 h-3.5 text-[#00F0FF] shrink-0 mt-0.5" />
                    </button>
                  ))}
                </div>
              </div>

              {/* Input Box OR QR Quishing Optical Panel */}
              {scanMode === 'qr' ? (
                <QrQuishingPanel
                  onDissectQrPayload={(decodedUrl) => {
                    setInputContent(decodedUrl);
                    executeScan('qr', decodedUrl);
                  }}
                />
              ) : (
                <div className="space-y-3">
                  {scanMode === 'url' ? (
                    <div className="flex flex-col sm:flex-row gap-3">
                      <input
                        type="text"
                        value={inputContent}
                        onChange={(e) => setInputContent(e.target.value)}
                        placeholder="Paste suspicious URL (e.g., https://pаypal.com.secure-session-auth.top/verify)..."
                        className="flex-1 px-4 py-3 rounded-xl bg-[#070A0F] border border-slate-700 font-mono text-sm text-white focus:outline-none focus:border-[#00F0FF]"
                      />
                      <button
                        onClick={() => executeScan()}
                        disabled={isScanning}
                        className="px-6 py-3 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-slate-950 font-mono text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-[0_0_25px_rgba(0,240,255,0.3)] shrink-0 transition-all"
                      >
                        <ScanLine className="w-4 h-4" />
                        {isScanning ? 'DISSECTING...' : 'LAUNCH X-RAY DISSECTION'}
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <textarea
                        rows={5}
                        value={inputContent}
                        onChange={(e) => setInputContent(e.target.value)}
                        placeholder={
                          scanMode === 'header'
                            ? 'Paste raw email headers (From, Return-Path, Reply-To, Authentication-Results, Received) and body...'
                            : 'Paste suspicious email or SMS message content here...'
                        }
                        className="w-full p-4 rounded-xl bg-[#070A0F] border border-slate-700 font-mono text-xs sm:text-sm text-white focus:outline-none focus:border-[#00F0FF]"
                      />
                      <div className="flex justify-end">
                        <button
                          onClick={() => executeScan()}
                          disabled={isScanning}
                          className="px-6 py-3 rounded-xl bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-slate-950 font-mono text-xs sm:text-sm font-bold flex items-center gap-2 shadow-[0_0_25px_rgba(0,240,255,0.3)] transition-all"
                        >
                          <ScanLine className="w-4 h-4" />
                          {isScanning ? 'DISSECTING...' : 'LAUNCH 4-LAYER X-RAY DISSECTION'}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* THE 4-LAYER INTERACTIVE X-RAY DISSECTION STAGE */}
            {activeScan && (
              <XrayDissectionStage
                scan={activeScan}
                onReportThreat={(scan) => handleOpenReportModal(scan)}
              />
            )}
          </div>
        )}

        {/* ===================================================================
            TAB 2: RED-TEAM VS. BLUE-TEAM EVASION MUTATOR LAB
           =================================================================== */}
        {activeNav === 'RED_VS_BLUE' && (
          <RedTeamEvasionLab
            onLoadIntoXray={(type, content) => {
              setScanMode(type);
              setInputContent(content);
              executeScan(type, content);
            }}
          />
        )}

        {/* ===================================================================
            TAB 3: SPOT-THE-PHISH CYBER RANGE SIMULATOR
           =================================================================== */}
        {activeNav === 'CYBER_RANGE' && (
          <CyberRangeSimulator
            onSendScenarioToXray={(content) => {
              setScanMode('email');
              setInputContent(content);
              executeScan('email', content);
            }}
          />
        )}

        {/* ===================================================================
            TAB 4: TELEMETRY DASHBOARD, SCAN HISTORY & THREAT REPORTS
           =================================================================== */}
        {activeNav === 'DASHBOARD_HISTORY' && (
          <div className="space-y-6">
            {/* 5 Analytical Telemetry Cards (PRD Section 4.4) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
              <div className="p-4 rounded-xl bg-[#0D121B] border border-slate-800">
                <div className="text-[11px] font-mono text-slate-400">TOTAL SCANS</div>
                <div className="text-2xl font-mono font-bold text-white mt-1">
                  {stats.totalScans}
                </div>
                <div className="text-[11px] font-mono text-[#00F0FF] mt-1">
                  All 4 Modalities Logged
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#0D121B] border border-slate-800">
                <div className="text-[11px] font-mono text-slate-400">SUSPICIOUS / CRITICAL</div>
                <div className="text-2xl font-mono font-bold text-[#FF2E54] mt-1">
                  {stats.suspiciousCount}
                </div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  {stats.criticalCount} Critical Vectors
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#0D121B] border border-slate-800">
                <div className="text-[11px] font-mono text-slate-400">VERIFIED SAFE</div>
                <div className="text-2xl font-mono font-bold text-[#00E599] mt-1">
                  {stats.safeCount}
                </div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  Zero False-Positive Control
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#0D121B] border border-slate-800">
                <div className="text-[11px] font-mono text-slate-400">EVASIVE ATTACKS CAUGHT</div>
                <div className="text-2xl font-mono font-bold text-[#FFB800] mt-1">
                  {stats.naiveBypassCount}
                </div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">
                  Missed by Basic Scanners
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#0D121B] border border-slate-800">
                <div className="text-[11px] font-mono text-slate-400">AVG X-RAY RISK SCORE</div>
                <div className="text-2xl font-mono font-bold text-white mt-1">
                  {stats.avgRiskScore}%
                </div>
                <div className="text-[11px] font-mono text-[#00F0FF] mt-1">
                  {stats.activeRulesCount} Active SOC Rules
                </div>
              </div>
            </div>

            {/* Filter & Search Bar (PRD Week 3 Day 20) */}
            <div className="rounded-xl border border-slate-800 bg-[#0D121B] p-5 space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <h2 className="text-base font-bold text-white font-mono flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#00F0FF]" />
                  FORENSIC SCAN ARCHIVE &amp; TELEMETRY LOGS
                </h2>

                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search URL, domain, case ID..."
                      className="pl-8 pr-3 py-1.5 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-[#00F0FF]"
                    />
                  </div>

                  <select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    className="px-3 py-1.5 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
                  >
                    <option value="ALL">All Modalities</option>
                    <option value="url">URL Scans</option>
                    <option value="email">Email Scans</option>
                    <option value="qr">QR Quishing</option>
                    <option value="header">Header Scans</option>
                  </select>

                  <select
                    value={filterRisk}
                    onChange={(e) => setFilterRisk(e.target.value)}
                    className="px-3 py-1.5 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
                  >
                    <option value="ALL">All Risk Levels</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW (Safe)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2.5">
                {history.map((item) => (
                  <div
                    key={item.id}
                    className="p-4 rounded-xl bg-[#090D14] border border-slate-800 hover:border-slate-700 flex flex-col lg:flex-row lg:items-center justify-between gap-4 transition-all"
                  >
                    <div className="space-y-1 min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap font-mono text-xs">
                        <span className="text-[#00F0FF] font-bold">{item.id}</span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase text-[10px]">
                          {item.scan_type}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                            item.risk_level === 'CRITICAL'
                              ? 'bg-[#FF2E54]/20 text-[#FF2E54]'
                              : item.risk_level === 'HIGH'
                                ? 'bg-[#FFB800]/20 text-[#FFB800]'
                                : 'bg-[#00E599]/20 text-[#00E599]'
                          }`}
                        >
                          {item.risk_level} ({item.risk_score}%)
                        </span>
                        <span className="text-slate-500 text-[11px]">
                          Basic Scanner: {item.naive_scanner_score}%
                        </span>
                      </div>
                      <p className="font-mono text-xs text-white truncate">{item.content}</p>
                      <p className="text-xs text-slate-400">{item.result}</p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => {
                          setActiveScan(item);
                          setActiveNav('XRAY_SCANNER');
                        }}
                        className="px-3 py-2 rounded-lg bg-[#00F0FF]/15 hover:bg-[#00F0FF]/25 text-[#00F0FF] border border-[#00F0FF]/40 font-mono text-xs font-bold"
                      >
                        Inspect in 4-Layer X-Ray ↗
                      </button>
                      <button
                        onClick={() => handleOpenReportModal(item)}
                        className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs"
                      >
                        File Report
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================
            TAB 5: SOC ADMIN COMMAND PANEL
           =================================================================== */}
        {activeNav === 'ADMIN_PANEL' && (
          <SocAdminPanel
            keywords={keywords}
            reports={reports}
            users={users}
            history={history}
            onAddKeyword={handleAddKeyword}
            onToggleKeyword={handleToggleKeyword}
            onDeleteKeyword={handleDeleteKeyword}
            onUpdateReportStatus={handleUpdateReportStatus}
            onUpdateUser={handleUpdateUser}
            onInspectScan={(scan) => {
              setActiveScan(scan);
              setActiveNav('XRAY_SCANNER');
            }}
          />
        )}
      </main>

      {/* =====================================================================
          MODAL 1: JWT LOGIN / REGISTER AUTHENTICATION
         ===================================================================== */}
      {authModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D121B] border border-slate-700 rounded-2xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-mono text-sm uppercase text-[#00F0FF] font-bold">
                {authMode === 'LOGIN' ? 'JWT Operator Login' : 'Register New Operator'}
              </h3>
              <button
                onClick={() => setAuthModalOpen(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3 rounded-lg bg-[#090D14] border border-slate-800 text-xs font-mono text-slate-300 space-y-1">
              <div className="text-[#00F0FF] font-bold">Pre-Seeded Demo Accounts (Password: vericore123):</div>
              <div>• Analyst: analyst@vericore.sec</div>
              <div>• SOC Admin: admin@vericore.sec</div>
            </div>

            {authError && (
              <div className="p-2.5 rounded bg-[#FF2E54]/20 border border-[#FF2E54] text-xs font-mono text-[#FF2E54]">
                {authError}
              </div>
            )}

            <form onSubmit={handleAuthSubmit} className="space-y-3">
              {authMode === 'REGISTER' && (
                <div>
                  <label className="text-xs font-mono text-slate-400 block mb-1">Full Name</label>
                  <input
                    type="text"
                    required
                    value={authForm.name}
                    onChange={(e) => setAuthForm({ ...authForm, name: e.target.value })}
                    className="w-full px-3 py-2 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
                  />
                </div>
              )}
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={authForm.email}
                  onChange={(e) => setAuthForm({ ...authForm, email: e.target.value })}
                  placeholder="analyst@vericore.sec"
                  className="w-full px-3 py-2 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
                />
              </div>
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Password</label>
                <input
                  type="password"
                  required
                  value={authForm.password}
                  onChange={(e) => setAuthForm({ ...authForm, password: e.target.value })}
                  placeholder="vericore123"
                  className="w-full px-3 py-2 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
                />
              </div>

              <button
                type="submit"
                className="w-full py-2.5 rounded-lg bg-[#00F0FF] text-slate-950 font-mono text-xs font-bold"
              >
                {authMode === 'LOGIN' ? 'Authenticate via JWT' : 'Create Account'}
              </button>
            </form>

            <div className="text-center text-xs font-mono text-slate-400 pt-2 border-t border-slate-800">
              {authMode === 'LOGIN' ? (
                <button onClick={() => setAuthMode('REGISTER')} className="text-[#00F0FF] hover:underline">
                  Need a new account? Register here
                </button>
              ) : (
                <button onClick={() => setAuthMode('LOGIN')} className="text-[#00F0FF] hover:underline">
                  Already registered? Sign in
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          MODAL 2: FILE THREAT REPORT TO SOC
         ===================================================================== */}
      {reportModalScan && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <form
            onSubmit={submitThreatReport}
            className="bg-[#0D121B] border border-slate-700 rounded-2xl max-w-lg w-full p-6 space-y-4"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="font-mono text-sm uppercase text-[#FF2E54] font-bold">
                Escalate Artifact to SOC Threat Reports
              </h3>
              <button
                type="button"
                onClick={() => setReportModalScan(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-mono text-slate-400">Classification</label>
              <input
                type="text"
                value={reportTypeInput}
                onChange={(e) => setReportTypeInput(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-mono text-slate-400">Forensic Details &amp; Justification</label>
              <textarea
                rows={4}
                value={reportDetailsInput}
                onChange={(e) => setReportDetailsInput(e.target.value)}
                className="w-full p-3 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white"
              />
            </div>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setReportModalScan(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-xs font-mono text-slate-300"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 rounded-lg bg-[#FF2E54] text-white text-xs font-mono font-bold"
              >
                Submit Official Report
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
