'use client';

import React, { useState } from 'react';
import {
  Shield,
  Users,
  KeyRound,
  FileWarning,
  Plus,
  Trash2,
  CheckCircle2,
  AlertOctagon,
  Sliders,
  Activity
} from 'lucide-react';
import { ScanRecord } from './XrayDissectionStage';

export interface KeywordRule {
  id: string;
  keyword: string;
  category: string;
  weight: number;
  active: boolean;
  added_by: string;
  created_at: string;
}

export interface ThreatReport {
  id: string;
  user_id: string;
  scan_id: string | null;
  report_type: string;
  target_artifact: string;
  risk_level: string;
  status: 'OPEN' | 'INVESTIGATING' | 'BLOCKLISTED' | 'FALSE_POSITIVE' | 'RESOLVED';
  details: string;
  analyst_notes: string;
  created_at: string;
}

export interface PlatformUser {
  id: string;
  name: string;
  email: string;
  role: 'user' | 'admin';
  status: 'active' | 'suspended';
  cyber_hygiene_score: number;
  scanCount: number;
  created_at: string;
}

interface Props {
  keywords: KeywordRule[];
  reports: ThreatReport[];
  users: PlatformUser[];
  history: ScanRecord[];
  onAddKeyword: (keyword: string, category: string, weight: number) => Promise<void>;
  onToggleKeyword: (id: string, active: boolean) => Promise<void>;
  onDeleteKeyword: (id: string) => Promise<void>;
  onUpdateReportStatus: (id: string, status: ThreatReport['status'], notes?: string) => Promise<void>;
  onUpdateUser: (id: string, updates: Partial<PlatformUser>) => Promise<void>;
  onInspectScan: (scan: ScanRecord) => void;
}

export default function SocAdminPanel({
  keywords,
  reports,
  users,
  history,
  onAddKeyword,
  onToggleKeyword,
  onDeleteKeyword,
  onUpdateReportStatus,
  onUpdateUser,
  onInspectScan
}: Props) {
  const [subTab, setSubTab] = useState<'KEYWORDS' | 'REPORTS' | 'USERS' | 'LOGS'>('KEYWORDS');
  const [newKw, setNewKw] = useState('');
  const [newCategory, setNewCategory] = useState('URGENCY');
  const [newWeight, setNewWeight] = useState(20);

  const handleCreateKeyword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKw.trim()) return;
    await onAddKeyword(newKw.trim(), newCategory, newWeight);
    setNewKw('');
  };

  return (
    <div className="space-y-6">
      {/* Top Admin Command Banner */}
      <div className="rounded-xl border border-[#00F0FF]/40 bg-[#0D121B] p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#00F0FF]/15 text-[#00F0FF] font-mono text-xs mb-1.5">
            <Shield className="w-3.5 h-3.5" />
            SOC ADMINISTRATOR COMMAND CENTER (PRD SECTION 5 &amp; 6.2)
          </div>
          <h2 className="text-xl font-bold text-white">
            Heuristic Rule Engine, Incident Reports &amp; User Governance
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Changes made to phishing keywords or TLD weights here immediately update the live 4-Layer X-Ray Forensics Engine.
          </p>
        </div>

        <div className="flex flex-wrap gap-2">
          {[
            { id: 'KEYWORDS', label: `Heuristic Rules (${keywords.length})`, icon: KeyRound },
            { id: 'REPORTS', label: `Threat Reports (${reports.length})`, icon: FileWarning },
            { id: 'USERS', label: `Users (${users.length})`, icon: Users },
            { id: 'LOGS', label: `Detection Logs (${history.length})`, icon: Activity }
          ].map((t) => {
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                onClick={() => setSubTab(t.id as typeof subTab)}
                className={`px-3.5 py-2 rounded-lg font-mono text-xs flex items-center gap-1.5 border transition-all ${
                  subTab === t.id
                    ? 'bg-[#00F0FF] text-slate-950 font-bold border-[#00F0FF]'
                    : 'bg-[#090D14] text-slate-300 border-slate-800 hover:border-slate-700'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* SUBTAB 1: MANAGE SUSPICIOUS KEYWORDS & HEURISTIC RULES */}
      {subTab === 'KEYWORDS' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <form
            onSubmit={handleCreateKeyword}
            className="lg:col-span-4 bg-[#0D121B] border border-slate-800 rounded-xl p-5 space-y-4 self-start"
          >
            <h3 className="font-mono text-xs uppercase text-[#00F0FF] flex items-center gap-2">
              <Plus className="w-4 h-4" />
              Add Live Phishing Heuristic Rule
            </h3>
            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-400">Keyword / Token / TLD</label>
              <input
                type="text"
                value={newKw}
                onChange={(e) => setNewKw(e.target.value)}
                placeholder="e.g., crypto airdrop, .buzz, confirm-kyc"
                className="w-full px-3 py-2 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-[#00F0FF]"
              />
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-mono text-slate-400">Manipulation Vector Category</label>
              <select
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#070A0F] border border-slate-700 text-xs font-mono text-white focus:outline-none focus:border-[#00F0FF]"
              >
                <option value="URGENCY">URGENCY &amp; COERCION</option>
                <option value="FEAR">FEAR &amp; CONSEQUENCE</option>
                <option value="AUTHORITY">AUTHORITY IMPERSONATION</option>
                <option value="CREDENTIAL">CREDENTIAL HARVESTING</option>
                <option value="SCARCITY">SCARCITY &amp; REWARD BAIT</option>
                <option value="URL_TOKEN">DECEPTIVE URL PATH TOKEN</option>
                <option value="SUSPICIOUS_TLD">HIGH-RISK TLD (.xyz, .zip, etc.)</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-400">Risk Weight Impact</span>
                <span className="text-[#00F0FF] font-bold">+{newWeight} pts</span>
              </div>
              <input
                type="range"
                min={5}
                max={45}
                value={newWeight}
                onChange={(e) => setNewWeight(Number(e.target.value))}
                className="w-full accent-[#00F0FF]"
              />
            </div>

            <button
              type="submit"
              className="w-full py-2.5 rounded-lg bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-slate-950 font-mono text-xs font-bold transition-all"
            >
              Deploy Rule to Live X-Ray Engine
            </button>
          </form>

          <div className="lg:col-span-8 bg-[#0D121B] border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="font-mono text-xs uppercase text-slate-300">
                Active Phishing Keyword &amp; TLD Signatures ({keywords.filter((k) => k.active).length} Active)
              </h3>
            </div>
            <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
              {keywords.map((kw) => (
                <div
                  key={kw.id}
                  className={`p-3 rounded-lg border flex items-center justify-between gap-3 ${
                    kw.active
                      ? 'bg-[#090D14] border-slate-800'
                      : 'bg-[#090D14]/40 border-slate-900 opacity-50'
                  }`}
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="font-mono text-xs font-bold text-white">
                      &ldquo;{kw.keyword}&rdquo;
                    </span>
                    <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-800 text-[#00F0FF]">
                      {kw.category}
                    </span>
                    <span className="font-mono text-xs text-[#FF2E54] font-bold">
                      +{kw.weight} RISK
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onToggleKeyword(kw.id, !kw.active)}
                      className={`px-2.5 py-1 rounded font-mono text-[10px] font-bold ${
                        kw.active
                          ? 'bg-[#00E599]/20 text-[#00E599] border border-[#00E599]/40'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {kw.active ? 'ACTIVE' : 'DISABLED'}
                    </button>
                    <button
                      onClick={() => onDeleteKeyword(kw.id)}
                      className="p-1.5 rounded bg-slate-800 hover:bg-[#FF2E54]/20 text-slate-400 hover:text-[#FF2E54] transition-all"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: MONITOR & TRIAGE THREAT REPORTS */}
      {subTab === 'REPORTS' && (
        <div className="bg-[#0D121B] border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-mono text-xs uppercase text-[#00F0FF]">
            SOC Incident &amp; Phishing Threat Reports Queue
          </h3>
          <div className="space-y-3">
            {reports.map((rep) => (
              <div
                key={rep.id}
                className="p-4 rounded-xl bg-[#090D14] border border-slate-800 space-y-3"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-[#00F0FF]">{rep.id}</span>
                    <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#FF2E54]/20 text-[#FF2E54]">
                      {rep.risk_level}
                    </span>
                    <span className="text-sm font-bold text-white">{rep.report_type}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {(['OPEN', 'INVESTIGATING', 'BLOCKLISTED', 'RESOLVED'] as const).map((st) => (
                      <button
                        key={st}
                        onClick={() => onUpdateReportStatus(rep.id, st)}
                        className={`px-2.5 py-1 rounded font-mono text-[10px] font-bold transition-all ${
                          rep.status === st
                            ? 'bg-[#00F0FF] text-slate-950'
                            : 'bg-slate-800 text-slate-400 hover:text-white'
                        }`}
                      >
                        {st}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="p-2.5 rounded bg-[#131B28] border border-slate-800 font-mono text-xs text-slate-200 break-all">
                  Artifact: {rep.target_artifact}
                </div>
                <p className="text-xs text-slate-300">{rep.details}</p>
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1 border-t border-slate-800/80">
                  <span>SOC Notes: {rep.analyst_notes}</span>
                  <span>{new Date(rep.created_at).toLocaleString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 3: USER MANAGEMENT */}
      {subTab === 'USERS' && (
        <div className="bg-[#0D121B] border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-mono text-xs uppercase text-[#00F0FF]">
            Platform User Directory &amp; Role Access Control
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {users.map((u) => (
              <div
                key={u.id}
                className="p-4 rounded-xl bg-[#090D14] border border-slate-800 flex items-center justify-between gap-4"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold text-white">{u.name}</span>
                    <span
                      className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                        u.role === 'admin'
                          ? 'bg-[#00F0FF]/20 text-[#00F0FF]'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {u.role}
                    </span>
                  </div>
                  <div className="text-xs font-mono text-slate-400">{u.email}</div>
                  <div className="text-[11px] font-mono text-slate-500">
                    Scans Run: {u.scanCount} // Hygiene Score: {u.cyber_hygiene_score}%
                  </div>
                </div>

                <div className="flex flex-col gap-2 shrink-0">
                  <button
                    onClick={() =>
                      onUpdateUser(u.id, { role: u.role === 'admin' ? 'user' : 'admin' })
                    }
                    className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 font-mono text-[10px] text-slate-200"
                  >
                    Switch to {u.role === 'admin' ? 'User' : 'Admin'}
                  </button>
                  <button
                    onClick={() =>
                      onUpdateUser(u.id, {
                        status: u.status === 'active' ? 'suspended' : 'active'
                      })
                    }
                    className={`px-3 py-1 rounded font-mono text-[10px] font-bold ${
                      u.status === 'active'
                        ? 'bg-[#00E599]/15 text-[#00E599]'
                        : 'bg-[#FF2E54]/20 text-[#FF2E54]'
                    }`}
                  >
                    {u.status === 'active' ? 'ACTIVE' : 'SUSPENDED'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUBTAB 4: GLOBAL DETECTION LOGS */}
      {subTab === 'LOGS' && (
        <div className="bg-[#0D121B] border border-slate-800 rounded-xl p-5 space-y-4">
          <h3 className="font-mono text-xs uppercase text-[#00F0FF]">
            Global Platform Detection Telemetry Logs
          </h3>
          <div className="space-y-2.5">
            {history.map((h) => (
              <div
                key={h.id}
                className="p-3.5 rounded-lg bg-[#090D14] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1 max-w-2xl">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    <span className="text-[#00F0FF]">{h.id}</span>
                    <span className="uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                      {h.scan_type}
                    </span>
                    <span
                      className={`font-bold ${
                        h.risk_score >= 50 ? 'text-[#FF2E54]' : 'text-[#00E599]'
                      }`}
                    >
                      X-Ray Score: {h.risk_score}% (Naive: {h.naive_scanner_score}%)
                    </span>
                  </div>
                  <div className="text-xs font-mono text-slate-300 truncate">{h.content}</div>
                </div>
                <button
                  onClick={() => onInspectScan(h)}
                  className="px-3 py-1.5 rounded bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 font-mono text-xs shrink-0 hover:bg-[#00F0FF]/25"
                >
                  Re-Open in X-Ray ↗
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
