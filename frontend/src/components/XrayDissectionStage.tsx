'use client';

import React, { useState, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Eye,
  Crosshair,
  Layers,
  Cpu,
  Globe,
  Radar,
  Terminal,
  Copy,
  Check,
  Flag,
  Download,
  AlertTriangle,
  Lock,
  Unlock,
  Mail,
  ExternalLink,
  Sparkles,
  ArrowRight
} from 'lucide-react';

export interface ScanRecord {
  id: string;
  user_id: string;
  scan_type: 'url' | 'email' | 'qr' | 'header';
  content: string;
  result: string;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  naive_scanner_score: number;
  recommendation?: string;
  created_at: string;
  forensic_layers: {
    layer1_surface: {
      title: string;
      subtitle: string;
      victimSummary: {
        kind: string;
        displayFrom?: string;
        subject?: string;
        previewBody?: string;
        ctaUrl?: string;
        displayUrl?: string;
        protocolBadge?: string;
        brandClaimed?: string;
        pageHeadline?: string;
      };
      xrayHotspots: {
        id: string;
        slot: string;
        victimSees: string;
        xrayReveals: string;
        severity: 'SAFE' | 'WARN' | 'CRITICAL';
        explanation: string;
      }[];
    };
    layer2_deception: {
      title: string;
      subtitle: string;
      radarAxes: { axis: string; score: number }[];
      homographAnalysis: {
        charBreakdown: {
          char: string;
          codePoint: string;
          isSpoof: boolean;
          isDigitSubstitution: boolean;
          looksLike: string;
        }[];
        unicodeSpoofs: {
          index: number;
          char: string;
          codePoint: string;
          looksLike: string;
          description: string;
        }[];
        isPunycode: boolean;
        regDomain: string;
        subdomains: string;
        matchedBrand: {
          brand: string;
          officialDomain: string;
          impersonationType: string;
          distance: number;
          isImpersonation: boolean;
          explanation: string;
        } | null;
      };
      inlineHighlights: {
        phrase: string;
        category: string;
        weight: number;
        explanation: string;
      }[];
      matchedKeywordCount: number;
    };
    layer3_wire: {
      title: string;
      subtitle: string;
      urlAnatomy: {
        part: string;
        value: string;
        status: 'SAFE' | 'WARN' | 'CRITICAL';
        detail: string;
      }[];
      entropy: {
        hostnameEntropy: number;
        payloadEntropy: number;
        dgaLikelihood: string;
        urlLength: number;
        subdomainDepth: number;
        hyphenCount: number;
      };
      dnsTelemetry: {
        isRawIp: boolean;
        resolved: boolean;
        latencyMs: number;
        aRecords: string[];
        mxRecords: string[];
        txtRecords: string[];
        spfPresent: boolean;
        dmarcPresent: boolean;
        note: string;
      };
      headerForensics: {
        hasExplicitHeaders: boolean;
        fromRaw: string;
        fromDomain: string | null;
        returnPathRaw: string;
        returnPathDomain: string | null;
        replyToRaw: string | null;
        replyToDomain: string | null;
        subjectRaw: string;
        spfStatus: string;
        dkimStatus: string;
        dmarcStatus: string;
        envelopeMismatch: boolean;
        replyToMismatch: boolean;
        hops: string[];
      };
    };
    layer4_intel: {
      title: string;
      subtitle: string;
      virusTotal: {
        mode: string;
        malicious: number;
        suspicious: number;
        harmless: number;
        undetected: number;
        totalEngines: number;
        flaggedVendors: string[];
      };
      googleSafeBrowsing: {
        mode: string;
        status: string;
        threatType: string;
        platformType: string;
      };
      redVsBlue: {
        naiveScannerScore: number;
        vericoreXrayScore: number;
        detectionDelta: number;
        bypassedNaiveScanner: boolean;
        evasionFlags: string[];
      };
      defangedIoc: {
        url: string;
        domain: string;
        firewallRule: string;
      };
    };
  };
}

interface Props {
  scan: ScanRecord;
  onReportThreat: (scan: ScanRecord) => void;
}

export default function XrayDissectionStage({ scan, onReportThreat }: Props) {
  // Depth Slider: 1 = Surface X-Ray, 2 = Deception Mask, 3 = Wire/Protocol, 4 = Threat Intel, 0 = Exploded All-4-Layers View
  const [activeDepth, setActiveDepth] = useState<number>(1);
  const [xrayMode, setXrayMode] = useState<'CURTAIN' | 'SPOTLIGHT'>('CURTAIN');
  const [curtainPercent, setCurtainPercent] = useState<number>(52);
  const [lensPos, setLensPos] = useState<{ x: number; y: number; active: boolean }>({
    x: 280,
    y: 140,
    active: true
  });
  const [copiedIoc, setCopiedIoc] = useState(false);
  const stageRef = useRef<HTMLDivElement>(null);

  const layers = scan.forensic_layers;
  const l1 = layers.layer1_surface;
  const l2 = layers.layer2_deception;
  const l3 = layers.layer3_wire;
  const l4 = layers.layer4_intel;

  const handleStageMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!stageRef.current) return;
    const rect = stageRef.current.getBoundingClientRect();
    const x = Math.max(0, Math.min(rect.width, e.clientX - rect.left));
    const y = Math.max(0, Math.min(rect.height, e.clientY - rect.top));
    if (xrayMode === 'SPOTLIGHT') {
      setLensPos({ x, y, active: true });
    }
  };

  const copyDefanged = () => {
    const text = `IOC URL: ${l4.defangedIoc.url}\nDomain: ${l4.defangedIoc.domain}\nFirewall Rule: ${l4.defangedIoc.firewallRule}`;
    navigator.clipboard.writeText(text);
    setCopiedIoc(true);
    setTimeout(() => setCopiedIoc(false), 2000);
  };

  const exportCaseDossier = () => {
    const reportBlob = new Blob([JSON.stringify(scan, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(reportBlob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VERICORE-XRAY-CASE-${scan.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const riskBadgeStyle =
    scan.risk_level === 'CRITICAL'
      ? 'bg-[#FF2E54]/15 text-[#FF2E54] border-[#FF2E54]/50'
      : scan.risk_level === 'HIGH'
        ? 'bg-[#FFB800]/15 text-[#FFB800] border-[#FFB800]/50'
        : scan.risk_level === 'MEDIUM'
          ? 'bg-amber-400/15 text-amber-300 border-amber-400/40'
          : 'bg-[#00E599]/15 text-[#00E599] border-[#00E599]/50';

  const riskBarColor =
    scan.risk_level === 'CRITICAL'
      ? 'bg-[#FF2E54]'
      : scan.risk_level === 'HIGH'
        ? 'bg-[#FFB800]'
        : scan.risk_level === 'MEDIUM'
          ? 'bg-amber-400'
          : 'bg-[#00E599]';

  // Helper to draw 6-axis radar polygon
  const renderRadarChart = (axes: { axis: string; score: number }[]) => {
    const size = 250;
    const center = size / 2;
    const radius = 86;
    const angleStep = (Math.PI * 2) / axes.length;

    const getPoint = (index: number, valuePercent: number) => {
      const angle = index * angleStep - Math.PI / 2;
      const r = (valuePercent / 100) * radius;
      return {
        x: center + r * Math.cos(angle),
        y: center + r * Math.sin(angle)
      };
    };

    const polygonPoints = axes
      .map((item, idx) => {
        const pt = getPoint(idx, Math.max(8, item.score));
        return `${pt.x},${pt.y}`;
      })
      .join(' ');

    return (
      <div className="flex flex-col items-center">
        <svg width={size} height={size} className="overflow-visible">
          {/* Concentric rings */}
          {[25, 50, 75, 100].map((ring) => {
            const pts = axes
              .map((_, idx) => {
                const p = getPoint(idx, ring);
                return `${p.x},${p.y}`;
              })
              .join(' ');
            return (
              <polygon
                key={ring}
                points={pts}
                fill="none"
                stroke="rgba(0, 240, 255, 0.14)"
                strokeDasharray={ring === 100 ? 'none' : '2 2'}
                strokeWidth="1"
              />
            );
          })}
          {/* Axis spokes */}
          {axes.map((item, idx) => {
            const end = getPoint(idx, 100);
            const labelPt = getPoint(idx, 124);
            return (
              <g key={item.axis}>
                <line
                  x1={center}
                  y1={center}
                  x2={end.x}
                  y2={end.y}
                  stroke="rgba(0, 240, 255, 0.2)"
                  strokeWidth="1"
                />
                <text
                  x={labelPt.x}
                  y={labelPt.y}
                  textAnchor="middle"
                  dominantBaseline="middle"
                  className="fill-slate-300 font-mono text-[9.5px]"
                >
                  {item.axis.split(' ')[0]} ({item.score}%)
                </text>
              </g>
            );
          })}
          {/* Threat Polygon */}
          <polygon
            points={polygonPoints}
            fill={scan.risk_score >= 50 ? 'rgba(255, 46, 84, 0.28)' : 'rgba(0, 229, 153, 0.25)'}
            stroke={scan.risk_score >= 50 ? '#FF2E54' : '#00E599'}
            strokeWidth="2"
          />
          {axes.map((item, idx) => {
            const pt = getPoint(idx, Math.max(8, item.score));
            return (
              <circle
                key={idx}
                cx={pt.x}
                cy={pt.y}
                r="3.5"
                fill={item.score >= 50 ? '#FF2E54' : '#00F0FF'}
              />
            );
          })}
        </svg>
      </div>
    );
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0D121B] shadow-2xl overflow-hidden">
      {/* TOP VERDICT TELEMETRY HEADER */}
      <div className="border-b border-slate-800/90 bg-[#090D14] p-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-slate-800 text-[#00F0FF] border border-[#00F0FF]/30">
                CASE #{scan.id.toUpperCase()}
              </span>
              <span className={`font-mono text-xs font-semibold px-2.5 py-0.5 rounded border ${riskBadgeStyle}`}>
                RISK LEVEL: {scan.risk_level} ({scan.risk_score}%)
              </span>
              {l4.redVsBlue.bypassedNaiveScanner && (
                <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-[#FF2E54]/20 text-[#FF2E54] border border-[#FF2E54]/40 flex items-center gap-1">
                  <Sparkles className="w-3.5 h-3.5" />
                  CAUGHT EVASIVE ATTACK (NAIVE SCANNER SCORED ONLY {scan.naive_scanner_score}%)
                </span>
              )}
            </div>
            <h2 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              {scan.risk_score >= 50 ? (
                <ShieldAlert className="w-6 h-6 text-[#FF2E54] shrink-0" />
              ) : (
                <ShieldCheck className="w-6 h-6 text-[#00E599] shrink-0" />
              )}
              <span>{scan.result}</span>
            </h2>
            <p className="text-xs text-slate-400 max-w-3xl">{scan.recommendation}</p>
          </div>

          {/* RIGHT METERS: VERICORE vs NAIVE SCANNER */}
          <div className="flex items-center gap-4 bg-[#0D121B] border border-slate-800 rounded-lg p-3 shrink-0">
            <div className="w-36">
              <div className="flex justify-between text-[11px] font-mono mb-1">
                <span className="text-slate-400">BASIC SCANNER</span>
                <span className="text-slate-300">{scan.naive_scanner_score}%</span>
              </div>
              <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-slate-500 transition-all duration-500"
                  style={{ width: `${scan.naive_scanner_score}%` }}
                />
              </div>
              <p className="text-[10px] text-slate-500 font-mono mt-1">Simple Keyword/HTTP Check</p>
            </div>

            <div className="h-9 w-[1px] bg-slate-800" />

            <div className="w-40">
              <div className="flex justify-between text-[11px] font-mono mb-1">
                <span className="text-[#00F0FF] font-semibold">VERICORE X-RAY</span>
                <span className="text-white font-bold">{scan.risk_score}%</span>
              </div>
              <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full ${riskBarColor} transition-all duration-500`}
                  style={{ width: `${scan.risk_score}%` }}
                />
              </div>
              <p className="text-[10px] text-[#00F0FF]/80 font-mono mt-1">4-Layer Deep Dissection</p>
            </div>
          </div>
        </div>

        {/* 4-LAYER INTERACTIVE DEPTH SCRUBBER BAR */}
        <div className="mt-5 pt-4 border-t border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="font-mono text-xs uppercase tracking-wider text-[#00F0FF] flex items-center gap-1.5">
              <Layers className="w-4 h-4" />
              X-RAY DEPTH SCRUBBER:
            </span>
            {[
              { depth: 1, label: 'L1: Victim vs. X-Ray Lens', icon: Eye },
              { depth: 2, label: 'L2: Deception & Homographs', icon: Radar },
              { depth: 3, label: 'L3: Wire, DNS & Entropy', icon: Cpu },
              { depth: 4, label: 'L4: Threat Intel & Verdict', icon: Globe },
              { depth: 0, label: 'Explode All 4 Layers', icon: Sliders }
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeDepth === tab.depth;
              return (
                <button
                  key={tab.depth}
                  onClick={() => setActiveDepth(tab.depth)}
                  className={`px-3 py-1.5 rounded-md font-mono text-xs transition-all flex items-center gap-1.5 border ${
                    isActive
                      ? 'bg-[#00F0FF]/15 text-[#00F0FF] border-[#00F0FF] shadow-[0_0_15px_rgba(0,240,255,0.2)]'
                      : 'bg-[#131B28]/70 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {activeDepth > 0 && (
            <div className="flex items-center gap-3 bg-[#131B28] px-3 py-1.5 rounded-lg border border-slate-800">
              <span className="font-mono text-[11px] text-slate-400">DEPTH SLIDER</span>
              <input
                type="range"
                min={1}
                max={4}
                step={1}
                value={activeDepth}
                onChange={(e) => setActiveDepth(Number(e.target.value))}
                className="w-28 accent-[#00F0FF] cursor-pointer"
              />
              <span className="font-mono text-xs text-[#00F0FF] font-bold">L{activeDepth}/4</span>
            </div>
          )}
        </div>
      </div>

      <div className="p-5 space-y-6">
        {/* =====================================================================
            LAYER 1: INTERACTIVE X-RAY CURTAIN & SPOTLIGHT LOUPE DISSECTION
           ===================================================================== */}
        {(activeDepth === 1 || activeDepth === 0) && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#131B28]/70 p-3.5 rounded-lg border border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#00F0FF] animate-pulse" />
                  {l1.title}
                </h3>
                <p className="text-xs text-slate-400">{l1.subtitle}</p>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => setXrayMode('CURTAIN')}
                  className={`px-3 py-1.5 rounded text-xs font-mono border transition-all flex items-center gap-1.5 ${
                    xrayMode === 'CURTAIN'
                      ? 'bg-[#00F0FF] text-slate-950 font-bold border-[#00F0FF]'
                      : 'bg-slate-900 text-slate-300 border-slate-700 hover:border-slate-500'
                  }`}
                >
                  <Sliders className="w-3.5 h-3.5" />
                  Split Curtain Slider
                </button>
                <button
                  onClick={() => setXrayMode('SPOTLIGHT')}
                  className={`px-3 py-1.5 rounded text-xs font-mono border transition-all flex items-center gap-1.5 ${
                    xrayMode === 'SPOTLIGHT'
                      ? 'bg-[#00F0FF] text-slate-950 font-bold border-[#00F0FF]'
                      : 'bg-slate-900 text-slate-300 border-slate-700 hover:border-slate-500'
                  }`}
                >
                  <Crosshair className="w-3.5 h-3.5" />
                  Spotlight X-Ray Lens
                </button>
              </div>
            </div>

            {xrayMode === 'CURTAIN' && (
              <div className="flex items-center gap-3 bg-[#090D14] px-4 py-2.5 rounded-lg border border-slate-800">
                <span className="font-mono text-xs text-slate-300 shrink-0">
                  👁️ HUMAN ILLUSION ({100 - curtainPercent}%)
                </span>
                <input
                  type="range"
                  min={5}
                  max={95}
                  value={curtainPercent}
                  onChange={(e) => setCurtainPercent(Number(e.target.value))}
                  className="w-full accent-[#00F0FF] cursor-ew-resize"
                />
                <span className="font-mono text-xs text-[#00F0FF] font-semibold shrink-0">
                  ☢️ FORENSIC X-RAY ({curtainPercent}%)
                </span>
              </div>
            )}

            {/* DUAL-PLANE SUPERIMPOSED X-RAY STAGE */}
            <div
              ref={stageRef}
              onMouseMove={handleStageMouseMove}
              className={`relative rounded-xl border border-slate-700 overflow-hidden select-none min-h-[340px] ${
                xrayMode === 'SPOTLIGHT' ? 'cursor-crosshair' : ''
              }`}
            >
              {/* PLANE A (BASE): WHAT THE VICTIM SEES (HUMAN SURFACE ILLUSION) */}
              <div className="p-6 bg-[#F8FAFC] text-slate-900 min-h-[340px] flex flex-col justify-between">
                <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-200 text-slate-700">
                      SURFACE LAYER // WHAT THE VICTIM SEES
                    </span>
                    <span className="text-xs text-slate-500">
                      Designed to look trustworthy and urgent to the naked eye
                    </span>
                  </div>
                  <span className="text-xs font-mono text-slate-500">
                    {xrayMode === 'SPOTLIGHT' ? 'Move cursor to X-Ray underneath' : 'Drag slider above to peel layer'}
                  </span>
                </div>

                {/* Victim Browser / Email Simulation */}
                <div className="bg-white rounded-lg border border-slate-300 shadow-sm p-4 space-y-3">
                  {l1.victimSummary.kind === 'email' ? (
                    <>
                      <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                        <div className="flex items-center gap-2 text-sm font-medium text-slate-800">
                          <Mail className="w-4 h-4 text-blue-600" />
                          <span>{l1.victimSummary.displayFrom}</span>
                          <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700 font-medium">
                            ✓ Verified Sender Lookalike
                          </span>
                        </div>
                        <span className="text-xs text-slate-400">Today, 14:04</span>
                      </div>
                      <div className="font-semibold text-base text-slate-900">
                        {l1.victimSummary.subject}
                      </div>
                    </>
                  ) : (
                    <div className="flex items-center gap-2 bg-slate-100 px-3 py-2 rounded-md border border-slate-200">
                      {l1.victimSummary.protocolBadge?.includes('HTTPS') ? (
                        <Lock className="w-4 h-4 text-emerald-600 shrink-0" />
                      ) : (
                        <Unlock className="w-4 h-4 text-amber-600 shrink-0" />
                      )}
                      <span className="text-xs font-medium text-emerald-700 shrink-0">
                        {l1.victimSummary.protocolBadge}
                      </span>
                      <span className="text-slate-300">|</span>
                      <span className="text-sm font-mono text-slate-800 truncate">
                        {l1.victimSummary.displayUrl}
                      </span>
                    </div>
                  )}

                  {/* Hotspots as seen by Victim */}
                  <div className="space-y-2.5 pt-1">
                    {l1.xrayHotspots.map((hs) => (
                      <div
                        key={hs.id}
                        className="p-3 rounded-md bg-slate-50 border border-slate-200 flex items-center justify-between gap-3"
                      >
                        <div className="space-y-0.5">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400">
                            {hs.slot} (SURFACE APPEARANCE)
                          </span>
                          <p className="text-sm font-medium text-slate-800 break-all">{hs.victimSees}</p>
                        </div>
                        <span className="px-2.5 py-1 rounded text-xs bg-blue-600 text-white font-medium shrink-0 flex items-center gap-1">
                          Looks Normal <ExternalLink className="w-3 h-3" />
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-between text-xs text-slate-500">
                  <span>Victim Perception: High visual trust / Urgency compliance</span>
                  <span className="font-mono">LAYER 01 // OPTICAL ILLUSION</span>
                </div>
              </div>

              {/* PLANE B (OVERLAY): FORENSIC X-RAY TRUTH REVEALED UNDER THE BEAM */}
              <div
                style={{
                  clipPath:
                    xrayMode === 'CURTAIN'
                      ? `inset(0 0 0 ${100 - curtainPercent}%)`
                      : `circle(165px at ${lensPos.x}px ${lensPos.y}px)`
                }}
                className="absolute inset-0 p-6 xray-scanline-surface bg-[#060B13] text-[#E6EDF7] min-h-[340px] flex flex-col justify-between border-l-2 border-[#00F0FF]"
              >
                <div className="flex items-center justify-between border-b border-[#00F0FF]/30 pb-3 mb-4">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/50">
                      X-RAY SUBSURFACE // FORENSIC REALITY
                    </span>
                    <span className="text-xs text-[#00F0FF]/80 font-mono">
                      DECEPTION MASK STRIPPED
                    </span>
                  </div>
                  <span className="text-xs font-mono text-[#FF2E54] font-bold">
                    RISK SCORE: {scan.risk_score}/100
                  </span>
                </div>

                <div className="bg-[#0B121E]/95 rounded-lg border border-[#00F0FF]/40 p-4 space-y-3 shadow-[0_0_30px_rgba(0,240,255,0.12)]">
                  {l1.victimSummary.kind === 'email' ? (
                    <>
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                        <div className="flex items-center gap-2 text-xs font-mono text-[#FF2E54]">
                          <AlertTriangle className="w-4 h-4 text-[#FF2E54]" />
                          <span>ACTUAL SMTP RETURN-PATH: {l3.headerForensics.returnPathRaw}</span>
                        </div>
                        <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#FF2E54]/20 text-[#FF2E54]">
                          SPF: {l3.headerForensics.spfStatus}
                        </span>
                      </div>
                      <div className="font-mono text-sm text-[#FFB800]">
                        [PSYCHOLOGICAL TRIGGER ANALYSIS] {l1.victimSummary.subject}
                      </div>
                    </>
                  ) : (
                    <div className="flex items-center gap-2 bg-[#131C2E] px-3 py-2 rounded-md border border-[#FF2E54]/40">
                      <AlertTriangle className="w-4 h-4 text-[#FF2E54] shrink-0" />
                      <span className="text-xs font-mono text-[#FF2E54] font-bold shrink-0">
                        ROOT HOST: {l2.homographAnalysis.regDomain || 'UNVERIFIED'}
                      </span>
                      <span className="text-slate-600">|</span>
                      <span className="text-xs font-mono text-[#00F0FF] truncate">
                        ENTROPY: {l3.entropy.hostnameEntropy} bits/char // DNS: {l3.dnsTelemetry.aRecords[0] || 'NXDOMAIN'}
                      </span>
                    </div>
                  )}

                  {/* Hotspots as revealed by X-Ray */}
                  <div className="space-y-2.5 pt-1">
                    {l1.xrayHotspots.map((hs) => (
                      <div
                        key={hs.id}
                        className={`p-3 rounded-md border flex items-center justify-between gap-3 ${
                          hs.severity === 'CRITICAL'
                            ? 'bg-[#FF2E54]/15 border-[#FF2E54]/60 text-white'
                            : hs.severity === 'WARN'
                              ? 'bg-[#FFB800]/15 border-[#FFB800]/60 text-white'
                              : 'bg-[#00E599]/15 border-[#00E599]/60 text-white'
                        }`}
                      >
                        <div className="space-y-0.5">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-[#00F0FF]">
                            {hs.slot} // X-RAY FORENSIC TRUTH
                          </span>
                          <p className="text-xs sm:text-sm font-mono font-bold break-all">
                            {hs.xrayReveals}
                          </p>
                        </div>
                        <span
                          className={`px-2 py-1 rounded text-[11px] font-mono font-bold shrink-0 ${
                            hs.severity === 'CRITICAL'
                              ? 'bg-[#FF2E54] text-white'
                              : hs.severity === 'WARN'
                                ? 'bg-[#FFB800] text-slate-950'
                                : 'bg-[#00E599] text-slate-950'
                          }`}
                        >
                          {hs.severity}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-4 flex items-center justify-between text-xs font-mono text-[#00F0FF]">
                  <span>X-RAY TELEMETRY: ACTIVE RADIOGRAPHY</span>
                  <span>LAYER 01 // SUBSURFACE EXPOSED</span>
                </div>
              </div>

              {/* Vertical Curtain Divider Line */}
              {xrayMode === 'CURTAIN' && (
                <div
                  style={{ left: `${100 - curtainPercent}%` }}
                  className="absolute top-0 bottom-0 w-1 bg-[#00F0FF] shadow-[0_0_20px_#00F0FF] pointer-events-none flex items-center justify-center"
                >
                  <div className="w-7 h-7 rounded-full bg-[#00F0FF] text-slate-950 flex items-center justify-center font-mono text-[10px] font-bold shadow-lg">
                    ⇄
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* =====================================================================
            LAYER 2: DECEPTION & SOCIAL ENGINEERING RADAR + HOMOGRAPH DIFF
           ===================================================================== */}
        {(activeDepth === 2 || activeDepth === 0) && (
          <div className="space-y-4 pt-2">
            <div className="bg-[#131B28]/70 p-3.5 rounded-lg border border-slate-800">
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <Radar className="w-4 h-4 text-[#00F0FF]" />
                {l2.title}
              </h3>
              <p className="text-xs text-slate-400">{l2.subtitle}</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              {/* 6-Axis Radar Chart */}
              <div className="lg:col-span-5 bg-[#090D14] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs text-[#00F0FF] uppercase">
                    6-Axis Manipulation Radar
                  </span>
                  <span className="font-mono text-xs text-slate-400">
                    {l2.matchedKeywordCount} Heuristic Triggers
                  </span>
                </div>
                {renderRadarChart(l2.radarAxes)}
                <div className="grid grid-cols-2 gap-2 mt-2 pt-2 border-t border-slate-800/80">
                  {l2.radarAxes.map((ax) => (
                    <div key={ax.axis} className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-400 truncate pr-2">{ax.axis}</span>
                      <span
                        className={
                          ax.score >= 50
                            ? 'text-[#FF2E54] font-bold'
                            : ax.score >= 25
                              ? 'text-[#FFB800]'
                              : 'text-[#00E599]'
                        }
                      >
                        {ax.score}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Character-by-Character Homograph & Brand Impersonation Inspector */}
              <div className="lg:col-span-7 bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-xs text-[#00F0FF] uppercase">
                    Unicode / Homograph & Brand Typosquatting Matrix
                  </span>
                  {l2.homographAnalysis.matchedBrand && (
                    <span
                      className={`font-mono text-xs px-2.5 py-0.5 rounded border ${
                        l2.homographAnalysis.matchedBrand.isImpersonation
                          ? 'bg-[#FF2E54]/15 text-[#FF2E54] border-[#FF2E54]/50'
                          : 'bg-[#00E599]/15 text-[#00E599] border-[#00E599]/50'
                      }`}
                    >
                      {l2.homographAnalysis.matchedBrand.impersonationType}: {l2.homographAnalysis.matchedBrand.brand}
                    </span>
                  )}
                </div>

                {l2.homographAnalysis.charBreakdown.length > 0 ? (
                  <div>
                    <p className="text-xs text-slate-400 mb-2">
                      Character-by-character codepoint radiology of hostname (spoofed non-ASCII or digit substitutions glow crimson/amber):
                    </p>
                    <div className="flex flex-wrap gap-1.5 bg-[#0D121B] p-3 rounded-lg border border-slate-800">
                      {l2.homographAnalysis.charBreakdown.map((c, idx) => (
                        <div
                          key={idx}
                          className={`px-2 py-1.5 rounded text-center font-mono border transition-transform hover:scale-110 ${
                            c.isSpoof
                              ? 'bg-[#FF2E54]/25 border-[#FF2E54] text-white shadow-[0_0_12px_rgba(255,46,84,0.4)]'
                              : c.isDigitSubstitution
                                ? 'bg-[#FFB800]/20 border-[#FFB800] text-[#FFB800]'
                                : 'bg-[#131B28] border-slate-800 text-slate-200'
                          }`}
                        >
                          <div className="text-sm font-bold">{c.char}</div>
                          <div className="text-[9px] text-slate-400">{c.codePoint}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-xs font-mono text-slate-400 bg-[#0D121B] p-3 rounded border border-slate-800">
                    No URL hostname extracted; focusing on linguistic & header manipulation vectors below.
                  </div>
                )}

                {l2.homographAnalysis.matchedBrand && (
                  <div
                    className={`p-3 rounded-lg border text-xs ${
                      l2.homographAnalysis.matchedBrand.isImpersonation
                        ? 'bg-[#FF2E54]/10 border-[#FF2E54]/40 text-slate-200'
                        : 'bg-[#00E599]/10 border-[#00E599]/40 text-slate-200'
                    }`}
                  >
                    <div className="font-mono font-bold mb-1">
                      Target Brand: {l2.homographAnalysis.matchedBrand.brand} (Official: {l2.homographAnalysis.matchedBrand.officialDomain}) // Edit Distance: {l2.homographAnalysis.matchedBrand.distance}
                    </div>
                    <p className="text-slate-300">{l2.homographAnalysis.matchedBrand.explanation}</p>
                  </div>
                )}

                {/* Inline Psychological Triggers */}
                <div className="space-y-2">
                  <span className="font-mono text-xs text-slate-400 uppercase block">
                    Detected Social Engineering & Lexical Triggers
                  </span>
                  {l2.inlineHighlights.length > 0 ? (
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {l2.inlineHighlights.map((item, i) => (
                        <div
                          key={i}
                          className="p-2.5 rounded-lg bg-[#131B28] border border-slate-800 flex items-start justify-between gap-3"
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs font-bold text-[#FFB800]">
                                &ldquo;{item.phrase}&rdquo;
                              </span>
                              <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-800 text-[#00F0FF]">
                                {item.category}
                              </span>
                            </div>
                            <p className="text-xs text-slate-400 mt-1">{item.explanation}</p>
                          </div>
                          <span className="font-mono text-xs font-bold text-[#FF2E54] shrink-0">
                            +{item.weight} RISK
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 rounded-lg bg-[#131B28]/60 border border-slate-800 text-xs font-mono text-slate-400">
                      Zero dictionary spam keywords matched. If risk is elevated, this indicates a Zero-Keyword Evasive Attack caught by Layer 3/4 protocol forensics.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            LAYER 3: PROTOCOL, ENTROPY, LIVE DNS & HEADER WIRE FORENSICS
           ===================================================================== */}
        {(activeDepth === 3 || activeDepth === 0) && (
          <div className="space-y-4 pt-2">
            <div className="bg-[#131B28]/70 p-3.5 rounded-lg border border-slate-800">
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <Cpu className="w-4 h-4 text-[#00F0FF]" />
                {l3.title}
              </h3>
              <p className="text-xs text-slate-400">{l3.subtitle}</p>
            </div>

            {/* Anatomical URL Decomposition Tree */}
            {l3.urlAnatomy.length > 0 && (
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-3">
                <span className="font-mono text-xs text-[#00F0FF] uppercase block">
                  Anatomical URL Decomposition Pipeline
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                  {l3.urlAnatomy.map((node, i) => (
                    <div
                      key={i}
                      className={`p-3 rounded-lg border ${
                        node.status === 'CRITICAL'
                          ? 'bg-[#FF2E54]/10 border-[#FF2E54]/50'
                          : node.status === 'WARN'
                            ? 'bg-[#FFB800]/10 border-[#FFB800]/50'
                            : 'bg-[#131B28]/80 border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                        <span className="text-slate-400">{node.part}</span>
                        <span
                          className={`px-1.5 py-0.2 rounded font-bold ${
                            node.status === 'CRITICAL'
                              ? 'text-[#FF2E54]'
                              : node.status === 'WARN'
                                ? 'text-[#FFB800]'
                                : 'text-[#00E599]'
                          }`}
                        >
                          {node.status}
                        </span>
                      </div>
                      <div className="font-mono text-sm font-bold text-white break-all mb-1.5">
                        {node.value}
                      </div>
                      <p className="text-[11px] text-slate-400 leading-relaxed">{node.detail}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* Information Entropy & Structural Math */}
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-3">
                <span className="font-mono text-xs text-[#00F0FF] uppercase block">
                  Shannon Information Entropy H(X)
                </span>
                <div className="grid grid-cols-2 gap-2.5">
                  <div className="bg-[#131B28] p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] font-mono text-slate-400">HOST ENTROPY</div>
                    <div className="text-lg font-mono font-bold text-white">
                      {l3.entropy.hostnameEntropy} <span className="text-xs text-slate-400">bits/ch</span>
                    </div>
                  </div>
                  <div className="bg-[#131B28] p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] font-mono text-slate-400">PAYLOAD ENTROPY</div>
                    <div className="text-lg font-mono font-bold text-white">
                      {l3.entropy.payloadEntropy} <span className="text-xs text-slate-400">bits/ch</span>
                    </div>
                  </div>
                  <div className="bg-[#131B28] p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] font-mono text-slate-400">SUBDOMAIN DEPTH</div>
                    <div className="text-lg font-mono font-bold text-white">{l3.entropy.subdomainDepth} dots</div>
                  </div>
                  <div className="bg-[#131B28] p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] font-mono text-slate-400">HYPHENATION</div>
                    <div className="text-lg font-mono font-bold text-white">{l3.entropy.hyphenCount} hyphens</div>
                  </div>
                </div>
                <div className="text-xs font-mono text-slate-400 pt-1">
                  DGA Classification: <span className="text-[#00F0FF]">{l3.entropy.dgaLikelihood}</span>
                </div>
              </div>

              {/* Live Node.js DNS Resolution Telemetry */}
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-[#00F0FF] uppercase">
                    Live Node DNS Telemetry
                  </span>
                  <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {l3.dnsTelemetry.latencyMs}ms
                  </span>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div className="p-2.5 rounded bg-[#131B28] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">IPV4 (A) RECORDS:</span>
                    <span className="text-white">
                      {l3.dnsTelemetry.aRecords.length > 0
                        ? l3.dnsTelemetry.aRecords.join(', ')
                        : 'NONE (Unresolved / Ephemeral)'}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-[#131B28] border border-slate-800">
                    <span className="text-slate-400 block text-[10px]">MAIL EXCHANGE (MX):</span>
                    <span className="text-white">
                      {l3.dnsTelemetry.mxRecords.length > 0
                        ? l3.dnsTelemetry.mxRecords.join(', ')
                        : 'No MX Records Configured'}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">{l3.dnsTelemetry.note}</p>
                </div>
              </div>

              {/* Email Header & Authentication Alignment (SPF / DKIM / DMARC) */}
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-3">
                <span className="font-mono text-xs text-[#00F0FF] uppercase block">
                  SMTP Header & Envelope Forensics
                </span>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between p-2 rounded bg-[#131B28] border border-slate-800">
                    <span className="text-slate-400">SPF Alignment:</span>
                    <span className={l3.headerForensics.spfStatus.includes('FAIL') ? 'text-[#FF2E54] font-bold' : 'text-[#00E599]'}>
                      {l3.headerForensics.spfStatus}
                    </span>
                  </div>
                  <div className="flex justify-between p-2 rounded bg-[#131B28] border border-slate-800">
                    <span className="text-slate-400">DKIM Signature:</span>
                    <span className={l3.headerForensics.dkimStatus.includes('FAIL') ? 'text-[#FF2E54] font-bold' : 'text-[#00E599]'}>
                      {l3.headerForensics.dkimStatus}
                    </span>
                  </div>
                  <div className="flex justify-between p-2 rounded bg-[#131B28] border border-slate-800">
                    <span className="text-slate-400">DMARC Policy:</span>
                    <span className={l3.headerForensics.dmarcStatus.includes('FAIL') ? 'text-[#FF2E54] font-bold' : 'text-[#00E599]'}>
                      {l3.headerForensics.dmarcStatus}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-[#131B28] border border-slate-800 text-[11px] break-all">
                    <span className="text-slate-400">Return-Path: </span>
                    <span className={l3.headerForensics.envelopeMismatch ? 'text-[#FF2E54] font-bold' : 'text-slate-200'}>
                      {l3.headerForensics.returnPathRaw}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            LAYER 4: GLOBAL THREAT INTEL, RED-VS-BLUE & DEFANGED IOC EXPORT
           ===================================================================== */}
        {(activeDepth === 4 || activeDepth === 0) && (
          <div className="space-y-4 pt-2">
            <div className="bg-[#131B28]/70 p-3.5 rounded-lg border border-slate-800">
              <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#00F0FF]" />
                {l4.title}
              </h3>
              <p className="text-xs text-slate-400">{l4.subtitle}</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* VirusTotal Multi-Engine Consensus */}
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-[#00F0FF] uppercase">
                    VirusTotal v3 Consensus
                  </span>
                  <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {l4.virusTotal.mode}
                  </span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span
                    className={`text-3xl font-mono font-bold ${
                      l4.virusTotal.malicious > 0 ? 'text-[#FF2E54]' : 'text-[#00E599]'
                    }`}
                  >
                    {l4.virusTotal.malicious}
                  </span>
                  <span className="text-sm font-mono text-slate-400">
                    / {l4.virusTotal.totalEngines} Security Vendors Flagged
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center font-mono text-xs">
                  <div className="p-2 rounded bg-[#FF2E54]/10 border border-[#FF2E54]/30 text-[#FF2E54]">
                    <div className="font-bold">{l4.virusTotal.malicious}</div>
                    <div className="text-[10px]">Malicious</div>
                  </div>
                  <div className="p-2 rounded bg-[#FFB800]/10 border border-[#FFB800]/30 text-[#FFB800]">
                    <div className="font-bold">{l4.virusTotal.suspicious}</div>
                    <div className="text-[10px]">Suspicious</div>
                  </div>
                  <div className="p-2 rounded bg-[#00E599]/10 border border-[#00E599]/30 text-[#00E599]">
                    <div className="font-bold">{l4.virusTotal.harmless}</div>
                    <div className="text-[10px]">Clean</div>
                  </div>
                </div>
                {l4.virusTotal.flaggedVendors.length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-1">
                    {l4.virusTotal.flaggedVendors.map((v) => (
                      <span
                        key={v}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300"
                      >
                        {v}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Google Safe Browsing API Verdict + Evasion Flags */}
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-[#00F0FF] uppercase">
                    Google Safe Browsing v4
                  </span>
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded font-bold ${
                      l4.googleSafeBrowsing.status === 'CLEAN'
                        ? 'bg-[#00E599]/20 text-[#00E599]'
                        : 'bg-[#FF2E54]/20 text-[#FF2E54]'
                    }`}
                  >
                    {l4.googleSafeBrowsing.status}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-[#131B28] border border-slate-800 text-xs font-mono">
                  <span className="text-slate-400 block text-[10px]">THREAT CLASSIFICATION:</span>
                  <span className="text-white font-bold">{l4.googleSafeBrowsing.threatType}</span>
                </div>
                <div className="space-y-1.5">
                  <span className="font-mono text-[10px] text-slate-400 uppercase block">
                    Red-Team Evasion Techniques Detected:
                  </span>
                  {l4.redVsBlue.evasionFlags.map((flag, idx) => (
                    <div
                      key={idx}
                      className="text-[11px] font-mono p-2 rounded bg-[#131B28] border border-slate-800 text-slate-200"
                    >
                      • {flag}
                    </div>
                  ))}
                </div>
              </div>

              {/* Defanged IOCs & Actionable SOC Response */}
              <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3">
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-[#00F0FF] uppercase flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5" />
                      Defanged IOC & Firewall Rule
                    </span>
                    <button
                      onClick={copyDefanged}
                      className="text-xs font-mono text-[#00F0FF] hover:underline flex items-center gap-1"
                    >
                      {copiedIoc ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedIoc ? 'Copied' : 'Copy IOCs'}
                    </button>
                  </div>
                  <div className="p-2.5 rounded bg-[#131B28] border border-slate-800 font-mono text-xs break-all space-y-1">
                    <div className="text-slate-400 text-[10px]">DEFANGED ARTIFACT:</div>
                    <div className="text-white">{l4.defangedIoc.url}</div>
                  </div>
                  <div className="p-2.5 rounded bg-[#131B28] border border-slate-800 font-mono text-xs break-all space-y-1">
                    <div className="text-slate-400 text-[10px]">AUTO-GENERATED FIREWALL RULE:</div>
                    <div className="text-[#00E599]">{l4.defangedIoc.firewallRule}</div>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 pt-2">
                  <button
                    onClick={() => onReportThreat(scan)}
                    className="flex-1 py-2 px-3 rounded-lg bg-[#FF2E54] hover:bg-[#FF2E54]/90 text-white font-mono text-xs font-bold flex items-center justify-center gap-1.5 transition-all"
                  >
                    <Flag className="w-3.5 h-3.5" />
                    Escalate to SOC Reports
                  </button>
                  <button
                    onClick={exportCaseDossier}
                    className="py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs flex items-center justify-center gap-1.5 transition-all"
                  >
                    <Download className="w-3.5 h-3.5" />
                    JSON Case File
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Quick Next-Layer Navigation Bar when viewing single layer */}
        {activeDepth > 0 && (
          <div className="flex items-center justify-between pt-3 border-t border-slate-800/80 text-xs font-mono">
            <span className="text-slate-400">
              Currently inspecting <strong className="text-[#00F0FF]">Layer {activeDepth} of 4</strong>
            </span>
            <div className="flex items-center gap-2">
              {activeDepth < 4 ? (
                <button
                  onClick={() => setActiveDepth(activeDepth + 1)}
                  className="px-3 py-1.5 rounded bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 hover:bg-[#00F0FF]/25 flex items-center gap-1.5"
                >
                  Peel Deeper to Layer {activeDepth + 1} <ArrowRight className="w-3.5 h-3.5" />
                </button>
              ) : (
                <button
                  onClick={() => setActiveDepth(0)}
                  className="px-3 py-1.5 rounded bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40 hover:bg-[#00F0FF]/25 flex items-center gap-1.5"
                >
                  Show All 4 Layers Simultaneously <Layers className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
