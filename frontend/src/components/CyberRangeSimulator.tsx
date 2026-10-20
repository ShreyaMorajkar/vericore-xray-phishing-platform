'use client';

import React, { useState } from 'react';
import { CYBER_RANGE_SCENARIOS, CyberRangeScenario } from '@/lib/presets';
import {
  Award,
  Eye,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  ArrowRight,
  Flag,
  Sparkles,
  RotateCcw
} from 'lucide-react';

interface Props {
  onSendScenarioToXray: (content: string) => void;
}

export default function CyberRangeSimulator({ onSendScenarioToXray }: Props) {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [xrayActive, setXrayActive] = useState(false);
  const [flaggedSegments, setFlaggedSegments] = useState<string[]>([]);
  const [submittedChoice, setSubmittedChoice] = useState<'PHISH' | 'LEGIT' | null>(null);
  const [score, setScore] = useState(0);
  const [streak, setStreak] = useState(0);
  const [completedIds, setCompletedIds] = useState<string[]>([]);

  const scenario: CyberRangeScenario = CYBER_RANGE_SCENARIOS[currentIndex];

  const toggleFlagSegment = (segId: string) => {
    if (submittedChoice) return;
    setFlaggedSegments((prev) =>
      prev.includes(segId) ? prev.filter((id) => id !== segId) : [...prev, segId]
    );
  };

  const handleVerdict = (choice: 'PHISH' | 'LEGIT') => {
    if (submittedChoice) return;
    setSubmittedChoice(choice);
    const isCorrect =
      (choice === 'PHISH' && scenario.isPhish) || (choice === 'LEGIT' && !scenario.isPhish);

    if (isCorrect) {
      setScore((s) => s + 250 + flaggedSegments.length * 30);
      setStreak((st) => st + 1);
    } else {
      setStreak(0);
    }
    if (!completedIds.includes(scenario.id)) {
      setCompletedIds((prev) => [...prev, scenario.id]);
    }
  };

  const nextScenario = () => {
    setSubmittedChoice(null);
    setFlaggedSegments([]);
    setXrayActive(false);
    setCurrentIndex((prev) => (prev + 1) % CYBER_RANGE_SCENARIOS.length);
  };

  const resetRange = () => {
    setCurrentIndex(0);
    setSubmittedChoice(null);
    setFlaggedSegments([]);
    setXrayActive(false);
    setScore(0);
    setStreak(0);
    setCompletedIds([]);
  };

  const isCorrect =
    submittedChoice &&
    ((submittedChoice === 'PHISH' && scenario.isPhish) ||
      (submittedChoice === 'LEGIT' && !scenario.isPhish));

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0D121B] p-6 space-y-6">
      {/* Header & Scoreboard */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#00F0FF]/15 border border-[#00F0FF]/40 text-[#00F0FF] font-mono text-xs mb-2">
            <Award className="w-3.5 h-3.5" />
            INTERACTIVE CYBER RANGE // PRD USE CASE 3: SECURITY AWARENESS TRAINING
          </div>
          <h2 className="text-xl font-bold text-white">
            &ldquo;Spot the Phish&rdquo; Forensic X-Ray Training Range
          </h2>
          <p className="text-xs text-slate-400 max-w-2xl mt-1">
            Click suspicious phrases to tag red flags, toggle the <strong className="text-[#00F0FF]">X-Ray Inspector</strong> to check raw headers and actual link destinations, then issue your verdict.
          </p>
        </div>

        <div className="flex items-center gap-3 bg-[#090D14] p-3 rounded-xl border border-slate-800 shrink-0">
          <div className="px-3 border-r border-slate-800">
            <div className="text-[10px] font-mono text-slate-400">ANALYST XP</div>
            <div className="text-lg font-mono font-bold text-[#00F0FF]">{score} XP</div>
          </div>
          <div className="px-3 border-r border-slate-800">
            <div className="text-[10px] font-mono text-slate-400">STREAK</div>
            <div className="text-lg font-mono font-bold text-[#00E599]">{streak} 🔥</div>
          </div>
          <div className="px-2">
            <div className="text-[10px] font-mono text-slate-400">PROGRESS</div>
            <div className="text-sm font-mono font-bold text-white">
              {completedIds.length}/{CYBER_RANGE_SCENARIOS.length}
            </div>
          </div>
          <button
            onClick={resetRange}
            title="Reset Cyber Range"
            className="p-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scenario Selector Pills */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex flex-wrap gap-2">
          {CYBER_RANGE_SCENARIOS.map((sc, idx) => (
            <button
              key={sc.id}
              onClick={() => {
                setCurrentIndex(idx);
                setSubmittedChoice(null);
                setFlaggedSegments([]);
              }}
              className={`px-3 py-1.5 rounded-lg font-mono text-xs border transition-all ${
                currentIndex === idx
                  ? 'bg-[#00F0FF] text-slate-950 font-bold border-[#00F0FF]'
                  : 'bg-[#090D14] text-slate-400 border-slate-800 hover:text-white'
              }`}
            >
              #{idx + 1} [{sc.difficulty}]
            </button>
          ))}
        </div>

        <button
          onClick={() => setXrayActive(!xrayActive)}
          className={`px-4 py-2 rounded-lg font-mono text-xs font-bold border flex items-center gap-2 transition-all ${
            xrayActive
              ? 'bg-[#00F0FF]/20 text-[#00F0FF] border-[#00F0FF] shadow-[0_0_18px_rgba(0,240,255,0.25)]'
              : 'bg-[#131B28] text-slate-200 border-slate-700 hover:border-[#00F0FF]'
          }`}
        >
          <Eye className="w-4 h-4" />
          {xrayActive ? 'X-RAY LENS: ACTIVE (PEELING SURFACE)' : 'ACTIVATE X-RAY LENS OVER EMAIL'}
        </button>
      </div>

      {/* Simulated Email Artifact Card */}
      <div
        className={`rounded-xl border p-5 transition-all space-y-4 ${
          xrayActive
            ? 'xray-scanline-surface bg-[#060B13] border-[#00F0FF]'
            : 'bg-[#090D14] border-slate-800'
        }`}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <span className="font-mono text-xs text-[#00F0FF]">{scenario.title}</span>
            <h3 className="text-lg font-bold text-white mt-0.5">{scenario.subject}</h3>
          </div>
          <span className="font-mono text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 self-start">
            DIFFICULTY: {scenario.difficulty}
          </span>
        </div>

        {/* Sender & Return-Path Header Box */}
        <div className="p-3.5 rounded-lg bg-[#131B28]/90 border border-slate-800 space-y-1.5 font-mono text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <span className="text-slate-400">DISPLAY FROM: </span>
              <span className="text-white font-bold">{scenario.senderDisplay}</span>
            </div>
            {xrayActive && (
              <span className="px-2 py-0.5 rounded bg-[#00F0FF]/15 text-[#00F0FF] border border-[#00F0FF]/40">
                {scenario.spfDmarc}
              </span>
            )}
          </div>
          {xrayActive && (
            <div className="pt-1 border-t border-slate-800 text-[#FFB800]">
              ☢️ X-RAY SMTP RETURN-PATH: <strong>{scenario.realReturnPath}</strong>
            </div>
          )}
        </div>

        {/* Interactive Body Segments (Click to Flag Red Flags) */}
        <div className="space-y-2.5">
          <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
            <Flag className="w-3.5 h-3.5 text-[#FFB800]" />
            Click any sentence below that you suspect is a social engineering red flag:
          </div>
          {scenario.bodySegments.map((seg) => {
            const isFlagged = flaggedSegments.includes(seg.id);
            return (
              <div
                key={seg.id}
                onClick={() => toggleFlagSegment(seg.id)}
                className={`p-3.5 rounded-lg border cursor-pointer transition-all space-y-1.5 ${
                  isFlagged
                    ? 'bg-[#FFB800]/15 border-[#FFB800] text-white'
                    : 'bg-[#0D121B] border-slate-800 hover:border-slate-700 text-slate-200'
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <p className="text-sm leading-relaxed">{seg.text}</p>
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded shrink-0 ${
                      isFlagged
                        ? 'bg-[#FFB800] text-slate-950 font-bold'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {isFlagged ? '🚩 FLAGGED' : 'TAG FLAG'}
                  </span>
                </div>
                {xrayActive && (
                  <p className="font-mono text-xs text-[#00F0FF] pt-1 border-t border-slate-800/80">
                    ☢️ {seg.xrayTruth}
                  </p>
                )}
              </div>
            );
          })}
        </div>

        {/* Embedded Call-to-Action Link Inspection */}
        <div className="p-4 rounded-lg bg-[#131B28] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="text-[10px] font-mono text-slate-400 uppercase">
              EMBEDDED BUTTON / ANCHOR LINK:
            </div>
            <div className="text-sm font-mono font-bold text-[#00F0FF] break-all">
              {scenario.ctaText}
            </div>
            {xrayActive && (
              <div className="text-xs font-mono text-[#FF2E54] font-bold pt-1">
                ☢️ ACTUAL HREF DESTINATION: {scenario.ctaActualHref}
              </div>
            )}
          </div>
          <button
            onClick={() =>
              onSendScenarioToXray(
                `From: ${scenario.senderDisplay}\nReturn-Path: ${scenario.realReturnPath}\nSubject: ${scenario.subject}\n\n${scenario.bodySegments.map((s) => s.text).join('\n')}\n\nLink: ${scenario.ctaActualHref}`
              )
            }
            className="px-3 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs font-mono text-[#00F0FF] shrink-0"
          >
            Open Full 4-Layer X-Ray ↗
          </button>
        </div>

        {/* Verdict Buttons or Debrief */}
        {!submittedChoice ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
            <button
              onClick={() => handleVerdict('PHISH')}
              className="py-3 px-4 rounded-xl bg-[#FF2E54] hover:bg-[#FF2E54]/90 text-white font-mono text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-lg transition-all"
            >
              <ShieldAlert className="w-4 h-4" />
              QUARANTINE // THIS IS PHISHING
            </button>
            <button
              onClick={() => handleVerdict('LEGIT')}
              className="py-3 px-4 rounded-xl bg-[#00E599] hover:bg-[#00E599]/90 text-slate-950 font-mono text-xs sm:text-sm font-bold flex items-center justify-center gap-2 shadow-lg transition-all"
            >
              <ShieldCheck className="w-4 h-4" />
              APPROVE // THIS IS LEGITIMATE
            </button>
          </div>
        ) : (
          <div
            className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
              isCorrect
                ? 'bg-[#00E599]/15 border-[#00E599] text-white'
                : 'bg-[#FF2E54]/15 border-[#FF2E54] text-white'
            }`}
          >
            <div className="space-y-1">
              <div className="font-mono text-sm font-bold flex items-center gap-2">
                {isCorrect ? (
                  <>
                    <CheckCircle2 className="w-5 h-5 text-[#00E599]" />
                    <span className="text-[#00E599]">EXCELLENT FORENSIC CALL! (+250 XP)</span>
                  </>
                ) : (
                  <>
                    <XCircle className="w-5 h-5 text-[#FF2E54]" />
                    <span className="text-[#FF2E54]">MISSED VERDICT — REVIEW FORENSIC DEBRIEF</span>
                  </>
                )}
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">{scenario.debrief}</p>
            </div>
            <button
              onClick={nextScenario}
              className="px-4 py-2.5 rounded-lg bg-[#00F0FF] text-slate-950 font-mono text-xs font-bold flex items-center gap-1.5 shrink-0"
            >
              Next Scenario <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
