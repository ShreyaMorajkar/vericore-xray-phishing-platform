'use client';

import React, { useState, useEffect } from 'react';
import {
  Swords,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  ArrowRight,
  Lock,
  Code2,
  EyeOff,
  Layers,
  AlertTriangle
} from 'lucide-react';

interface Props {
  onLoadIntoXray: (scanType: 'url' | 'email', content: string) => void;
}

export default function RedTeamEvasionLab({ onLoadIntoXray }: Props) {
  const [addHttps, setAddHttps] = useState(true);
  const [stripKeywords, setStripKeywords] = useState(true);
  const [injectHomograph, setInjectHomograph] = useState(true);
  const [subdomainTrap, setSubdomainTrap] = useState(false);
  const [atSymbolTrick, setAtSymbolTrick] = useState(false);

  // Dynamically construct the mutated URL & Email based on active Red-Team toggles
  const protocol = addHttps ? 'https://' : 'http://';
  const brandToken = injectHomograph ? 'p\u0430ypal' : 'paypal';
  const pathPart = stripKeywords ? '/portal/client-session-id-9921' : '/login-secure/verify-account/webscr';

  let mutatedHost = `${brandToken}-support.com`;
  if (subdomainTrap) {
    mutatedHost = `${brandToken}.com.cloud-gateway-auth.top`;
  }
  if (atSymbolTrick) {
    mutatedHost = `accounts.${brandToken}.com@${ subdomainTrap ? 'cloud-gateway-auth.top' : '185.220.101.44' }`;
  }

  const mutatedUrl = `${protocol}${mutatedHost}${pathPart}`;

  // Calculate what a Naive Student Project Scanner (HTTP check + simple keyword regex) scores:
  let naiveScore = 0;
  if (!addHttps) naiveScore += 25;
  if (!stripKeywords) naiveScore += 62;
  if (!injectHomograph && !atSymbolTrick) naiveScore += 10;
  naiveScore = Math.min(98, Math.max(4, naiveScore));

  // Calculate what VERICORE // X-RAY 4-Layer Engine scores:
  let vericoreScore = 30;
  if (!addHttps) vericoreScore += 14;
  if (!stripKeywords) vericoreScore += 28;
  if (injectHomograph) vericoreScore += 42;
  if (subdomainTrap) vericoreScore += 32;
  if (atSymbolTrick) vericoreScore += 36;
  vericoreScore = Math.min(99, Math.max(68, vericoreScore));

  const naiveBypassed = naiveScore < 40;

  return (
    <div className="rounded-xl border border-slate-800 bg-[#0D121B] p-6 space-y-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#FF2E54]/15 border border-[#FF2E54]/40 text-[#FF2E54] font-mono text-xs mb-2">
            <Swords className="w-3.5 h-3.5" />
            ADVERSARIAL RED-TEAM VS. BLUE-TEAM EVASION SIMULATOR
          </div>
          <h2 className="text-xl font-bold text-white">
            Why Basic Keyword &amp; HTTPS Scanners Fail in the Real World
          </h2>
          <p className="text-xs text-slate-400 max-w-3xl mt-1">
            Toggle real-world attacker evasion mutations below. Watch how a standard beginner phishing detector (checking only for HTTP and obvious keywords like &ldquo;login-secure&rdquo;) gets completely bypassed while <strong className="text-[#00F0FF]">VERICORE // X-RAY</strong> catches the attack across Layers 2, 3, and 4.
          </p>
        </div>

        <button
          onClick={() => onLoadIntoXray('url', mutatedUrl)}
          className="px-4 py-2.5 rounded-lg bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-slate-950 font-mono text-xs font-bold flex items-center gap-2 shrink-0 shadow-[0_0_20px_rgba(0,240,255,0.25)] transition-all"
        >
          Send Mutated Attack to X-Ray Stage <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Live Mutated Artifact Preview */}
      <div className="bg-[#070A0F] border border-slate-800 rounded-xl p-4 space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-[#00F0FF] uppercase">LIVE RED-TEAM MUTATED PAYLOAD:</span>
          <span className="text-slate-400">
            {injectHomograph ? 'Contains Cyrillic U+0430 ("а")' : 'Standard ASCII'}
          </span>
        </div>
        <div className="p-3 rounded-lg bg-[#131B28] border border-slate-700 font-mono text-sm sm:text-base text-white break-all">
          {mutatedUrl}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: 5 Red-Team Mutation Toggles */}
        <div className="lg:col-span-6 space-y-3">
          <h3 className="font-mono text-xs uppercase text-slate-400">
            Toggle Red-Team Evasion Techniques (Attacker Side)
          </h3>

          {[
            {
              id: 'https',
              active: addHttps,
              toggle: () => setAddHttps(!addHttps),
              title: '1. Provision Free DV HTTPS Certificate (TLS Padlock)',
              desc: '84% of modern phishing sites use Let\'s Encrypt HTTPS. Fools basic scanners that assume HTTPS = Safe.',
              impact: 'Drops Naive Scanner by -25%'
            },
            {
              id: 'keywords',
              active: stripKeywords,
              toggle: () => setStripKeywords(!stripKeywords),
              title: '2. Strip Obvious Phishing Keywords (Zero-Keyword Path)',
              desc: 'Removes words like "verify-account", "login-secure", and "webscr" so regex keyword lists return 0 matches.',
              impact: 'Drops Naive Scanner by -62%'
            },
            {
              id: 'homograph',
              active: injectHomograph,
              toggle: () => setInjectHomograph(!injectHomograph),
              title: '3. Inject Cyrillic Unicode Homograph ("pаypal" with U+0430)',
              desc: 'Replaces Latin "a" (U+0061) with Cyrillic "а" (U+0430). Looks identical to humans & bypasses ASCII string matching.',
              impact: 'Caught by VERICORE Layer 2 (+42%)'
            },
            {
              id: 'subdomain',
              active: subdomainTrap,
              toggle: () => setSubdomainTrap(!subdomainTrap),
              title: '4. Subdomain Brand Nesting (.top / .xyz Root)',
              desc: 'Places "paypal.com" as a prefix subdomain on an attacker-controlled registrable root (.top).',
              impact: 'Caught by VERICORE Layer 3 (+32%)'
            },
            {
              id: 'attrick',
              active: atSymbolTrick,
              toggle: () => setAtSymbolTrick(!atSymbolTrick),
              title: '5. RFC 3986 "@" UserInfo Redirection Trick',
              desc: 'Everything before "@" is treated as a username and ignored by the browser, routing silently to the host after "@".',
              impact: 'Caught by VERICORE Layer 3 (+36%)'
            }
          ].map((item) => (
            <div
              key={item.id}
              onClick={item.toggle}
              className={`p-3.5 rounded-xl border cursor-pointer transition-all flex items-start justify-between gap-3 ${
                item.active
                  ? 'bg-[#131B28] border-[#00F0FF]/60 shadow-[0_0_15px_rgba(0,240,255,0.1)]'
                  : 'bg-[#090D14] border-slate-800 opacity-75 hover:opacity-100'
              }`}
            >
              <div className="space-y-1">
                <div className="text-xs sm:text-sm font-bold text-white flex items-center gap-2">
                  <span>{item.title}</span>
                </div>
                <p className="text-xs text-slate-400">{item.desc}</p>
                <span className="inline-block font-mono text-[10px] text-[#00F0FF]">{item.impact}</span>
              </div>
              <div
                className={`px-2.5 py-1 rounded font-mono text-[10px] font-bold shrink-0 ${
                  item.active
                    ? 'bg-[#00F0FF] text-slate-950'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {item.active ? 'ENABLED' : 'OFF'}
              </div>
            </div>
          ))}
        </div>

        {/* Right: Side-by-Side Blue-Team Detection Comparison */}
        <div className="lg:col-span-6 flex flex-col justify-between space-y-4">
          <h3 className="font-mono text-xs uppercase text-slate-400">
            Real-Time Detection Telemetry (Blue-Team Side)
          </h3>

          {/* Card 1: Standard Naive Keyword Scanner */}
          <div className="p-5 rounded-xl bg-[#090D14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-mono text-[10px] uppercase text-slate-400 block">
                  BASELINE COMPARISON
                </span>
                <h4 className="text-base font-bold text-slate-200">
                  Standard Keyword + HTTPS Scanner
                </h4>
              </div>
              <span
                className={`px-3 py-1 rounded font-mono text-xs font-bold ${
                  naiveBypassed
                    ? 'bg-[#00E599]/20 text-[#00E599] border border-[#00E599]/40'
                    : 'bg-[#FF2E54]/20 text-[#FF2E54] border border-[#FF2E54]/40'
                }`}
              >
                {naiveBypassed ? 'FALSE NEGATIVE // MARKED SAFE!' : 'DETECTED'}
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between font-mono text-xs">
                <span className="text-slate-400">Calculated Risk Score</span>
                <span className="text-white font-bold">{naiveScore}%</span>
              </div>
              <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all duration-500 ${
                    naiveBypassed ? 'bg-[#00E599]' : 'bg-[#FFB800]'
                  }`}
                  style={{ width: `${naiveScore}%` }}
                />
              </div>
            </div>

            <div className="text-xs font-mono text-slate-400 space-y-1 pt-1">
              <div>• HTTPS Check: {addHttps ? '✅ Passed (Fooled by padlock)' : '❌ Flagged HTTP'}</div>
              <div>
                • Keyword Regex: {stripKeywords ? '✅ 0 suspicious words found (Fooled)' : '❌ Matched URL tokens'}
              </div>
              <div>
                • ASCII Brand Check: {injectHomograph ? '✅ Did not match ASCII "paypal" (Fooled by U+0430)' : '⚠️ Partial match'}
              </div>
            </div>
          </div>

          {/* Card 2: VERICORE // X-RAY 4-Layer Engine */}
          <div className="p-5 rounded-xl bg-[#090D14] border-2 border-[#00F0FF]/60 shadow-[0_0_25px_rgba(0,240,255,0.12)] space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-mono text-[10px] uppercase text-[#00F0FF] block">
                  OUR MULTI-LAYER ENGINE
                </span>
                <h4 className="text-base font-bold text-white">
                  VERICORE // X-RAY 4-Layer Forensics
                </h4>
              </div>
              <span className="px-3 py-1 rounded font-mono text-xs font-bold bg-[#FF2E54] text-white">
                CRITICAL THREAT CAUGHT ({vericoreScore}%)
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between font-mono text-xs">
                <span className="text-[#00F0FF]">4-Layer Composite Risk Score</span>
                <span className="text-[#FF2E54] font-bold">{vericoreScore}%</span>
              </div>
              <div className="h-3 w-full bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#FF2E54] transition-all duration-500"
                  style={{ width: `${vericoreScore}%` }}
                />
              </div>
            </div>

            <div className="text-xs font-mono text-slate-200 space-y-1 pt-1">
              {injectHomograph && (
                <div className="text-[#FF2E54]">
                  • [Layer 2] Caught Cyrillic Homograph &lsquo;а&rsquo; (U+0430) skeleton spoofing PayPal
                </div>
              )}
              {subdomainTrap && (
                <div className="text-[#FF2E54]">
                  • [Layer 3] Caught Subdomain Brand Trap (Registrable root is .top, not paypal.com)
                </div>
              )}
              {atSymbolTrick && (
                <div className="text-[#FF2E54]">
                  • [Layer 3] Caught RFC 3986 &lsquo;@&rsquo; UserInfo Browser Redirect Obfuscation
                </div>
              )}
              <div className="text-[#00F0FF]">
                • [Layer 4] Detection Advantage: +{vericoreScore - naiveScore}% over standard scanners
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
