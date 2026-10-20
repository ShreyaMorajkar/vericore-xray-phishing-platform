'use client';

import React, { useState, useEffect } from 'react';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import { QrCode, Upload, ScanLine, ShieldAlert, CheckCircle2, Sparkles } from 'lucide-react';

interface Props {
  onDissectQrPayload: (decodedUrl: string) => void;
}

const SAMPLE_QR_CAMPAIGNS = [
  {
    id: 'qr-m365',
    title: 'Fake Microsoft 365 MFA Re-Authentication QR',
    tag: 'CRITICAL QUISHING',
    payload: 'https://microsoft-sso.verify-account.zip/m365-qr-reauth?otp=required&session=8821'
  },
  {
    id: 'qr-paypal-idn',
    title: 'Cyrillic PayPal Invoice Dispute QR',
    tag: 'HOMOGRAPH QUISHING',
    payload: 'https://p\u0430ypal.com.dispute-resolution.top/webscr?cmd=_claim'
  },
  {
    id: 'qr-raw-ip',
    title: 'VIP Wi-Fi Captive Portal Credential Harvester',
    tag: 'RAW IPv4 QUISHING',
    payload: 'http://185.220.101.44:8080/portal/login-secure?redirect= corporate-sso'
  },
  {
    id: 'qr-safe',
    title: 'Official GitHub Security Advisories QR',
    tag: 'BENIGN CONTROL',
    payload: 'https://github.com/security/advisories'
  }
];

export default function QrQuishingPanel({ onDissectQrPayload }: Props) {
  const [selectedCampaign, setSelectedCampaign] = useState(SAMPLE_QR_CAMPAIGNS[0]);
  const [customQrText, setCustomQrText] = useState(SAMPLE_QR_CAMPAIGNS[0].payload);
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [decodedFromUpload, setDecodedFromUpload] = useState<string | null>(null);
  const [uploadStatus, setUploadStatus] = useState<string>('');

  useEffect(() => {
    QRCode.toDataURL(customQrText || 'https://vericore.sec', {
      width: 220,
      margin: 2,
      color: {
        dark: '#070A0F',
        light: '#F8FAFC'
      }
    })
      .then((url) => setQrDataUrl(url))
      .catch(() => {});
  }, [customQrText]);

  const handleSelectCampaign = (camp: (typeof SAMPLE_QR_CAMPAIGNS)[0]) => {
    setSelectedCampaign(camp);
    setCustomQrText(camp.payload);
    setDecodedFromUpload(null);
    setUploadStatus(`Loaded sample QR matrix: ${camp.title}`);
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (ev) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.drawImage(img, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
          setDecodedFromUpload(code.data);
          setCustomQrText(code.data);
          setUploadStatus('Successfully decoded QR matrix via HTML5 Canvas + jsQR!');
        } else {
          setUploadStatus('No valid QR matrix found in uploaded image. Try downloading our generated QR and uploading it!');
        }
      };
      img.src = ev.target?.result as string;
    };
    reader.readAsDataURL(file);
  };

  return (
    <div className="bg-[#090D14] border border-slate-800 rounded-xl p-4 space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div>
          <h4 className="font-mono text-xs uppercase text-[#00F0FF] flex items-center gap-2">
            <QrCode className="w-4 h-4" />
            QR Code &ldquo;Quishing&rdquo; Optical Decoder & Test Generator
          </h4>
          <p className="text-xs text-slate-400">
            Attackers embed malicious URLs inside QR codes to bypass email text scanners. Upload a QR image or generate a test Quishing vector below.
          </p>
        </div>

        <label className="px-3 py-2 rounded-lg bg-[#131B28] hover:bg-slate-800 border border-[#00F0FF]/40 text-[#00F0FF] font-mono text-xs cursor-pointer flex items-center gap-2 shrink-0 transition-all">
          <Upload className="w-3.5 h-3.5" />
          Upload QR Image (.PNG/.JPG)
          <input type="file" accept="image/*" onChange={handleImageUpload} className="hidden" />
        </label>
      </div>

      {/* Preset Quishing Vectors */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
        {SAMPLE_QR_CAMPAIGNS.map((camp) => (
          <button
            key={camp.id}
            onClick={() => handleSelectCampaign(camp)}
            className={`p-2.5 rounded-lg border text-left transition-all ${
              selectedCampaign.id === camp.id
                ? 'bg-[#00F0FF]/15 border-[#00F0FF] text-white'
                : 'bg-[#131B28]/70 border-slate-800 text-slate-300 hover:border-slate-700'
            }`}
          >
            <div className="text-[10px] font-mono text-[#00F0FF] mb-0.5">{camp.tag}</div>
            <div className="text-xs font-semibold line-clamp-1">{camp.title}</div>
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center bg-[#0D121B] p-4 rounded-xl border border-slate-800">
        {/* Rendered QR Matrix */}
        <div className="md:col-span-4 flex flex-col items-center justify-center">
          <div className="relative p-3 bg-white rounded-xl shadow-lg border-2 border-[#00F0FF]">
            {qrDataUrl ? (
              <img src={qrDataUrl} alt="QR Payload" className="w-40 h-40 object-contain" />
            ) : (
              <div className="w-40 h-40 flex items-center justify-center text-xs text-slate-500 font-mono">
                Generating...
              </div>
            )}
            <div className="mt-1.5 text-center font-mono text-[10px] text-slate-700 font-bold">
              OPTICAL MATRIX PREVIEW
            </div>
          </div>
        </div>

        {/* Decoded Hidden Stream */}
        <div className="md:col-span-8 space-y-3">
          <div className="flex items-center justify-between">
            <span className="font-mono text-xs text-[#00F0FF] flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              DECODED PAYLOAD STREAM INSIDE QR MATRIX:
            </span>
            {decodedFromUpload && (
              <span className="font-mono text-[11px] text-[#00E599] flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Decoded from Image Upload
              </span>
            )}
          </div>

          <input
            type="text"
            value={customQrText}
            onChange={(e) => setCustomQrText(e.target.value)}
            placeholder="Enter URL to encode into QR or upload a QR image..."
            className="w-full px-3.5 py-2.5 rounded-lg bg-[#070A0F] border border-slate-700 font-mono text-xs text-white focus:outline-none focus:border-[#00F0FF]"
          />

          {uploadStatus && (
            <p className="text-xs font-mono text-slate-400">{uploadStatus}</p>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              onClick={() => onDissectQrPayload(customQrText)}
              className="px-4 py-2.5 rounded-lg bg-[#00F0FF] hover:bg-[#00F0FF]/90 text-slate-950 font-mono text-xs font-bold flex items-center gap-2 shadow-[0_0_20px_rgba(0,240,255,0.25)] transition-all"
            >
              <ScanLine className="w-4 h-4" />
              Dissect Decoded QR Payload in 4-Layer X-Ray
            </button>
            {qrDataUrl && (
              <a
                href={qrDataUrl}
                download="vericore-test-qr.png"
                className="px-3 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs transition-all"
              >
                Download QR (.PNG) to Test Upload
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
