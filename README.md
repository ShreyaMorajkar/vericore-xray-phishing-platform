# VERICORE // X-RAY — Multi-Layer Phishing Dissection & Threat Intelligence Platform

> **AI Phishing Detection Platform (Major Project)** — Built with **Next.js 14 (React, TypeScript, Tailwind CSS)** + **Node.js / Express.js REST API** + **4-Layer X-Ray Forensics Engine**.

---

## Why VERICORE // X-RAY Stands Out

While standard phishing detection projects simply check if a URL starts with `http://` or matches a basic list of spam words—and output a static *"Risk Level: HIGH"* card—**VERICORE // X-RAY** introduces an interactive **4-Layer Anatomical X-Ray Dissection Paradigm**:

1. **Interactive Split-Screen X-Ray Curtain & Circular Spotlight Loupe (`Layer 1`)**
   - Peel back the surface of any scanned URL, Email, Raw Header, or QR Code in real time.
   - Compare **"What the Victim Sees"** (optical trust illusion, HTTPS padlock, spoofed display name) against **"What the Attacker Hid Underneath"** (actual SMTP `Return-Path`, Cyrillic Unicode homographs, subdomain traps, and psychological coercion tags).
2. **Psychological & Visual Deception Mask (`Layer 2`)**
   - **6-Axis Social Engineering Radar Chart**: Quantifies manipulation across *Urgency & Coercion*, *Authority Spoofing*, *Fear & Consequence*, *Scarcity & Bait*, *Credential Harvesting*, and *Visual/Link Deception*.
   - **Character-by-Character Unicode Homograph & Brand Typosquatting Matrix**: Detects IDN Cyrillic/Greek lookalike characters (e.g., `pаypal.com` using `U+0430`) and computes Levenshtein edit distance + skeleton normalization against 20+ global brands.
3. **Protocol, Entropy & Wire Forensics (`Layer 3`)**
   - **Exploded Anatomical URL Decomposition Pipeline**: Grades `Protocol`, `UserInfo (@ Trick)`, `Subdomain Chain`, `Registrable Root Domain`, `TLD`, `Path`, and `Query Payload`.
   - **Shannon Information Entropy $H(X)$**: Computes bits/character entropy to detect Domain Generation Algorithms (DGA) and randomized phishing paths.
   - **Live Node.js DNS Telemetry & SMTP Header Alignment**: Performs live `A`, `MX`, and `TXT/SPF` lookups and parses raw email headers (`From` vs. `Return-Path`, `Reply-To`, `SPF`, `DKIM`, `DMARC`).
4. **Global Threat Intel & Red-Team vs. Blue-Team Verdict (`Layer 4`)**
   - **VirusTotal v3 + Google Safe Browsing v4 Integration**: Supports live API keys in `.env` with a seamless hybrid 92-vendor consensus engine so the platform works 100% out-of-the-box.
   - **Red-Team vs. Blue-Team Evasion Lab**: Interactive mutation workbench proving how attackers bypass naive keyword/HTTPS scanners (`4% Low Risk`) while VERICORE catches them (`94% Critical Risk`).
   - **QR Code "Quishing" Optical Decoder & Generator**: Upload any QR image (`.png`/`.jpg`) to decode hidden URLs via HTML5 Canvas + `jsQR`, or generate test Quishing matrices.
   - **"Spot the Phish" Cyber Range Simulator**: Gamified cybersecurity awareness training module (PRD Use Case 3) where users activate the X-Ray lens, tag red flags, and earn Analyst XP.

---

## Quick Start (One-Command Local Launch)

```bash
# Start both the Express Backend API (http://localhost:5000) and Next.js Frontend (http://localhost:3000)
npm run dev
```

Or run them in separate terminals:
```bash
# Terminal 1 — Backend API (Port 5000)
cd backend
npm run dev

# Terminal 2 — Frontend Web App (Port 3000)
cd frontend
npm run dev
```

### Demo Credentials (Or use the 1-Click Role Switcher in the Top Bar)
- **Security Analyst (User)**: `analyst@vericore.sec` / `vericore123`
- **SOC Lead (Admin)**: `admin@vericore.sec` / `vericore123`

---

## Project Architecture & PRD Traceability

| PRD Requirement | Implementation in VERICORE // X-RAY |
| :--- | :--- |
| **4.1 URL Scanner** | Multi-layer URL Probe with HTTPS check, suspicious tokens, Levenshtein brand typosquatting, Unicode homographs, live DNS, and VirusTotal/Safe Browsing ([xrayEngine.js](file:///c:/Shreya/Old%20Laptop%20folders/skill%20stacking/Labmentix%20internship/Projects/AI%20Phishing%20detection%20platform%20Major%20Project/backend/engine/xrayEngine.js)) |
| **4.2 Email Content Analysis** | 6-Axis Social Engineering Radar, inline psychological trigger highlights, plus Raw SMTP Header (`SPF`/`DKIM`/`DMARC` & `Return-Path`) forensics |
| **4.3 Risk Analysis System** | Dual-score telemetry comparing **Basic Keyword Scanner Score** vs. **VERICORE 4-Layer Composite Risk Score** |
| **4.4 Dashboard & History** | 5 live telemetry cards, filterable/searchable Scan History archive, 1-click re-inspection in the X-Ray Stage, and JSON Case Dossier export |
| **5 & 6 User + Admin Roles** | JWT Authentication + 1-Click Role Switcher (`Analyst User` ↔ `SOC Admin`), dynamic Keyword/TLD Rule CRUD, Threat Report triage, and User Management ([SocAdminPanel.tsx](file:///c:/Shreya/Old%20Laptop%20folders/skill%20stacking/Labmentix%20internship/Projects/AI%20Phishing%20detection%20platform%20Major%20Project/frontend/src/components/SocAdminPanel.tsx)) |
| **7 Use Case 3 (Awareness)** | Interactive **"Spot the Phish" Cyber Range Simulator** ([CyberRangeSimulator.tsx](file:///c:/Shreya/Old%20Laptop%20folders/skill%20stacking/Labmentix%20internship/Projects/AI%20Phishing%20detection%20platform%20Major%20Project/frontend/src/components/CyberRangeSimulator.tsx)) |
| **11 Database Design** | Persistent relational store ([db.js](file:///c:/Shreya/Old%20Laptop%20folders/skill%20stacking/Labmentix%20internship/Projects/AI%20Phishing%20detection%20platform%20Major%20Project/backend/db.js)) + PostgreSQL/Supabase SQL schema ([schema.sql](file:///c:/Shreya/Old%20Laptop%20folders/skill%20stacking/Labmentix%20internship/Projects/AI%20Phishing%20detection%20platform%20Major%20Project/schema.sql)) |
