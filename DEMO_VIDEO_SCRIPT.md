# 🎬 VERICORE // X-RAY — 6-Minute Master Demo Video Script & Shot-by-Shot Guide

**Total Duration:** `06:00` (360 Seconds)  
**Target URL:** `http://localhost:3000` (Frontend) & `http://localhost:5000` (Backend API)  
**Presenter Goal:** Show evaluators both **100% PRD Compliance** and **Why VERICORE // X-RAY is miles ahead of standard keyword/HTTPS phishing scanners**.

---

## ⏱️ Segment 1 — The Hook & Problem Statement (`00:00 – 00:45` | 45s)

### 🖥️ On-Screen Action
1. Start on the main **VERICORE // X-RAY** workbench at `http://localhost:3000`.
2. Point your cursor at the top header showing **`4-LAYER ENGINE ONLINE`** and the **4 Modality Probes** (`URL Forensics Probe`, `Email Spectrometer`, `Raw SMTP Headers`, `QR "Quishing" Decoder`).
3. Hover over the **Instant Threat & Benign Test Specimens** bar.

### 🎙️ Voiceover Script
> *"Hi everyone! Today I’m presenting **VERICORE // X-RAY** — a Multi-Layer Phishing Dissection and Threat Intelligence Platform built with Next.js 14, TypeScript, Tailwind CSS, and a Node.js Express REST API.*
>
> *When most beginners build a phishing detector, they only check two things: does the URL have `HTTPS`, and does the text contain obvious spam words like 'verify immediately'?*
>
> *The problem is that in the real world, 84% of modern phishing sites use valid HTTPS certificates, and attackers use Unicode homographs, subdomain traps, and spoofed email headers to bypass basic keyword scanners. So instead of building a black-box form that just outputs 'High Risk', I engineered an **Interactive 4-Layer X-Ray Dissection Stage** that lets users and SOC analysts physically peel back a phishing attack layer by layer."*

---

## ⏱️ Segment 2 — Layer 1: Split-Screen X-Ray Curtain & Spotlight Lens (`00:45 – 01:45` | 60s)

### 🖥️ On-Screen Action
1. Click the first preset: **`IDN Homograph + Subdomain Trap`** (`https://pаypal.com.secure-session-auth.top/myaccount/verify?session=99812`).
2. Point out the top comparison meter: **Basic Scanner scores only `20%`**, whereas **VERICORE X-RAY scores `99% CRITICAL`**.
3. On **Layer 1 (`L1: Victim vs. X-Ray Lens`)**, drag the **Split Curtain Slider** back and forth from `15%` to `85%`.
4. Click **`Spotlight X-Ray Lens`** and move your cursor in a circle across the white victim card to reveal the dark cyan radiography layer underneath.

### 🎙️ Voiceover Script
> *"Let’s test an evasive attack right now: `https://pаypal.com.secure-session-auth.top`. Notice at the top right that a basic keyword scanner scores this at only 20% risk because it uses HTTPS!*
>
> *Now look at **Layer 1 — Surface Illusion vs. X-Ray Truth**. On the left side of this draggable X-Ray Curtain, you see **What the Victim Sees**: a reassuring HTTPS padlock and what looks like `paypal.com`.*
>
> *As I drag the X-Ray Curtain across—or switch to the **Circular Spotlight X-Ray Lens** and hover my cursor over the address bar—the surface illusion is stripped away in real time. Underneath the beam, VERICORE exposes that the letter 'a' in `pаypal` is actually a Russian Cyrillic character (`U+0430`), and the true destination root domain is `.top`, not `paypal.com`!"*

---

## ⏱️ Segment 3 — Layer 2: 6-Axis Social Engineering Radar & Homograph Matrix (`01:45 – 02:35` | 50s)

### 🖥️ On-Screen Action
1. Scrub the **Depth Slider** (or click the tab) to **`L2: Deception & Homographs`**.
2. Point to the **6-Axis Manipulation Radar Chart** on the left and the **Character-by-Character Unicode Codepoint Matrix** on the right (where `а` `U+0430` glows crimson).
3. Next, click the preset **`PRD Example: Bank Suspension Alert`** (`"Your bank account will be suspended. Verify immediately."`) or **`Spoofed PayPal Urgent Suspension`** to show inline psychological trigger tags.

### 🎙️ Voiceover Script
> *"Peeling deeper to **Layer 2 — The Psychological and Visual Deception Mask**, VERICORE performs two forensic checks.*
>
> *First, on the right, our **Unicode Homograph and Brand Typosquatting Matrix** inspects every single character of the hostname by its hex codepoint. You can see Latin characters in slate, while character #2—Cyrillic Small Letter A (`U+0430`)—glows crimson alongside our Levenshtein edit-distance detector.*
>
> *Second, when we scan the **PRD Email Example**—'Your bank account will be suspended. Verify immediately'—our **6-Axis Social Engineering Radar** maps the psychological manipulation across Urgency, Authority, Fear, Scarcity, Credential Harvesting, and Visual Deception, explaining why each phrase is used to panic the victim."*

---

## ⏱️ Segment 4 — Layer 3 & Layer 4: Wire Forensics, Live DNS, Header Spoofing & Threat Intel (`02:35 – 03:35` | 60s)

### 🖥️ On-Screen Action
1. Click the preset **`Polite Executive Wire Fraud (BEC)`** (or stay on the current scan) and switch to **`L3: Wire, DNS & Entropy`**.
2. Show the **Anatomical URL Decomposition Pipeline**, **Shannon Information Entropy $H(X)$**, **Live Node.js DNS Telemetry**, and **SMTP Header (`SPF`/`DKIM`/`DMARC`) Alignment**.
3. Click **`L4: Threat Intel & Verdict`** to show **VirusTotal 92-Engine Consensus**, **Google Safe Browsing v4**, and click **`Copy IOCs`** / **`JSON Case File`**.
4. Click the **`Verified GitHub Security Advisory`** preset (`https://github.com/security/advisories`) to prove zero false positives (`LOW 4%`).

### 🎙️ Voiceover Script
> *"Moving to **Layer 3 — Protocol, Entropy, and Wire Forensics**, VERICORE explodes the URL into its anatomical tree—grading the Protocol, UserInfo `@` redirect tricks, Subdomain chain, Registrable Root, TLD, and Path. We also calculate **Shannon Information Entropy** in bits per character to catch algorithmically generated domains, run live **Node.js DNS resolution** for IPv4 `A` and `MX` records, and parse raw email headers to catch `From` versus `Return-Path` envelope spoofing and `SPF`/`DKIM`/`DMARC` failures.*
>
> *Finally, **Layer 4** aggregates global threat intelligence from **VirusTotal** and **Google Safe Browsing**, generates defanged IOCs (`hxxps://...`) and firewall rules ready for a SOC team, and exports a complete JSON Forensic Case Dossier. And when we test an official domain like `github.com/security`, VERICORE verifies it at 4% Low Risk with zero false positives."*

---

## ⏱️ Segment 5 — QR "Quishing" Decoder, Red-vs-Blue Evasion Lab & Cyber Range (`03:35 – 04:50` | 75s)

### 🖥️ On-Screen Action
1. In the scanner, click **`QR "Quishing" Decoder`**, cycle through the sample QR matrices (or upload a downloaded QR `.png`), and click **`Dissect Decoded QR Payload in 4-Layer X-Ray`**.
2. In the top navigation bar, click **`Red vs. Blue Lab`**. Toggle the 5 attacker evasion switches (`Provision Free DV HTTPS`, `Strip Obvious Phishing Keywords`, `Inject Cyrillic Homograph`, `Subdomain Brand Nesting`, `RFC 3986 '@' Trick`) and point to the live side-by-side scorebars.
3. Click **`Spot-the-Phish Range`** in the top nav. Activate **`ACTIVATE X-RAY LENS OVER EMAIL`**, click the red-flag sentences to tag them, and click **`QUARANTINE // THIS IS PHISHING`** to earn `+250 XP`.

### 🎙️ Voiceover Script
> *"Beyond standard text and URLs, modern attackers hide phishing links inside QR codes—known as **Quishing**—to bypass email filters. Our built-in **QR Optical Decoder** uses HTML5 Canvas and `jsQR` to decode uploaded QR images in the browser and pipe the hidden URL straight into our 4-Layer X-Ray.*
>
> *Next, in the **Red-Team vs. Blue-Team Evasion Simulator**, we can interactively toggle real-world attacker mutations. Watch what happens when an attacker adds a free HTTPS certificate, removes obvious spam words, and uses a Cyrillic homograph: a standard keyword scanner drops to **14% Low Risk—a complete false negative**, while VERICORE catches it at **99% Critical Risk**.*
>
> *And to fulfill **PRD Use Case 3: Cybersecurity Awareness**, I built the **Spot-the-Phish Cyber Range**. Students and employees can activate an X-Ray lens over simulated emails, tag red flags in the text, inspect the true `Return-Path` and `href`, and earn Analyst XP and streaks."*

---

## ⏱️ Segment 6 — Telemetry Dashboard, Threat Reports & SOC Admin Command Center (`04:50 – 06:00` | 70s)

### 🖥️ On-Screen Action
1. Click **`Telemetry & History`** in the top nav. Show the 5 telemetry cards, search/filter the scan archive by `CRITICAL` or `URL Scans`, and click **`File Report`** on any scan.
2. In the top-right header, click **`SOC Admin`** in the 1-Click Role Switcher (or open the JWT Login modal to show `admin@vericore.sec`).
3. Inside the **SOC Admin Panel**, add a new live heuristic rule (e.g., keyword: `crypto-airdrop`, category: `SCARCITY`, weight: `+30`), then switch to **`Threat Reports`** and update an incident status to **`BLOCKLISTED`**, and show **`Users`** and **`Detection Logs`**.

### 🎙️ Voiceover Script
> *"For continuous monitoring, the **Telemetry & History Dashboard** tracks total scans, safe versus critical detections, average risk scores, and evasive attacks caught, with full search and modality filtering.*
>
> *Finally, switching from **Analyst User** to **SOC Admin**—powered by JWT authentication—unlocks the **SOC Administrator Command Center**. Here, admins can deploy new phishing keyword or TLD heuristic rules that immediately update the live X-Ray scoring engine without restarting the server. Admins can also triage user-submitted Threat Reports from `OPEN` to `BLOCKLISTED`, manage user accounts and roles, and audit global detection logs.*
>
> *By combining full PRD compliance with an interactive 4-Layer X-Ray Dissection architecture, **VERICORE // X-RAY** turns phishing detection from a black-box guess into transparent, explainable cybersecurity forensics. Thank you!"*
