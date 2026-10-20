export interface ThreatPreset {
  id: string;
  label: string;
  badge: string;
  scanType: 'url' | 'email' | 'qr' | 'header';
  content: string;
  summary: string;
}

export const THREAT_PRESETS: ThreatPreset[] = [
  {
    id: 'preset-homograph-paypal',
    label: 'IDN Homograph + Subdomain Trap',
    badge: 'CRITICAL // URL',
    scanType: 'url',
    content: 'https://p\u0430ypal.com.secure-session-auth.top/myaccount/verify?session=99812',
    summary: 'Uses Cyrillic "а" (U+0430) + HTTPS padlock + nested subdomain to fool both humans and basic keyword scanners.'
  },
  {
    id: 'preset-bec-email',
    label: 'Spoofed PayPal Urgent Suspension',
    badge: 'CRITICAL // EMAIL',
    scanType: 'email',
    content: `From: PayPal Security <security@paypal.com>
Return-Path: <bounce-alert@mail-auth-relay.xyz>
Reply-To: <verify-now@support-desk-pp.top>
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Subject: URGENT: Your account suspended due to unauthorized login attempt

Dear Customer,
We detected an unauthorized login attempt on your account from an unrecognized device. Your account suspended within 24 hours unless you verify immediately and update payment method.

Click here to confirm your identity: http://login-secure-paypal-update.xyz/webscr?cmd=_login-run`,
    summary: 'Classic high-pressure spear-phishing email with envelope Return-Path spoofing, SPF/DMARC failure, and credential harvesting link.'
  },
  {
    id: 'preset-userinfo-at-trick',
    label: 'RFC 3986 "@" Browser Redirect Trick',
    badge: 'HIGH // URL',
    scanType: 'url',
    content: 'https://accounts.google.com.oauth.token@185.220.101.44/signin/v2/identifier?service=mail',
    summary: 'Abuses the URL "@" userinfo syntax: browsers ignore "accounts.google.com..." and silently route to raw IP 185.220.101.44.'
  },
  {
    id: 'preset-qr-quishing',
    label: 'Microsoft 365 MFA QR Quishing',
    badge: 'CRITICAL // QR',
    scanType: 'qr',
    content: 'https://microsoft-sso.verify-account.zip/m365-qr-reauth?otp=required&tenant=enterprise',
    summary: 'Malicious QR payload abusing Google\'s ".zip" TLD and combo-squatting Microsoft SSO to steal mobile 2FA session tokens.'
  },
  {
    id: 'preset-ceo-wire',
    label: 'Polite Executive Wire Fraud (BEC)',
    badge: 'HIGH // HEADER',
    scanType: 'header',
    content: `From: Vikram Singhania (CEO) <v.singhania@acmecorp.com>
Return-Path: <mailer-daemon@swift-invoice-relay.ru>
Reply-To: <v.singhania.exec@gmail-corporate.xyz>
Authentication-Results: mx.enterprise.local; spf=softfail; dkim=fail; dmarc=fail
Subject: Confidential Q4 Vendor Settlement — Wire Transfer Today

Hi Finance Team,
Are you at your desk? We need to close the confidential acquisition escrow before 4 PM. Please process the wire transfer for the attached vendor coordinates and confirm your identity code once queued.`,
    summary: 'Business Email Compromise (BEC) where Reply-To & Return-Path divert funds to an external .ru/.xyz relay.'
  },
  {
    id: 'preset-prd-url',
    label: 'PRD Example: PayPal Combo-Squatting URL',
    badge: 'HIGH // PRD 4.1',
    scanType: 'url',
    content: 'http://secure-paypal-login-free.com',
    summary: 'Exact PRD Section 4.1 test URL: unencrypted HTTP + hyphenated PayPal combo-squatting + login-free bait.'
  },
  {
    id: 'preset-prd-email',
    label: 'PRD Example: Bank Suspension Alert',
    badge: 'HIGH // PRD 4.2',
    scanType: 'email',
    content: 'Your bank account will be suspended. Verify immediately.',
    summary: 'Exact PRD Section 4.2 test email: combines financial fear ("bank account... suspended") with extreme urgency ("Verify immediately").'
  },
  {
    id: 'preset-benign-github',
    label: 'Verified GitHub Security Advisory',
    badge: 'BENIGN // CONTROL',
    scanType: 'url',
    content: 'https://github.com/security/advisories',
    summary: 'Authentic, verified official GitHub security domain to demonstrate zero false-positive calibration.'
  }
];

export interface CyberRangeScenario {
  id: string;
  title: string;
  difficulty: 'ROOKIE' | 'ANALYST' | 'ELITE';
  isPhish: boolean;
  senderDisplay: string;
  realReturnPath: string;
  spfDmarc: string;
  subject: string;
  bodySegments: {
    id: string;
    text: string;
    isRedFlag: boolean;
    xrayTruth: string;
  }[];
  ctaText: string;
  ctaActualHref: string;
  debrief: string;
}

export const CYBER_RANGE_SCENARIOS: CyberRangeScenario[] = [
  {
    id: 'cr-1',
    title: 'Scenario #01 // The Unicode Apple ID Lockout',
    difficulty: 'ANALYST',
    isPhish: true,
    senderDisplay: 'Apple Support <no-reply@apple.com>',
    realReturnPath: '<bounce-991@icloud-verify-id.top>',
    spfDmarc: 'SPF: FAIL // DMARC: FAIL (Quarantine)',
    subject: 'Action Required: Your Apple ID has been locked for security reasons',
    bodySegments: [
      {
        id: 'seg-1',
        text: 'Dear Client, we noticed an unauthorized sign-in attempt to your iCloud keychain from Moscow, RU.',
        isRedFlag: true,
        xrayTruth: '[FEAR + GEOGRAPHIC PANIC TRIGGER] Manufactured foreign login alert designed to trigger immediate panic.'
      },
      {
        id: 'seg-2',
        text: 'If you do not verify your identity within 12 hours, your Apple ID and photos will be permanently deleted.',
        isRedFlag: true,
        xrayTruth: '[EXTREME COERCION + ARTIFICIAL DEADLINE] Apple never deletes iCloud data with a 12-hour ultimatum.'
      },
      {
        id: 'seg-3',
        text: 'Please review the support reference #APL-88219 in your settings portal below.',
        isRedFlag: false,
        xrayTruth: '[NEUTRAL FILLER] Standard procedural phrasing used to mimic authentic support tickets.'
      }
    ],
    ctaText: 'https://apple.com/account/recover',
    ctaActualHref: 'https://\u0430pple.com.id-unlock.xyz/auth',
    debrief: 'Caught! The anchor text claims "https://apple.com/account/recover", but X-Ray inspection reveals the actual href uses Cyrillic "а" (U+0430) on a disposable .xyz domain, and Return-Path fails SPF.'
  },
  {
    id: 'cr-2',
    title: 'Scenario #02 // Official AWS Billing Threshold Notification',
    difficulty: 'ANALYST',
    isPhish: false,
    senderDisplay: 'Amazon Web Services <no-reply-aws@amazon.com>',
    realReturnPath: '<20261020-bounce@bounces.amazon.com>',
    spfDmarc: 'SPF: PASS // DKIM: PASS // DMARC: PASS',
    subject: 'AWS Budgets: Monthly Free Tier usage alert for account #4491-0021',
    bodySegments: [
      {
        id: 'seg-1',
        text: 'Your AWS account 4491-0021 has exceeded 85% of the usage limit for Amazon RDS Free Tier for October 2026.',
        isRedFlag: false,
        xrayTruth: '[FACTUAL TELEMETRY] Specific account ID and informational threshold notification with zero coercive threats.'
      },
      {
        id: 'seg-2',
        text: 'You can inspect your current usage breakdown by logging into your AWS Management Console directly.',
        isRedFlag: false,
        xrayTruth: '[SAFE SECURITY PRACTICE] Encourages navigating to the console rather than demanding credentials or OTPs.'
      }
    ],
    ctaText: 'https://console.aws.amazon.com/billing/home',
    ctaActualHref: 'https://console.aws.amazon.com/billing/home',
    debrief: 'Legitimate Email! SPF, DKIM, and DMARC all align with amazon.com, the link destination matches the visible text on the official amazon.com root domain, and no urgent coercion is used.'
  },
  {
    id: 'cr-3',
    title: 'Scenario #03 // Zero-Keyword GitHub OAuth Token Drain',
    difficulty: 'ELITE',
    isPhish: true,
    senderDisplay: 'GitHub Dependabot <notifications@github-security-bot.com>',
    realReturnPath: '<SRS0=882a@github-security-bot.com>',
    spfDmarc: 'SPF: PASS (for lookalike domain) // Brand Check: IMPERSONATION',
    subject: 'Repository Dependency Graph Update — PR #412 Ready for Review',
    bodySegments: [
      {
        id: 'seg-1',
        text: 'A new automated pull request has been opened to patch CVE-2026-4410 in package-lock.json.',
        isRedFlag: false,
        xrayTruth: '[ZERO-KEYWORD EVASION] Attacker deliberately uses calm, technical developer language with zero spam keywords!'
      },
      {
        id: 'seg-2',
        text: 'Note: Because your organization updated SAML SSO, please re-authorize your Personal Access Token on the diff viewer.',
        isRedFlag: true,
        xrayTruth: '[SUBTLE CREDENTIAL HARVEST] GitHub PR diff views never ask you to re-enter a Personal Access Token.'
      }
    ],
    ctaText: 'View Pull Request #412 on GitHub',
    ctaActualHref: 'https://github.com.pr-diff-viewer.top/login/oauth',
    debrief: 'Elite Catch! This attack bypasses 100% of naive keyword scanners because it uses calm developer jargon and passes SPF on its own lookalike domain ("github-security-bot.com"), while the link uses a subdomain trap ("github.com.pr-diff-viewer.top").'
  },
  {
    id: 'cr-4',
    title: 'Scenario #04 // HR Annual Benefits Enrollment Reminder',
    difficulty: 'ROOKIE',
    isPhish: true,
    senderDisplay: 'People & Culture HR <hr-benefits@company-internal-portal.zip>',
    realReturnPath: '<admin@company-internal-portal.zip>',
    spfDmarc: 'SPF: NEUTRAL // TLD Alert: .ZIP File-Confusion TLD',
    subject: 'FINAL NOTICE: Submit your tax & bank routing form or payroll pauses Friday',
    bodySegments: [
      {
        id: 'seg-1',
        text: 'All employees must re-enter their direct deposit banking details and OTP pin before 5:00 PM today or October salary disbursement will be frozen.',
        isRedFlag: true,
        xrayTruth: '[PAYROLL FEAR + OTP HARVESTING] Legitimate HR portals never ask for banking OTP pins or threaten immediate salary freezes.'
      },
      {
        id: 'seg-2',
        text: 'Download or open the benefits-update.zip portal below to complete verification.',
        isRedFlag: true,
        xrayTruth: '[.ZIP TOP-LEVEL DOMAIN CONFUSION] Uses the ".zip" TLD so chat/email clients turn a file name into a live external web link.'
      }
    ],
    ctaText: 'https://company-internal-portal.zip/payroll-otp',
    ctaActualHref: 'https://company-internal-portal.zip/payroll-otp',
    debrief: 'Spot on! Uses the notorious ".zip" TLD plus payroll freeze intimidation to harvest banking OTPs.'
  }
];
