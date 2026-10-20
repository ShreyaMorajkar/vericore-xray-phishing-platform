import type { Metadata } from 'next';
import { Space_Grotesk, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  variable: '--font-space',
  weight: ['400', '500', '600', '700']
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  weight: ['400', '500', '600', '700']
});

export const metadata: Metadata = {
  title: 'VERICORE // X-RAY — Multi-Layer Phishing Dissection & Threat Intelligence Platform',
  description:
    'Interactive 4-Layer Anatomical URL, Email, Header & QR Code Phishing Dissection Engine with Split-Screen X-Ray Curtain, Spotlight Loupe, Social Engineering Radar, and Red-Team Evasion Lab.'
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${spaceGrotesk.variable} ${jetbrainsMono.variable} dark`}>
      <body className="font-sans antialiased min-h-screen bg-[#070A0F] text-[#E6EDF7] selection:bg-[#00F0FF]/25 selection:text-[#00F0FF]">
        {children}
      </body>
    </html>
  );
}
