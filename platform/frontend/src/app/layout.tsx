import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { ZenShell } from "@/components/shell/zen-shell";

const sans = Inter({ subsets: ["latin"], variable: "--font-geist-sans" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-geist-mono" });

export const metadata: Metadata = {
  title: "ACSP — Zen Security",
  description: "Local AI Cloud Security Platform — research-grade SOC dashboard",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${sans.variable} ${mono.variable} font-sans`}>
        <ZenShell>{children}</ZenShell>
      </body>
    </html>
  );
}
