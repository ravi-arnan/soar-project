import type { Metadata } from "next";
import "./globals.css";

import { Viewport } from "next";

export const metadata: Metadata = {
  title: "Wazuh — Fleet Monitor",
  description:
    "Dashboard fleet SOAR: status agent Wazuh + soar-agent ringan, security events, integrity monitoring.",
};

export const viewport: Viewport = {
  themeColor: "#011a2f",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="id" className="h-full bg-[#F5F7FA] text-[#1A1C21]">
      <body className="min-h-full flex flex-col bg-[#F5F7FA] text-[#1A1C21] antialiased">
        {children}
      </body>
    </html>
  );
}
