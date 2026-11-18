import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Wazuh - SOAR Fleet Monitor",
  description:
    "Dashboard fleet SOAR berbasis Wazuh UI: status agent, security events, integrity monitoring, threat intelligence, dan orkestrasi n8n.",
};

export const viewport: Viewport = {
  themeColor: "#006BB4",
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
