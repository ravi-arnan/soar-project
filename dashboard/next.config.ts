import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

const SECURITY_HEADERS = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      "font-src 'self' data:",
      "connect-src 'self' https://cloudflareinsights.com",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join("; "),
  },
];

const nextConfig: NextConfig = {
  output: "standalone",
  turbopack: { root: projectRoot },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: SECURITY_HEADERS,
      },
    ];
  },
  // Hanya endpoint enrollment/installer publik & healthz yang di-rewrite langsung ke fleet-monitor;
  // seluruh endpoint data dashboard (/api/fleet, /api/events*, /api/metrics, /api/scan-results, dll.)
  // dilayani oleh Route Handler Next.js terautentikasi.
  async rewrites() {
    const rawBase =
      process.env.FLEET_API_URL ||
      (process.env.NODE_ENV === "production"
        ? "http://host.docker.internal:8080"
        : "http://127.0.0.1:8080");
    const base = rawBase.split("?")[0].replace(/\/$/, "");
    return [
      { source: "/api/enroll/request", destination: `${base}/api/enroll/request` },
      { source: "/api/enroll/status", destination: `${base}/api/enroll/status` },
      { source: "/api/enroll/script/:os", destination: `${base}/api/enroll/script/:os` },
      { source: "/api/update/script/:os", destination: `${base}/api/update/script/:os` },
      { source: "/api/installer/:path*", destination: `${base}/api/installer/:path*` },
      { source: "/api/heartbeat", destination: `${base}/api/heartbeat` },
      { source: "/api/commands/ack", destination: `${base}/api/commands/ack` },
      { source: "/api/scan-result", destination: `${base}/api/scan-result` },
      { source: "/api/agent/webhook/:path*", destination: `${base}/api/agent/webhook/:path*` },
      { source: "/healthz", destination: `${base}/healthz` },
    ];
  },
};

export default nextConfig;
