import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  // Standalone: image runtime kecil untuk ravi-debian (ThinkPad X260).
  output: "standalone",
  // Batasi root ke folder dashboard ini (parent /home/ravi/Projects punya
  // lockfile lain yang bikin resolusi CSS/package salah).
  turbopack: { root: projectRoot },
  // Teruskan /api/* ke fleet-monitor.py supaya fetch same-origin (tanpa CORS).
  // CAVEAT: Next.js memanggil rewrites() SEKALI saat `next build` lalu
  // meng-serialize destination-nya ke .next/routes-manifest.json (build-time),
  // BUKAN membaca ulang per request di runtime. Jadi nilai FLEET_API_URL yang
  // dipakai adalah yang ada di env build. Lihat Dockerfile: ARG FLEET_API_URL
  // (default host.docker.internal:8080) wajib lolos ke builder lewat ENV/ARG.
  async rewrites() {
    const base = process.env.FLEET_API_URL || "http://host.docker.internal:8080";
    return [
      {
        source: "/api/:path*",
        destination: `${base}/api/:path*`,
      },
      {
        source: "/healthz",
        destination: `${base}/healthz`,
      },
    ];
  },
};

export default nextConfig;
