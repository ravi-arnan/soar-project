import { fleetBaseUrl } from "../../../../lib/requestGuard.ts";

export const runtime = "nodejs";

const SAFE_HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?$/;

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const osParam = (url.searchParams.get("os") || "linux").toLowerCase();
  const scriptPaths: Record<string, string> = {
    linux: "/api/enroll/script/linux",
    windows: "/api/enroll/script/windows",
    macos: "/api/enroll/script/macos",
  };
  const scriptPath = scriptPaths[osParam] || "/api/enroll/script/linux";
  const upstreamUrl = `${fleetBaseUrl()}${scriptPath}`;

  const rawHost = (request.headers.get("x-forwarded-host") || request.headers.get("host") || "").split(",")[0]?.trim() || "";
  const safeHost = SAFE_HOST_RE.test(rawHost) ? rawHost : "";
  const rawProto = (request.headers.get("x-forwarded-proto") || "").split(",")[0]?.trim().toLowerCase();
  const safeProto = rawProto === "https" ? "https" : "http";

  try {
    const headers: Record<string, string> = { Accept: "text/plain" };
    if (safeHost) headers["X-Forwarded-Host"] = safeHost;
    headers["X-Forwarded-Proto"] = safeProto;

    const upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });

    const scriptText = await upstream.text();
    return new Response(scriptText, {
      status: upstream.status,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });
  } catch {
    return new Response('echo "Gagal mengunduh skrip installer dari server SOAR"; exit 1\n', {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}
