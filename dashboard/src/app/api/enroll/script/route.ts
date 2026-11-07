export const runtime = "nodejs";

function fleetBaseUrl(): string {
  const rawBase = process.env.FLEET_API_URL || "http://127.0.0.1:8080";
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export async function GET(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const osParam = (url.searchParams.get("os") || "linux").toLowerCase();
  const scriptPath = osParam === "windows" ? "/api/enroll/script/windows" : "/api/enroll/script/linux";
  const upstreamUrl = `${fleetBaseUrl()}${scriptPath}`;

  // Meneruskan host header publik ke backend
  const host = request.headers.get("host") || "127.0.0.1:3000";
  const proto = request.headers.get("x-forwarded-proto") || (host.includes("soar.raviarnan.dev") ? "https" : "http");

  try {
    const upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        Host: host,
        "X-Forwarded-Proto": proto,
        Accept: "text/plain",
      },
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
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return new Response(`echo "Gagal mengunduh installer: ${msg}"; exit 1`, {
      status: 502,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }
}
