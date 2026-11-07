import {
  getAuthorizedSession,
  isValidSession,
  sessionFromRequest,
  validLoginToken,
} from "../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 8 * 1024;

function isDashboardRequestAuthorized(request: Request): boolean {
  // Dalam mode development lokal di localhost, izinkan agar pengujian dashboard mulus
  if (process.env.NODE_ENV === "development") {
    const host = request.headers.get("host") || "";
    if (host.startsWith("localhost:") || host.startsWith("127.0.0.1:")) {
      return true;
    }
  }
  const secret = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  const value = sessionFromRequest(request);
  return Boolean(validLoginToken(secret) && value && isValidSession(value, secret));
}

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

function fleetBaseUrl(): string {
  const rawBase = process.env.FLEET_API_URL || "http://127.0.0.1:8080";
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export async function GET(request: Request): Promise<Response> {
  if (!isDashboardRequestAuthorized(request)) {
    return errorResponse("login dashboard diperlukan", 401);
  }
  const sessionUser = getAuthorizedSession(request);
  if (sessionUser && sessionUser.role !== "admin") {
    return errorResponse("Akses ditolak: Hanya role 'admin' yang dapat mengelola API Key", 403);
  }

  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);
  }

  const upstreamUrl = `${fleetBaseUrl()}/api/keys`;
  try {
    const upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });

    const body = await upstream.json();
    return Response.json(body, { status: upstream.status });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal menghubungi backend fleet: ${msg}`, 502);
  }
}

export async function POST(request: Request): Promise<Response> {
  if (!isDashboardRequestAuthorized(request)) {
    return errorResponse("login dashboard diperlukan", 401);
  }
  const sessionUser = getAuthorizedSession(request);
  if (sessionUser && sessionUser.role !== "admin") {
    return errorResponse("Akses ditolak: Hanya role 'admin' yang dapat mengelola API Key", 403);
  }

  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);
  }

  let body: unknown;
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return errorResponse("body request terlalu besar", 413);
    }
    body = JSON.parse(text);
  } catch {
    return errorResponse("body json tidak valid", 400);
  }

  if (typeof body !== "object" || body === null) {
    return errorResponse("body harus berupa object", 400);
  }

  const payload = body as Record<string, unknown>;
  const isRevoke = payload.action === "revoke";
  const upstreamPath = isRevoke ? "/api/keys/revoke" : "/api/keys";
  const upstreamUrl = `${fleetBaseUrl()}${upstreamPath}`;

  try {
    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });

    const resData = await upstream.json();
    return Response.json(resData, { status: upstream.status });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal memproses request ke backend fleet: ${msg}`, 502);
  }
}
