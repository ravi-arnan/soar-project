import {
  resolveAuthorizedSession,
} from "../../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 32 * 1024;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

function fleetBaseUrl(): string {
  const rawBase = process.env.FLEET_API_URL || "http://127.0.0.1:8080";
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export async function GET(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) {
    return errorResponse("Login dashboard diperlukan", 401);
  }

  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);
  }

  const upstreamUrl = `${fleetBaseUrl()}/api/settings/threat-intel`;
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
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal menghubungi backend fleet: ${msg}`, 502);
  }
}

export async function POST(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) {
    return errorResponse("Login dashboard diperlukan", 401);
  }

  // Hanya role admin yang berhak mengubah konfigurasi AI & Threat Intel
  if (user.role !== "admin") {
    return errorResponse("Akses ditolak: Hanya role 'admin' yang dapat mengubah konfigurasi sistem", 403);
  }

  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);
  }

  let body: unknown;
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return errorResponse("Body request terlalu besar", 413);
    }
    body = JSON.parse(text);
  } catch {
    return errorResponse("Body JSON tidak valid", 400);
  }

  if (typeof body !== "object" || body === null) {
    return errorResponse("Body harus berupa object JSON", 400);
  }

  const upstreamUrl = `${fleetBaseUrl()}/api/settings/threat-intel`;
  try {
    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ...(body as Record<string, unknown>),
        updated_by: user.username || user.email,
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });

    const resData = await upstream.json();
    return Response.json(resData, { status: upstream.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal memperbarui konfigurasi ke backend: ${msg}`, 502);
  }
}
