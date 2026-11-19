import { fleetBaseUrl, originAllowed, readBoundedJson } from "../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../lib/session.ts";

export const runtime = "nodejs";
const MAX_BODY_BYTES = 8 * 1024;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

export async function GET(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) return errorResponse("Login dashboard diperlukan", 401);
  if (user.role !== "admin") {
    return errorResponse("Akses ditolak: Hanya role 'admin' yang dapat mengelola API Key", 403);
  }
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);

  try {
    const upstream = await fetch(`${fleetBaseUrl()}/api/keys`, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${commandToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return errorResponse(`Gagal menghubungi backend fleet: ${err instanceof Error ? err.message : String(err)}`, 502);
  }
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) return errorResponse("Origin tidak diizinkan", 403);
  const user = await resolveAuthorizedSession(request);
  if (!user) return errorResponse("Login dashboard diperlukan", 401);
  if (user.role !== "admin") {
    return errorResponse("Akses ditolak: Hanya role 'admin' yang dapat mengelola API Key", 403);
  }
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);

  const parsed = await readBoundedJson(request, MAX_BODY_BYTES);
  if (!parsed.ok) return errorResponse(parsed.error, parsed.status);
  if (typeof parsed.data !== "object" || parsed.data === null || Array.isArray(parsed.data)) {
    return errorResponse("Body harus berupa object", 400);
  }

  const payload = parsed.data as Record<string, unknown>;
  const upstreamPath = payload.action === "revoke" ? "/api/keys/revoke" : "/api/keys";
  try {
    const upstream = await fetch(`${fleetBaseUrl()}${upstreamPath}`, {
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
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return errorResponse(`Gagal memproses request ke backend fleet: ${err instanceof Error ? err.message : String(err)}`, 502);
  }
}
