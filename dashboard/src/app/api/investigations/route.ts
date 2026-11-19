import { fleetBaseUrl, originAllowed, readBoundedJson } from "../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../lib/session.ts";

export const runtime = "nodejs";
const MAX_BODY_BYTES = 128 * 1024;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

export async function GET(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) return errorResponse("Login dashboard diperlukan", 401);
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);

  const url = new URL(request.url);
  const qs = url.searchParams.toString();
  const upstreamUrl = `${fleetBaseUrl()}/api/investigations${qs ? `?${qs}` : ""}`;

  try {
    const upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: { Accept: "application/json", Authorization: `Bearer ${commandToken}` },
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return errorResponse(`Gagal mengambil investigasi AI Agent: ${err instanceof Error ? err.message : String(err)}`, 502);
  }
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) return errorResponse("Origin tidak diizinkan", 403);
  const user = await resolveAuthorizedSession(request);
  if (!user) return errorResponse("Login dashboard diperlukan", 401);
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);

  const parsed = await readBoundedJson(request, MAX_BODY_BYTES);
  if (!parsed.ok) return errorResponse(parsed.error, parsed.status);
  if (typeof parsed.data !== "object" || parsed.data === null || Array.isArray(parsed.data)) {
    return errorResponse("Body harus berupa JSON object", 400);
  }
  const body = parsed.data as Record<string, unknown>;

  const action = typeof body.action === "string" ? body.action.trim().toLowerCase() : "create";
  if (action === "delete") {
    if (user.role !== "admin") {
      return errorResponse("Hanya Admin yang dapat menghapus laporan investigasi", 403);
    }
    try {
      const upstream = await fetch(`${fleetBaseUrl()}/api/investigations/delete`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${commandToken}`,
        },
        body: JSON.stringify({ id: body.id }),
        cache: "no-store",
        signal: AbortSignal.timeout(8_000),
      });
      return Response.json(await upstream.json(), { status: upstream.status });
    } catch (err) {
      return errorResponse(`Gagal menghapus investigasi: ${err instanceof Error ? err.message : String(err)}`, 502);
    }
  }

  if (user.role !== "admin" && user.role !== "analyst") {
    return errorResponse("Akses ditolak: Viewer bersifat read-only", 403);
  }

  // Paksa identitas actor dari sesi terautentikasi (cegah created_by spoofing)
  const sanitizedBody = { ...body, created_by: `dashboard:${user.username}` };
  try {
    const upstream = await fetch(`${fleetBaseUrl()}/api/investigations`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      body: JSON.stringify(sanitizedBody),
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return errorResponse(`Gagal menyimpan investigasi: ${err instanceof Error ? err.message : String(err)}`, 502);
  }
}
