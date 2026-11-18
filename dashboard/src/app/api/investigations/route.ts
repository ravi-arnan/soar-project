import { resolveAuthorizedSession } from "../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 128 * 1024;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

function fleetBaseUrl(): string {
  const rawBase =
    process.env.FLEET_API_URL ||
    (process.env.NODE_ENV === "production"
      ? "http://host.docker.internal:8080"
      : "http://127.0.0.1:8080");
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

  const url = new URL(request.url);
  const qs = url.searchParams.toString();
  const upstreamUrl = `${fleetBaseUrl()}/api/investigations${qs ? `?${qs}` : ""}`;

  try {
    const upstream = await fetch(upstreamUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });

    const data = await upstream.json();
    return Response.json(data, { status: upstream.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal mengambil investigasi AI Agent: ${msg}`, 502);
  }
}

export async function POST(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) {
    return errorResponse("Login dashboard diperlukan", 401);
  }

  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);
  }

  let body: Record<string, unknown>;
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return errorResponse("Payload investigasi terlalu besar", 413);
    }
    const parsed = JSON.parse(text);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return errorResponse("Body harus berupa JSON object", 400);
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return errorResponse("Format JSON tidak valid", 400);
  }

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
      const data = await upstream.json();
      return Response.json(data, { status: upstream.status });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return errorResponse(`Gagal menghapus investigasi: ${msg}`, 502);
    }
  }

  if (user.role !== "admin" && user.role !== "analyst") {
    return errorResponse("Akses ditolak: Viewer bersifat read-only", 403);
  }

  try {
    const upstream = await fetch(`${fleetBaseUrl()}/api/investigations`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      body: JSON.stringify({
        ...body,
        created_by: body.created_by || `dashboard:${user.username}`,
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(8_000),
    });
    const data = await upstream.json();
    return Response.json(data, { status: upstream.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal menyimpan investigasi: ${msg}`, 502);
  }
}
