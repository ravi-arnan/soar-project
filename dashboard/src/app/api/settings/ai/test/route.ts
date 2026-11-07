import {
  resolveAuthorizedSession,
} from "../../../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 8 * 1024;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

function fleetBaseUrl(): string {
  const rawBase = process.env.FLEET_API_URL || "http://127.0.0.1:8080";
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export async function POST(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) {
    return errorResponse("Login dashboard diperlukan", 401);
  }

  // Admin dan Analyst diizinkan melakukan uji coba inferensi AI
  if (user.role !== "admin" && user.role !== "analyst") {
    return errorResponse("Akses ditolak: Hanya Admin dan Analyst yang dapat menguji model AI", 403);
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

  const upstreamUrl = `${fleetBaseUrl()}/api/settings/ai/test`;
  try {
    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      cache: "no-store",
      signal: AbortSignal.timeout(25_000),
    });

    const resData = await upstream.json();
    return Response.json(resData, { status: upstream.status });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal menguji inferensi AI: ${msg}`, 502);
  }
}
