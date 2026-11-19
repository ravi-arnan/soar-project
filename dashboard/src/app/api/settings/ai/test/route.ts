import { fleetBaseUrl, originAllowed, readBoundedJson } from "../../../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../../../lib/session.ts";

export const runtime = "nodejs";
const MAX_BODY_BYTES = 64 * 1024;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) return errorResponse("Origin tidak diizinkan", 403);
  const user = await resolveAuthorizedSession(request);
  if (!user) return errorResponse("Login dashboard diperlukan", 401);
  if (user.role !== "admin" && user.role !== "analyst") {
    return errorResponse("Akses ditolak: Hanya Admin dan Analyst yang dapat menguji model AI", 403);
  }
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) return errorResponse("FLEET_COMMAND_TOKEN belum dikonfigurasi", 503);

  const parsed = await readBoundedJson(request, MAX_BODY_BYTES);
  if (!parsed.ok) return errorResponse(parsed.error, parsed.status);

  try {
    const upstream = await fetch(`${fleetBaseUrl()}/api/settings/ai/test`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(parsed.data),
      cache: "no-store",
      signal: AbortSignal.timeout(25_000),
    });
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return errorResponse(`Gagal menguji inferensi AI: ${err instanceof Error ? err.message : String(err)}`, 502);
  }
}
