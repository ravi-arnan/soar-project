import {
  fleetBaseUrl,
  originAllowed,
  proxyAuthenticatedFleetGet,
  readBoundedJson,
} from "../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../lib/session.ts";

export const runtime = "nodejs";
const MAX_BODY_BYTES = 32 * 1024;

export async function GET(request: Request): Promise<Response> {
  return proxyAuthenticatedFleetGet(request, "/api/triage", resolveAuthorizedSession);
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return Response.json({ error: "Origin tidak diizinkan" }, { status: 403 });
  }
  const user = await resolveAuthorizedSession(request);
  if (!user) {
    return Response.json({ error: "Login dashboard diperlukan" }, { status: 401 });
  }
  if (user.role === "viewer") {
    return Response.json({ error: "Akses ditolak: Role viewer bersifat read-only" }, { status: 403 });
  }
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return Response.json({ error: "FLEET_COMMAND_TOKEN belum dikonfigurasi" }, { status: 503 });
  }
  const parsed = await readBoundedJson(request, MAX_BODY_BYTES);
  if (!parsed.ok) {
    return Response.json({ error: parsed.error }, { status: parsed.status });
  }
  if (typeof parsed.data !== "object" || parsed.data === null || Array.isArray(parsed.data)) {
    return Response.json({ error: "Body harus berupa JSON object" }, { status: 400 });
  }
  const body = parsed.data as Record<string, unknown>;
  const actor = user.email || user.username || "analyst";
  try {
    const upstream = await fetch(`${fleetBaseUrl()}/api/triage`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      body: JSON.stringify({
        ...body,
        updated_by: actor,
        actor,
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return Response.json(
      { error: `Gagal memperbarui status triage: ${err instanceof Error ? err.message : String(err)}` },
      { status: 502 },
    );
  }
}
