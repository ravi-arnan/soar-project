import { fleetBaseUrl } from "../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../lib/session.ts";

export const runtime = "nodejs";

export async function GET(request: Request): Promise<Response> {
  const user = await resolveAuthorizedSession(request);
  if (!user) {
    return Response.json({ error: "Login dashboard diperlukan" }, { status: 401 });
  }
  if (user.role !== "admin" && user.role !== "analyst") {
    return Response.json({ error: "Akses ditolak: Hanya Admin dan Analyst yang dapat melihat Audit Trail" }, { status: 403 });
  }
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return Response.json({ error: "FLEET_COMMAND_TOKEN belum dikonfigurasi" }, { status: 503 });
  }
  const url = new URL(request.url);
  const qs = url.searchParams.toString();
  try {
    const upstream = await fetch(`${fleetBaseUrl()}/api/audit${qs ? `?${qs}` : ""}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(10_000),
    });
    return Response.json(await upstream.json(), { status: upstream.status });
  } catch (err) {
    return Response.json(
      { error: `Gagal memuat audit log: ${err instanceof Error ? err.message : String(err)}` },
      { status: 502 },
    );
  }
}
