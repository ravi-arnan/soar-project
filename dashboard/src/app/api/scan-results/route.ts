import { proxyAuthenticatedFleetGet } from "../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../lib/session.ts";

export const runtime = "nodejs";

export async function GET(request: Request): Promise<Response> {
  return proxyAuthenticatedFleetGet(request, "/api/scan-results", resolveAuthorizedSession);
}
