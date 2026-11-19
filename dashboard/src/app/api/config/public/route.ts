import { maskEmail } from "../../../../lib/twoFactor.ts";

export const runtime = "nodejs";

export async function GET(): Promise<Response> {
  const publicSoarUrl = (process.env.PUBLIC_SOAR_URL || "").trim().replace(/\/$/, "");
  const publicEnrollUrl = (process.env.PUBLIC_ENROLL_URL || publicSoarUrl || "").trim().replace(/\/$/, "");
  const wazuhManagerHost = (process.env.WAZUH_MANAGER_HOST || "127.0.0.1").trim();
  const adminEmail = (process.env.ADMIN_EMAIL || "").trim();

  return Response.json(
    {
      publicSoarUrl,
      publicEnrollUrl,
      wazuhManagerHost,
      adminEmailMasked: adminEmail ? maskEmail(adminEmail) : "",
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}
