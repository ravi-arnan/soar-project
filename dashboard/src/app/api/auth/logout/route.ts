import { isHttpsRequest, originAllowed } from "../../../../lib/requestGuard.ts";
import { clearCachedEmailSession, SESSION_COOKIE_NAME } from "../../../../lib/session.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return Response.json({ error: "Origin tidak diizinkan" }, { status: 403 });
  }

  const cfEmail = request.headers.get("cf-access-authenticated-user-email");
  const hasCfAccess = Boolean(
    cfEmail?.trim() || request.headers.get("cf-access-jwt-assertion")?.trim(),
  );

  clearCachedEmailSession(cfEmail);
  const secure = isHttpsRequest(request);
  const cookie = `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;

  return Response.json(
    {
      success: true,
      message: "Sesi berhasil ditutup",
      cloudflareAccess: hasCfAccess,
      logoutUrl: hasCfAccess ? "/cdn-cgi/access/logout" : null,
    },
    {
      status: 200,
      headers: { "Set-Cookie": cookie },
    },
  );
}
