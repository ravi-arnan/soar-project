import { clearCachedEmailSession, SESSION_COOKIE_NAME } from "../../../../lib/session.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  const cfEmail = request.headers.get("cf-access-authenticated-user-email");
  const hasCfAccess = Boolean(
    cfEmail?.trim() || request.headers.get("cf-access-jwt-assertion")?.trim(),
  );

  clearCachedEmailSession(cfEmail);

  const forwardedProto = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim();
  const secure =
    new URL(request.url).protocol === "https:" ||
    request.headers.get("origin")?.startsWith("https://") === true ||
    forwardedProto === "https";

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
