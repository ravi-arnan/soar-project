import {
  clientIpFromCf,
  isHttpsRequest,
  originAllowed,
  readBoundedJson,
} from "../../../../../lib/requestGuard.ts";
import {
  createSessionToken,
  resolveAuthorizedSession,
  sessionCookie,
  touchUserLastLogin,
  validLoginToken,
} from "../../../../../lib/session.ts";
import { verifyStoredOtp } from "../../../../../lib/twoFactor.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return Response.json({ error: "Origin tidak diizinkan" }, { status: 403 });
  }

  const session = await resolveAuthorizedSession(request);
  if (!session) {
    return Response.json({ error: "Sesi login awal diperlukan sebelum verifikasi 2FA." }, { status: 401 });
  }
  if (session.role !== "admin") {
    return Response.json({ error: "Akses ditolak: hanya role Admin." }, { status: 403 });
  }

  const expectedToken = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  if (!validLoginToken(expectedToken)) {
    return Response.json({ error: "Dashboard auth belum dikonfigurasi di server" }, { status: 503 });
  }

  const parsed = await readBoundedJson(request, 2048);
  if (!parsed.ok) {
    return Response.json({ error: parsed.error }, { status: parsed.status });
  }

  const body = parsed.data;
  if (
    typeof body !== "object" ||
    body === null ||
    !("code" in body) ||
    typeof (body as { code?: unknown }).code !== "string"
  ) {
    return Response.json({ error: "Parameter 'code' wajib diisi" }, { status: 400 });
  }

  const clientIp = clientIpFromCf(request);
  const otpKey = `${session.username}:${clientIp}`;
  const result = verifyStoredOtp(otpKey, (body as { code: string }).code);

  if (!result.success) {
    return Response.json({ error: result.error || "Kode verifikasi tidak valid" }, { status: 401 });
  }

  const adminEmail = (session.email || process.env.ADMIN_EMAIL || "").trim();
  await touchUserLastLogin({ username: session.username, email: adminEmail });
  const token = createSessionToken(expectedToken, {
    username: session.username,
    role: "admin",
    email: adminEmail,
    name: session.name || "SOAR Administrator",
  });
  const secure = isHttpsRequest(request);

  return Response.json(
    { success: true, message: "Autentikasi 2FA berhasil. Akses terbuka." },
    {
      status: 200,
      headers: { "Set-Cookie": sessionCookie(token, secure) },
    },
  );
}
