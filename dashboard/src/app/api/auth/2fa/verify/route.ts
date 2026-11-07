import {
  createSessionToken,
  sessionCookie,
  validLoginToken,
} from "../../../../../lib/session.ts";
import { verifyStoredOtp } from "../../../../../lib/twoFactor.ts";

export const runtime = "nodejs";

function originAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return (process.env.DASHBOARD_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .includes(origin);
}

function clientIdentifier(request: Request): string {
  const cf = request.headers.get("cf-connecting-ip")?.trim();
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return cf || forwarded || "local-admin-client";
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return Response.json({ error: "Origin tidak diizinkan" }, { status: 403 });
  }

  const expectedToken = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  if (!validLoginToken(expectedToken)) {
    return Response.json({ error: "Dashboard auth belum dikonfigurasi di server" }, { status: 503 });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "Format body JSON tidak valid" }, { status: 400 });
  }

  if (
    typeof body !== "object" ||
    body === null ||
    !("code" in body) ||
    typeof body.code !== "string"
  ) {
    return Response.json({ error: "Parameter 'code' wajib diisi" }, { status: 400 });
  }

  const clientId = clientIdentifier(request);
  const result = verifyStoredOtp(clientId, body.code);

  if (!result.success) {
    return Response.json({ error: result.error || "Kode verifikasi tidak valid" }, { status: 401 });
  }

  // OTP valid! Terbitkan cookie sesi resmi SOAR dengan role Admin
  const adminEmail = process.env.ADMIN_EMAIL ?? "raviarnankeren@gmail.com";
  const token = createSessionToken(expectedToken, {
    username: "admin",
    role: "admin",
    email: adminEmail,
    name: "Ravi Arnan (SOC Lead)",
  });
  const secure =
    new URL(request.url).protocol === "https:" ||
    request.headers.get("origin")?.startsWith("https://") === true;

  return Response.json(
    { success: true, message: "Autentikasi 2FA berhasil. Akses terbuka." },
    {
      status: 200,
      headers: { "Set-Cookie": sessionCookie(token, secure) },
    },
  );
}
