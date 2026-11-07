import { createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE_NAME = "soar_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60;

export type UserRole = "admin" | "analyst" | "viewer";

export interface SessionUser {
  username: string;
  role: UserRole;
  email?: string;
  name?: string;
}

export function secretMatches(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function validLoginToken(value: string): boolean {
  return (
    value.length >= 32 &&
    !["your-", "isi-dengan", "replace-", "generate-"].some((prefix) =>
      value.toLowerCase().startsWith(prefix),
    )
  );
}

function legacySignature(expires: string, secret: string): string {
  return createHmac("sha256", secret).update(`soar-session:${expires}`).digest("base64url");
}

function userSessionSignature(expires: string, payloadEncoded: string, secret: string): string {
  return createHmac("sha256", secret).update(`soar-session:${expires}:${payloadEncoded}`).digest("base64url");
}

export function createSessionToken(
  secret: string,
  user?: SessionUser,
  now = Date.now(),
): string {
  const expires = String(Math.floor(now / 1000) + SESSION_TTL_SECONDS);
  if (!user) {
    return `${expires}.${legacySignature(expires, secret)}`;
  }
  const payloadEncoded = Buffer.from(JSON.stringify(user)).toString("base64url");
  const sig = userSessionSignature(expires, payloadEncoded, secret);
  return `${expires}.${payloadEncoded}.${sig}`;
}

export function parseSession(
  value: string,
  secret: string,
  now = Date.now(),
): { valid: boolean; user?: SessionUser; expires?: number } {
  if (!value) return { valid: false };
  const parts = value.split(".");
  if (parts.length === 2) {
    const [expires, sig] = parts;
    if (!expires || !sig || !/^\d+$/.test(expires)) return { valid: false };
    if (Number(expires) <= Math.floor(now / 1000)) return { valid: false };
    const valid = secretMatches(sig, legacySignature(expires, secret));
    if (!valid) return { valid: false };
    return {
      valid: true,
      expires: Number(expires),
      user: {
        username: "master_admin",
        role: "admin",
        name: "Administrator",
      },
    };
  }
  if (parts.length === 3) {
    const [expires, payloadEncoded, sig] = parts;
    if (!expires || !payloadEncoded || !sig || !/^\d+$/.test(expires)) return { valid: false };
    if (Number(expires) <= Math.floor(now / 1000)) return { valid: false };
    const valid = secretMatches(sig, userSessionSignature(expires, payloadEncoded, secret));
    if (!valid) return { valid: false };
    try {
      const decodedJson = Buffer.from(payloadEncoded, "base64url").toString("utf-8");
      const user = JSON.parse(decodedJson) as SessionUser;
      if (!user.username || !["admin", "analyst", "viewer"].includes(user.role)) {
        return { valid: false };
      }
      return { valid: true, expires: Number(expires), user };
    } catch {
      return { valid: false };
    }
  }
  return { valid: false };
}

export function isValidSession(value: string, secret: string, now = Date.now()): boolean {
  return parseSession(value, secret, now).valid;
}

export function sessionFromRequest(request: Request): string | null {
  const prefix = `${SESSION_COOKIE_NAME}=`;
  const value = (request.headers.get("cookie") ?? "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return value ? value.slice(prefix.length) : null;
}

export function getAuthorizedSession(
  request: Request,
  secret = process.env.DASHBOARD_LOGIN_TOKEN ?? "",
  now = Date.now(),
): SessionUser | null {
  // 1. Cloudflare Access Zero Trust (Email-based authentication via tunnel)
  const cfEmail = request.headers.get("cf-access-authenticated-user-email")?.trim().toLowerCase();
  if (cfEmail) {
    const adminEmail = (process.env.ADMIN_EMAIL ?? "raviarnankeren@gmail.com").trim().toLowerCase();
    if (cfEmail === adminEmail) {
      return {
        username: "admin",
        role: "admin",
        email: cfEmail,
        name: "Ravi Arnan (SOC Lead)",
      };
    }
    return {
      username: cfEmail.split("@")[0],
      role: "viewer",
      email: cfEmail,
      name: cfEmail,
    };
  }

  // 2. Cookie sesi resmi SOAR (dari verifikasi 2FA Dual-Channel Email & Telegram)
  if (!validLoginToken(secret)) return null;
  const cookieValue = sessionFromRequest(request);
  if (!cookieValue) return null;
  const parsed = parseSession(cookieValue, secret, now);
  return parsed.valid && parsed.user ? parsed.user : null;
}

export function sessionCookie(value: string, secure: boolean): string {
  const attributes = [
    `${SESSION_COOKIE_NAME}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${SESSION_TTL_SECONDS}`,
  ];
  if (secure) attributes.push("Secure");
  return attributes.join("; ");
}
