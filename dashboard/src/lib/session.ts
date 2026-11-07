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

const emailRoleCache = new Map<string, { user: SessionUser; expires: number }>();

function fleetBaseUrl(): string {
  const rawBase =
    process.env.FLEET_API_URL ||
    (process.env.NODE_ENV === "production"
      ? "http://host.docker.internal:8080"
      : "http://127.0.0.1:8080");
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export async function resolveAuthorizedSession(
  request: Request,
  secret = process.env.DASHBOARD_LOGIN_TOKEN ?? "",
  now = Date.now(),
): Promise<SessionUser | null> {
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

    // Cek cache in-memory untuk performa 0ms
    const cached = emailRoleCache.get(cfEmail);
    if (cached && cached.expires > now) {
      return cached.user;
    }

    // Lookup user role dari database fleet-monitor
    try {
      const lookupUrl = `${fleetBaseUrl()}/api/users/lookup?email=${encodeURIComponent(cfEmail)}`;
      const res = await fetch(lookupUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-store",
        signal: AbortSignal.timeout(3000),
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.user) {
          const user: SessionUser = {
            username: data.user.username,
            role: data.user.role,
            email: data.user.email || cfEmail,
            name: data.user.name || data.user.username,
          };
          emailRoleCache.set(cfEmail, { user, expires: now + 60_000 });
          return user;
        }
      }
    } catch {
      // Fallback jika backend unreachable
    }

    const fallbackUser: SessionUser = {
      username: cfEmail.split("@")[0],
      role: "viewer",
      email: cfEmail,
      name: cfEmail,
    };
    emailRoleCache.set(cfEmail, { user: fallbackUser, expires: now + 30_000 });
    return fallbackUser;
  }

  // 2. Cookie sesi resmi SOAR (dari verifikasi 2FA Dual-Channel Email & Telegram)
  if (!validLoginToken(secret)) return null;
  const cookieValue = sessionFromRequest(request);
  if (!cookieValue) return null;
  const parsed = parseSession(cookieValue, secret, now);
  return parsed.valid && parsed.user ? parsed.user : null;
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
    const cached = emailRoleCache.get(cfEmail);
    if (cached && cached.expires > now) {
      return cached.user;
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
