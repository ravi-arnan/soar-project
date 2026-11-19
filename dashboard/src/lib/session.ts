import { createHmac, createPublicKey, createVerify, timingSafeEqual, type JsonWebKey } from "node:crypto";
import { fleetBaseUrl } from "./requestGuard.ts";

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

/** Hapus cache role email Cloudflare Access (dipanggil saat logout). */
export function clearCachedEmailSession(email?: string | null): void {
  const normalized = email?.trim().toLowerCase();
  if (normalized) {
    emailRoleCache.delete(normalized);
  }
}

// --- Cloudflare Access JWT (RS256) JWKS Verification ---
type CfJwk = JsonWebKey & { kid?: string };
let cfJwksCache: { domain: string; keys: CfJwk[]; expires: number } | null = null;

export function clearCfJwksCache(): void {
  cfJwksCache = null;
}

async function fetchCfJwks(teamDomain: string, now: number): Promise<CfJwk[]> {
  if (cfJwksCache && cfJwksCache.domain === teamDomain && cfJwksCache.expires > now) {
    return cfJwksCache.keys;
  }
  const cleanDomain = teamDomain.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const certsUrl = `https://${cleanDomain}/cdn-cgi/access/certs`;
  const res = await fetch(certsUrl, {
    method: "GET",
    headers: { Accept: "application/json" },
    cache: "no-store",
    signal: AbortSignal.timeout(4000),
  });
  if (!res.ok) return [];
  const body = (await res.json()) as { keys?: CfJwk[] };
  const keys = Array.isArray(body?.keys) ? body.keys : [];
  cfJwksCache = { domain: teamDomain, keys, expires: now + 10 * 60_000 };
  return keys;
}

export async function verifyCloudflareAccessJwt(
  jwtToken: string,
  teamDomain: string,
  expectedAud: string,
  now = Date.now(),
  jwksOverride?: CfJwk[],
): Promise<{ valid: boolean; email?: string }> {
  const parts = jwtToken.trim().split(".");
  if (parts.length !== 3) return { valid: false };
  const [headerB64, payloadB64, sigB64] = parts;
  try {
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf-8")) as {
      alg?: string;
      kid?: string;
    };
    if (header.alg !== "RS256" || !header.kid) return { valid: false };

    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf-8")) as {
      aud?: string | string[];
      exp?: number;
      nbf?: number;
      email?: string;
    };
    const nowSec = Math.floor(now / 1000);
    if (typeof payload.exp !== "number" || payload.exp <= nowSec) return { valid: false };
    if (typeof payload.nbf === "number" && payload.nbf > nowSec + 60) return { valid: false };

    const audList = Array.isArray(payload.aud) ? payload.aud : typeof payload.aud === "string" ? [payload.aud] : [];
    if (!expectedAud || !audList.includes(expectedAud)) return { valid: false };

    const keys = jwksOverride ?? (await fetchCfJwks(teamDomain, now));
    const jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) return { valid: false };

    const pubKey = createPublicKey({ key: jwk, format: "jwk" });
    const verifier = createVerify("RSA-SHA256");
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const sigBuf = Buffer.from(sigB64, "base64url");
    if (!verifier.verify(pubKey, sigBuf)) return { valid: false };

    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : "";
    return email ? { valid: true, email } : { valid: false };
  } catch {
    return { valid: false };
  }
}

async function verifiedCloudflareEmail(request: Request, now: number): Promise<string | null> {
  const cfJwt = request.headers.get("cf-access-jwt-assertion")?.trim() ?? "";
  const cfEmailHeader = request.headers.get("cf-access-authenticated-user-email")?.trim().toLowerCase() ?? "";
  const teamDomain = (process.env.CF_ACCESS_TEAM_DOMAIN ?? "").trim();
  const expectedAud = (process.env.CF_ACCESS_AUD ?? "").trim();

  if (teamDomain && expectedAud) {
    if (!cfJwt) return null;
    const verified = await verifyCloudflareAccessJwt(cfJwt, teamDomain, expectedAud, now);
    if (!verified.valid || !verified.email) return null;
    if (cfEmailHeader && cfEmailHeader !== verified.email) return null;
    return verified.email;
  }

  // Tanpa CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD, tolak header email mentah (anti header spoofing)
  // kecuali opt-in eksplisit hanya untuk test/local dev.
  if (process.env.ALLOW_UNVERIFIED_CF_HEADERS === "true" && cfEmailHeader) {
    return cfEmailHeader;
  }
  return null;
}

/** Catat timestamp login terakhir di backend fleet-monitor (best-effort, non-fatal). */
export async function touchUserLastLogin(identity: {
  username?: string;
  email?: string;
}): Promise<void> {
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken || (!identity.username && !identity.email)) return;
  try {
    await fetch(`${fleetBaseUrl()}/api/users`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      body: JSON.stringify({
        action: "touch_login",
        username: identity.username || "",
        email: identity.email || "",
      }),
      cache: "no-store",
      signal: AbortSignal.timeout(1500),
    });
  } catch {
    // Non-fatal
  }
}

export async function resolveAuthorizedSession(
  request: Request,
  secret = process.env.DASHBOARD_LOGIN_TOKEN ?? "",
  now = Date.now(),
): Promise<SessionUser | null> {
  // 1. Cloudflare Access Zero Trust (JWT terverifikasi RS256 JWKS)
  const cfEmail = await verifiedCloudflareEmail(request, now);
  if (cfEmail) {
    const cached = emailRoleCache.get(cfEmail);
    if (cached && cached.expires > now) {
      return cached.user;
    }

    const adminEmail = (process.env.ADMIN_EMAIL ?? "").trim().toLowerCase();
    if (adminEmail && cfEmail === adminEmail) {
      const adminUser: SessionUser = {
        username: "admin",
        role: "admin",
        email: cfEmail,
        name: "SOAR Administrator",
      };
      await touchUserLastLogin({ username: "admin", email: cfEmail });
      emailRoleCache.set(cfEmail, { user: adminUser, expires: now + 60_000 });
      return adminUser;
    }

    const commandToken = process.env.FLEET_COMMAND_TOKEN ?? "";
    if (commandToken) {
      try {
        const lookupUrl = `${fleetBaseUrl()}/api/users/lookup?email=${encodeURIComponent(cfEmail)}`;
        const res = await fetch(lookupUrl, {
          method: "GET",
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${commandToken}`,
          },
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
            await touchUserLastLogin({ username: user.username, email: cfEmail });
            emailRoleCache.set(cfEmail, { user, expires: now + 60_000 });
            return user;
          }
        }
      } catch {
        // Fallback jika backend unreachable
      }
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

  // 2. Cookie sesi resmi SOAR (HMAC-SHA256 HttpOnly SameSite=Strict)
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
  // Jalur sinkron hanya menerima CF header jika ALLOW_UNVERIFIED_CF_HEADERS=true (test lokal);
  // route produksi wajib memanggil resolveAuthorizedSession (async JWT verification).
  const cfEmail = request.headers.get("cf-access-authenticated-user-email")?.trim().toLowerCase();
  if (cfEmail && process.env.ALLOW_UNVERIFIED_CF_HEADERS === "true") {
    const adminEmail = (process.env.ADMIN_EMAIL ?? "").trim().toLowerCase();
    if (adminEmail && cfEmail === adminEmail) {
      return {
        username: "admin",
        role: "admin",
        email: cfEmail,
        name: "SOAR Administrator",
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
