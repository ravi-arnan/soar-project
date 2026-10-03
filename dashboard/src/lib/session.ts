import { createHmac, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE_NAME = "soar_session";
const SESSION_TTL_SECONDS = 8 * 60 * 60;

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

function signature(expires: string, secret: string): string {
  return createHmac("sha256", secret).update(`soar-session:${expires}`).digest("base64url");
}

export function createSessionToken(secret: string, now = Date.now()): string {
  const expires = Math.floor(now / 1000) + SESSION_TTL_SECONDS;
  const value = String(expires);
  return `${value}.${signature(value, secret)}`;
}

export function isValidSession(value: string, secret: string, now = Date.now()): boolean {
  const [expires, providedSignature] = value.split(".");
  if (!expires || !providedSignature || !/^\d+$/.test(expires)) return false;
  if (Number(expires) <= Math.floor(now / 1000)) return false;
  return secretMatches(providedSignature, signature(expires, secret));
}

export function sessionFromRequest(request: Request): string | null {
  const prefix = `${SESSION_COOKIE_NAME}=`;
  const value = (request.headers.get("cookie") ?? "")
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(prefix));
  return value ? value.slice(prefix.length) : null;
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
