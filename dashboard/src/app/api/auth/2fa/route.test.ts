import assert from "node:assert/strict";
import test from "node:test";
import { createSessionToken } from "../../../../lib/session.ts";
import {
  generateOtp,
  getOtpCooldown,
  maskEmail,
  storeOtp,
  verifyStoredOtp,
} from "../../../../lib/twoFactor.ts";
import { POST as verifyOtp } from "./verify/route.ts";

const originalToken = process.env.DASHBOARD_LOGIN_TOKEN;
const originalOrigins = process.env.DASHBOARD_ALLOWED_ORIGINS;
const originalEmail = process.env.ADMIN_EMAIL;

const validSecret = "test-secret-token-" + "x".repeat(32);

test.beforeEach(() => {
  process.env.DASHBOARD_LOGIN_TOKEN = validSecret;
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  process.env.ADMIN_EMAIL = "admin@example.com";
});

test.after(() => {
  if (originalToken === undefined) delete process.env.DASHBOARD_LOGIN_TOKEN;
  else process.env.DASHBOARD_LOGIN_TOKEN = originalToken;
  if (originalOrigins === undefined) delete process.env.DASHBOARD_ALLOWED_ORIGINS;
  else process.env.DASHBOARD_ALLOWED_ORIGINS = originalOrigins;
  if (originalEmail === undefined) delete process.env.ADMIN_EMAIL;
  else process.env.ADMIN_EMAIL = originalEmail;
});

test("maskEmail helper masking logic", () => {
  assert.equal(maskEmail("administrator@example.com"), "a****r@example.com");
  assert.equal(maskEmail("ab@test.com"), "a*@test.com");
  assert.equal(maskEmail("admin@soar.dev"), "a***n@soar.dev");
});

test("generateOtp produces 6-digit cryptographically random numeric string", () => {
  for (let i = 0; i < 20; i++) {
    const code = generateOtp();
    assert.match(code, /^\d{6}$/);
    const num = Number(code);
    assert.ok(num >= 100000 && num <= 999999);
  }
});

test("storeOtp and verifyStoredOtp lifecycle", () => {
  const key = "admin:198.51.100.1";
  storeOtp(key, "123456");

  const wrongRes = verifyStoredOtp(key, "999999");
  assert.equal(wrongRes.success, false);
  assert.match(wrongRes.error ?? "", /Kode salah/);

  const correctRes = verifyStoredOtp(key, "123456");
  assert.equal(correctRes.success, true);

  const reuseRes = verifyStoredOtp(key, "123456");
  assert.equal(reuseRes.success, false);
});

test("verifyStoredOtp expired handling", () => {
  const key = "admin:198.51.100.2";
  const now = Date.now();
  storeOtp(key, "654321", now - 10000);
  const res = verifyStoredOtp(key, "654321", now + 6 * 60 * 1000);
  assert.equal(res.success, false);
  assert.match(res.error ?? "", /kedaluwarsa/);
});

test("getOtpCooldown rate limits consecutive requests", () => {
  const key = "admin:198.51.100.3";
  const now = Date.now();
  storeOtp(key, "111222", now);
  const cd = getOtpCooldown(key, now + 5000);
  assert.ok(cd > 0 && cd <= 30);
  assert.equal(getOtpCooldown(key, now + 35000), 0);
});

test("2FA verify requires authenticated admin session (step-up auth)", async () => {
  const clientIp = "198.51.100.10";
  storeOtp(`admin:${clientIp}`, "555888");

  // Tanpa sesi login awal harus DITOLAK 401 (anti passwordless escalation)
  const unauthReq = new Request("http://dashboard.test/api/auth/2fa/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://dashboard.test",
      "cf-connecting-ip": clientIp,
    },
    body: JSON.stringify({ code: "555888" }),
  });
  const unauthResp = await verifyOtp(unauthReq);
  assert.equal(unauthResp.status, 401);

  // Dengan sesi admin awal yang sah, step-up 2FA berhasil 200
  const adminCookie = createSessionToken(validSecret, {
    username: "admin",
    role: "admin",
    email: "admin@example.com",
    name: "SOAR Administrator",
  });
  const verifyReq = new Request("http://dashboard.test/api/auth/2fa/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://dashboard.test",
      "cf-connecting-ip": clientIp,
      cookie: `soar_session=${adminCookie}`,
    },
    body: JSON.stringify({ code: "555888" }),
  });

  const verifyResp = await verifyOtp(verifyReq);
  assert.equal(verifyResp.status, 200);
  const cookie = verifyResp.headers.get("set-cookie") ?? "";
  assert.match(cookie, /soar_session=/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
});
