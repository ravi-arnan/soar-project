import assert from "node:assert/strict";
import test from "node:test";
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
const originalBrevo = process.env.BREVO_API_KEY;
const originalEmail = process.env.ADMIN_EMAIL;

const validSecret = "test-secret-token-" + "x".repeat(32);

test.beforeEach(() => {
  process.env.DASHBOARD_LOGIN_TOKEN = validSecret;
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  process.env.ADMIN_EMAIL = "raviarnankeren@gmail.com";
});

test.after(() => {
  if (originalToken === undefined) delete process.env.DASHBOARD_LOGIN_TOKEN;
  else process.env.DASHBOARD_LOGIN_TOKEN = originalToken;
  if (originalOrigins === undefined) delete process.env.DASHBOARD_ALLOWED_ORIGINS;
  else process.env.DASHBOARD_ALLOWED_ORIGINS = originalOrigins;
  if (originalBrevo === undefined) delete process.env.BREVO_API_KEY;
  else process.env.BREVO_API_KEY = originalBrevo;
  if (originalEmail === undefined) delete process.env.ADMIN_EMAIL;
  else process.env.ADMIN_EMAIL = originalEmail;
});

test("maskEmail helper masking logic", () => {
  assert.equal(maskEmail("raviarnankeren@gmail.com"), "r****n@gmail.com");
  assert.equal(maskEmail("ab@test.com"), "a*@test.com");
  assert.equal(maskEmail("admin@soar.dev"), "a***n@soar.dev");
});

test("generateOtp produces 6-digit numeric string", () => {
  for (let i = 0; i < 20; i++) {
    const code = generateOtp();
    assert.match(code, /^\d{6}$/);
    const num = Number(code);
    assert.ok(num >= 100000 && num <= 999999);
  }
});

test("storeOtp and verifyStoredOtp lifecycle", () => {
  const key = "test-client-1";
  storeOtp(key, "123456");

  // Percobaan salah
  const wrongRes = verifyStoredOtp(key, "999999");
  assert.equal(wrongRes.success, false);
  assert.match(wrongRes.error ?? "", /Kode salah/);

  // Percobaan benar
  const correctRes = verifyStoredOtp(key, "123456");
  assert.equal(correctRes.success, true);

  // Sekali pakai (harus sudah hangus)
  const reuseRes = verifyStoredOtp(key, "123456");
  assert.equal(reuseRes.success, false);
});

test("verifyStoredOtp expired handling", () => {
  const key = "test-client-expired";
  const now = Date.now();
  storeOtp(key, "654321", now - 10000);

  // Panggil dengan waktu 6 menit kemudian (melewati 5 menit TTL)
  const res = verifyStoredOtp(key, "654321", now + 6 * 60 * 1000);
  assert.equal(res.success, false);
  assert.match(res.error ?? "", /kedaluwarsa/);
});

test("getOtpCooldown rate limits consecutive requests", () => {
  const key = "test-client-cd";
  const now = Date.now();
  storeOtp(key, "111222", now);

  const cd = getOtpCooldown(key, now + 5000); // 5 detik setelah request
  assert.ok(cd > 0 && cd <= 30);

  const cdDone = getOtpCooldown(key, now + 35000); // 35 detik kemudian
  assert.equal(cdDone, 0);
});

test("2FA API Endpoints flow (request and verify)", async () => {
  const clientKey = "test-e2e-client";

  // Simulasikan inject OTP ke store langsung untuk menghindari pemanggilan network eksternal
  storeOtp(clientKey, "555888");

  const verifyReq = new Request("http://dashboard.test/api/auth/2fa/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://dashboard.test",
      "cf-connecting-ip": clientKey,
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
