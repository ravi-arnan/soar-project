import assert from "node:assert/strict";
import test from "node:test";
import {
  createSessionToken,
  isValidSession,
  parseSession,
  getAuthorizedSession,
} from "../../../lib/session.ts";
import type { SessionUser } from "../../../lib/session.ts";

const secret = "testing-rbac-secret-token-" + "x".repeat(32);

test("RBAC session token generation and parsing", () => {
  // 1. Legacy token format (2-part)
  const legacyToken = createSessionToken(secret);
  assert.equal(isValidSession(legacyToken, secret), true);
  const legacyParsed = parseSession(legacyToken, secret);
  assert.equal(legacyParsed.valid, true);
  assert.equal(legacyParsed.user?.role, "admin");

  // 2. Analyst token format (3-part)
  const analystUser: SessionUser = {
    username: "analyst1",
    role: "analyst",
    email: "analyst1@soar.local",
    name: "Tier 2 Responder",
  };
  const analystToken = createSessionToken(secret, analystUser);
  assert.equal(isValidSession(analystToken, secret), true);
  const analystParsed = parseSession(analystToken, secret);
  assert.equal(analystParsed.valid, true);
  assert.equal(analystParsed.user?.username, "analyst1");
  assert.equal(analystParsed.user?.role, "analyst");
  assert.equal(analystParsed.user?.name, "Tier 2 Responder");

  // 3. Viewer token format (3-part)
  const viewerUser: SessionUser = {
    username: "auditor1",
    role: "viewer",
    name: "SOC Auditor",
  };
  const viewerToken = createSessionToken(secret, viewerUser);
  assert.equal(isValidSession(viewerToken, secret), true);
  const viewerParsed = parseSession(viewerToken, secret);
  assert.equal(viewerParsed.valid, true);
  assert.equal(viewerParsed.user?.role, "viewer");

  // 4. Tampered token payload
  const [expires, , sig] = viewerToken.split(".");
  const tamperedPayload = Buffer.from(
    JSON.stringify({ username: "hacker", role: "admin" }),
  ).toString("base64url");
  const tamperedToken = `${expires}.${tamperedPayload}.${sig}`;
  assert.equal(isValidSession(tamperedToken, secret), false);
  assert.equal(parseSession(tamperedToken, secret).valid, false);

  // 5. Expired token
  const pastTime = Date.now() - 10 * 60 * 60 * 1000;
  const expiredToken = createSessionToken(secret, viewerUser, pastTime);
  assert.equal(isValidSession(expiredToken, secret), false);
  assert.equal(parseSession(expiredToken, secret).valid, false);

  // 6. getAuthorizedSession from Request
  const req = new Request("http://localhost:3000/api/commands", {
    headers: {
      cookie: `soar_session=${analystToken}; other=value`,
    },
  });
  const authorized = getAuthorizedSession(req, secret);
  assert.notEqual(authorized, null);
  assert.equal(authorized?.username, "analyst1");
  assert.equal(authorized?.role, "analyst");

  // 7. Cloudflare Access Email Header
  process.env.ADMIN_EMAIL = "raviarnankeren@gmail.com";
  const cfAdminReq = new Request("http://localhost:3000/api/commands", {
    headers: {
      "cf-access-authenticated-user-email": "raviarnankeren@gmail.com",
    },
  });
  const cfAdmin = getAuthorizedSession(cfAdminReq, secret);
  assert.notEqual(cfAdmin, null);
  assert.equal(cfAdmin?.role, "admin");
  assert.equal(cfAdmin?.email, "raviarnankeren@gmail.com");
});
