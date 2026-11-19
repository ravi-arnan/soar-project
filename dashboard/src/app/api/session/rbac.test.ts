import assert from "node:assert/strict";
import { createSign, generateKeyPairSync, type JsonWebKey } from "node:crypto";
import test from "node:test";
import {
  createSessionToken,
  isValidSession,
  parseSession,
  getAuthorizedSession,
  resolveAuthorizedSession,
  verifyCloudflareAccessJwt,
} from "../../../lib/session.ts";
import type { SessionUser } from "../../../lib/session.ts";

const secret = "testing-rbac-secret-token-" + "x".repeat(32);

test("RBAC session token generation, parsing, and unverified CF header rejection", async () => {
  const legacyToken = createSessionToken(secret);
  assert.equal(isValidSession(legacyToken, secret), true);
  const legacyParsed = parseSession(legacyToken, secret);
  assert.equal(legacyParsed.valid, true);
  assert.equal(legacyParsed.user?.role, "admin");

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

  const viewerUser: SessionUser = {
    username: "auditor1",
    role: "viewer",
    name: "SOC Auditor",
  };
  const viewerToken = createSessionToken(secret, viewerUser);
  assert.equal(isValidSession(viewerToken, secret), true);

  // Tampered token payload
  const [expires, , sig] = viewerToken.split(".");
  const tamperedPayload = Buffer.from(
    JSON.stringify({ username: "hacker", role: "admin" }),
  ).toString("base64url");
  const tamperedToken = `${expires}.${tamperedPayload}.${sig}`;
  assert.equal(isValidSession(tamperedToken, secret), false);

  // Expired token
  const pastTime = Date.now() - 10 * 60 * 60 * 1000;
  const expiredToken = createSessionToken(secret, viewerUser, pastTime);
  assert.equal(isValidSession(expiredToken, secret), false);

  // Cookie session authorized
  const req = new Request("http://localhost:3000/api/commands", {
    headers: { cookie: `soar_session=${analystToken}; other=value` },
  });
  const authorized = getAuthorizedSession(req, secret);
  assert.equal(authorized?.username, "analyst1");
  assert.equal(authorized?.role, "analyst");

  // Raw cf-access-authenticated-user-email TANPA JWT harus DITOLAK (anti header spoofing)
  delete process.env.ALLOW_UNVERIFIED_CF_HEADERS;
  delete process.env.CF_ACCESS_TEAM_DOMAIN;
  delete process.env.CF_ACCESS_AUD;
  process.env.ADMIN_EMAIL = "admin@example.com";
  const spoofReq = new Request("http://localhost:3000/api/commands", {
    headers: { "cf-access-authenticated-user-email": "admin@example.com" },
  });
  assert.equal(await resolveAuthorizedSession(spoofReq, secret), null);
  assert.equal(getAuthorizedSession(spoofReq, secret), null);
});

test("Cloudflare Access JWT RS256 signature, audience, and expiry verification", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...(publicKey.export({ format: "jwk" }) as JsonWebKey), kid: "kid-test-1" };

  function signJwt(payloadObj: Record<string, unknown>, kid = "kid-test-1"): string {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(payloadObj)).toString("base64url");
    const signer = createSign("RSA-SHA256");
    signer.update(`${header}.${payload}`);
    signer.end();
    const signature = signer.sign(privateKey).toString("base64url");
    return `${header}.${payload}.${signature}`;
  }

  const now = Date.now();
  const validJwt = signJwt({
    aud: ["aud-soar-123"],
    email: "admin@example.com",
    exp: Math.floor(now / 1000) + 3600,
  });

  const okRes = await verifyCloudflareAccessJwt(validJwt, "team.cloudflareaccess.com", "aud-soar-123", now, [jwk]);
  assert.equal(okRes.valid, true);
  assert.equal(okRes.email, "admin@example.com");

  // Wrong AUD rejected
  const badAud = await verifyCloudflareAccessJwt(validJwt, "team.cloudflareaccess.com", "wrong-aud", now, [jwk]);
  assert.equal(badAud.valid, false);

  // Expired JWT rejected
  const expiredJwt = signJwt({
    aud: ["aud-soar-123"],
    email: "admin@example.com",
    exp: Math.floor(now / 1000) - 10,
  });
  const expRes = await verifyCloudflareAccessJwt(expiredJwt, "team.cloudflareaccess.com", "aud-soar-123", now, [jwk]);
  assert.equal(expRes.valid, false);
});

test("WS6 proxy routes enforce authentication, RBAC viewer restrictions, and CSRF origin checks", async () => {
  const { GET: getAudit } = await import("../audit/route.ts");
  const { POST: postTriage } = await import("../triage/route.ts");
  const { POST: postHitl } = await import("../hitl/route.ts");
  const { POST: postEnroll } = await import("../enroll/route.ts");

  process.env.DASHBOARD_LOGIN_TOKEN = secret;
  process.env.FLEET_COMMAND_TOKEN = "cmd-" + "k".repeat(48);
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://localhost:3000";

  const viewerToken = createSessionToken(secret, {
    username: "viewer1",
    role: "viewer",
    email: "viewer1@soar.local",
  });
  const analystToken = createSessionToken(secret, {
    username: "analyst1",
    role: "analyst",
    email: "analyst1@soar.local",
  });

  // 1. Unauthenticated audit GET -> 401
  const unauthAudit = await getAudit(new Request("http://localhost:3000/api/audit"));
  assert.equal(unauthAudit.status, 401);

  // 2. Viewer audit GET -> 403
  const viewerAudit = await getAudit(
    new Request("http://localhost:3000/api/audit", {
      headers: { cookie: `soar_session=${viewerToken}` },
    }),
  );
  assert.equal(viewerAudit.status, 403);

  // 3. Viewer triage POST -> 403
  const viewerTriage = await postTriage(
    new Request("http://localhost:3000/api/triage", {
      method: "POST",
      headers: {
        origin: "http://localhost:3000",
        "content-type": "application/json",
        cookie: `soar_session=${viewerToken}`,
      },
      body: JSON.stringify({ event_key: "evt1", status: "resolved" }),
    }),
  );
  assert.equal(viewerTriage.status, 403);

  // 4. Viewer HITL resolve POST -> 403
  const viewerHitl = await postHitl(
    new Request("http://localhost:3000/api/hitl", {
      method: "POST",
      headers: {
        origin: "http://localhost:3000",
        "content-type": "application/json",
        cookie: `soar_session=${viewerToken}`,
      },
      body: JSON.stringify({ did: "did1", action: "quarantine" }),
    }),
  );
  assert.equal(viewerHitl.status, 403);

  // 5. Analyst enroll rotate POST -> 403 (admin only)
  const analystRotate = await postEnroll(
    new Request("http://localhost:3000/api/enroll", {
      method: "POST",
      headers: {
        origin: "http://localhost:3000",
        "content-type": "application/json",
        cookie: `soar_session=${analystToken}`,
      },
      body: JSON.stringify({ action: "rotate", agent_id: "009" }),
    }),
  );
  assert.equal(analystRotate.status, 403);
});
