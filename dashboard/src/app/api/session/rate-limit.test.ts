import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "./route.ts";

const originalToken = process.env.DASHBOARD_LOGIN_TOKEN;
const originalOrigins = process.env.DASHBOARD_ALLOWED_ORIGINS;
const validToken = "server-login-" + "a".repeat(32);

test.after(() => {
  if (originalToken === undefined) delete process.env.DASHBOARD_LOGIN_TOKEN;
  else process.env.DASHBOARD_LOGIN_TOKEN = originalToken;
  if (originalOrigins === undefined) delete process.env.DASHBOARD_ALLOWED_ORIGINS;
  else process.env.DASHBOARD_ALLOWED_ORIGINS = originalOrigins;
});

test("rate limits login attempts across spoofed forwarding headers", async () => {
  process.env.DASHBOARD_LOGIN_TOKEN = validToken;
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await POST(
      new Request("http://dashboard.test/api/session", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://dashboard.test",
          "x-forwarded-for": `198.51.100.${attempt + 10}`,
        },
        body: JSON.stringify({ token: "wrong-login" }),
      }),
    );
    assert.equal(response.status, 401);
  }

  const blockedResponse = await POST(
    new Request("http://dashboard.test/api/session", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://dashboard.test",
        "x-forwarded-for": "198.51.100.99",
      },
      body: JSON.stringify({ token: "wrong-login" }),
    }),
  );
  assert.equal(blockedResponse.status, 429);
  assert.ok(Number(blockedResponse.headers.get("retry-after")) > 0);
});
