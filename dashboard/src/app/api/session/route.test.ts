import assert from "node:assert/strict";
import test from "node:test";
import { validLoginToken } from "../../../lib/session.ts";
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

test("session login boundary", async () => {
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test,https://dashboard.test";
  process.env.DASHBOARD_LOGIN_TOKEN = validToken;
  assert.equal(process.env.DASHBOARD_LOGIN_TOKEN, validToken);
  assert.equal(validLoginToken(validToken), true);
  const validRequest = new Request("http://dashboard.test/api/session", {
    method: "POST",
    headers: { "content-type": "application/json", origin: "http://dashboard.test" },
    body: JSON.stringify({ token: validToken }),
  });
  const validResponse = await POST(validRequest);
  const cookie = validResponse.headers.get("set-cookie") ?? "";
  assert.equal(validResponse.status, 204);
  assert.match(cookie, /soar_session=/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);

  const secureProxyResponse = await POST(
    new Request("http://dashboard.test/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://dashboard.test" },
      body: JSON.stringify({ token: validToken }),
    }),
  );
  assert.equal(secureProxyResponse.status, 204);
  assert.match(secureProxyResponse.headers.get("set-cookie") ?? "", /Secure/);

  process.env.DASHBOARD_LOGIN_TOKEN = "your-dashboard-login-token-min-32-chars";
  const placeholderResponse = await POST(
    new Request("http://dashboard.test/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://dashboard.test" },
      body: JSON.stringify({ token: "your-dashboard-login-token-min-32-chars" }),
    }),
  );
  assert.equal(placeholderResponse.status, 503);

  process.env.DASHBOARD_LOGIN_TOKEN = validToken;
  const invalidResponse = await POST(
    new Request("http://dashboard.test/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://dashboard.test" },
      body: JSON.stringify({ token: "wrong-login" }),
    }),
  );
  assert.equal(invalidResponse.status, 401);

  const oversizedBody = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(JSON.stringify({ token: "x".repeat(5000) })));
      controller.close();
    },
  });
  const oversizedResponse = await POST(
    new Request("http://dashboard.test/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://dashboard.test" },
      body: oversizedBody,
      duplex: "half",
    } as RequestInit & { duplex: "half" }),
  );
  assert.equal(oversizedResponse.status, 413);

  const hangingBody = new ReadableStream<Uint8Array>({ start() {} });
  const hangingResponse = await POST(
    new Request("http://dashboard.test/api/session", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://dashboard.test" },
      body: hangingBody,
      duplex: "half",
    } as RequestInit & { duplex: "half" }),
  );
  assert.equal(hangingResponse.status, 408);
});
