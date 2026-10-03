import assert from "node:assert/strict";
import test from "node:test";
import { createSessionToken } from "../../../lib/session.ts";
import { POST } from "./route.ts";

const originalFetch = globalThis.fetch;
const originalToken = process.env.FLEET_COMMAND_TOKEN;
const originalFleetUrl = process.env.FLEET_API_URL;
const originalOrigins = process.env.DASHBOARD_ALLOWED_ORIGINS;
const originalLoginToken = process.env.DASHBOARD_LOGIN_TOKEN;
const loginToken = "server-login-" + "a".repeat(32);
const sessionCookie = createSessionToken(loginToken);
process.env.DASHBOARD_LOGIN_TOKEN = loginToken;

test.after(() => {
  globalThis.fetch = originalFetch;
  process.env.FLEET_COMMAND_TOKEN = originalToken;
  process.env.FLEET_API_URL = originalFleetUrl;
  process.env.DASHBOARD_ALLOWED_ORIGINS = originalOrigins;
  if (originalLoginToken === undefined) {
    delete process.env.DASHBOARD_LOGIN_TOKEN;
  } else {
    process.env.DASHBOARD_LOGIN_TOKEN = originalLoginToken;
  }
});

test("returns 503 when server command credentials are missing", { concurrency: false }, async () => {
  delete process.env.FLEET_COMMAND_TOKEN;
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      cookie: `soar_session=${sessionCookie}`,
      "content-type": "application/json",
      origin: "http://dashboard.test",
    },
    body: JSON.stringify({ agent_id: "009", action: "scan", target: "/home/ravi/Downloads" }),
  });

  const response = await POST(request);

  assert.equal(response.status, 503);
});

test("forwards only a server-side bearer token and dashboard actor", { concurrency: false }, async () => {
  process.env.FLEET_COMMAND_TOKEN = "server-token";
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  let receivedUrl = "";
  let receivedInit: RequestInit | undefined;
  globalThis.fetch = async (input, init) => {
    receivedUrl = String(input);
    receivedInit = init;
    return new Response(JSON.stringify({ status: "queued" }), { status: 200 });
  };
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      authorization: "Bearer client-token",
      cookie: `soar_session=${sessionCookie}`,
      "content-type": "application/json",
      origin: "http://dashboard.test",
    },
    body: JSON.stringify({
      agent_id: "009",
      action: "quarantine",
      target: "/home/ravi/Downloads/eicar.com",
      by: "forged-client",
    }),
  });

  const response = await POST(request);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body, { status: "queued" });
  assert.equal(receivedUrl, "http://fleet.test/api/commands");
  assert.equal((receivedInit?.headers as Record<string, string>).Authorization, "Bearer server-token");
  assert.deepEqual(JSON.parse(String(receivedInit?.body)), {
    agent_id: "009",
    action: "quarantine",
    target: "/home/ravi/Downloads/eicar.com",
    by: "dashboard",
  });
});

test("rejects a command request without an authenticated identity", { concurrency: false }, async () => {
  process.env.FLEET_COMMAND_TOKEN = "server-token";
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://dashboard.test",
    },
    body: JSON.stringify({ agent_id: "009", action: "scan", target: "/home/ravi/Downloads" }),
  });

  const response = await POST(request);

  assert.equal(response.status, 401);
});

test("rejects a command request without an authenticated browser origin", { concurrency: false }, async () => {
  process.env.FLEET_COMMAND_TOKEN = "server-token";
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      cookie: `soar_session=${sessionCookie}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ agent_id: "009", action: "scan", target: "/home/ravi/Downloads" }),
  });

  const response = await POST(request);

  assert.equal(response.status, 403);
});

test("rejects a request from an unconfigured origin", { concurrency: false }, async () => {
  process.env.FLEET_COMMAND_TOKEN = "server-token";
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      cookie: `soar_session=${sessionCookie}`,
      "content-type": "application/json",
      origin: "https://evil.example",
    },
    body: JSON.stringify({ agent_id: "009", action: "scan", target: "/home/ravi/Downloads" }),
  });

  const response = await POST(request);

  assert.equal(response.status, 403);
});

test("maps an upstream rejection to a generic gateway error", { concurrency: false }, async () => {
  process.env.FLEET_COMMAND_TOKEN = "server-token";
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: "internal detail" }), { status: 500 });
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      cookie: `soar_session=${sessionCookie}`,
      "content-type": "application/json",
      origin: "http://dashboard.test",
    },
    body: JSON.stringify({ agent_id: "009", action: "scan", target: "/home/ravi/Downloads" }),
  });

  const response = await POST(request);
  const body = await response.json();

  assert.equal(response.status, 502);
  assert.deepEqual(body, { error: "fleet monitor menolak command" });
});
