import assert from "node:assert/strict";
import test from "node:test";
import { createSessionToken } from "../../../lib/session.ts";
import { POST } from "./route.ts";

const originalLoginToken = process.env.DASHBOARD_LOGIN_TOKEN;
const placeholderLoginToken = "your-dashboard-login-token-min-32-chars";
const placeholderSessionCookie = createSessionToken(placeholderLoginToken);

test.after(() => {
  if (originalLoginToken === undefined) {
    delete process.env.DASHBOARD_LOGIN_TOKEN;
  } else {
    process.env.DASHBOARD_LOGIN_TOKEN = originalLoginToken;
  }
});

test("rejects a session signed with a placeholder dashboard token", async () => {
  process.env.FLEET_COMMAND_TOKEN = "server-token";
  process.env.FLEET_API_URL = "http://fleet.test";
  process.env.DASHBOARD_ALLOWED_ORIGINS = "http://dashboard.test";
  process.env.DASHBOARD_LOGIN_TOKEN = placeholderLoginToken;
  const request = new Request("http://dashboard.test/api/commands", {
    method: "POST",
    headers: {
      cookie: `soar_session=${placeholderSessionCookie}`,
      "content-type": "application/json",
      origin: "http://dashboard.test",
    },
    body: JSON.stringify({ agent_id: "009", action: "scan", target: "/home/ravi/Downloads" }),
  });

  const response = await POST(request);

  assert.equal(response.status, 401);
});
