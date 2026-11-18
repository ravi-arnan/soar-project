import assert from "node:assert/strict";
import test from "node:test";
import { POST } from "./route.ts";

test("logout clears local cookie and returns CF Access logout URL when authenticated via Cloudflare Access", async () => {
  const req = new Request("http://127.0.0.1:3000/api/auth/logout", {
    method: "POST",
    headers: {
      "cf-access-authenticated-user-email": "raviarnankeren@gmail.com",
      "x-forwarded-proto": "https",
    },
  });

  const res = await POST(req);
  assert.equal(res.status, 200);
  const setCookie = res.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /^soar_session=;/);
  assert.match(setCookie, /Max-Age=0/);
  assert.match(setCookie, /Secure/);

  const body = (await res.json()) as {
    success: boolean;
    cloudflareAccess: boolean;
    logoutUrl: string | null;
  };
  assert.equal(body.success, true);
  assert.equal(body.cloudflareAccess, true);
  assert.equal(body.logoutUrl, "/cdn-cgi/access/logout");
});

test("logout clears local cookie without redirect URL for non-CF-Access session", async () => {
  const req = new Request("http://localhost:3000/api/auth/logout", {
    method: "POST",
  });

  const res = await POST(req);
  assert.equal(res.status, 200);
  const setCookie = res.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /^soar_session=;/);
  assert.match(setCookie, /Max-Age=0/);
  assert.doesNotMatch(setCookie, /Secure/);

  const body = (await res.json()) as {
    success: boolean;
    cloudflareAccess: boolean;
    logoutUrl: string | null;
  };
  assert.equal(body.success, true);
  assert.equal(body.cloudflareAccess, false);
  assert.equal(body.logoutUrl, null);
});
