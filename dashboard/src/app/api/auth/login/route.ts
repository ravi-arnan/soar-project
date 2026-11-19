import {
  clientIpFromCf,
  fleetBaseUrl,
  isHttpsRequest,
  originAllowed,
  readBoundedJson,
  SlidingWindowLimiter,
} from "../../../../lib/requestGuard.ts";
import {
  createSessionToken,
  sessionCookie,
  validLoginToken,
  type SessionUser,
} from "../../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 4096;
const loginLimiter = new SlidingWindowLimiter(5, 15 * 60 * 1000);

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return errorResponse("origin tidak diizinkan", 403);
  }

  const expectedSecret = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  if (!validLoginToken(expectedSecret)) {
    return errorResponse("dashboard auth belum dikonfigurasi di server", 503);
  }

  const parsed = await readBoundedJson(request, MAX_BODY_BYTES);
  if (!parsed.ok) {
    return errorResponse(parsed.error, parsed.status);
  }

  const body = parsed.data;
  if (
    typeof body !== "object" ||
    body === null ||
    !("username" in body) ||
    !("password" in body) ||
    typeof (body as { username?: unknown }).username !== "string" ||
    typeof (body as { password?: unknown }).password !== "string"
  ) {
    return errorResponse("Username dan password wajib diisi", 400);
  }

  const username = (body as { username: string }).username.trim();
  const password = (body as { password: string }).password;
  const rlKey = `${clientIpFromCf(request)}:${username.toLowerCase()}`;
  const rl = loginLimiter.check(rlKey);
  if (!rl.allowed) {
    return Response.json(
      { error: "Terlalu banyak percobaan login gagal. Coba lagi nanti." },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSecs) } },
    );
  }

  const upstreamUrl = `${fleetBaseUrl()}/api/auth/login`;
  try {
    const upstream = await fetch(upstreamUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ username, password }),
      cache: "no-store",
      signal: AbortSignal.timeout(5_000),
    });

    const resData = await upstream.json();
    if (!upstream.ok || !resData.success || !resData.user) {
      loginLimiter.recordFailure(rlKey);
      return errorResponse(resData.error || "Username atau password salah", upstream.status === 429 ? 429 : 401);
    }

    loginLimiter.clear(rlKey);
    const sessionUser: SessionUser = {
      username: resData.user.username,
      role: resData.user.role,
      email: resData.user.email || "",
      name: resData.user.name || resData.user.username,
    };

    const token = createSessionToken(expectedSecret, sessionUser);
    const secure = isHttpsRequest(request);

    return Response.json(
      { success: true, user: sessionUser },
      {
        status: 200,
        headers: { "Set-Cookie": sessionCookie(token, secure) },
      },
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return errorResponse(`Gagal memverifikasi kredensial ke backend fleet: ${msg}`, 502);
  }
}
