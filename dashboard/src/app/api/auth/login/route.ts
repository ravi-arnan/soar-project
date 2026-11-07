import {
  createSessionToken,
  sessionCookie,
  validLoginToken,
  type SessionUser,
} from "../../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 4096;

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

function originAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return (process.env.DASHBOARD_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .includes(origin);
}

function fleetBaseUrl(): string {
  const rawBase = process.env.FLEET_API_URL || "http://127.0.0.1:8080";
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return errorResponse("origin tidak diizinkan", 403);
  }

  const expectedSecret = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  if (!validLoginToken(expectedSecret)) {
    return errorResponse("dashboard auth belum dikonfigurasi di server", 503);
  }

  let body: unknown;
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) {
      return errorResponse("body request terlalu besar", 413);
    }
    body = JSON.parse(text);
  } catch {
    return errorResponse("Format JSON tidak valid", 400);
  }

  if (
    typeof body !== "object" ||
    body === null ||
    !("username" in body) ||
    !("password" in body) ||
    typeof body.username !== "string" ||
    typeof body.password !== "string"
  ) {
    return errorResponse("Username dan password wajib diisi", 400);
  }

  const username = body.username.trim();
  const password = body.password;

  // Teruskan ke backend fleet-monitor /api/auth/login
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
      return errorResponse(resData.error || "Username atau password salah", 401);
    }

    const sessionUser: SessionUser = {
      username: resData.user.username,
      role: resData.user.role,
      email: resData.user.email || "",
      name: resData.user.name || resData.user.username,
    };

    const token = createSessionToken(expectedSecret, sessionUser);
    const secure =
      new URL(request.url).protocol === "https:" ||
      request.headers.get("origin")?.startsWith("https://") === true;

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
