import {
  createSessionToken,
  secretMatches,
  sessionCookie,
  validLoginToken,
} from "../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 4096;
const MAX_TOKEN_LENGTH = 512;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX_ATTEMPTS = 5;
const BODY_READ_TIMEOUT_MS = 5_000;
const rateLimit = new Map<string, { attempts: number; resetAt: number }>();

class BodyReadTimeoutError extends Error {}

function errorResponse(message: string, status: number, headers?: HeadersInit): Response {
  return Response.json({ error: message }, { status, headers });
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

function rateLimitState(key: string, now: number): { blocked: boolean; retryAfter: number } {
  const current = rateLimit.get(key);
  if (!current || current.resetAt <= now) {
    rateLimit.delete(key);
    return { blocked: false, retryAfter: 0 };
  }
  return {
    blocked: current.attempts >= RATE_LIMIT_MAX_ATTEMPTS,
    retryAfter: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
  };
}

function recordAttempt(key: string, now: number): void {
  const current = rateLimit.get(key);
  if (!current || current.resetAt <= now) {
    rateLimit.set(key, { attempts: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return;
  }
  rateLimit.set(key, { attempts: current.attempts + 1, resetAt: current.resetAt });
  if (rateLimit.size > 10_000) {
    const oldestKey = rateLimit.keys().next().value;
    if (oldestKey !== undefined) rateLimit.delete(oldestKey);
  }
}

function readChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new BodyReadTimeoutError()), BODY_READ_TIMEOUT_MS);
    reader.read().then(
      (result) => {
        clearTimeout(timeout);
        resolve(result);
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

async function readJsonBody(request: Request): Promise<unknown> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new SyntaxError("Content-Length tidak valid");
    }
    if (length > MAX_BODY_BYTES) {
      throw new RangeError("body login terlalu besar");
    }
  }
  if (!request.body) {
    throw new SyntaxError("body login tidak valid");
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    let result: ReadableStreamReadResult<Uint8Array>;
    try {
      result = await readChunk(reader);
    } catch (error) {
      await reader.cancel();
      throw error;
    }
    if (result.done) break;
    size += result.value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new RangeError("body login terlalu besar");
    }
    chunks.push(result.value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder().decode(body));
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return errorResponse("origin tidak diizinkan", 403);
  }
  const expectedToken = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  if (!validLoginToken(expectedToken)) {
    return errorResponse("dashboard auth belum dikonfigurasi", 503);
  }
  const key = "dashboard-login";
  const now = Date.now();
  const state = rateLimitState(key, now);
  if (state.blocked) {
    return errorResponse("terlalu banyak percobaan login", 429, {
      "Retry-After": String(state.retryAfter),
    });
  }
  recordAttempt(key, now);

  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return errorResponse("Content-Type harus application/json", 415);
  }
  let body: unknown;
  try {
    body = await readJsonBody(request);
  } catch (error) {
    if (error instanceof BodyReadTimeoutError) {
      return errorResponse("body login timeout", 408);
    }
    if (error instanceof RangeError) {
      return errorResponse(error.message, 413);
    }
    return errorResponse("body login tidak valid", 400);
  }
  if (
    typeof body !== "object" ||
    body === null ||
    !("token" in body) ||
    typeof body.token !== "string" ||
    body.token.length > MAX_TOKEN_LENGTH ||
    !secretMatches(body.token, expectedToken)
  ) {
    return errorResponse("login gagal", 401);
  }
  rateLimit.delete(key);
  const token = createSessionToken(expectedToken);
  const secure =
    new URL(request.url).protocol === "https:" || request.headers.get("origin")?.startsWith("https://") === true;
  return new Response(null, {
    status: 204,
    headers: { "Set-Cookie": sessionCookie(token, secure) },
  });
}
