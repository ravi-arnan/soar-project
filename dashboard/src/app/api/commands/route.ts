import { isValidSession, sessionFromRequest, validLoginToken } from "../../../lib/session.ts";

export const runtime = "nodejs";

const MAX_BODY_BYTES = 8 * 1024;
const MAX_AGENT_ID_LENGTH = 64;
const MAX_TARGET_LENGTH = 4096;
const ACTIONS = new Set(["quarantine", "sinkhole", "scan"]);

type CommandPayload = {
  agent_id: string;
  action: string;
  target: string;
  by: "dashboard";
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDashboardRequestAuthorized(request: Request): boolean {
  const secret = process.env.DASHBOARD_LOGIN_TOKEN ?? "";
  const value = sessionFromRequest(request);
  return Boolean(validLoginToken(secret) && value && isValidSession(value, secret));
}

function isAllowedOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const configured = new Set(
    (process.env.DASHBOARD_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean),
  );
  return configured.has(origin);
}

function fleetCommandUrl(value: string): URL | null {
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    if (url.username || url.password || url.search || url.hash) return null;
    return new URL('/api/commands', url);
  } catch {
    return null;
  }
}

function errorResponse(message: string, status: number): Response {
  return Response.json({ error: message }, { status });
}

async function readJsonBody(request: Request): Promise<unknown> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isSafeInteger(length) || length < 0) {
      throw new SyntaxError("Content-Length tidak valid");
    }
    if (length > MAX_BODY_BYTES) {
      throw new RangeError("body command terlalu besar");
    }
  }
  if (!request.body) {
    throw new SyntaxError("body command tidak valid");
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    size += result.value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new RangeError("body command terlalu besar");
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
  if (!isDashboardRequestAuthorized(request)) {
    return errorResponse("login dashboard diperlukan", 401);
  }
  if (!isAllowedOrigin(request)) {
    return errorResponse("origin tidak diizinkan", 403);
  }

  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  const fleetUrl = process.env.FLEET_API_URL;
  const commandUrl = fleetUrl ? fleetCommandUrl(fleetUrl) : null;
  if (!commandToken || !commandUrl) {
    return errorResponse("command service belum dikonfigurasi", 503);
  }

  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    return errorResponse("Content-Type harus application/json", 415);
  }

  let body: unknown;
  try {
    body = await readJsonBody(request);
  } catch (error) {
    if (error instanceof RangeError) {
      return errorResponse(error.message, 413);
    }
    return errorResponse("body command tidak valid", 400);
  }
  if (!isRecord(body)) {
    return errorResponse("body command harus object", 400);
  }

  const { agent_id, action, target } = body;
  if (
    typeof agent_id !== "string" ||
    typeof action !== "string" ||
    typeof target !== "string"
  ) {
    return errorResponse("command tidak valid", 400);
  }
  const normalizedAgentId = agent_id.trim();
  const normalizedAction = action.trim();
  const normalizedTarget = target.trim();
  if (
    !/^[A-Za-z0-9._-]{1,64}$/.test(normalizedAgentId) ||
    normalizedAgentId.length > MAX_AGENT_ID_LENGTH ||
    !ACTIONS.has(normalizedAction) ||
    !normalizedTarget ||
    normalizedTarget.length > MAX_TARGET_LENGTH ||
    [...normalizedTarget].some((char) => char.charCodeAt(0) < 32)
  ) {
    return errorResponse("command tidak valid", 400);
  }

  const command: CommandPayload = {
    agent_id: normalizedAgentId,
    action: normalizedAction,
    target: normalizedTarget,
    by: "dashboard",
  };

  let upstream: Response;
  try {
    upstream = await fetch(commandUrl, {
      method: "POST",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(command),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return errorResponse("fleet monitor tidak dapat dihubungi", 502);
  }

  let responseBody: unknown;
  try {
    responseBody = await upstream.json();
  } catch {
    return errorResponse("respons fleet monitor tidak valid", 502);
  }

  if (!upstream.ok) {
    const status = upstream.status === 400 ? 400 : 502;
    return errorResponse("fleet monitor menolak command", status);
  }

  return Response.json(responseBody, { status: 200 });
}
