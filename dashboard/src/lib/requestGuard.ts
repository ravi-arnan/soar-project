export function fleetBaseUrl(): string {
  const rawBase =
    process.env.FLEET_API_URL ||
    (process.env.NODE_ENV === "production"
      ? "http://host.docker.internal:8080"
      : "http://127.0.0.1:8080");
  return rawBase.split("?")[0].replace(/\/$/, "");
}

export function originAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const configured = (process.env.DASHBOARD_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (configured.includes(origin)) return true;
  // Izinkan same-origin secara eksplisit bila host cocok dengan origin
  const host = (request.headers.get("x-forwarded-host") || request.headers.get("host") || "").split(",")[0]?.trim();
  if (!host) return false;
  try {
    const parsed = new URL(origin);
    return parsed.host === host;
  } catch {
    return false;
  }
}

export function isHttpsRequest(request: Request): boolean {
  try {
    if (new URL(request.url).protocol === "https:") return true;
  } catch {
    // ignore invalid URL
  }
  const xfProto = request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim().toLowerCase();
  if (xfProto === "https") return true;
  return request.headers.get("origin")?.startsWith("https://") === true;
}

export function clientIpFromCf(request: Request): string {
  const cf = request.headers.get("cf-connecting-ip")?.trim();
  if (cf && /^[0-9a-fA-F:.]{3,64}$/.test(cf)) return cf;
  return "local-client";
}

export async function readBoundedJson(
  request: Request,
  maxBytes = 65536,
): Promise<{ ok: true; data: unknown } | { ok: false; status: number; error: string }> {
  const contentLength = request.headers.get("content-length");
  if (contentLength) {
    const declared = Number(contentLength);
    if (!Number.isFinite(declared) || declared < 0) {
      return { ok: false, status: 400, error: "Header Content-Length tidak valid" };
    }
    if (declared > maxBytes) {
      return { ok: false, status: 413, error: "Payload request terlalu besar" };
    }
  }
  const reader = request.body?.getReader();
  if (!reader) {
    return { ok: true, data: {} };
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { ok: false, status: 413, error: "Payload request terlalu besar" };
      }
      chunks.push(value);
    }
  }
  const raw = Buffer.concat(chunks).toString("utf-8").trim();
  if (!raw) return { ok: true, data: {} };
  try {
    return { ok: true, data: JSON.parse(raw) };
  } catch {
    return { ok: false, status: 400, error: "Format JSON tidak valid" };
  }
}

export class SlidingWindowLimiter {
  private readonly buckets = new Map<string, number[]>();
  private readonly maxAttempts: number;
  private readonly windowMs: number;
  private readonly maxKeys: number;

  constructor(maxAttempts = 5, windowMs = 15 * 60 * 1000, maxKeys = 2000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
  }

  check(key: string, now = Date.now()): { allowed: boolean; retryAfterSecs: number } {
    const recent = (this.buckets.get(key) ?? []).filter((ts) => now - ts < this.windowMs);
    if (recent.length >= this.maxAttempts) {
      const oldest = recent[0] ?? now;
      const retryAfterSecs = Math.max(1, Math.ceil((this.windowMs - (now - oldest)) / 1000));
      this.buckets.set(key, recent);
      return { allowed: false, retryAfterSecs };
    }
    if (recent.length > 0) {
      this.buckets.set(key, recent);
    } else {
      this.buckets.delete(key);
    }
    return { allowed: true, retryAfterSecs: 0 };
  }

  recordFailure(key: string, now = Date.now()): void {
    const recent = (this.buckets.get(key) ?? []).filter((ts) => now - ts < this.windowMs);
    recent.push(now);
    this.buckets.set(key, recent);
    if (this.buckets.size > this.maxKeys) {
      const firstKey = this.buckets.keys().next().value;
      if (firstKey !== undefined) this.buckets.delete(firstKey);
    }
  }

  clear(key: string): void {
    this.buckets.delete(key);
  }
}

export async function proxyAuthenticatedFleetGet(
  request: Request,
  upstreamPath: string,
  resolveSession: (req: Request) => Promise<{ username: string; role: string } | null>,
  timeoutMs = 15_000,
): Promise<Response> {
  const user = await resolveSession(request);
  if (!user) {
    return Response.json({ error: "Login dashboard diperlukan" }, { status: 401 });
  }
  const commandToken = process.env.FLEET_COMMAND_TOKEN;
  if (!commandToken) {
    return Response.json({ error: "FLEET_COMMAND_TOKEN belum dikonfigurasi" }, { status: 503 });
  }
  const url = new URL(request.url);
  const qs = url.searchParams.toString();
  const target = `${fleetBaseUrl()}${upstreamPath}${qs ? `?${qs}` : ""}`;
  try {
    const upstream = await fetch(target, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${commandToken}`,
      },
      cache: "no-store",
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: {
        "Content-Type": upstream.headers.get("content-type") || "application/json",
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    return Response.json(
      { error: `Gagal menghubungi backend fleet: ${err instanceof Error ? err.message : String(err)}` },
      { status: 502 },
    );
  }
}
