import { randomInt, timingSafeEqual } from "node:crypto";
import https from "node:https";

export const OTP_TTL_MS = 5 * 60 * 1000; // 5 menit
export const OTP_COOLDOWN_MS = 30 * 1000; // 30 detik
export const MAX_VERIFY_ATTEMPTS = 5;
const MAX_OTP_STORE_ENTRIES = 1000;

type OtpEntry = {
  code: string;
  expiresAt: number;
  lastRequestedAt: number;
  attempts: number;
};

const otpStore = new Map<string, OtpEntry>();

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeTelegramMarkdown(text: string): string {
  return text.replace(/[`*_[\]()~>#+=|{}.!-]/g, "");
}

export function maskEmail(email: string): string {
  if (!email || !email.includes("@")) return "admin@example.com";
  const [user, domain] = email.split("@");
  if (user.length <= 2) return `${user[0]}*@${domain}`;
  const first = user[0];
  const last = user[user.length - 1];
  const stars = "*".repeat(Math.min(user.length - 2, 4));
  return `${first}${stars}${last}@${domain}`;
}

export function generateOtp(): string {
  return String(randomInt(100000, 1000000));
}

export function getOtpCooldown(key: string, now = Date.now()): number {
  const entry = otpStore.get(key);
  if (!entry) return 0;
  const elapsed = now - entry.lastRequestedAt;
  if (elapsed < OTP_COOLDOWN_MS) {
    return Math.ceil((OTP_COOLDOWN_MS - elapsed) / 1000);
  }
  return 0;
}

export function storeOtp(key: string, code: string, now = Date.now()): void {
  if (otpStore.size >= MAX_OTP_STORE_ENTRIES) {
    for (const [k, v] of otpStore.entries()) {
      if (now > v.expiresAt) otpStore.delete(k);
    }
    if (otpStore.size >= MAX_OTP_STORE_ENTRIES) {
      const oldest = otpStore.keys().next().value;
      if (oldest !== undefined) otpStore.delete(oldest);
    }
  }
  otpStore.set(key, {
    code,
    expiresAt: now + OTP_TTL_MS,
    lastRequestedAt: now,
    attempts: 0,
  });
}

export function verifyStoredOtp(
  key: string,
  providedCode: string,
  now = Date.now(),
): { success: boolean; error?: string } {
  const entry = otpStore.get(key);
  if (!entry) {
    return { success: false, error: "Kode verifikasi belum diminta atau sudah kedaluwarsa." };
  }
  if (now > entry.expiresAt) {
    otpStore.delete(key);
    return { success: false, error: "Kode verifikasi telah kedaluwarsa. Silakan minta kode baru." };
  }
  if (entry.attempts >= MAX_VERIFY_ATTEMPTS) {
    otpStore.delete(key);
    return { success: false, error: "Terlalu banyak percobaan salah. Silakan minta kode baru." };
  }

  const cleanProvided = providedCode.trim();
  const validBuffer = Buffer.from(entry.code);
  const providedBuffer = Buffer.from(cleanProvided);

  const isMatch =
    validBuffer.length === providedBuffer.length &&
    timingSafeEqual(validBuffer, providedBuffer);

  if (!isMatch) {
    entry.attempts += 1;
    const remaining = MAX_VERIFY_ATTEMPTS - entry.attempts;
    return {
      success: false,
      error: `Kode salah. Sisa percobaan: ${remaining} kali.`,
    };
  }

  otpStore.delete(key);
  return { success: true };
}

function postHttpsIpv4(
  hostname: string,
  path: string,
  headers: Record<string, string>,
  bodyStr: string,
  timeoutMs = 10000,
): Promise<{ status: number; data: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname,
        port: 443,
        path,
        method: "POST",
        family: 4,
        headers: {
          ...headers,
          "Content-Length": String(Buffer.byteLength(bodyStr)),
        },
        timeout: timeoutMs,
      },
      (res) => {
        let raw = "";
        res.on("data", (chunk) => {
          raw += chunk;
        });
        res.on("end", () => {
          resolve({ status: res.statusCode || 0, data: raw });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("HTTPS request timeout")));
    req.on("error", (err) => reject(err));
    req.write(bodyStr);
    req.end();
  });
}

export async function sendResendEmail(
  apiKey: string,
  recipientEmail: string,
  otpCode: string,
  clientIp = "127.0.0.1",
): Promise<{ success: boolean; message?: string }> {
  if (!apiKey || !recipientEmail) {
    return { success: false, message: "Kredensial Resend atau email admin belum dikonfigurasi." };
  }
  const safeIp = escapeHtml(clientIp.slice(0, 64));
  const safeOtp = escapeHtml(otpCode);

  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Verifikasi Keamanan SOAR Console</title>
</head>
<body style="margin: 0; padding: 30px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background-color: #f4f6f8; color: #1a1c21;">
  <div style="max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #d3dae6; border-radius: 8px; overflow: hidden;">
    <div style="background-color: #0b192c; padding: 24px; text-align: center;">
      <h1 style="margin: 0; color: #ffffff; font-size: 20px; font-weight: 600;">SOAR Security Operation Center</h1>
      <p style="margin: 6px 0 0 0; color: #94a3b8; font-size: 13px;">Verifikasi Dua Langkah (2FA) Akses Konsol Administratif</p>
    </div>
    <div style="padding: 30px;">
      <p style="margin: 0 0 16px 0; font-size: 14px; color: #334155;">Halo Administrator,</p>
      <p style="margin: 0 0 24px 0; font-size: 14px; color: #334155;">
        Permintaan step-up 2FA untuk pengelolaan <strong>API Keys</strong> dan <strong>Active Response</strong> terdeteksi.
      </p>
      <div style="background-color: #f8fafc; border: 2px dashed #006bb4; border-radius: 8px; padding: 20px; text-align: center; margin: 24px 0;">
        <span style="font-family: monospace; font-size: 34px; font-weight: 700; color: #006bb4; letter-spacing: 8px;">${safeOtp}</span>
      </div>
      <p style="margin: 0 0 8px 0; font-size: 13px; color: #64748b;">Masa berlaku kode: <strong>5 menit</strong>.</p>
      <p style="margin: 0 0 20px 0; font-size: 13px; color: #64748b;">
        Alamat IP Pemohon: <code style="background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-size: 12px;">${safeIp}</code>
      </p>
    </div>
    <div style="background-color: #f8fafc; padding: 16px; text-align: center; border-top: 1px solid #e2e8f0;">
      <span style="font-size: 11px; color: #94a3b8;">SOAR Autonomous Defense System &middot; SecOps</span>
    </div>
  </div>
</body>
</html>`.trim();

  const payload = JSON.stringify({
    from: "SOAR Security Console <onboarding@resend.dev>",
    to: [recipientEmail],
    subject: `[SOAR Console] Kode Verifikasi 2FA: ${safeOtp}`,
    html,
  });

  try {
    const res = await postHttpsIpv4(
      "api.resend.com",
      "/emails",
      {
        Accept: "application/json",
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      payload,
    );
    if (res.status < 200 || res.status >= 300) {
      let msg = `HTTP ${res.status} dari Resend API`;
      try {
        const j = JSON.parse(res.data);
        if (j.message) msg = j.message;
      } catch {
        // ignore
      }
      return { success: false, message: msg };
    }
    return { success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Gagal menghubungi Resend API: ${msg}` };
  }
}

export async function sendTelegramOtp(
  botToken: string,
  chatId: string,
  otpCode: string,
  clientIp = "127.0.0.1",
): Promise<{ success: boolean; message?: string }> {
  if (!botToken || !chatId) {
    return { success: false, message: "Kredensial Telegram Bot belum dikonfigurasi." };
  }
  const safeIp = escapeTelegramMarkdown(clientIp.slice(0, 64)) || "local-client";
  const text =
    `*VERIFIKASI 2FA DASHBOARD SOAR*\n\n` +
    `Kode verifikasi sesi Anda: \`${otpCode}\`\n\n` +
    `Masa berlaku: *5 menit*\n` +
    `IP Pemohon: \`${safeIp}\`\n\n` +
    `_Gunakan kode ini di form dashboard untuk membuka pengelolaan API Key._`;

  const payload = JSON.stringify({
    chat_id: chatId,
    text,
    parse_mode: "Markdown",
  });

  try {
    const res = await postHttpsIpv4(
      "api.telegram.org",
      `/bot${botToken}/sendMessage`,
      { "content-type": "application/json" },
      payload,
    );
    if (res.status !== 200) {
      return { success: false, message: `HTTP ${res.status} Telegram Bot API` };
    }
    return { success: true };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `Gagal mengirim ke Telegram: ${msg}` };
  }
}
