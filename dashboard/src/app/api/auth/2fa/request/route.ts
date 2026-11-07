import {
  generateOtp,
  getOtpCooldown,
  maskEmail,
  sendResendEmail,
  sendTelegramOtp,
  storeOtp,
} from "../../../../../lib/twoFactor.ts";

export const runtime = "nodejs";

function originAllowed(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  return (process.env.DASHBOARD_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .includes(origin);
}

function clientIdentifier(request: Request): string {
  const cf = request.headers.get("cf-connecting-ip")?.trim();
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return cf || forwarded || "local-admin-client";
}

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return Response.json({ error: "Origin tidak diizinkan" }, { status: 403 });
  }

  const clientId = clientIdentifier(request);
  const cooldown = getOtpCooldown(clientId);
  if (cooldown > 0) {
    return Response.json(
      {
        error: `Silakan tunggu ${cooldown} detik sebelum meminta kode verifikasi baru.`,
        cooldown,
      },
      { status: 429 },
    );
  }

  const adminEmail = (process.env.ADMIN_EMAIL ?? "raviarnankeren@gmail.com").trim();
  const resendKey = (process.env.RESEND_API_KEY ?? "").trim();
  const tgToken = (process.env.TELEGRAM_BOT_TOKEN ?? "").trim();
  const tgChatId = (process.env.TELEGRAM_CHAT_ID ?? "").trim();

  const otpCode = generateOtp();
  storeOtp(clientId, otpCode);

  // Kirim secara paralel ke Resend Email & Telegram Bot
  const [resendResult, tgResult] = await Promise.all([
    sendResendEmail(resendKey, adminEmail, otpCode, clientId),
    sendTelegramOtp(tgToken, tgChatId, otpCode, clientId),
  ]);

  const atLeastOneSent = resendResult.success || tgResult.success;

  if (!atLeastOneSent) {
    return Response.json(
      {
        error: "Gagal mengirim kode verifikasi ke email maupun Telegram.",
        details: {
          email_error: resendResult.message,
          telegram_error: tgResult.message,
        },
      },
      { status: 502 },
    );
  }

  let channelMsg = `Kode verifikasi telah dikirim ke ${maskEmail(adminEmail)}`;
  if (resendResult.success && tgResult.success) {
    channelMsg = `Kode verifikasi telah dikirim ke ${maskEmail(adminEmail)} dan Telegram Bot.`;
  } else if (!resendResult.success && tgResult.success) {
    channelMsg = "Kode verifikasi telah dikirim ke Telegram Bot admin.";
  }

  return Response.json({
    success: true,
    maskedEmail: maskEmail(adminEmail),
    cooldownSeconds: 30,
    expiresInMinutes: 5,
    channels: {
      email: resendResult.success,
      telegram: tgResult.success,
    },
    message: channelMsg,
  });
}
