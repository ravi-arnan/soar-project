import { clientIpFromCf, originAllowed } from "../../../../../lib/requestGuard.ts";
import { resolveAuthorizedSession } from "../../../../../lib/session.ts";
import {
  generateOtp,
  getOtpCooldown,
  maskEmail,
  sendResendEmail,
  sendTelegramOtp,
  storeOtp,
} from "../../../../../lib/twoFactor.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  if (!originAllowed(request)) {
    return Response.json({ error: "Origin tidak diizinkan" }, { status: 403 });
  }

  // Step-up 2FA: wajib sudah terautentikasi sebagai Admin terlebih dahulu (faktor pertama)
  const session = await resolveAuthorizedSession(request);
  if (!session) {
    return Response.json({ error: "Silakan login terlebih dahulu sebelum meminta OTP 2FA." }, { status: 401 });
  }
  if (session.role !== "admin") {
    return Response.json({ error: "Akses ditolak: 2FA administratif hanya untuk role Admin." }, { status: 403 });
  }

  const clientIp = clientIpFromCf(request);
  const otpKey = `${session.username}:${clientIp}`;
  const cooldown = getOtpCooldown(otpKey);
  if (cooldown > 0) {
    return Response.json(
      {
        error: `Silakan tunggu ${cooldown} detik sebelum meminta kode verifikasi baru.`,
        cooldown,
      },
      { status: 429 },
    );
  }

  const adminEmail = (session.email || process.env.ADMIN_EMAIL || "").trim();
  const resendKey = (process.env.RESEND_API_KEY ?? "").trim();
  const tgToken = (process.env.TELEGRAM_BOT_TOKEN ?? "").trim();
  const tgChatId = (process.env.TELEGRAM_CHAT_ID ?? "").trim();

  const otpCode = generateOtp();
  storeOtp(otpKey, otpCode);

  const [resendResult, tgResult] = await Promise.all([
    sendResendEmail(resendKey, adminEmail, otpCode, clientIp),
    sendTelegramOtp(tgToken, tgChatId, otpCode, clientIp),
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
