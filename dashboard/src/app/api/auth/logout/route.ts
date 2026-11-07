import { SESSION_COOKIE_NAME } from "../../../../lib/session.ts";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  const secure =
    new URL(request.url).protocol === "https:" ||
    request.headers.get("origin")?.startsWith("https://") === true;

  const cookie = `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`;

  return Response.json(
    { success: true, message: "Sesi berhasil ditutup" },
    {
      status: 200,
      headers: { "Set-Cookie": cookie },
    },
  );
}
