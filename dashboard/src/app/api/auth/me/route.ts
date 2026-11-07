import { getAuthorizedSession } from "../../../../lib/session.ts";

export const runtime = "nodejs";

export async function GET(request: Request): Promise<Response> {
  const user = getAuthorizedSession(request);
  if (!user) {
    return Response.json({ authenticated: false, user: null }, { status: 200 });
  }

  return Response.json(
    {
      authenticated: true,
      user: {
        username: user.username,
        role: user.role,
        email: user.email || "",
        name: user.name || user.username,
      },
    },
    { status: 200 },
  );
}
