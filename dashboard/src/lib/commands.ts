export interface DashboardCommand {
  agent_id: string;
  action: "quarantine" | "sinkhole" | "scan";
  target: string;
}

async function sendCommand(command: DashboardCommand): Promise<Response> {
  return fetch("/api/commands", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...command, by: "dashboard" }),
  });
}

export async function postCommand(command: DashboardCommand): Promise<Response> {
  const first = await sendCommand(command);
  if (first.status !== 401) return first;
  const token = window.prompt("Masukkan DASHBOARD_LOGIN_TOKEN:");
  if (!token) return first;
  const login = await fetch("/api/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!login.ok) return login;
  return sendCommand(command);
}
