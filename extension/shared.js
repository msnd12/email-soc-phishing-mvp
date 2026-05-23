const DEFAULT_API_BASE_URL = "http://localhost:4000";
const DEFAULT_DASHBOARD_URL = "http://localhost:5173";

export async function getSettings() {
  const result = await chrome.storage.local.get(["apiBaseUrl", "dashboardUrl", "session"]);
  return {
    apiBaseUrl: result.apiBaseUrl || DEFAULT_API_BASE_URL,
    dashboardUrl: result.dashboardUrl || DEFAULT_DASHBOARD_URL,
    session: result.session || null
  };
}

export async function saveSettings(input) {
  await chrome.storage.local.set({
    apiBaseUrl: normalizeBaseUrl(input.apiBaseUrl || DEFAULT_API_BASE_URL),
    dashboardUrl: normalizeBaseUrl(input.dashboardUrl || DEFAULT_DASHBOARD_URL)
  });
}

export async function saveSession(session) {
  await chrome.storage.local.set({ session });
}

export async function clearSession() {
  await chrome.storage.local.remove("session");
}

export async function api(path, options = {}) {
  const settings = await getSettings();
  const response = await fetch(`${settings.apiBaseUrl}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(settings.session?.token ? { authorization: `Bearer ${settings.session.token}` } : {}),
      ...(options.headers || {})
    }
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(payload.message || response.statusText);
  }
  return payload;
}

export function normalizeBaseUrl(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

export function severityFromScore(score) {
  const value = Number(score || 0);
  if (value >= 90) return "Critical";
  if (value >= 70) return "High";
  if (value >= 50) return "Medium";
  if (value >= 30) return "Low";
  return "Informational";
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function formatError(error) {
  if (error instanceof Error) return error.message;
  return "Request failed";
}
