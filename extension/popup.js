import { api, clearSession, escapeHtml, formatError, getSettings, saveSession, severityFromScore } from "./shared.js";

const app = document.getElementById("app");

let state = {
  busy: false,
  status: "",
  settings: null,
  overview: null,
  connections: [],
  alerts: [],
  pageLinks: [],
  scanResults: []
};

document.querySelector('[data-action="open-options"]').addEventListener("click", () => {
  chrome.runtime.openOptionsPage();
});

async function init() {
  state.settings = await getSettings();
  if (state.settings.session) {
    await refresh();
  } else {
    renderLogin();
  }
}

async function login(event) {
  event.preventDefault();
  state.busy = true;
  renderLogin();
  const form = new FormData(event.currentTarget);
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: form.get("email"),
        password: form.get("password")
      })
    });
    await saveSession(result);
    state.settings = await getSettings();
    state.status = "Signed in to Email SOC.";
    await refresh();
  } catch (error) {
    state.status = formatError(error);
    state.busy = false;
    renderLogin();
  }
}

async function refresh() {
  state.busy = true;
  renderApp();
  try {
    const [overview, connections, alerts] = await Promise.all([
      api("/api/email-alerts/overview"),
      api("/api/email/connections"),
      api("/api/email-alerts")
    ]);
    state.overview = overview;
    state.connections = connections;
    state.alerts = alerts.slice(0, 5);
    state.status ||= "Connected to backend.";
  } catch (error) {
    state.status = formatError(error);
  } finally {
    state.busy = false;
    renderApp();
  }
}

async function logout() {
  await clearSession();
  state.settings = await getSettings();
  state.status = "";
  renderLogin();
}

async function connectGmail() {
  try {
    const result = await api("/api/email/oauth/gmail/start");
    await chrome.tabs.create({ url: result.url });
  } catch (error) {
    state.status = formatError(error);
    renderApp();
  }
}

async function fetchLatest() {
  state.busy = true;
  state.status = "Fetching latest Gmail messages.";
  renderApp();
  try {
    const mailbox = state.connections[0]?.mailbox;
    const result = await api("/api/email/poll/gmail", {
      method: "POST",
      body: JSON.stringify({ mailbox, maxResults: 10 })
    });
    state.status = `Ingested ${result.ingested} Gmail message${result.ingested === 1 ? "" : "s"}.`;
    await refresh();
  } catch (error) {
    state.status = formatError(error);
  } finally {
    state.busy = false;
    renderApp();
  }
}

async function openDashboard(path = "") {
  const settings = await getSettings();
  await chrome.tabs.create({ url: `${settings.dashboardUrl}${path}` });
}

async function extractLinksFromCurrentPage() {
  state.busy = true;
  state.status = "Reading visible links from the active mail tab.";
  state.scanResults = [];
  renderApp();
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !/^https:\/\/(mail\.google\.com|outlook\.office(?:365)?\.com)\//.test(tab.url || "")) {
      throw new Error("Open Gmail or Outlook in this window, then try again.");
    }
    const response = await chrome.tabs.sendMessage(tab.id, { type: "EMAIL_SOC_EXTRACT_LINKS" });
    state.pageLinks = response.links || [];
    state.status = state.pageLinks.length
      ? `Found ${state.pageLinks.length} visible external link${state.pageLinks.length === 1 ? "" : "s"}.`
      : "No visible external links found on this mail page.";
  } catch (error) {
    state.status = formatError(error);
  } finally {
    state.busy = false;
    renderApp();
  }
}

async function scanExtractedLinks() {
  state.busy = true;
  state.status = "Scanning extracted links with configured threat-intel providers.";
  state.scanResults = [];
  renderApp();
  try {
    const links = state.pageLinks.slice(0, 10);
    const results = [];
    for (const link of links) {
      results.push({
        url: link.url,
        scans: await api("/api/threat/scan-url", {
          method: "POST",
          body: JSON.stringify({ url: link.url })
        })
      });
    }
    state.scanResults = results;
    state.status = `Scanned ${results.length} URL${results.length === 1 ? "" : "s"}.`;
  } catch (error) {
    state.status = formatError(error);
  } finally {
    state.busy = false;
    renderApp();
  }
}

function renderLogin() {
  app.innerHTML = `
    <form class="panel login-form" data-login-form>
      <label>Email<input name="email" type="email" value="analyst@example.com" autocomplete="email" /></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" /></label>
      ${state.status ? `<p class="notice error">${escapeHtml(state.status)}</p>` : ""}
      <button class="primary" type="submit" ${state.busy ? "disabled" : ""}>Login</button>
      <button class="secondary" type="button" data-action="open-options">API settings</button>
    </form>`;
  app.querySelector("[data-login-form]").addEventListener("submit", login);
  app.querySelector('[data-action="open-options"]').addEventListener("click", () => chrome.runtime.openOptionsPage());
}

function renderApp() {
  const connected = state.connections[0]?.mailbox;
  app.innerHTML = `
    ${state.status ? `<p class="notice">${escapeHtml(state.status)}</p>` : ""}
    <section class="panel">
      <div class="session-line">
        <span>${escapeHtml(state.settings?.session?.user?.email || "Analyst")}</span>
        <button class="link-button" data-action="logout">Logout</button>
      </div>
      <p class="muted">${connected ? `Gmail connected: ${escapeHtml(connected)}` : "No Gmail mailbox connected yet."}</p>
      <div class="button-grid">
        <button class="primary" data-action="fetch" ${state.busy ? "disabled" : ""}>Fetch latest</button>
        <button class="secondary" data-action="connect">Connect Gmail</button>
        <button class="secondary" data-action="dashboard">Dashboard</button>
        <button class="secondary" data-action="refresh" ${state.busy ? "disabled" : ""}>Refresh</button>
      </div>
    </section>
    <section class="metrics">
      ${metric("Scanned", state.overview?.emails_scanned_today || 0)}
      ${metric("Suspicious", state.overview?.suspicious_emails || 0)}
      ${metric("Phishing", state.overview?.phishing_emails || 0)}
      ${metric("Bad URLs", state.overview?.malicious_urls || 0)}
    </section>
    <section class="panel">
      <div class="section-title">
        <h2>Recent Alerts</h2>
        <button class="link-button" data-action="dashboard-alerts">Open full view</button>
      </div>
      <div class="alert-list">${state.alerts.length ? state.alerts.map(alertRow).join("") : '<p class="muted">No open email alerts yet.</p>'}</div>
    </section>
    <section class="panel">
      <div class="section-title">
        <h2>Current Mail Page</h2>
        <span class="muted">${state.pageLinks.length} links</span>
      </div>
      <div class="button-grid">
        <button class="secondary" data-action="extract" ${state.busy ? "disabled" : ""}>Extract visible links</button>
        <button class="primary" data-action="scan-links" ${state.busy || !state.pageLinks.length ? "disabled" : ""}>Scan links</button>
      </div>
      <div class="link-list">${state.pageLinks.slice(0, 5).map(linkRow).join("")}</div>
      <div class="scan-list">${state.scanResults.map(scanRow).join("")}</div>
    </section>`;

  bind("[data-action='logout']", logout);
  bind("[data-action='fetch']", fetchLatest);
  bind("[data-action='connect']", connectGmail);
  bind("[data-action='dashboard']", () => openDashboard());
  bind("[data-action='dashboard-alerts']", () => openDashboard());
  bind("[data-action='refresh']", refresh);
  bind("[data-action='extract']", extractLinksFromCurrentPage);
  bind("[data-action='scan-links']", scanExtractedLinks);
}

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${Number(value || 0)}</strong></div>`;
}

function alertRow(alert) {
  const severity = alert.severity || severityFromScore(alert.risk_score);
  return `
    <button class="alert-row" data-alert-id="${escapeHtml(alert.id)}" title="Open dashboard for alert">
      <span><strong>${escapeHtml(alert.subject || "(no subject)")}</strong><small>${escapeHtml(alert.sender)}</small></span>
      <b class="risk risk-${severity.toLowerCase()}">${Number(alert.risk_score || 0)}<small>${escapeHtml(severity)}</small></b>
    </button>`;
}

function linkRow(link) {
  let domain = link.url;
  try {
    domain = new URL(link.url).hostname;
  } catch {
    domain = link.url;
  }
  return `<div class="url-row"><strong>${escapeHtml(domain)}</strong><small>${escapeHtml(link.text || link.url)}</small></div>`;
}

function scanRow(result) {
  let domain = result.url;
  try {
    domain = new URL(result.url).hostname;
  } catch {
    domain = result.url;
  }
  return `
    <div class="scan-row">
      <strong>${escapeHtml(domain)}</strong>
      ${(result.scans || []).map((scan) => `<span>${escapeHtml(scan.provider)}: ${escapeHtml(scan.verdict)} (${Number(scan.maliciousCount || 0)}/${Number(scan.suspiciousCount || 0)})</span>`).join("")}
    </div>`;
}

function bind(selector, handler) {
  const element = app.querySelector(selector);
  if (element) element.addEventListener("click", handler);
}

app.addEventListener("click", (event) => {
  const row = event.target.closest("[data-alert-id]");
  if (!row) return;
  void openDashboard();
});

void init();
