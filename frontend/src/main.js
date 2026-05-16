const API_BASE_URL = localStorage.getItem("emailSocApiBaseUrl") || "http://localhost:4000";
const root = document.getElementById("root");

let session = readSession();
let state = {
  overview: {},
  alerts: [],
  messages: [],
  connections: [],
  detail: {},
  messageDetail: {},
  selectedId: null,
  selectedMessageId: null,
  status: "",
  busy: false
};

function readSession() {
  const raw = localStorage.getItem("emailSocSession");
  return raw ? JSON.parse(raw) : null;
}

function writeSession(value) {
  session = value;
  if (value) localStorage.setItem("emailSocSession", JSON.stringify(value));
  else localStorage.removeItem("emailSocSession");
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(session?.token ? { authorization: `Bearer ${session.token}` } : {}),
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

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function riskClass(severity) {
  return `risk risk-${String(severity || "info").toLowerCase()}`;
}

function risk(score, severity) {
  return `<span class="${riskClass(severity)}">${Number(score || 0)}<small>${escapeHtml(severity || "")}</small></span>`;
}

function formatError(error) {
  return error instanceof Error ? error.message : "Request failed";
}

async function login(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  try {
    const result = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: form.get("email"),
        password: form.get("password")
      })
    });
    writeSession(result);
    state.status = "";
    render();
    await refresh();
  } catch (error) {
    document.querySelector("[data-login-error]").textContent = formatError(error);
  }
}

async function refresh() {
  if (!session) return;
  state.busy = true;
  render();
  try {
    const [overview, alerts, messages, connections] = await Promise.all([
      api("/api/email-alerts/overview"),
      api("/api/email-alerts"),
      api("/api/email/messages"),
      api("/api/email/connections")
    ]);
    state.overview = overview;
    state.alerts = alerts;
    state.messages = messages;
    state.connections = connections;
    if (!state.selectedId && alerts[0]?.id) state.selectedId = alerts[0].id;
    if (!state.selectedId && !state.selectedMessageId && messages[0]?.id) state.selectedMessageId = messages[0].id;
    if (state.selectedId && alerts.some((alert) => alert.id === state.selectedId)) {
      await loadDetail(state.selectedId, false);
    } else if (state.selectedMessageId && messages.some((message) => message.id === state.selectedMessageId)) {
      await loadMessage(state.selectedMessageId, false);
    } else if (alerts[0]?.id) {
      await loadDetail(alerts[0].id, false);
    } else if (messages[0]?.id) {
      await loadMessage(messages[0].id, false);
    } else {
      state.detail = {};
      state.messageDetail = {};
    }
  } catch (error) {
    state.status = formatError(error);
  } finally {
    state.busy = false;
    render();
  }
}

async function loadDetail(id, rerender = true) {
  state.selectedId = id;
  state.selectedMessageId = null;
  try {
    state.detail = await api(`/api/email-alerts/${id}`);
    state.messageDetail = {};
  } catch (error) {
    state.status = formatError(error);
  }
  if (rerender) render();
}

async function loadMessage(id, rerender = true) {
  state.selectedMessageId = id;
  state.selectedId = null;
  try {
    state.messageDetail = await api(`/api/email/messages/${id}`);
    state.detail = {};
  } catch (error) {
    state.status = formatError(error);
  }
  if (rerender) render();
}

async function connectGmail() {
  try {
    const result = await api("/api/email/oauth/gmail/start");
    window.location.href = result.url;
  } catch (error) {
    state.status = formatError(error);
    render();
  }
}

async function pollGmail() {
  state.busy = true;
  render();
  try {
    const mailbox = state.connections[0]?.mailbox || undefined;
    const result = await api("/api/email/poll/gmail", {
      method: "POST",
      body: JSON.stringify({ mailbox, maxResults: 10 })
    });
    state.status = `Gmail poll complete. Ingested ${result.ingested} real message${result.ingested === 1 ? "" : "s"}.`;
    await refresh();
  } catch (error) {
    state.status = formatError(error);
  } finally {
    state.busy = false;
    render();
  }
}

async function updateAlert(verdict) {
  const alert = state.detail.alert;
  if (!alert) return;
  await api(`/api/email-alerts/${alert.id}/status`, {
    method: "PATCH",
    body: JSON.stringify({ verdict, status: verdict === "safe" ? "false_positive" : "triaged" })
  });
  state.status = `Alert marked ${verdict}. Audit log written.`;
  await refresh();
}

async function playbook(action) {
  const alert = state.detail.alert;
  if (!alert) return;
  const result = await api(`/api/playbooks/${action}`, {
    method: "POST",
    body: JSON.stringify({
      alertId: alert.id,
      emailMessageId: alert.email_message_id,
      sender: alert.sender,
      domain: alert.sender_domain,
      recipient: alert.recipient
    })
  });
  state.status = result.result?.message || result.status;
  await loadDetail(alert.id);
}

async function createIncident() {
  const alert = state.detail.alert;
  if (!alert) return;
  const result = await api(`/api/email-alerts/${alert.id}/create-incident`, {
    method: "POST",
    body: JSON.stringify({})
  });
  state.status = `Incident created: ${result.incidentId}`;
  await refresh();
}

async function exportReport() {
  const alert = state.detail.alert;
  if (!alert) return;
  const result = await api(`/api/reports/email-alert/${alert.id}`, {
    method: "POST",
    body: JSON.stringify({})
  });
  state.status = `Evidence report created: ${result.reportId}`;
  render();
}

async function rescanEmail() {
  const alert = state.detail.alert;
  if (!alert) return;
  const result = await api(`/api/email/rescan/${alert.email_message_id}`, {
    method: "POST",
    body: JSON.stringify({})
  });
  state.status = `Email rescanned. New risk score: ${result.riskScore}, verdict: ${result.verdict}.`;
  await refresh();
}

function renderLogin() {
  root.innerHTML = `
    <main class="login-shell">
      <section class="login-panel">
        <div class="brand-mark">SOC</div>
        <h1>Email SOC Phishing Detection</h1>
        <p>Sign in with the analyst user you seeded, then connect Gmail and scan real inbound mail.</p>
        <form class="login-form" data-login-form>
          <label>Email<input name="email" value="analyst@example.com" autocomplete="email" /></label>
          <label>Password<input name="password" type="password" autocomplete="current-password" /></label>
          <div class="error" data-login-error hidden></div>
          <button class="primary" type="submit">Login</button>
        </form>
      </section>
    </main>`;
  const error = root.querySelector("[data-login-error]");
  error.hidden = true;
  root.querySelector("[data-login-form]").addEventListener("submit", (event) => {
    error.hidden = false;
    error.textContent = "";
    void login(event);
  });
}

function renderApp() {
  const selected = state.alerts.find((alert) => alert.id === state.selectedId) || state.alerts[0];
  const alert = state.detail.alert;
  const selectedMessage = state.messages.find((message) => message.id === state.selectedMessageId);
  const message = state.messageDetail.message;
  root.innerHTML = `
    <main class="app-shell">
      <aside class="sidebar">
        <div class="sidebar-brand"><span class="brand-dot">SOC</span><span>Email SOC</span></div>
        <nav><a class="active">Phishing MVP</a></nav>
        <button class="ghost logout" data-action="logout">Logout</button>
      </aside>
      <section class="main-panel">
        <header class="topbar">
          <div>
            <h1>Email Security Overview</h1>
            <p>${state.connections.length ? `Connected mailbox: ${escapeHtml(state.connections[0].mailbox)}` : "No Gmail mailbox connected yet"}</p>
          </div>
          <div class="actions">
            <button class="secondary" data-action="connect">Connect Gmail</button>
            <button class="primary" data-action="poll" ${state.busy || !state.connections.length ? "disabled" : ""}>Fetch latest</button>
          </div>
        </header>
        <section class="metrics-grid">
          ${metric("Emails scanned today", state.overview.emails_scanned_today || 0)}
          ${metric("Suspicious emails", state.overview.suspicious_emails || 0)}
          ${metric("Phishing emails", state.overview.phishing_emails || 0)}
          ${metric("Malicious URLs", state.overview.malicious_urls_detected || 0)}
        </section>
        ${state.status ? `<div class="notice">${escapeHtml(state.status)}</div>` : ""}
        <section class="workspace">
          <div class="list-column">
            <div class="alert-list">
              <div class="section-heading">
                <h2>Suspicious Emails</h2>
                <button class="icon-button" data-action="refresh" title="Refresh alerts">Refresh</button>
              </div>
              <div class="table">
                <div class="row header"><span>Subject</span><span>Sender</span><span>Risk</span><span>Status</span></div>
                ${state.alerts.map((row) => alertRow(row, selected?.id)).join("")}
                ${state.alerts.length ? "" : '<div class="empty">No active suspicious alerts. Safe and false-positive messages are listed below.</div>'}
              </div>
            </div>
            <div class="alert-list">
              <div class="section-heading">
                <h2>Recent Emails</h2>
                <span class="section-count">${state.messages.length} scanned</span>
              </div>
              <div class="table">
                <div class="row header message-header"><span>Subject</span><span>Sender</span><span>Risk</span><span>Verdict</span></div>
                ${state.messages.map((row) => messageRow(row, selectedMessage?.id)).join("")}
                ${state.messages.length ? "" : '<div class="empty">No emails scanned yet. Connect Gmail, then click Fetch latest.</div>'}
              </div>
            </div>
          </div>
          ${alert ? detailPanel(state.detail) : message ? messagePanel(state.messageDetail) : '<div class="detail empty-detail">Select an alert or recent email to review evidence.</div>'}
        </section>
      </section>
    </main>`;
  bindActions();
}

function metric(label, value) {
  return `<div class="metric"><div class="metric-icon">SOC</div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function alertRow(row, selectedId) {
  return `
    <button class="row alert-row ${row.id === selectedId ? "selected" : ""}" data-alert-id="${escapeHtml(row.id)}">
      <span>${escapeHtml(row.subject || "(no subject)")}</span>
      <span>${escapeHtml(row.sender)}</span>
      ${risk(row.risk_score, row.severity)}
      <span>${escapeHtml(row.status)}</span>
    </button>`;
}

function messageRow(row, selectedId) {
  const severity = severityFromScore(row.risk_score);
  return `
    <button class="row alert-row message-row ${row.id === selectedId ? "selected" : ""}" data-message-id="${escapeHtml(row.id)}">
      <span>${escapeHtml(row.subject || "(no subject)")}</span>
      <span>${escapeHtml(row.sender)}</span>
      ${risk(row.risk_score, severity)}
      <span class="verdict-pill">${escapeHtml(row.verdict || "safe")}</span>
    </button>`;
}

function severityFromScore(score) {
  const value = Number(score || 0);
  if (value >= 90) return "Critical";
  if (value >= 70) return "High";
  if (value >= 50) return "Medium";
  if (value >= 30) return "Low";
  return "Informational";
}

function detailPanel(detail) {
  const alert = detail.alert;
  const reasons = (alert.reasons || []).map((reason) => `<li>${escapeHtml(reason)}</li>`).join("");
  const urls = (detail.urls || []).map(urlCard).join("");
  const timeline = (detail.timeline || []).map((item) => `
    <div><strong>${escapeHtml(item.action)}</strong><span>${escapeHtml(new Date(item.created_at).toLocaleString())}</span></div>
  `).join("");
  return `
    <article class="detail">
      <div class="detail-header">
        <div><h2>${escapeHtml(alert.subject || "(no subject)")}</h2><p>${escapeHtml(alert.sender)} to ${escapeHtml(alert.recipient)}</p></div>
        ${risk(alert.risk_score, alert.severity)}
      </div>
      <section class="evidence-block">
        <h3>AI Explanation</h3>
        <ul class="reason-list">${reasons}</ul>
        <div class="recommendation"><span>${escapeHtml(alert.recommended_action)}</span></div>
      </section>
      <section class="evidence-grid">
        ${evidence("SPF", alert.authentication_results?.spf || "unknown")}
        ${evidence("DKIM", alert.authentication_results?.dkim || "unknown")}
        ${evidence("DMARC", alert.authentication_results?.dmarc || "unknown")}
        ${evidence("Reply-To", alert.reply_to || "none")}
      </section>
      <section class="evidence-block">
        <h3>Extracted URLs and Scan Results</h3>
        <div class="url-stack">${urls || "<p>No URLs were extracted from this email.</p>"}</div>
      </section>
      <section class="button-row">
        <button data-disposition="safe">Mark safe</button>
        <button data-disposition="suspicious">Mark suspicious</button>
        <button data-disposition="phishing">Mark phishing</button>
        <button data-disposition="malicious">Mark malicious</button>
      </section>
      <section class="button-row">
        <button data-action="incident">Create incident</button>
        <button data-playbook="block-sender">Block sender</button>
        <button data-playbook="block-domain">Block domain</button>
        <button data-playbook="quarantine-email">Quarantine email</button>
        <button data-playbook="notify-user">Notify user</button>
        <button data-action="rescan">Rescan email</button>
        <button data-action="report">Export report</button>
      </section>
      <section class="evidence-block">
        <h3>Timeline</h3>
        <div class="timeline">${timeline || "<p>No analyst actions recorded yet.</p>"}</div>
      </section>
    </article>`;
}

function messagePanel(detail) {
  const message = detail.message;
  const urls = (detail.urls || []).map(urlCard).join("");
  const attachments = (detail.attachments || []).map((attachment) => `<li>${escapeHtml(attachment.filename)}</li>`).join("");
  return `
    <article class="detail">
      <div class="detail-header">
        <div><h2>${escapeHtml(message.subject || "(no subject)")}</h2><p>${escapeHtml(message.sender)} to ${escapeHtml(message.recipient)}</p></div>
        ${risk(message.risk_score, severityFromScore(message.risk_score))}
      </div>
      <section class="evidence-block">
        <h3>Email Verdict</h3>
        <div class="recommendation"><span>${escapeHtml(message.verdict || "safe")} email. No active SOC alert exists for this message.</span></div>
        <p>${escapeHtml(message.body_preview || "No preview available.")}</p>
      </section>
      <section class="evidence-grid">
        ${evidence("SPF", message.authentication_results?.spf || "unknown")}
        ${evidence("DKIM", message.authentication_results?.dkim || "unknown")}
        ${evidence("DMARC", message.authentication_results?.dmarc || "unknown")}
        ${evidence("Reply-To", message.reply_to || "none")}
      </section>
      <section class="evidence-block">
        <h3>Extracted URLs and Scan Results</h3>
        <div class="url-stack">${urls || "<p>No URLs were extracted from this email.</p>"}</div>
      </section>
      <section class="evidence-block">
        <h3>Attachments</h3>
        ${attachments ? `<ul class="reason-list">${attachments}</ul>` : "<p>No attachments found.</p>"}
      </section>
    </article>`;
}

function evidence(label, value) {
  return `<div class="evidence"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function urlCard(url) {
  const scans = (url.scan_results || []).map((scan) => (
    `<span>${escapeHtml(scan.provider)}: ${escapeHtml(scan.verdict)} (${Number(scan.malicious_count || 0)}/${Number(scan.suspicious_count || 0)})</span>`
  )).join("");
  const severity = url.verdict === "malicious" ? "Critical" : url.verdict === "suspicious" ? "Medium" : "Informational";
  return `
    <div class="url-card">
      <div><strong>${escapeHtml(url.domain)}</strong><p>${escapeHtml(url.normalized_url)}</p></div>
      ${risk(url.risk_score, severity)}
      <div class="scan-list">${scans}</div>
    </div>`;
}

function bindActions() {
  root.querySelector("[data-action='logout']")?.addEventListener("click", () => {
    writeSession(null);
    render();
  });
  root.querySelector("[data-action='connect']")?.addEventListener("click", () => void connectGmail());
  root.querySelector("[data-action='poll']")?.addEventListener("click", () => void pollGmail());
  root.querySelector("[data-action='refresh']")?.addEventListener("click", () => void refresh());
  root.querySelector("[data-action='incident']")?.addEventListener("click", () => void createIncident());
  root.querySelector("[data-action='report']")?.addEventListener("click", () => void exportReport());
  root.querySelector("[data-action='rescan']")?.addEventListener("click", () => void rescanEmail());
  root.querySelectorAll("[data-alert-id]").forEach((node) => {
    node.addEventListener("click", () => void loadDetail(node.getAttribute("data-alert-id")));
  });
  root.querySelectorAll("[data-message-id]").forEach((node) => {
    node.addEventListener("click", () => void loadMessage(node.getAttribute("data-message-id")));
  });
  root.querySelectorAll("[data-disposition]").forEach((node) => {
    node.addEventListener("click", () => void updateAlert(node.getAttribute("data-disposition")));
  });
  root.querySelectorAll("[data-playbook]").forEach((node) => {
    node.addEventListener("click", () => void playbook(node.getAttribute("data-playbook")));
  });
}

function render() {
  if (!session) renderLogin();
  else renderApp();
}

render();
if (session) void refresh();
setInterval(() => {
  if (session) void refresh();
}, 30000);
