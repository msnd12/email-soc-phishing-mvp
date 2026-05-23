const BLOCKED_HOSTS = new Set([
  "mail.google.com",
  "accounts.google.com",
  "ssl.gstatic.com",
  "www.gstatic.com",
  "outlook.office.com",
  "outlook.office365.com",
  "login.microsoftonline.com"
]);

function extractVisibleLinks() {
  const links = [];
  const seen = new Set();
  for (const anchor of document.querySelectorAll("a[href]")) {
    const href = anchor.href;
    if (!href || !/^https?:\/\//i.test(href)) continue;
    let url;
    try {
      url = new URL(href);
    } catch {
      continue;
    }
    if (BLOCKED_HOSTS.has(url.hostname)) continue;
    if (seen.has(url.href)) continue;
    seen.add(url.href);
    links.push({
      url: url.href,
      text: anchor.textContent?.replace(/\s+/g, " ").trim().slice(0, 180) || ""
    });
    if (links.length >= 25) break;
  }
  return links;
}

function ensureBadge() {
  if (document.getElementById("email-soc-extension-badge")) return;
  const badge = document.createElement("div");
  badge.id = "email-soc-extension-badge";
  badge.textContent = "Email SOC active";
  badge.style.cssText = [
    "position:fixed",
    "right:16px",
    "bottom:16px",
    "z-index:2147483647",
    "padding:8px 10px",
    "border-radius:6px",
    "background:#102034",
    "color:#fff",
    "font:600 12px Arial,sans-serif",
    "box-shadow:0 10px 26px rgba(15,23,42,.22)",
    "opacity:.86"
  ].join(";");
  document.documentElement.appendChild(badge);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "EMAIL_SOC_EXTRACT_LINKS") return false;
  sendResponse({
    pageTitle: document.title,
    pageUrl: location.href,
    links: extractVisibleLinks()
  });
  return true;
});

if (location.hostname.includes("mail.google.com") || location.hostname.includes("outlook.office")) {
  ensureBadge();
}
