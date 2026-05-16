export const TRUSTED_BRAND_DOMAINS = [
  "microsoft.com",
  "microsoftonline.com",
  "office.com",
  "office365.com",
  "outlook.com",
  "live.com",
  "windows.net",
  "azure.com",
  "google.com",
  "gmail.com",
  "googleapis.com",
  "googleusercontent.com",
  "gstatic.com",
  "apple.com",
  "icloud.com",
  "paypal.com",
  "paypalobjects.com",
  "docusign.com",
  "dropbox.com",
  "dropboxstatic.com",
  "dropboxusercontent.com",
  "okta.com",
  "github.com",
  "githubusercontent.com"
];

export const KNOWN_EMAIL_SERVICE_DOMAINS = [
  "rs6.net",
  "constantcontact.com",
  "list-manage.com",
  "mailchimp.com",
  "sendgrid.net",
  "sendgrid.com",
  "hubspotemail.net",
  "hubspot.com",
  "marketo.com",
  "mktoweb.com",
  "mailgun.org",
  "amazonses.com",
  "sfmc-content.com",
  "exacttarget.com",
  "pardot.com",
  "eloqua.com",
  "campaignmonitor.com",
  "createsend.com",
  "activehosted.com",
  "klaviyomail.com"
];

export function isTrustedBrandDomain(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  return TRUSTED_BRAND_DOMAINS.some((domain) => normalized === domain || normalized.endsWith(`.${domain}`));
}

export function isKnownEmailServiceDomain(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);
  return KNOWN_EMAIL_SERVICE_DOMAINS.some((domain) => normalized === domain || normalized.endsWith(`.${domain}`));
}

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.$/, "");
}
