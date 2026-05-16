import { domainToASCII } from "node:url";
import { isTrustedBrandDomain } from "./trusted-brand-domains";

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "cutt.ly",
  "rebrand.ly",
  "s.id",
  "lnkd.in"
]);

const SUSPICIOUS_TLDS = new Set(["zip", "mov", "click", "top", "xyz", "icu", "rest", "cam", "quest", "support"]);
const RISK_KEYWORDS = ["login", "verify", "update", "secure", "account", "password", "billing", "bank", "office", "microsoft", "wallet"];
const BRAND_WORDS = ["microsoft", "google", "apple", "paypal", "docusign", "dropbox", "okta", "github", "office", "outlook"];

export const URL_ML_FEATURES = [
  "url_length",
  "hostname_length",
  "path_length",
  "query_length",
  "dot_count",
  "hyphen_count",
  "digit_ratio",
  "entropy",
  "has_at_symbol",
  "is_ip_host",
  "is_punycode",
  "uses_https",
  "has_port",
  "subdomain_count",
  "is_shortener",
  "suspicious_tld",
  "brand_lookalike",
  "percent_encoded",
  "double_slash_in_path",
  "many_query_params",
  "risk_keyword_count",
  "has_hex_token",
  "path_depth",
  "hostname_digit_count",
  "hostname_vowel_ratio"
] as const;

export type UrlMlFeatureName = (typeof URL_ML_FEATURES)[number];

export type UrlMlFeatureVector = {
  names: readonly UrlMlFeatureName[];
  values: number[];
  normalizedUrl: string;
  domain: string;
};

export function extractUrlMlFeatures(rawUrl: string): UrlMlFeatureVector | null {
  const url = normalizeInput(rawUrl);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    try {
      parsed = new URL(`https://${url}`);
    } catch {
      return null;
    }
  }

  parsed.hash = "";
  const hostname = parsed.hostname.toLowerCase();
  const asciiHostname = domainToASCII(hostname);
  const domainParts = hostname.split(".").filter(Boolean);
  const tld = domainParts.at(-1) ?? "";
  const path = parsed.pathname ?? "";
  const query = parsed.search ?? "";
  const compactHost = hostname.replace(/[^a-z0-9]/g, "");

  const values = [
    clamp(parsed.toString().length / 220),
    clamp(hostname.length / 80),
    clamp(path.length / 160),
    clamp(query.length / 160),
    clamp(count(parsed.toString(), ".") / 12),
    clamp(count(parsed.toString(), "-") / 12),
    ratio(parsed.toString().match(/\d/g)?.length ?? 0, parsed.toString().length),
    clamp(entropy(parsed.toString()) / 5),
    parsed.username || parsed.password || parsed.toString().includes("@") ? 1 : 0,
    isIp(hostname) ? 1 : 0,
    asciiHostname.startsWith("xn--") || asciiHostname.includes(".xn--") ? 1 : 0,
    parsed.protocol === "https:" ? 1 : 0,
    parsed.port ? 1 : 0,
    clamp(Math.max(0, domainParts.length - 2) / 6),
    isShortener(hostname) ? 1 : 0,
    SUSPICIOUS_TLDS.has(tld) ? 1 : 0,
    !isTrustedBrandDomain(hostname) && BRAND_WORDS.some((brand) => compactHost.includes(brand) && !hostname.endsWith(`${brand}.com`)) ? 1 : 0,
    /%[0-9a-f]{2}/i.test(rawUrl) ? 1 : 0,
    path.slice(1).includes("//") ? 1 : 0,
    (query.match(/[?&][^=]+=/g)?.length ?? 0) >= 4 ? 1 : 0,
    clamp(RISK_KEYWORDS.filter((word) => parsed.toString().toLowerCase().includes(word)).length / 5),
    /[a-f0-9]{16,}/i.test(parsed.toString()) ? 1 : 0,
    clamp(path.split("/").filter(Boolean).length / 8),
    clamp((hostname.match(/\d/g)?.length ?? 0) / 10),
    ratio(hostname.match(/[aeiou]/g)?.length ?? 0, hostname.replace(/[^a-z]/g, "").length)
  ];

  return {
    names: URL_ML_FEATURES,
    values,
    normalizedUrl: parsed.toString(),
    domain: hostname
  };
}

function normalizeInput(value: string): string {
  try {
    return decodeURIComponent(value.trim());
  } catch {
    return value.trim();
  }
}

function count(value: string, token: string): number {
  return value.split(token).length - 1;
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? clamp(numerator / denominator) : 0;
}

function clamp(value: number): number {
  return Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
}

function entropy(value: string): number {
  if (!value.length) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let result = 0;
  for (const seen of counts.values()) {
    const probability = seen / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

function isIp(hostname: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
}

function isShortener(hostname: string): boolean {
  return SHORTENER_DOMAINS.has(hostname) || [...SHORTENER_DOMAINS].some((shortener) => hostname.endsWith(`.${shortener}`));
}
