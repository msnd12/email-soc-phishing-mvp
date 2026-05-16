import { Injectable } from "@nestjs/common";
import { domainToASCII } from "node:url";
import { ExtractedUrl } from "../common/types";
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
const BRANDS = ["microsoft", "office", "outlook", "google", "gmail", "apple", "paypal", "docusign", "dropbox", "okta", "github"];
const URL_REGEX = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
const ANCHOR_REGEX = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
const TAG_REGEX = /<[^>]+>/g;

@Injectable()
export class UrlExtractorService {
  extract(text?: string, html?: string): ExtractedUrl[] {
    const candidates: Array<{ url: string; displayText?: string }> = [];
    const pushTextUrls = (value?: string) => {
      if (!value) return;
      for (const match of value.matchAll(URL_REGEX)) {
        candidates.push({ url: match[0] });
      }
    };

    pushTextUrls(text);
    pushTextUrls(html);

    if (html) {
      for (const match of html.matchAll(ANCHOR_REGEX)) {
        const displayText = this.plainText(match[2]);
        candidates.push({ url: match[1], displayText });
      }
    }

    const seen = new Set<string>();
    return candidates
      .map((candidate) => this.analyze(candidate.url, candidate.displayText))
      .filter((item): item is ExtractedUrl => Boolean(item))
      .filter((item) => {
        const key = `${item.normalizedUrl}|${item.displayText ?? ""}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });
  }

  analyze(rawUrl: string, displayText?: string): ExtractedUrl | null {
    const decoded = this.safeDecode(rawUrl.trim().replace(/[.,;:!?]+$/, ""));
    let parsed: URL;
    try {
      parsed = new URL(decoded);
    } catch {
      return null;
    }

    parsed.hash = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    const domain = parsed.hostname;
    const asciiDomain = domainToASCII(domain);
    const tld = domain.split(".").pop()?.toLowerCase() ?? "";
    const isIpUrl = this.isIp(domain);
    const isPunycode = asciiDomain.startsWith("xn--") || asciiDomain.includes(".xn--");
    const isShortened = SHORTENER_DOMAINS.has(domain) || [...SHORTENER_DOMAINS].some((shortener) => domain.endsWith(`.${shortener}`));
    const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
    const isLookalike = this.looksLikeBrand(domain);
    const hasMismatchedAnchor = this.hasMismatchedAnchor(displayText, domain);

    const reasons: string[] = [];
    if (isShortened) reasons.push("URL uses a known shortener");
    if (isPunycode) reasons.push("Domain uses punycode, which can hide homograph attacks");
    if (isIpUrl) reasons.push("URL points directly to an IP address");
    if (isSuspiciousTld) reasons.push(`Domain uses suspicious TLD .${tld}`);
    if (isLookalike) reasons.push("Domain resembles a commonly impersonated brand");
    if (hasMismatchedAnchor) reasons.push("Anchor text claims a different destination");

    return {
      originalUrl: rawUrl,
      normalizedUrl: parsed.toString(),
      displayText,
      domain,
      isShortened,
      isPunycode,
      isIpUrl,
      isSuspiciousTld,
      isLookalike,
      hasMismatchedAnchor,
      redirectChain: [],
      reasons
    };
  }

  private safeDecode(value: string): string {
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }

  private plainText(html: string): string {
    return html.replace(TAG_REGEX, " ").replace(/\s+/g, " ").trim();
  }

  private isIp(hostname: string): boolean {
    return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":");
  }

  private looksLikeBrand(domain: string): boolean {
    if (isTrustedBrandDomain(domain)) return false;
    const compact = domain.replace(/[^a-z0-9]/g, "");
    return BRANDS.some((brand) => compact.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.com.`));
  }

  private hasMismatchedAnchor(displayText: string | undefined, actualDomain: string): boolean {
    if (!displayText) return false;
    const match = displayText.match(URL_REGEX);
    if (!match?.[0]) return false;
    try {
      const shown = new URL(match[0]).hostname.toLowerCase();
      return shown !== actualDomain && !actualDomain.endsWith(`.${shown}`);
    } catch {
      return false;
    }
  }
}
