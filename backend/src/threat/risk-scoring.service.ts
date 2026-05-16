import { Injectable } from "@nestjs/common";
import { AuthResults, Verdict } from "../common/types";
import { severityFromRiskScore, verdictFromRiskScore } from "../common/severity";
import { loadUrlMlModel, predictUrlPhishing, UrlMlModel } from "./url-ml-model";
import { isKnownEmailServiceDomain, isTrustedBrandDomain } from "./trusted-brand-domains";

export type UrlSignal = {
  id?: string;
  normalizedUrl?: string;
  domain?: string;
  isShortened?: boolean;
  isPunycode?: boolean;
  isIpUrl?: boolean;
  isSuspiciousTld?: boolean;
  isLookalike?: boolean;
  hasMismatchedAnchor?: boolean;
  verdict?: Verdict;
  maliciousCount?: number;
  suspiciousCount?: number;
};

export type ScoreInput = {
  sender: string;
  senderDomain?: string;
  replyTo?: string;
  returnPath?: string;
  subject?: string;
  bodyPreview?: string;
  authenticationResults?: AuthResults;
  urls: UrlSignal[];
  attachments: Array<{ filename: string }>;
};

export type ScoreOutput = {
  riskScore: number;
  verdict: "safe" | "suspicious" | "phishing" | "malicious";
  confidence: number;
  severity: ReturnType<typeof severityFromRiskScore>;
  reasons: string[];
  recommendedAction: string;
};

const EXECUTIVE_WORDS = ["ceo", "cfo", "payroll", "finance", "hr", "it support", "security team"];
const URGENT_WORDS = ["urgent", "immediately", "verify", "password", "suspended", "invoice", "wire", "payment", "gift card"];
const RISKY_EXTENSIONS = [".exe", ".scr", ".js", ".vbs", ".iso", ".lnk", ".hta", ".bat", ".cmd", ".zip", ".rar", ".7z"];

@Injectable()
export class RiskScoringService {
  private readonly urlMlModel: UrlMlModel | null;

  constructor() {
    this.urlMlModel = loadUrlMlModel();
  }

  score(input: ScoreInput): ScoreOutput {
    let score = 0;
    const reasons: string[] = [];
    const auth = input.authenticationResults ?? {};
    const authenticatedSender = this.hasPassingAuth(auth);

    if (auth.dmarc && auth.dmarc !== "pass") {
      score += 20;
      reasons.push(`DMARC ${auth.dmarc}`);
    }
    if (auth.spf && auth.spf !== "pass") {
      score += 12;
      reasons.push(`SPF ${auth.spf}`);
    }
    if (auth.dkim && auth.dkim !== "pass") {
      score += 12;
      reasons.push(`DKIM ${auth.dkim}`);
    }

    if (input.replyTo && input.sender && !this.sameOrganizationDomain(input.replyTo, input.sender)) {
      score += 12;
      reasons.push("Reply-To domain differs from sender domain");
    }
    if (input.returnPath && input.sender && !this.sameOrganizationDomain(input.returnPath, input.sender)) {
      score += 10;
      reasons.push("Return-Path domain differs from sender domain");
    }

    const text = `${input.subject ?? ""} ${input.bodyPreview ?? ""}`.toLowerCase();
    if (URGENT_WORDS.some((word) => text.includes(word))) {
      score += 10;
      reasons.push("Urgent or credential/payment themed language detected");
    }
    if (!authenticatedSender && EXECUTIVE_WORDS.some((word) => text.includes(word))) {
      score += 8;
      reasons.push("Potential executive or trusted-team impersonation language");
    }

    for (const url of input.urls) {
      let hasUrlHeuristicSignal = false;
      let hasThreatIntelSignal = false;
      const trustedUrlDomain = url.domain ? isTrustedBrandDomain(url.domain) : false;
      if (url.isShortened) {
        hasUrlHeuristicSignal = true;
        this.add(8, "Suspicious link uses a shortener", reasons, (value) => (score += value));
      }
      if (url.isPunycode) {
        hasUrlHeuristicSignal = true;
        this.add(14, "Suspicious link uses punycode", reasons, (value) => (score += value));
      }
      if (url.isIpUrl) {
        hasUrlHeuristicSignal = true;
        this.add(14, "Suspicious link points to an IP address", reasons, (value) => (score += value));
      }
      if (url.isSuspiciousTld) {
        hasUrlHeuristicSignal = true;
        this.add(8, "Suspicious link uses a risky TLD", reasons, (value) => (score += value));
      }
      if (url.isLookalike && !trustedUrlDomain) {
        hasUrlHeuristicSignal = true;
        this.add(12, "Suspicious link resembles a trusted brand", reasons, (value) => (score += value));
      }
      if (url.hasMismatchedAnchor) {
        hasUrlHeuristicSignal = true;
        this.add(15, "Link text does not match the real destination", reasons, (value) => (score += value));
      }
      if ((url.maliciousCount ?? 0) > 0 || url.verdict === "malicious") {
        hasThreatIntelSignal = true;
        this.add(45, "Threat intelligence marked a URL malicious", reasons, (value) => (score += value));
      } else if ((url.suspiciousCount ?? 0) > 0 || url.verdict === "suspicious") {
        hasThreatIntelSignal = true;
        this.add(25, "Threat intelligence marked a URL suspicious", reasons, (value) => (score += value));
      }
      if (this.urlMlModel && url.normalizedUrl) {
        const prediction = predictUrlPhishing(url.normalizedUrl, this.urlMlModel);
        if (prediction) {
          const veryHighConfidenceThreshold = Math.max(0.9, prediction.threshold + 0.45);
          const highConfidenceThreshold = Math.max(0.75, prediction.threshold + 0.3);
          const knownEmailInfrastructure = url.domain ? isKnownEmailServiceDomain(url.domain) : false;
          const hasCorroboration = hasUrlHeuristicSignal || hasThreatIntelSignal;
          let aiScore = 0;
          if (prediction.probability >= veryHighConfidenceThreshold) {
            aiScore = 35;
          } else if (prediction.probability >= highConfidenceThreshold) {
            aiScore = 30;
          } else if (prediction.probability >= prediction.threshold) {
            aiScore = 10;
          }

          if (aiScore > 0 && !hasCorroboration) {
            aiScore = authenticatedSender || knownEmailInfrastructure ? 0 : Math.min(aiScore, 10);
          }

          if (aiScore > 0) {
            score += aiScore;
            if (aiScore >= 30) {
              reasons.push(`AI URL model predicts ${Math.round(prediction.probability * 100)}% phishing probability for ${url.domain ?? "URL"}`);
            } else {
              reasons.push(`AI URL model found elevated phishing probability (${Math.round(prediction.probability * 100)}%)`);
            }
            for (const feature of prediction.topFeatures.slice(0, aiScore >= 30 ? 3 : 2)) {
              reasons.push(`AI feature signal: ${feature.name}`);
            }
          }
        }
      }
    }

    for (const attachment of input.attachments) {
      const filename = attachment.filename.toLowerCase();
      if (RISKY_EXTENSIONS.some((ext) => filename.endsWith(ext))) {
        score += 15;
        reasons.push(`Risky attachment extension: ${attachment.filename}`);
      }
    }

    score = Math.min(100, Math.max(0, score));
    const verdict = verdictFromRiskScore(score);
    return {
      riskScore: score,
      verdict,
      confidence: Math.min(95, 45 + reasons.length * 8),
      severity: severityFromRiskScore(score),
      reasons: reasons.length ? [...new Set(reasons)] : ["No suspicious indicators crossed the alert threshold"],
      recommendedAction: this.recommendedAction(verdict)
    };
  }

  private add(points: number, reason: string, reasons: string[], addScore: (value: number) => void) {
    addScore(points);
    reasons.push(reason);
  }

  private domainOf(email: string): string {
    return email.split("@").pop()?.toLowerCase().replace(/[> )]/g, "") ?? "";
  }

  private sameOrganizationDomain(left: string, right: string): boolean {
    const leftDomain = this.domainOf(left);
    const rightDomain = this.domainOf(right);
    if (!leftDomain || !rightDomain) return false;
    if (leftDomain === rightDomain) return true;
    if (leftDomain.endsWith(`.${rightDomain}`) || rightDomain.endsWith(`.${leftDomain}`)) return true;
    return this.registrableDomain(leftDomain) === this.registrableDomain(rightDomain);
  }

  private registrableDomain(domain: string): string {
    const parts = domain.split(".").filter(Boolean);
    if (parts.length <= 2) return domain;
    const secondLevelCountryTlds = new Set(["ac", "co", "com", "edu", "gov", "net", "org"]);
    const tld = parts.at(-1) ?? "";
    const sld = parts.at(-2) ?? "";
    if (tld.length === 2 && secondLevelCountryTlds.has(sld) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  private hasPassingAuth(auth: AuthResults): boolean {
    return auth.spf === "pass" && auth.dkim === "pass" && auth.dmarc === "pass";
  }

  private recommendedAction(verdict: string): string {
    if (verdict === "malicious") return "Quarantine the email, block the sender/domain, and create an incident.";
    if (verdict === "phishing") return "Quarantine if integration is configured, notify the user, and investigate related messages.";
    if (verdict === "suspicious") return "Review evidence, check similar messages, and mark the disposition.";
    return "No response needed unless analyst review finds new evidence.";
  }
}
