import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import { URL_ML_FEATURES } from "./url-ml-features";
import { RiskScoringService } from "./risk-scoring.service";

const modelPath = path.join(os.tmpdir(), "email-soc-test-url-model.json");

describe("RiskScoringService", () => {
  beforeEach(() => {
    fs.writeFileSync(
      modelPath,
      JSON.stringify({
        modelType: "logistic_regression",
        version: 1,
        trainedAt: new Date(0).toISOString(),
        positiveSource: "test",
        negativeSource: "test",
        positiveCount: 1,
        negativeCount: 1,
        featureNames: URL_ML_FEATURES,
        weights: URL_ML_FEATURES.map(() => 0),
        bias: 2.2,
        threshold: 0.5
      })
    );
    process.env.URL_AI_MODEL_PATH = modelPath;
  });

  it("does not alert on AI-only marketing links from an authenticated sender", () => {
    const service = new RiskScoringService();

    const result = service.score({
      sender: "learn@eccouncil.org",
      senderDomain: "eccouncil.org",
      replyTo: "learnersupport@eccouncil.org",
      subject: "Turn Your Cybersecurity Experience Into Certification",
      bodyPreview: "A newsletter with a Constant Contact tracking link.",
      authenticationResults: { spf: "pass", dkim: "pass", dmarc: "pass" },
      urls: [
        {
          normalizedUrl: "https://c6nhlkcab.cc.rs6.net/tn.jsp?f=001newsletter",
          domain: "c6nhlkcab.cc.rs6.net"
        },
        {
          normalizedUrl: "https://audience.constantcontact.com/preferences/unsubscribe",
          domain: "audience.constantcontact.com"
        }
      ],
      attachments: []
    });

    expect(result.riskScore).toBe(0);
    expect(result.verdict).toBe("safe");
    expect(result.reasons.some((reason) => reason.includes("AI URL model"))).toBe(false);
  });

  it("uses the AI score when a suspicious URL heuristic corroborates it", () => {
    const service = new RiskScoringService();

    const result = service.score({
      sender: "security@example.net",
      senderDomain: "example.net",
      subject: "Account review",
      bodyPreview: "Please review your account.",
      authenticationResults: {},
      urls: [
        {
          normalizedUrl: "https://login-microsoft-support.click/verify",
          domain: "login-microsoft-support.click",
          isSuspiciousTld: true
        }
      ],
      attachments: []
    });

    expect(result.riskScore).toBeGreaterThanOrEqual(30);
    expect(result.reasons.some((reason) => reason.includes("AI URL model"))).toBe(true);
  });

  it("does not penalize authenticated same-organization return-path subdomains", () => {
    const service = new RiskScoringService();

    const result = service.score({
      sender: "no-reply@dropbox.com",
      senderDomain: "dropbox.com",
      returnPath: "bounce@email.dropbox.com",
      subject: "New sign in to your Dropbox account",
      bodyPreview: "Security notification from Dropbox.",
      authenticationResults: { spf: "pass", dkim: "pass", dmarc: "pass" },
      urls: [
        {
          normalizedUrl: "https://cfl.dropboxstatic.com/static/logo.png",
          domain: "cfl.dropboxstatic.com",
          isLookalike: true
        }
      ],
      attachments: []
    });

    expect(result.riskScore).toBe(0);
    expect(result.verdict).toBe("safe");
  });
});
