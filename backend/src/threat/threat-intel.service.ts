import { Inject, Injectable } from "@nestjs/common";
import { AppConfig, CONFIG } from "../config";
import { fetchJson } from "../common/fetch-json";
import { DbService } from "../db/db.service";
import { Verdict } from "../common/types";

export type ScanVerdict = {
  provider: "virustotal" | "urlscan" | "safe_browsing" | "web_risk";
  scanId?: string;
  maliciousCount: number;
  suspiciousCount: number;
  harmlessCount: number;
  verdict: Verdict | "not_configured";
  rawResponse: Record<string, unknown>;
};

@Injectable()
export class ThreatIntelService {
  constructor(
    private readonly db: DbService,
    @Inject(CONFIG) private readonly config: AppConfig
  ) {}

  async scanEmailUrl(emailUrlId: string, normalizedUrl: string): Promise<ScanVerdict[]> {
    const results = await this.scanUrl(normalizedUrl);
    for (const result of results) {
      await this.db.query(
        `INSERT INTO url_scan_results
          (email_url_id, provider, scan_id, malicious_count, suspicious_count, harmless_count, verdict, raw_response)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
        [
          emailUrlId,
          result.provider,
          result.scanId ?? null,
          result.maliciousCount,
          result.suspiciousCount,
          result.harmlessCount,
          result.verdict,
          JSON.stringify(result.rawResponse)
        ]
      );
      await this.persistIndicator("url", normalizedUrl, result);
    }
    return results;
  }

  async scanUrl(url: string): Promise<ScanVerdict[]> {
    const providers = await Promise.allSettled([
      this.scanVirusTotal(url),
      this.scanUrlscan(url),
      this.scanSafeBrowsing(url)
    ]);
    return providers.map((provider) => {
      if (provider.status === "fulfilled") return provider.value;
      return {
        provider: "web_risk" as const,
        maliciousCount: 0,
        suspiciousCount: 0,
        harmlessCount: 0,
        verdict: "unknown" as const,
        rawResponse: { error: provider.reason instanceof Error ? provider.reason.message : String(provider.reason) }
      };
    });
  }

  async lookup(input: { indicatorType: string; indicatorValue: string }) {
    if (input.indicatorType === "url") {
      const scans = await this.scanUrl(input.indicatorValue);
      for (const scan of scans) {
        await this.persistIndicator("url", input.indicatorValue, scan);
      }
      return { indicator: input, results: scans };
    }

    const result = await this.db.query(
      `SELECT * FROM threat_intel_results
       WHERE indicator_type = $1 AND indicator_value = $2
       ORDER BY checked_at DESC
       LIMIT 20`,
      [input.indicatorType, input.indicatorValue]
    );
    return { indicator: input, results: result.rows };
  }

  private async scanVirusTotal(url: string): Promise<ScanVerdict> {
    const apiKey = this.config.threatIntel.virusTotalApiKey;
    if (!apiKey) return this.notConfigured("virustotal");

    const id = Buffer.from(url).toString("base64url");
    const details = await fetchJson<any>(`https://www.virustotal.com/api/v3/urls/${id}`, {
      headers: { "x-apikey": apiKey }
    }).catch(async (error) => {
      if (!String(error.message).startsWith("404")) throw error;
      const body = new URLSearchParams({ url });
      await fetchJson<any>("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: { "x-apikey": apiKey, "content-type": "application/x-www-form-urlencoded" },
        body
      });
      return fetchJson<any>(`https://www.virustotal.com/api/v3/urls/${id}`, {
        headers: { "x-apikey": apiKey }
      });
    });

    const stats = details?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = Number(stats.malicious ?? 0);
    const suspicious = Number(stats.suspicious ?? 0);
    const harmless = Number(stats.harmless ?? 0);
    return {
      provider: "virustotal",
      scanId: details?.data?.id,
      maliciousCount: malicious,
      suspiciousCount: suspicious,
      harmlessCount: harmless,
      verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "safe",
      rawResponse: details
    };
  }

  private async scanUrlscan(url: string): Promise<ScanVerdict> {
    const apiKey = this.config.threatIntel.urlscanApiKey;
    if (!apiKey) return this.notConfigured("urlscan");

    const response = await fetchJson<any>("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": apiKey, "content-type": "application/json" },
      body: JSON.stringify({ url, visibility: "private", tags: ["email-soc-phishing-mvp"] })
    });

    return {
      provider: "urlscan",
      scanId: response.uuid,
      maliciousCount: 0,
      suspiciousCount: 0,
      harmlessCount: 0,
      verdict: "unknown",
      rawResponse: response
    };
  }

  private async scanSafeBrowsing(url: string): Promise<ScanVerdict> {
    const apiKey = this.config.threatIntel.safeBrowsingApiKey;
    if (!apiKey) return this.notConfigured("safe_browsing");

    const response = await fetchJson<any>(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          client: {
            clientId: "email-soc-phishing-mvp",
            clientVersion: "0.1.0"
          },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );

    const matches = Array.isArray(response.matches) ? response.matches : [];
    return {
      provider: "safe_browsing",
      scanId: matches[0]?.cacheDuration,
      maliciousCount: matches.length,
      suspiciousCount: 0,
      harmlessCount: matches.length ? 0 : 1,
      verdict: matches.length ? "malicious" : "safe",
      rawResponse: response
    };
  }

  private notConfigured(provider: ScanVerdict["provider"]): ScanVerdict {
    return {
      provider,
      maliciousCount: 0,
      suspiciousCount: 0,
      harmlessCount: 0,
      verdict: "not_configured",
      rawResponse: { status: "integration_not_configured" }
    };
  }

  private async persistIndicator(indicatorType: string, indicatorValue: string, result: ScanVerdict): Promise<void> {
    await this.db.query(
      `INSERT INTO threat_intel_results
        (indicator_type, indicator_value, provider, verdict, malicious_count, suspicious_count, raw_response)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
      [
        indicatorType,
        indicatorValue,
        result.provider,
        result.verdict,
        result.maliciousCount,
        result.suspiciousCount,
        JSON.stringify(result.rawResponse)
      ]
    );
  }
}
