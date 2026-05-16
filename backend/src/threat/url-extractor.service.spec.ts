import { describe, expect, it } from "vitest";
import { UrlExtractorService } from "./url-extractor.service";

describe("UrlExtractorService", () => {
  it("extracts URLs and flags mismatched anchors, shorteners, and suspicious TLDs", () => {
    const service = new UrlExtractorService();
    const urls = service.extract(
      "Verify immediately: https://bit.ly/reset-now",
      '<a href="https://login-microsoft-support.click/verify">https://microsoft.com</a>'
    );

    expect(urls.length).toBeGreaterThanOrEqual(2);
    expect(urls.some((url) => url.isShortened)).toBe(true);
    expect(urls.some((url) => url.hasMismatchedAnchor)).toBe(true);
    expect(urls.some((url) => url.isSuspiciousTld)).toBe(true);
  });

  it("does not flag legitimate Microsoft subdomains as lookalikes", () => {
    const service = new UrlExtractorService();
    const urls = service.extract("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");

    expect(urls[0].isLookalike).toBe(false);
  });

  it("does not flag trusted Google and Dropbox asset domains as lookalikes", () => {
    const service = new UrlExtractorService();
    const urls = service.extract("https://fonts.googleapis.com/css2?family=Inter https://cfl.dropboxstatic.com/static/logo.png");

    expect(urls).toHaveLength(2);
    expect(urls.every((url) => !url.isLookalike)).toBe(true);
  });
});
