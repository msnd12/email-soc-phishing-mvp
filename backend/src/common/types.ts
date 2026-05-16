export type Verdict = "safe" | "suspicious" | "phishing" | "malicious" | "unknown";
export type Severity = "Informational" | "Low" | "Medium" | "High" | "Critical";

export type AuthResults = {
  spf?: string;
  dkim?: string;
  dmarc?: string;
  raw?: string[];
};

export type NormalizedEmail = {
  provider: "gmail" | "microsoft";
  providerMessageId: string;
  mailbox: string;
  sender: string;
  senderDomain?: string;
  recipient: string;
  replyTo?: string;
  returnPath?: string;
  subject?: string;
  receivedAt?: string;
  bodyPreview?: string;
  bodyText?: string;
  htmlBody?: string;
  sanitizedHtml?: string;
  authenticationResults: AuthResults;
  sourceIps: string[];
  headers: Array<{ name: string; value: string }>;
  attachments: Array<{ filename: string; contentType?: string; sizeBytes?: number; sha256?: string }>;
};

export type ExtractedUrl = {
  originalUrl: string;
  normalizedUrl: string;
  displayText?: string;
  domain?: string;
  isShortened: boolean;
  isPunycode: boolean;
  isIpUrl: boolean;
  isSuspiciousTld: boolean;
  isLookalike: boolean;
  hasMismatchedAnchor: boolean;
  redirectChain: string[];
  reasons: string[];
};
