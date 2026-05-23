import crypto from "node:crypto";
import { loadEnvFile } from "./load-env";

export type AppConfig = {
  port: number;
  appUrl: string;
  databaseUrl: string;
  redisUrl?: string;
  jwtSecret: string;
  encryptionKey: Buffer;
  fullMessageStorageEnabled: boolean;
  extensionAllowedOrigins: string[];
  google: {
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
    projectId?: string;
    pubsubTopic?: string;
    pubsubSubscription?: string;
  };
  microsoft: {
    clientId?: string;
    clientSecret?: string;
    tenantId?: string;
    webhookSecret?: string;
  };
  threatIntel: {
    virusTotalApiKey?: string;
    urlscanApiKey?: string;
    safeBrowsingApiKey?: string;
    webRiskApiKey?: string;
  };
};

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function encryptionKeyFromEnv(): Buffer {
  const raw = requireEnv("ENCRYPTION_KEY");
  const base64 = Buffer.from(raw, "base64");
  if (base64.length === 32) {
    return base64;
  }
  const utf8 = Buffer.from(raw, "utf8");
  if (utf8.length === 32) {
    return utf8;
  }
  return crypto.createHash("sha256").update(raw).digest();
}

export function loadConfig(): AppConfig {
  loadEnvFile();
  return {
    port: Number(process.env.PORT ?? 4000),
    appUrl: process.env.APP_URL ?? "http://localhost:5173",
    databaseUrl: requireEnv("DATABASE_URL"),
    redisUrl: process.env.REDIS_URL,
    jwtSecret: requireEnv("JWT_SECRET"),
    encryptionKey: encryptionKeyFromEnv(),
    fullMessageStorageEnabled: process.env.FULL_MESSAGE_STORAGE_ENABLED === "true",
    extensionAllowedOrigins: (process.env.EXTENSION_ALLOWED_ORIGINS ?? "")
      .split(",")
      .map((origin) => origin.trim())
      .filter(Boolean),
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI,
      projectId: process.env.GOOGLE_PROJECT_ID,
      pubsubTopic: process.env.GOOGLE_PUBSUB_TOPIC,
      pubsubSubscription: process.env.GOOGLE_PUBSUB_SUBSCRIPTION
    },
    microsoft: {
      clientId: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
      tenantId: process.env.MICROSOFT_TENANT_ID,
      webhookSecret: process.env.MICROSOFT_WEBHOOK_SECRET
    },
    threatIntel: {
      virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
      urlscanApiKey: process.env.URLSCAN_API_KEY,
      safeBrowsingApiKey: process.env.GOOGLE_SAFE_BROWSING_API_KEY,
      webRiskApiKey: process.env.GOOGLE_WEB_RISK_API_KEY
    }
  };
}

export const CONFIG = Symbol("CONFIG");
