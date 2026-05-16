CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'analyst',
  display_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS provider_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  access_token_encrypted TEXT NOT NULL,
  refresh_token_encrypted TEXT,
  scope TEXT,
  expiry_date TIMESTAMPTZ,
  last_history_id TEXT,
  watch_expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, mailbox)
);

CREATE TABLE IF NOT EXISTS email_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  provider_message_id TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  sender TEXT NOT NULL,
  sender_domain TEXT,
  recipient TEXT NOT NULL,
  reply_to TEXT,
  return_path TEXT,
  subject TEXT,
  received_at TIMESTAMPTZ,
  body_preview TEXT,
  body_text TEXT,
  sanitized_html TEXT,
  authentication_results JSONB NOT NULL DEFAULT '{}'::JSONB,
  source_ips TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  risk_score INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'safe',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_message_id, mailbox)
);

CREATE TABLE IF NOT EXISTS email_headers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_message_id UUID NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_urls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_message_id UUID NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
  original_url TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  display_text TEXT,
  domain TEXT,
  is_shortened BOOLEAN NOT NULL DEFAULT FALSE,
  is_punycode BOOLEAN NOT NULL DEFAULT FALSE,
  is_ip_url BOOLEAN NOT NULL DEFAULT FALSE,
  is_suspicious_tld BOOLEAN NOT NULL DEFAULT FALSE,
  is_lookalike BOOLEAN NOT NULL DEFAULT FALSE,
  has_mismatched_anchor BOOLEAN NOT NULL DEFAULT FALSE,
  redirect_chain JSONB NOT NULL DEFAULT '[]'::JSONB,
  risk_score INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'safe',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS url_scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_url_id UUID NOT NULL REFERENCES email_urls(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  scan_id TEXT,
  malicious_count INTEGER NOT NULL DEFAULT 0,
  suspicious_count INTEGER NOT NULL DEFAULT 0,
  harmless_count INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'unknown',
  raw_response JSONB NOT NULL DEFAULT '{}'::JSONB,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_attachments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_message_id UUID NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  content_type TEXT,
  size_bytes INTEGER,
  sha256 TEXT,
  risk_score INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_intel_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  indicator_type TEXT NOT NULL,
  indicator_value TEXT NOT NULL,
  provider TEXT NOT NULL,
  verdict TEXT NOT NULL DEFAULT 'unknown',
  malicious_count INTEGER NOT NULL DEFAULT 0,
  suspicious_count INTEGER NOT NULL DEFAULT 0,
  raw_response JSONB NOT NULL DEFAULT '{}'::JSONB,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_message_id UUID NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
  subject TEXT,
  sender TEXT NOT NULL,
  recipient TEXT NOT NULL,
  severity TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  verdict TEXT NOT NULL,
  detection_reason TEXT NOT NULL,
  reasons JSONB NOT NULL DEFAULT '[]'::JSONB,
  recommended_action TEXT NOT NULL,
  assigned_analyst UUID REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(email_message_id)
);

CREATE TABLE IF NOT EXISTS email_incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  severity TEXT NOT NULL,
  campaign_key TEXT NOT NULL,
  summary TEXT NOT NULL,
  alert_ids UUID[] NOT NULL DEFAULT ARRAY[]::UUID[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_email_incidents_campaign_key ON email_incidents(campaign_key);

CREATE TABLE IF NOT EXISTS playbook_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id UUID REFERENCES email_alerts(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  result JSONB NOT NULL DEFAULT '{}'::JSONB,
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id UUID NOT NULL REFERENCES email_alerts(id) ON DELETE CASCADE,
  report_json JSONB NOT NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_email_messages_received_at ON email_messages(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_messages_verdict ON email_messages(verdict);
CREATE INDEX IF NOT EXISTS idx_email_urls_domain ON email_urls(domain);
CREATE UNIQUE INDEX IF NOT EXISTS idx_email_urls_message_url_display
  ON email_urls(email_message_id, normalized_url, COALESCE(display_text, ''));
CREATE INDEX IF NOT EXISTS idx_url_scan_results_provider ON url_scan_results(provider);
CREATE INDEX IF NOT EXISTS idx_email_alerts_status ON email_alerts(status);
CREATE INDEX IF NOT EXISTS idx_email_alerts_created_at ON email_alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
