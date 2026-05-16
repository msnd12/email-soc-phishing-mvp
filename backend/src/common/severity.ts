import { Severity } from "./types";

export function severityFromRiskScore(score: number): Severity {
  if (score >= 90) return "Critical";
  if (score >= 70) return "High";
  if (score >= 50) return "Medium";
  if (score >= 30) return "Low";
  return "Informational";
}

export function verdictFromRiskScore(score: number): "safe" | "suspicious" | "phishing" | "malicious" {
  if (score >= 90) return "malicious";
  if (score >= 70) return "phishing";
  if (score >= 30) return "suspicious";
  return "safe";
}
