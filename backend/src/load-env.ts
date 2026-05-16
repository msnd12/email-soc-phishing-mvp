import fs from "node:fs";
import path from "node:path";

export function loadEnvFile(): void {
  const candidates = [
    process.env.ENV_FILE,
    path.resolve(process.cwd(), ".env"),
    path.resolve(process.cwd(), "..", ".env")
  ].filter(Boolean) as string[];

  const envPath = candidates.find((candidate) => fs.existsSync(candidate));
  if (!envPath) return;

  const content = fs.readFileSync(envPath, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const equals = line.indexOf("=");
    if (equals <= 0) continue;
    const key = line.slice(0, equals).trim();
    const value = stripQuotes(line.slice(equals + 1).trim());
    if (!(key in process.env)) {
      process.env[key] = value;
    }
  }
}

function stripQuotes(value: string): string {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1);
  }
  return value;
}
