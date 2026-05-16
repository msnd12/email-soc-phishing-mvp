import fs from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { loadEnvFile } from "../load-env";

async function main() {
  loadEnvFile();
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required");
  }
  const sqlPath = path.resolve(process.cwd(), "db", "schema.sql");
  const sql = await fs.readFile(sqlPath, "utf8");
  const pool = new Pool({ connectionString: databaseUrl });
  try {
    await pool.query(sql);
    console.log("Database schema is up to date.");
  } finally {
    await pool.end();
  }
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
