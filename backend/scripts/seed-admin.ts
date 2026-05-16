import bcrypt from "bcryptjs";
import { Pool } from "pg";
import { loadEnvFile } from "../src/load-env";

async function main() {
  loadEnvFile();
  const databaseUrl = process.env.DATABASE_URL;
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!databaseUrl || !email || !password) {
    throw new Error("DATABASE_URL, ADMIN_EMAIL and ADMIN_PASSWORD are required");
  }
  if (password.length < 12) {
    throw new Error("ADMIN_PASSWORD must be at least 12 characters");
  }
  const pool = new Pool({ connectionString: databaseUrl });
  try {
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      `INSERT INTO users (email, password_hash, role, display_name)
       VALUES ($1, $2, 'admin', 'SOC Admin')
       ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = 'admin'`,
      [email.toLowerCase(), hash]
    );
    console.log(`Admin user ready: ${email}`);
  } finally {
    await pool.end();
  }
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
