import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { DbService } from "../db/db.service";
import { AppConfig, CONFIG } from "../config";

export type AuthUser = {
  id: string;
  email: string;
  role: string;
  displayName?: string;
};

@Injectable()
export class AuthService {
  constructor(
    private readonly db: DbService,
    @Inject(CONFIG) private readonly config: AppConfig
  ) {}

  async login(email: string, password: string): Promise<{ token: string; user: AuthUser }> {
    const result = await this.db.query<{
      id: string;
      email: string;
      password_hash: string;
      role: string;
      display_name: string | null;
    }>("SELECT id, email, password_hash, role, display_name FROM users WHERE email = $1", [email.toLowerCase()]);

    const row = result.rows[0];
    if (!row || !(await bcrypt.compare(password, row.password_hash))) {
      throw new UnauthorizedException("Invalid email or password");
    }

    const user = {
      id: row.id,
      email: row.email,
      role: row.role,
      displayName: row.display_name ?? undefined
    };
    const token = jwt.sign({ sub: user.id, email: user.email, role: user.role }, this.config.jwtSecret, {
      expiresIn: "8h"
    });
    return { token, user };
  }

  async verifyToken(token: string): Promise<AuthUser> {
    try {
      const payload = jwt.verify(token, this.config.jwtSecret) as { sub: string };
      const result = await this.db.query<{ id: string; email: string; role: string; display_name: string | null }>(
        "SELECT id, email, role, display_name FROM users WHERE id = $1",
        [payload.sub]
      );
      const row = result.rows[0];
      if (!row) {
        throw new UnauthorizedException("User no longer exists");
      }
      return {
        id: row.id,
        email: row.email,
        role: row.role,
        displayName: row.display_name ?? undefined
      };
    } catch {
      throw new UnauthorizedException("Invalid token");
    }
  }
}
