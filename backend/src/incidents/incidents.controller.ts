import { Controller, Get, UseGuards } from "@nestjs/common";
import { AuthGuard } from "../auth/auth.guard";
import { DbService } from "../db/db.service";

@Controller("/api/email-incidents")
@UseGuards(AuthGuard)
export class IncidentsController {
  constructor(private readonly db: DbService) {}

  @Get()
  async list() {
    const result = await this.db.query("SELECT * FROM email_incidents ORDER BY updated_at DESC LIMIT 100");
    return result.rows;
  }
}
