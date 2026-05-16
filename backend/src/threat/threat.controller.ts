import { Body, Controller, Get, Param, Post, UseGuards } from "@nestjs/common";
import { IsIn, IsString } from "class-validator";
import { AuthGuard } from "../auth/auth.guard";
import { DbService } from "../db/db.service";
import { ThreatIntelService } from "./threat-intel.service";

class ScanUrlDto {
  @IsString()
  url!: string;
}

class LookupDto {
  @IsIn(["url", "domain", "ip", "file_hash", "sender_email"])
  indicatorType!: string;

  @IsString()
  indicatorValue!: string;
}

@Controller("/api/threat")
@UseGuards(AuthGuard)
export class ThreatController {
  constructor(
    private readonly threatIntel: ThreatIntelService,
    private readonly db: DbService
  ) {}

  @Post("/scan-url")
  scanUrl(@Body() body: ScanUrlDto) {
    return this.threatIntel.scanUrl(body.url);
  }

  @Get("/url/:id")
  async getUrl(@Param("id") id: string) {
    const url = await this.db.query("SELECT * FROM email_urls WHERE id = $1", [id]);
    const scans = await this.db.query("SELECT * FROM url_scan_results WHERE email_url_id = $1 ORDER BY scanned_at DESC", [id]);
    return { url: url.rows[0], scans: scans.rows };
  }

  @Post("/lookup")
  lookup(@Body() body: LookupDto) {
    return this.threatIntel.lookup(body);
  }
}
