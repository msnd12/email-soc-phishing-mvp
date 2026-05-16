import { Body, Controller, Post, Req, UseGuards } from "@nestjs/common";
import { IsOptional, IsString } from "class-validator";
import { AuthGuard } from "../auth/auth.guard";
import { PlaybooksService } from "./playbooks.service";

class PlaybookDto {
  @IsOptional()
  @IsString()
  alertId?: string;

  @IsOptional()
  @IsString()
  emailMessageId?: string;

  @IsOptional()
  @IsString()
  sender?: string;

  @IsOptional()
  @IsString()
  domain?: string;

  @IsOptional()
  @IsString()
  recipient?: string;
}

@Controller("/api/playbooks")
@UseGuards(AuthGuard)
export class PlaybooksController {
  constructor(private readonly playbooks: PlaybooksService) {}

  @Post("/quarantine-email")
  quarantine(@Body() body: PlaybookDto, @Req() req: any) {
    return this.playbooks.run("quarantine_email", { ...body }, req.user, { ip: req.ip, userAgent: req.headers["user-agent"] });
  }

  @Post("/block-sender")
  blockSender(@Body() body: PlaybookDto, @Req() req: any) {
    return this.playbooks.run("block_sender", { ...body }, req.user, { ip: req.ip, userAgent: req.headers["user-agent"] });
  }

  @Post("/block-domain")
  blockDomain(@Body() body: PlaybookDto, @Req() req: any) {
    return this.playbooks.run("block_domain", { ...body }, req.user, { ip: req.ip, userAgent: req.headers["user-agent"] });
  }

  @Post("/notify-user")
  notifyUser(@Body() body: PlaybookDto, @Req() req: any) {
    return this.playbooks.run("notify_user", { ...body }, req.user, { ip: req.ip, userAgent: req.headers["user-agent"] });
  }
}
