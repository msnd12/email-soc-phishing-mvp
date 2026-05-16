import { Body, Controller, Get, Param, Patch, Post, Req, UseGuards } from "@nestjs/common";
import { IsOptional, IsString, IsUUID } from "class-validator";
import { AuthGuard } from "../auth/auth.guard";
import { AlertsService } from "./alerts.service";

class UpdateStatusDto {
  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  verdict?: string;
}

class AssignDto {
  @IsUUID()
  analystId!: string;
}

@Controller("/api/email-alerts")
@UseGuards(AuthGuard)
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Get()
  list() {
    return this.alerts.list();
  }

  @Get("/overview")
  overview() {
    return this.alerts.overview();
  }

  @Get("/:id")
  detail(@Param("id") id: string) {
    return this.alerts.detail(id);
  }

  @Patch("/:id/status")
  updateStatus(@Param("id") id: string, @Body() body: UpdateStatusDto, @Req() req: any) {
    return this.alerts.updateStatus(id, body, req.user, {
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
  }

  @Post("/:id/assign")
  assign(@Param("id") id: string, @Body() body: AssignDto, @Req() req: any) {
    return this.alerts.assign(id, body.analystId, req.user, {
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
  }

  @Post("/:id/create-incident")
  createIncident(@Param("id") id: string, @Req() req: any) {
    return this.alerts.createIncident(id, req.user, {
      ip: req.ip,
      userAgent: req.headers["user-agent"]
    });
  }
}
