import { Module } from "@nestjs/common";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { APP_GUARD } from "@nestjs/core";
import { CommonModule } from "./common/common.module";
import { AuthModule } from "./auth/auth.module";
import { DbModule } from "./db/db.module";
import { EmailModule } from "./email/email.module";
import { ThreatModule } from "./threat/threat.module";
import { AlertsModule } from "./alerts/alerts.module";
import { AuditModule } from "./audit/audit.module";
import { PlaybooksModule } from "./playbooks/playbooks.module";
import { IncidentsModule } from "./incidents/incidents.module";
import { ReportsModule } from "./reports/reports.module";

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        ttl: 60_000,
        limit: 120
      }
    ]),
    CommonModule,
    DbModule,
    AuditModule,
    AuthModule,
    ThreatModule,
    AlertsModule,
    EmailModule,
    PlaybooksModule,
    IncidentsModule,
    ReportsModule
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    }
  ]
})
export class AppModule {}
