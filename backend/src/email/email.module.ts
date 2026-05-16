import { Module } from "@nestjs/common";
import { AlertsModule } from "../alerts/alerts.module";
import { ThreatModule } from "../threat/threat.module";
import { EmailController } from "./email.controller";
import { EmailProcessorService } from "./email-processor.service";
import { GmailConnectorService } from "./gmail-connector.service";

@Module({
  imports: [ThreatModule, AlertsModule],
  controllers: [EmailController],
  providers: [GmailConnectorService, EmailProcessorService],
  exports: [EmailProcessorService, GmailConnectorService]
})
export class EmailModule {}
