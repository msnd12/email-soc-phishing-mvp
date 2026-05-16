import { Module } from "@nestjs/common";
import { ThreatController } from "./threat.controller";
import { ThreatIntelService } from "./threat-intel.service";
import { UrlExtractorService } from "./url-extractor.service";
import { RiskScoringService } from "./risk-scoring.service";

@Module({
  controllers: [ThreatController],
  providers: [ThreatIntelService, UrlExtractorService, RiskScoringService],
  exports: [ThreatIntelService, UrlExtractorService, RiskScoringService]
})
export class ThreatModule {}
