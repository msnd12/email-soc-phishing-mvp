import { Global, Module } from "@nestjs/common";
import { CONFIG, loadConfig } from "../config";
import { CryptoService } from "./crypto.service";

@Global()
@Module({
  providers: [
    {
      provide: CONFIG,
      useFactory: loadConfig
    },
    CryptoService
  ],
  exports: [CONFIG, CryptoService]
})
export class CommonModule {}
