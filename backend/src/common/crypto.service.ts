import crypto from "node:crypto";
import { Inject, Injectable } from "@nestjs/common";
import { AppConfig, CONFIG } from "../config";

@Injectable()
export class CryptoService {
  constructor(@Inject(CONFIG) private readonly config: AppConfig) {}

  encrypt(value: string | null | undefined): string | null {
    if (!value) {
      return null;
    }
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.config.encryptionKey, iv);
    const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]).toString("base64");
  }

  decrypt(value: string | null | undefined): string | null {
    if (!value) {
      return null;
    }
    const packed = Buffer.from(value, "base64");
    const iv = packed.subarray(0, 12);
    const tag = packed.subarray(12, 28);
    const encrypted = packed.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", this.config.encryptionKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  }
}
