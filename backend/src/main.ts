import "reflect-metadata";
import { ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import helmet from "helmet";
import { AppModule } from "./app.module";
import { loadConfig } from "./config";

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: false });
  const config = loadConfig();
  const allowedOrigins = new Set([config.appUrl, "http://localhost:5173", ...config.extensionAllowedOrigins]);

  app.getHttpAdapter().getInstance().disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false
    })
  );
  app.enableCors({
    origin(origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) {
      if (!origin || allowedOrigins.has(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error(`CORS origin not allowed: ${origin}`), false);
    },
    credentials: true,
    allowedHeaders: ["Authorization", "Content-Type", "x-ms-client-state", "x-goog-channel-token"],
    methods: ["GET", "POST", "PATCH", "OPTIONS"]
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true
    })
  );
  await app.listen(config.port);
  console.log(`Email SOC phishing MVP API listening on http://localhost:${config.port}`);
}

void bootstrap();
