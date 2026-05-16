import "reflect-metadata";
import { ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import helmet from "helmet";
import { AppModule } from "./app.module";
import { loadConfig } from "./config";

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: false });
  const config = loadConfig();

  app.getHttpAdapter().getInstance().disable("x-powered-by");
  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false
    })
  );
  app.enableCors({
    origin: [config.appUrl, "http://localhost:5173"],
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
