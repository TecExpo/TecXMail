# Entry point
// Backend (NestJS)
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import * as compression from 'compression';
import * as rateLimit from 'express-rate-limit';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.use(helmet()); // Security headers
  app.use(compression()); // Performance boost
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  }));

  await app.listen(3000);
}
bootstrap();
