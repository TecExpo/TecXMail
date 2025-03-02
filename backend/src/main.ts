// Backend (NestJS)
// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import * as compression from 'compression';
import * as rateLimit from 'express-rate-limit';
import { Logger, ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as cookieParser from 'cookie-parser';
import * as session from 'express-session';
import * as passport from 'passport';
import * as csurf from 'csurf';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  
  app.use(helmet()); // Security headers
  app.use(compression()); // Performance boost
  app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  }));

  app.enableCors({
    origin: configService.get('CORS_ORIGIN') || '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    allowedHeaders: 'Content-Type, Accept',
    credentials: true,
  });
  
  app.useGlobalPipes(new ValidationPipe()); // Data validation
  app.use(cookieParser()); // Enable secure cookie handling
  
  app.use(session({
    secret: configService.get('SESSION_SECRET') || 'default_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production' },
  }));
  
  app.use(passport.initialize());
  app.use(passport.session());
  
  app.use(csurf()); // CSRF protection

  const port = configService.get('PORT') || 3000;
  await app.listen(port);
  Logger.log(`🚀 Server running on http://localhost:${port}`);
}
bootstrap();

// Authentication Controller - src/auth/auth.controller.ts
import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() body) {
    return this.authService.register(body);
  }

  @Post('login')
  async login(@Body() body) {
    return this.authService.login(body);
  }
}
