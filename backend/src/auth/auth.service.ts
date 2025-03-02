// Authentication Service - src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import * as nodemailer from 'nodemailer';
import * as speakeasy from 'speakeasy';
import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'logs/auth.log' }),
  ],
});

@Injectable()
export class AuthService {
  private users = [];
  private otps = new Map();
  private mfaSecrets = new Map();

  constructor(private readonly configService: ConfigService) {}

  async register(userData: any) {
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    this.users.push({ email: userData.email, password: hashedPassword, role: 'user', verified: false });
    logger.info(`User registered: ${userData.email}`);
    this.sendVerificationEmail(userData.email);
    return { message: 'User registered successfully. Please verify your email.' };
  }

  async sendVerificationEmail(email: string) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    this.otps.set(email, otp);
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: this.configService.get('EMAIL_USER'),
        pass: this.configService.get('EMAIL_PASS'),
      },
    });
    await transporter.sendMail({
      from: 'noreply@example.com',
      to: email,
      subject: 'Verify Your Email',
      text: `Your OTP for email verification is: ${otp}`,
    });
    logger.info(`Verification email sent to: ${email}`);
  }

  async verifyEmail(email: string, otp: string) {
    if (this.otps.get(email) === otp) {
      this.users.find(u => u.email === email).verified = true;
      this.otps.delete(email);
      logger.info(`Email verified: ${email}`);
      return { message: 'Email verified successfully' };
    }
    logger.error(`Failed email verification attempt for: ${email}`);
    throw new Error('Invalid OTP');
  }

  async login(userData: any) {
    const user = this.users.find(u => u.email === userData.email);
    if (!user || !(await bcrypt.compare(userData.password, user.password))) {
      logger.error(`Failed login attempt for: ${userData.email}`);
      throw new Error('Invalid credentials');
    }
    if (!user.verified) {
      logger.error(`Unverified email login attempt: ${userData.email}`);
      throw new Error('Email not verified');
    }
    const secret = this.configService.get('JWT_SECRET') || 'default_secret';
    const token = jwt.sign({ email: user.email, role: user.role }, secret, { expiresIn: '1h' });
    logger.info(`Successful login: ${userData.email}`);
    return { message: 'Login successful', token };
  }

  async enableMFA(email: string) {
    const secret = speakeasy.generateSecret({ length: 20 });
    this.mfaSecrets.set(email, secret.base32);
    logger.info(`MFA enabled for: ${email}`);
    return { message: 'MFA enabled', secret: secret.otpauth_url };
  }

  async verifyMFA(email: string, token: string) {
    const secret = this.mfaSecrets.get(email);
    if (!secret) {
      logger.error(`MFA verification attempt failed for: ${email}`);
      throw new Error('MFA not enabled');
    }
    const verified = speakeasy.totp.verify({ secret, encoding: 'base32', token });
    if (!verified) {
      logger.error(`Invalid MFA token for: ${email}`);
      throw new Error('Invalid MFA token');
    }
    logger.info(`MFA verified successfully for: ${email}`);
    return { message: 'MFA verified successfully' };
  }
}
