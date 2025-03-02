// Authentication Service - src/auth/auth.service.ts
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(private readonly configService: ConfigService) {}

  async register(userData: any) {
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    // Store user in database (mocked for now)
    return { message: 'User registered successfully', hashedPassword };
  }

  async login(userData: any) {
    const secret = this.configService.get('JWT_SECRET') || 'default_secret';
    const token = jwt.sign({ email: userData.email, role: 'user' }, secret, { expiresIn: '1h' });
    return { message: 'Login successful', token };
  }
}
