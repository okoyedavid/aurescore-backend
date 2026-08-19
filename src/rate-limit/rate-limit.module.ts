import { Module } from '@nestjs/common';
import { LoginRateLimitService } from './login-rate-limit.service';

@Module({
  providers: [LoginRateLimitService],
  exports: [LoginRateLimitService],
})
export class RateLimitModule {}
