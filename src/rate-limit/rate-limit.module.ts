import { Module } from '@nestjs/common';
import { LoginRateLimitService } from './login-rate-limit.service';
import { SensitiveActionRateLimitService } from './sensitive-action-rate-limit.service';

@Module({
  providers: [LoginRateLimitService, SensitiveActionRateLimitService],
  exports: [LoginRateLimitService, SensitiveActionRateLimitService],
})
export class RateLimitModule {}
