import { Module } from '@nestjs/common';
import { OAuthRateLimitService } from './oauth-rate-limit.service';

@Module({
  providers: [OAuthRateLimitService],
  exports: [OAuthRateLimitService],
})
export class OAuthCommonModule {}
