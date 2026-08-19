import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHmac } from 'node:crypto';
import { RedisService } from '../redis/redis.service';

@Injectable()
export class OAuthRateLimitService {
  private readonly pepper: string;

  constructor(
    private readonly redis: RedisService,
    configService: ConfigService,
  ) {
    this.pepper =
      configService.get<string>('RATE_LIMIT_PEPPER') ??
      configService.getOrThrow<string>('VERIFICATION_CODE_PEPPER');
  }

  async consume(
    operation: string,
    source: string,
    limit: number,
    windowSeconds: number,
  ): Promise<void> {
    const fingerprint = createHmac('sha256', this.pepper)
      .update(`${operation}:${source}`)
      .digest('hex');
    const result = await this.redis.client.eval(
      `
        local count = redis.call('INCR', KEYS[1])
        if count == 1 then
          redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return count
      `,
      {
        keys: [`rate-limit:oauth:${operation}:${fingerprint}`],
        arguments: [windowSeconds.toString()],
      },
    );

    if (typeof result !== 'number') {
      throw new Error('Redis returned an invalid OAuth rate-limit response');
    }
    if (result > limit) {
      throw new HttpException(
        'Too many OAuth requests. Please try again later.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }
}
