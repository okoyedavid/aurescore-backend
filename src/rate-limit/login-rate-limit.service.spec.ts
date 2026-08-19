import { HttpException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';
import { LoginRateLimitService } from './login-rate-limit.service';

describe('LoginRateLimitService', () => {
  const redisClient = {
    eval: jest.fn(),
    del: jest.fn(),
  };
  const redis = { client: redisClient } as unknown as RedisService;
  const config = {
    get: jest.fn().mockReturnValue(undefined),
    getOrThrow: jest.fn().mockReturnValue('rate-limit-test-pepper'),
  } as unknown as ConfigService;
  let service: LoginRateLimitService;

  beforeEach(() => {
    jest.clearAllMocks();
    config.get = jest.fn().mockReturnValue(undefined);
    service = new LoginRateLimitService(redis, config);
  });

  it('atomically consumes separate opaque IP and account buckets', async () => {
    redisClient.eval.mockResolvedValue([1, 1]);

    await service.consumeLoginAttempt('user@example.com', '8.8.8.8');

    const calls = redisClient.eval.mock.calls as unknown as Array<
      [unknown, { keys: string[]; arguments: string[] }]
    >;
    const options = calls[0][1];
    expect(options.keys).toHaveLength(2);
    expect(options.keys[0]).toMatch(/^rate-limit:login:ip:[a-f0-9]{64}$/);
    expect(options.keys[1]).toMatch(/^rate-limit:login:account:[a-f0-9]{64}$/);
    expect(options.keys.join(' ')).not.toContain('user@example.com');
    expect(options.keys.join(' ')).not.toContain('8.8.8.8');
    expect(options.arguments).toEqual(['900']);
  });

  it('returns a generic 429 when either bucket exceeds its limit', async () => {
    redisClient.eval.mockResolvedValue([1, 9]);

    try {
      await service.consumeLoginAttempt('user@example.com', '8.8.8.8');
      throw new Error('Expected the rate limit to reject the request');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(429);
    }
  });
});
