import { ConfigService } from '@nestjs/config';
import { VerificationCodeService } from './verification-code.service';
import { RedisService } from '../redis/redis.service';

describe('VerificationCodeService', () => {
  const transaction = {
    set: jest.fn().mockReturnThis(),
    del: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([]),
  };
  const redisClient = {
    eval: jest.fn(),
    set: jest.fn(),
    multi: jest.fn(() => transaction),
    del: jest.fn(),
  };
  const redis = { client: redisClient } as unknown as RedisService;
  const config = {
    getOrThrow: jest.fn(() => 'test-verification-pepper'),
  } as unknown as ConfigService;

  let service: VerificationCodeService;

  beforeEach(() => {
    jest.clearAllMocks();
    transaction.set.mockReturnThis();
    transaction.del.mockReturnThis();
    transaction.exec.mockResolvedValue([]);
    service = new VerificationCodeService(redis, config);
  });

  it('issues a six-digit code with TTL and cooldown protection', async () => {
    redisClient.eval.mockResolvedValueOnce(1);
    redisClient.set.mockResolvedValueOnce('OK');

    const issued = await service.issueEmailCode(
      'user@example.com',
      '127.0.0.1',
    );

    expect(issued.code).toMatch(/^\d{6}$/);
    expect(redisClient.set).toHaveBeenCalledWith(
      expect.stringContaining('verification:email:cooldown:'),
      '1',
      { EX: 60, NX: true },
    );
    expect(transaction.set).toHaveBeenCalledWith(
      expect.stringContaining('verification:email:code:'),
      expect.any(String),
      { EX: 300 },
    );
  });

  it('maps an atomic successful consume to verified', async () => {
    redisClient.eval.mockResolvedValueOnce(1);

    await expect(
      service.consumeEmailCode('user@example.com', '123456'),
    ).resolves.toBe('verified');
  });

  it('maps an exhausted-attempt response safely', async () => {
    redisClient.eval.mockResolvedValueOnce(-2);

    await expect(
      service.consumeEmailCode('user@example.com', '123456'),
    ).resolves.toBe('attempts-exhausted');
  });
});
