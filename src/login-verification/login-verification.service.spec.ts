import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';
import { LoginVerificationService } from './login-verification.service';

describe('LoginVerificationService', () => {
  const transaction = {
    set: jest.fn().mockReturnThis(),
    del: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([]),
  };
  const redisClient = {
    eval: jest.fn(),
    set: jest.fn(),
    get: jest.fn(),
    multi: jest.fn(() => transaction),
    del: jest.fn(),
  };
  const redis = { client: redisClient } as unknown as RedisService;
  const config = {
    getOrThrow: jest.fn(() => 'test-login-verification-pepper'),
  } as unknown as ConfigService;

  let service: LoginVerificationService;

  beforeEach(() => {
    jest.clearAllMocks();
    transaction.set.mockReturnThis();
    transaction.del.mockReturnThis();
    transaction.exec.mockResolvedValue([]);
    service = new LoginVerificationService(redis, config);
  });

  it('issues an opaque challenge and a six-digit code with bounded TTLs', async () => {
    redisClient.eval.mockResolvedValueOnce([1, 1, 1]);
    redisClient.set.mockResolvedValueOnce('OK').mockResolvedValueOnce('OK');

    const issued = await service.issueChallenge('user-id', '127.0.0.1');

    expect(issued.challengeId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(issued.code).toMatch(/^\d{6}$/);
    expect(redisClient.set).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining('login-verification:challenge:'),
      JSON.stringify({
        userId: 'user-id',
        authenticationMethod: 'password',
      }),
      { EX: 600 },
    );
    expect(transaction.set).toHaveBeenCalledWith(
      expect.stringContaining('login-verification:code:'),
      expect.any(String),
      { EX: 300 },
    );
  });

  it('atomically consumes a valid challenge into its bound user ID', async () => {
    redisClient.eval.mockResolvedValueOnce(
      JSON.stringify({
        userId: 'user-id',
        authenticationMethod: 'password',
      }),
    );

    await expect(
      service.consumeChallenge(
        '5b62ad10-ec14-4afd-b240-c43fb56f3c98',
        '123456',
      ),
    ).resolves.toEqual({
      status: 'verified',
      userId: 'user-id',
      authenticationMethod: 'password',
    });

    const calls = redisClient.eval.mock.calls as unknown as Array<
      [string, { keys: string[] }]
    >;
    expect(calls[0][0]).toContain("redis.call('DEL'");
    expect(calls[0][1].keys[0]).toContain('login-verification:challenge:');
  });

  it('does not issue mail data for an unknown resend challenge', async () => {
    redisClient.get.mockResolvedValueOnce(null);

    await expect(
      service.resendChallenge(
        '5b62ad10-ec14-4afd-b240-c43fb56f3c98',
        '127.0.0.1',
      ),
    ).resolves.toBeNull();
    expect(redisClient.eval).not.toHaveBeenCalled();
  });
});
