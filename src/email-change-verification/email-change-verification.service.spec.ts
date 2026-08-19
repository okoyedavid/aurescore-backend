import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';
import { EmailChangeVerificationService } from './email-change-verification.service';

describe('EmailChangeVerificationService', () => {
  const transaction = {
    set: jest.fn().mockReturnThis(),
    del: jest.fn().mockReturnThis(),
    exec: jest.fn().mockResolvedValue([]),
  };
  const client = {
    set: jest.fn(),
    multi: jest.fn(() => transaction),
    eval: jest.fn(),
    del: jest.fn(),
  };
  const service = new EmailChangeVerificationService(
    { client } as unknown as RedisService,
    {
      getOrThrow: jest.fn(() => 'test-pepper'),
    } as unknown as ConfigService,
  );

  beforeEach(() => {
    jest.clearAllMocks();
    transaction.set.mockReturnThis();
    transaction.del.mockReturnThis();
  });

  it('binds a six-digit code to an opaque user/email challenge', async () => {
    client.set.mockResolvedValue('OK');

    const issued = await service.issue('user-id', 'new@example.com');

    expect(issued.code).toMatch(/^\d{6}$/);
    expect(issued.challengeId).toMatch(/^[0-9a-f-]{36}$/);
    const calls = transaction.set.mock.calls as unknown as Array<
      [string, string, { EX: number }]
    >;
    expect(calls[0][0]).toContain('email-change:challenge:');
    const payload: unknown = JSON.parse(calls[0][1]);
    expect(payload).toEqual({
      userId: 'user-id',
      newEmail: 'new@example.com',
    });
    expect(calls[0][2]).toEqual({ EX: 600 });
  });

  it('atomically consumes the challenge into its bound identity', async () => {
    client.eval.mockResolvedValue(
      JSON.stringify({ userId: 'user-id', newEmail: 'new@example.com' }),
    );

    await expect(
      service.consume('5b62ad10-ec14-4afd-b240-c43fb56f3c98', '123456'),
    ).resolves.toEqual({
      status: 'verified',
      userId: 'user-id',
      newEmail: 'new@example.com',
    });
  });
});
