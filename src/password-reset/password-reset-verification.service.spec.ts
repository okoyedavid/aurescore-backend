import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';
import { PasswordResetVerificationService } from './password-reset-verification.service';

describe('PasswordResetVerificationService', () => {
  const multi = {
    set: jest.fn(),
    del: jest.fn(),
    exec: jest.fn(),
  };
  const client = {
    eval: jest.fn(),
    get: jest.fn(),
    multi: jest.fn(() => multi),
  };
  const redis = { client } as unknown as RedisService;
  const config = {
    getOrThrow: jest.fn(() => 'password-reset-test-pepper'),
  } as unknown as ConfigService;
  const service = new PasswordResetVerificationService(redis, config);

  beforeEach(() => {
    jest.clearAllMocks();
    multi.set.mockReturnValue(multi);
    multi.del.mockReturnValue(multi);
    multi.exec.mockResolvedValue([]);
    client.get.mockResolvedValue(null);
  });

  it('issues an isolated six-digit challenge after rate limiting', async () => {
    client.eval.mockResolvedValue(1);

    const result = await service.issue(
      'user@example.com',
      'user-id',
      '8.8.8.8',
    );

    expect(result.challengeId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(result.code).toMatch(/^\d{6}$/);
    expect(client.eval.mock.calls).toHaveLength(1);
    expect(multi.set.mock.calls).toHaveLength(4);
    expect(JSON.stringify(multi.set.mock.calls)).not.toContain(result.code);
  });

  it('maps an exhausted challenge without exposing stored state', async () => {
    client.eval.mockResolvedValue('attempts-exhausted');

    await expect(
      service.consume('efabb652-13e9-4c6d-8b12-0b2242636890', '123456'),
    ).resolves.toEqual({ status: 'attempts-exhausted' });
  });
});
