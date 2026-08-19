import { ConfigService } from '@nestjs/config';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../database/prisma.service';
import { EmailService } from '../email/email.service';
import { RedisService } from '../redis/redis.service';
import { SensitiveActionVerificationService } from './sensitive-action-verification.service';

describe('SensitiveActionVerificationService', () => {
  const multi = { set: jest.fn(), del: jest.fn(), exec: jest.fn() };
  const client = {
    set: jest.fn(),
    eval: jest.fn(),
    getDel: jest.fn(),
    del: jest.fn(),
    multi: jest.fn(() => multi),
  };
  const prisma = {
    user: { findUnique: jest.fn() },
  } as unknown as PrismaService;
  const email = {
    sendSensitiveActionCode: jest.fn(),
  } as unknown as EmailService;
  const audit = { recordBestEffort: jest.fn() } as unknown as AuditService;
  const config = {
    getOrThrow: jest.fn(() => 'sensitive-action-test-pepper'),
  } as unknown as ConfigService;
  const service = new SensitiveActionVerificationService(
    { client } as unknown as RedisService,
    prisma,
    email,
    audit,
    config,
  );
  const context = {
    requestMetadata: {
      requestId: 'request-id',
      ipAddress: '8.8.8.8',
      userAgent: 'test',
      method: 'POST',
      path: '/api/account/security-verification/request',
    },
    location: { city: null, region: null, country: null },
  };

  beforeEach(() => {
    jest.clearAllMocks();
    multi.set.mockReturnValue(multi);
    multi.del.mockReturnValue(multi);
    multi.exec.mockResolvedValue([]);
    client.set.mockResolvedValue('OK');
  });

  it('issues an email challenge only for a provider-only account', async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      email: 'user@example.com',
      passwordHash: null,
    });

    const result = await service.issue(
      'user-id',
      'session-id',
      'change-two-factor',
      context,
    );

    expect(result.challengeId).toBeTruthy();
    expect(
      (email.sendSensitiveActionCode as jest.Mock).mock.calls,
    ).toHaveLength(1);
    expect(JSON.stringify(multi.set.mock.calls)).not.toContain('123456');
  });

  it('rejects a one-use authorization presented for a different action', async () => {
    client.getDel.mockResolvedValue(
      JSON.stringify({
        userId: 'user-id',
        userSessionId: 'session-id',
        action: 'set-password',
      }),
    );

    await expect(
      service.consumeAuthorization(
        'reauth-token',
        'user-id',
        'session-id',
        'change-email',
      ),
    ).rejects.toThrow('Fresh security verification is required');
    expect(client.getDel.mock.calls).toHaveLength(1);
  });
});
