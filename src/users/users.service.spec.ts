import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../database/prisma.service';
import { EmailChangeVerificationService } from '../email-change-verification/email-change-verification.service';
import { EmailService } from '../email/email.service';
import { UsersService } from './users.service';
import { SensitiveActionRateLimitService } from '../rate-limit/sensitive-action-rate-limit.service';
import { SensitiveActionVerificationService } from '../sensitive-action/sensitive-action-verification.service';

describe('UsersService', () => {
  const context = {
    requestMetadata: {
      requestId: 'request-id',
      ipAddress: '8.8.8.8',
      userAgent: 'test-agent',
      method: 'PATCH',
      path: '/api/account/password',
    },
    location: { city: null, region: null, country: 'Nigeria' },
  };
  const transaction = {
    user: { update: jest.fn() },
    userPreference: { upsert: jest.fn() },
    authSession: { updateMany: jest.fn() },
    userSession: { updateMany: jest.fn() },
    oAuthGrant: { updateMany: jest.fn() },
  };
  const prismaMock = {
    user: {
      findUnique: jest.fn(),
      findUniqueOrThrow: jest.fn(),
    },
    $transaction: jest.fn((callback: (client: typeof transaction) => unknown) =>
      Promise.resolve(callback(transaction)),
    ),
  };
  const auditMock = {
    record: jest.fn(),
    recordBestEffort: jest.fn(),
  };
  const sensitiveRateLimits = { consume: jest.fn(), reset: jest.fn() };
  const sensitiveVerification = { consumeAuthorization: jest.fn() };
  const service = new UsersService(
    prismaMock as unknown as PrismaService,
    auditMock as unknown as AuditService,
    {} as EmailChangeVerificationService,
    {} as EmailService,
    sensitiveRateLimits as unknown as SensitiveActionRateLimitService,
    sensitiveVerification as unknown as SensitiveActionVerificationService,
  );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('fetches the current user through an explicit password-free projection', async () => {
    prismaMock.user.findUniqueOrThrow.mockResolvedValue({ id: 'user-id' });

    await service.getCurrentUser('user-id');

    const calls = prismaMock.user.findUniqueOrThrow.mock
      .calls as unknown as Array<[{ select: Record<string, unknown> }]>;
    expect(calls[0][0].select.passwordHash).toBe(true);
    expect(calls[0][0].select.email).toBe(true);
    expect(calls[0][0].select.preferences).toBeDefined();
  });

  it('changes the password while preserving the caller session', async () => {
    prismaMock.user.findUniqueOrThrow.mockResolvedValue({
      passwordHash:
        '$argon2id$v=19$m=19456,p=1,t=2$vnqdgSXrPWJ2LQoM/KocTQ$yAo23u2KFYc+81T86cNGCfzE9LX+ylVX2F5mR09jYEQ',
    });
    transaction.user.update.mockResolvedValue({});
    transaction.authSession.updateMany.mockResolvedValue({ count: 2 });
    transaction.userSession.updateMany.mockResolvedValue({ count: 2 });

    await service.changePassword(
      'user-id',
      'current-session-id',
      {
        currentPassword: 'not-a-real-user-password',
        newPassword: 'a-completely-new-password',
      },
      context,
    );

    const userSessionCalls = transaction.userSession.updateMany.mock
      .calls as unknown as Array<[{ data: { revokedAt: Date } }]>;
    const revokedAt = userSessionCalls[0][0].data.revokedAt;
    expect(revokedAt).toBeInstanceOf(Date);
    expect(transaction.userSession.updateMany).toHaveBeenCalledWith({
      where: {
        userId: 'user-id',
        userSessionId: { not: 'current-session-id' },
        revokedAt: null,
      },
      data: { revokedAt },
    });
    const authSessionCalls = transaction.authSession.updateMany.mock
      .calls as unknown as Array<
      [{ where: { userSession: Record<string, unknown> } }]
    >;
    expect(authSessionCalls[0][0].where.userSession).toEqual({
      userId: 'user-id',
      userSessionId: { not: 'current-session-id' },
    });
  });

  it('allows a provider-only user to enable 2FA after email reauthentication', async () => {
    prismaMock.user.findUniqueOrThrow.mockResolvedValue({
      passwordHash: null,
      preferences: { twoFactorEnabled: false },
    });
    transaction.userPreference.upsert.mockResolvedValue({
      desktopNotifications: true,
      twoFactorEnabled: true,
    });

    await service.updatePreferences(
      'user-id',
      'session-id',
      { twoFactorEnabled: true, reauthToken: 'one-use-token' },
      context,
    );

    expect(sensitiveVerification.consumeAuthorization.mock.calls).toEqual([
      ['one-use-token', 'user-id', 'session-id', 'change-two-factor'],
    ]);
    expect(sensitiveRateLimits.consume.mock.calls).toHaveLength(0);
  });

  it('revokes only an OAuth grant owned by the caller', async () => {
    transaction.oAuthGrant.updateMany.mockResolvedValue({ count: 1 });

    await expect(
      service.revokeOAuthGrant('user-id', 'grant-id-value', context),
    ).resolves.toEqual({ message: 'Application access revoked successfully' });
    const calls = transaction.oAuthGrant.updateMany.mock
      .calls as unknown as Array<
      [{ where: Record<string, unknown>; data: { revokedAt: Date } }]
    >;
    expect(calls[0][0].where).toEqual({
      grantId: 'grant-id-value',
      userId: 'user-id',
      revokedAt: null,
    });
    expect(calls[0][0].data.revokedAt).toBeInstanceOf(Date);
  });
});
