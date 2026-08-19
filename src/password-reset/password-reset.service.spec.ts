import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../database/prisma.service';
import { EmailService } from '../email/email.service';
import { PasswordResetVerificationService } from './password-reset-verification.service';
import { PasswordResetService } from './password-reset.service';

describe('PasswordResetService', () => {
  const transaction = {
    user: { updateMany: jest.fn() },
    authSession: { updateMany: jest.fn() },
    userSession: { updateMany: jest.fn() },
  };
  const prisma = {
    user: { findUnique: jest.fn() },
    $transaction: jest.fn(
      (operation: (database: typeof transaction) => unknown) =>
        operation(transaction),
    ),
  } as unknown as PrismaService;
  const verification = {
    issue: jest.fn(),
    consume: jest.fn(),
    invalidate: jest.fn(),
  } as unknown as PasswordResetVerificationService;
  const email = {
    sendPasswordResetCode: jest.fn(),
    sendPasswordResetNotice: jest.fn(),
  } as unknown as EmailService;
  const audit = {
    record: jest.fn(),
    recordBestEffort: jest.fn(),
  } as unknown as AuditService;
  const service = new PasswordResetService(prisma, verification, email, audit);
  const context = {
    requestMetadata: {
      requestId: 'request-id',
      ipAddress: '8.8.8.8',
      userAgent: 'test',
      method: 'POST',
      path: '/api/auth/password-reset/request',
    },
    location: { city: null, region: null, country: 'Nigeria' },
  };

  beforeEach(() => jest.clearAllMocks());

  it('returns an indistinguishable challenge for an unknown email', async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);
    (verification.issue as jest.Mock).mockResolvedValue({
      challengeId: 'challenge-id',
      code: '123456',
      deliveryId: 'delivery-id',
    });

    await expect(
      service.request({ email: 'missing@example.com' }, context),
    ).resolves.toEqual({
      message:
        'If an eligible account exists, a password-reset code has been sent.',
      challengeId: 'challenge-id',
    });
    expect((verification.issue as jest.Mock).mock.calls[0]).toEqual([
      'missing@example.com',
      null,
      '8.8.8.8',
    ]);
    expect((email.sendPasswordResetCode as jest.Mock).mock.calls).toHaveLength(
      0,
    );
  });

  it('changes the password and revokes every existing session atomically', async () => {
    const oldHash =
      '$argon2id$v=19$m=65536,p=4,t=3$vHaavnYlRfMg0aNnb4v43g$nxokufbk5hoF0MsNtgCTSD3QYJCvKdH2CgQYF0x5gME';
    (verification.consume as jest.Mock).mockResolvedValue({
      status: 'verified',
      userId: 'user-id',
    });
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: 'user-id',
      email: 'user@example.com',
      passwordHash: oldHash,
    });
    transaction.user.updateMany.mockResolvedValue({ count: 1 });
    transaction.authSession.updateMany.mockResolvedValue({ count: 3 });
    transaction.userSession.updateMany.mockResolvedValue({ count: 2 });

    await expect(
      service.confirm(
        {
          challengeId: 'efabb652-13e9-4c6d-8b12-0b2242636890',
          code: '123456',
          newPassword: 'a-new-secure-password',
        },
        context,
      ),
    ).resolves.toEqual({
      message: 'Password reset successfully. Sign in with your new password.',
    });
    expect(transaction.authSession.updateMany.mock.calls).toHaveLength(1);
    expect(transaction.userSession.updateMany.mock.calls).toHaveLength(1);
    expect((audit.record as jest.Mock).mock.calls).toHaveLength(1);
    expect((email.sendPasswordResetNotice as jest.Mock).mock.calls).toEqual([
      ['user@example.com'],
    ]);
  });
});
