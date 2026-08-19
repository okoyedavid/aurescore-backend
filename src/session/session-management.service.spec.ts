import { AuditService } from '../audit/audit.service';
import { AuthTokenService } from '../auth-token/auth-token.service';
import { PrismaService } from '../database/prisma.service';
import { SessionService } from './session.service';

describe('SessionService management', () => {
  const context = {
    requestMetadata: {
      requestId: 'request-id',
      ipAddress: '8.8.8.8',
      userAgent: 'test-agent',
      method: 'DELETE',
      path: '/api/sessions/session-id',
    },
    location: { city: null, region: null, country: 'Nigeria' },
  };
  const transaction = {
    authSession: { updateMany: jest.fn() },
    userSession: { updateMany: jest.fn() },
  };
  const prismaMock = {
    userSession: {
      findMany: jest.fn(),
      findFirst: jest.fn(),
    },
    $transaction: jest.fn((callback: (client: typeof transaction) => unknown) =>
      Promise.resolve(callback(transaction)),
    ),
  };
  const auditMock = { record: jest.fn(), recordBestEffort: jest.fn() };
  const service = new SessionService(
    prismaMock as unknown as PrismaService,
    {} as AuthTokenService,
    auditMock as unknown as AuditService,
  );

  beforeEach(() => jest.clearAllMocks());

  it('lists only the user sessions and marks the caller', async () => {
    prismaMock.userSession.findMany.mockResolvedValue([
      {
        userSessionId: 'current-session',
        authSessions: [{ expiresAt: new Date('2026-08-19T00:00:00Z') }],
      },
    ]);

    const result = await service.listUserSessions('user-id', 'current-session');

    expect(prismaMock.userSession.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'user-id' } }),
    );
    expect(result[0]).toMatchObject({
      userSessionId: 'current-session',
      isCurrent: true,
    });
    expect(result[0]).not.toHaveProperty('authSessions');
  });

  it('revokes an owned current session and reports cookie clearing', async () => {
    prismaMock.userSession.findFirst.mockResolvedValue({
      userSessionId: 'current-session',
      revokedAt: null,
    });
    transaction.authSession.updateMany.mockResolvedValue({ count: 1 });
    transaction.userSession.updateMany.mockResolvedValue({ count: 1 });

    await expect(
      service.revokeUserSession(
        'user-id',
        'current-session',
        'current-session',
        context,
      ),
    ).resolves.toEqual({
      message: 'Session revoked successfully',
      currentSessionRevoked: true,
    });
    expect(prismaMock.userSession.findFirst).toHaveBeenCalledWith({
      where: { userSessionId: 'current-session', userId: 'user-id' },
      select: { userSessionId: true, revokedAt: true },
    });
  });
});
