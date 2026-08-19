import type { RequestLocationContext } from '../location/location.service';
import { AuthTokenService } from '../auth-token/auth-token.service';
import { PrismaService } from '../database/prisma.service';
import { SessionService } from './session.service';
import { AuditService } from '../audit/audit.service';

const REQUEST_CONTEXT: RequestLocationContext = {
  requestMetadata: {
    requestId: 'request-id',
    ipAddress: '8.8.8.8',
    userAgent: 'test-agent',
    method: 'POST',
    path: '/api/auth/login',
  },
  location: {
    city: 'Mountain View',
    region: 'California',
    country: 'United States',
  },
};

const auditMock = {
  record: jest.fn().mockResolvedValue(undefined),
  recordBestEffort: jest.fn().mockResolvedValue(undefined),
};
const audit = auditMock as unknown as AuditService;

describe('SessionService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('creates, authenticates, and pins a login session atomically', async () => {
    const tokens = {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      accessTokenExpiresAt: new Date('2026-08-17T17:15:00.000Z'),
      refreshTokenExpiresAt: new Date('2026-08-18T17:00:00.000Z'),
    };
    const transaction = {
      authSession: {
        updateMany: jest.fn(),
        create: jest
          .fn()
          .mockResolvedValue({ authSessionId: 'auth-session-id' }),
      },
      userSession: {
        findMany: jest.fn().mockResolvedValue([]),
        create: jest
          .fn()
          .mockResolvedValue({ userSessionId: 'user-session-id' }),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn(),
      },
    };
    const prisma = {
      $transaction: jest.fn(
        (callback: (client: typeof transaction) => unknown) =>
          Promise.resolve(callback(transaction)),
      ),
    } as unknown as PrismaService;
    const issueTokenPair = jest.fn().mockResolvedValue(tokens);
    const hashRefreshToken = jest.fn().mockReturnValue('refresh-token-hash');
    const authTokens = {
      issueTokenPair,
      hashRefreshToken,
    } as unknown as AuthTokenService;
    const service = new SessionService(prisma, authTokens, audit);

    const result = await service.createLoginSession('user-id', REQUEST_CONTEXT);

    expect(transaction.userSession.create).toHaveBeenCalledWith({
      data: {
        userId: 'user-id',
        currentAuthSessionId: null,
        userAgent: 'test-agent',
        ipAddress: '8.8.8.8',
        city: 'Mountain View',
        region: 'California',
        country: 'United States',
      },
      select: { userSessionId: true },
    });
    expect(issueTokenPair).toHaveBeenCalledWith('user-id', 'user-session-id');
    expect(transaction.authSession.create).toHaveBeenCalledWith({
      data: {
        userSessionId: 'user-session-id',
        refreshTokenHash: 'refresh-token-hash',
        expiresAt: tokens.refreshTokenExpiresAt,
      },
      select: { authSessionId: true },
    });
    expect(transaction.userSession.update).toHaveBeenCalledWith({
      where: { userSessionId: 'user-session-id' },
      data: { currentAuthSessionId: 'auth-session-id' },
    });
    expect(
      transaction.userSession.create.mock.invocationCallOrder[0],
    ).toBeLessThan(issueTokenPair.mock.invocationCallOrder[0]);
    expect(issueTokenPair.mock.invocationCallOrder[0]).toBeLessThan(
      transaction.authSession.create.mock.invocationCallOrder[0],
    );
    expect(
      transaction.authSession.create.mock.invocationCallOrder[0],
    ).toBeLessThan(transaction.userSession.update.mock.invocationCallOrder[0]);
    expect(auditMock.record).toHaveBeenCalledWith(
      {
        eventType: 'authentication.login.succeeded',
        category: 'authentication',
        outcome: 'success',
        userId: 'user-id',
        userSessionId: 'user-session-id',
        authSessionId: 'auth-session-id',
        context: REQUEST_CONTEXT,
        metadata: { authenticationMethod: 'password' },
      },
      transaction,
    );
    expect(result).toEqual({ userSessionId: 'user-session-id', tokens });
  });

  describe('refreshSession', () => {
    const now = new Date('2026-08-17T17:00:00.000Z');
    const refreshTokenExpiresAt = new Date('2026-08-18T17:00:00.000Z');
    const claims = {
      userId: 'user-id',
      userSessionId: 'user-session-id',
      tokenId: 'old-token-id',
      issuedAt: new Date('2026-08-17T16:00:00.000Z'),
      expiresAt: refreshTokenExpiresAt,
    };
    const tokens = {
      accessToken: 'new-access-token',
      refreshToken: 'new-refresh-token',
      accessTokenExpiresAt: new Date('2026-08-17T17:15:00.000Z'),
      refreshTokenExpiresAt: new Date('2026-08-18T17:00:00.000Z'),
    };
    const activeUserSession = {
      userId: 'user-id',
      currentAuthSessionId: 'current-auth-session-id',
      revokedAt: null,
      user: {
        emailVerifiedAt: new Date('2026-08-01T00:00:00.000Z'),
        status: 'active',
      },
    };
    const currentAuthSession = {
      authSessionId: 'current-auth-session-id',
      userSessionId: 'user-session-id',
      refreshTokenHash: 'old-refresh-token-hash',
      replacedByAuthSessionId: null,
      expiresAt: refreshTokenExpiresAt,
      revokedAt: null,
    };

    afterEach(() => {
      jest.useRealTimers();
    });

    function createRefreshHarness() {
      const transaction = {
        userSession: {
          findUnique: jest.fn().mockResolvedValue(activeUserSession),
          updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        },
        authSession: {
          findUnique: jest.fn().mockResolvedValue(currentAuthSession),
          updateMany: jest.fn().mockResolvedValue({ count: 1 }),
          create: jest.fn().mockResolvedValue({}),
        },
      };
      const transactionRunner = jest.fn(
        (callback: (client: typeof transaction) => unknown) =>
          Promise.resolve(callback(transaction)),
      );
      const prisma = {
        $transaction: transactionRunner,
      } as unknown as PrismaService;
      const verifyRefreshToken = jest.fn().mockResolvedValue(claims);
      const authTokens = {
        verifyRefreshToken,
        hashRefreshToken: jest.fn((token: string) =>
          token === 'old-refresh-token'
            ? 'old-refresh-token-hash'
            : 'new-refresh-token-hash',
        ),
        issueTokenPair: jest.fn().mockResolvedValue(tokens),
      } as unknown as AuthTokenService;

      return {
        service: new SessionService(prisma, authTokens, audit),
        transaction,
        transactionRunner,
        verifyRefreshToken,
      };
    }

    it('rejects an invalid signature before opening a transaction', async () => {
      const { service, transactionRunner, verifyRefreshToken } =
        createRefreshHarness();
      verifyRefreshToken.mockRejectedValue(new Error('invalid signature'));

      await expect(
        service.refreshSession('invalid-refresh-token', REQUEST_CONTEXT),
      ).resolves.toEqual({ status: 'rejected' });
      expect(verifyRefreshToken).toHaveBeenCalledWith('invalid-refresh-token');
      expect(transactionRunner).not.toHaveBeenCalled();
    });

    it('claims the current auth session and moves the pin atomically', async () => {
      jest.useFakeTimers().setSystemTime(now);
      const { service, transaction } = createRefreshHarness();

      await expect(
        service.refreshSession('old-refresh-token', REQUEST_CONTEXT),
      ).resolves.toEqual({ status: 'rotated', tokens });

      const updateCalls = transaction.authSession.updateMany.mock
        .calls as unknown as Array<
        [{ data: { replacedByAuthSessionId: string } }]
      >;
      const replacementAuthSessionId =
        updateCalls[0][0].data.replacedByAuthSessionId;
      expect(typeof replacementAuthSessionId).toBe('string');
      expect(transaction.authSession.updateMany).toHaveBeenCalledWith({
        where: {
          authSessionId: 'current-auth-session-id',
          userSessionId: 'user-session-id',
          refreshTokenHash: 'old-refresh-token-hash',
          replacedByAuthSessionId: null,
          revokedAt: null,
          expiresAt: { gt: now },
        },
        data: {
          replacedByAuthSessionId: replacementAuthSessionId,
          revokedAt: now,
          lastSeenAt: now,
        },
      });

      const createCalls = transaction.authSession.create.mock
        .calls as unknown as Array<[{ data: { authSessionId: string } }]>;
      expect(createCalls[0][0].data.authSessionId).toBe(
        replacementAuthSessionId,
      );
      expect(transaction.authSession.create).toHaveBeenCalledWith({
        data: {
          authSessionId: replacementAuthSessionId,
          userSessionId: 'user-session-id',
          refreshTokenHash: 'new-refresh-token-hash',
          expiresAt: tokens.refreshTokenExpiresAt,
        },
      });
      expect(transaction.userSession.updateMany).toHaveBeenCalledWith({
        where: {
          userSessionId: 'user-session-id',
          currentAuthSessionId: 'current-auth-session-id',
          revokedAt: null,
        },
        data: {
          currentAuthSessionId: replacementAuthSessionId,
          lastSeenAt: now,
        },
      });
    });

    it('reports an old token replayed within one minute as already rotated', async () => {
      jest.useFakeTimers().setSystemTime(now);
      const { service, transaction } = createRefreshHarness();
      transaction.authSession.findUnique
        .mockResolvedValueOnce({
          ...currentAuthSession,
          refreshTokenHash: 'current-refresh-token-hash',
        })
        .mockResolvedValueOnce({
          userSessionId: 'user-session-id',
          replacedByAuthSessionId: 'current-auth-session-id',
          revokedAt: new Date(now.getTime() - 30_000),
        });

      await expect(
        service.refreshSession('old-refresh-token', REQUEST_CONTEXT),
      ).resolves.toEqual({ status: 'already-rotated' });
      expect(transaction.userSession.updateMany).not.toHaveBeenCalled();
      expect(transaction.authSession.updateMany).not.toHaveBeenCalled();
    });

    it('revokes the chain when an old token is replayed after one minute', async () => {
      jest.useFakeTimers().setSystemTime(now);
      const { service, transaction } = createRefreshHarness();
      transaction.authSession.findUnique
        .mockResolvedValueOnce({
          ...currentAuthSession,
          refreshTokenHash: 'current-refresh-token-hash',
        })
        .mockResolvedValueOnce({
          userSessionId: 'user-session-id',
          replacedByAuthSessionId: 'current-auth-session-id',
          revokedAt: new Date(now.getTime() - 60_001),
        });

      await expect(
        service.refreshSession('old-refresh-token', REQUEST_CONTEXT),
      ).resolves.toEqual({ status: 'rejected' });
      expect(transaction.userSession.updateMany).toHaveBeenCalledWith({
        where: { userSessionId: 'user-session-id', revokedAt: null },
        data: { revokedAt: now },
      });
      expect(auditMock.record).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'security.refresh_token.replay_detected',
          outcome: 'blocked',
          severity: 'critical',
          reason: 'late_refresh_replay',
        }),
        transaction,
      );
      expect(transaction.authSession.updateMany).toHaveBeenCalledWith({
        where: { userSessionId: 'user-session-id', revokedAt: null },
        data: { revokedAt: now },
      });
    });

    it('lets only one concurrent request claim the current auth session', async () => {
      jest.useFakeTimers().setSystemTime(now);
      const { service, transaction } = createRefreshHarness();
      transaction.authSession.updateMany.mockResolvedValue({ count: 0 });

      await expect(
        service.refreshSession('old-refresh-token', REQUEST_CONTEXT),
      ).resolves.toEqual({ status: 'already-rotated' });
      expect(transaction.authSession.create).not.toHaveBeenCalled();
      expect(transaction.userSession.updateMany).not.toHaveBeenCalled();
    });
  });
});
