import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthTokenService } from '../auth-token/auth-token.service';
import { PrismaService } from '../database/prisma.service';
import { AccessTokenGuard } from './access-token.guard';
import type { AuthenticatedRequest } from './authenticated-request';

describe('AccessTokenGuard', () => {
  const authTokens = {
    verifyAccessToken: jest.fn(),
  };
  const prisma = {
    userSession: {
      findUnique: jest.fn(),
    },
  };
  const request = {
    cookies: { accessToken: 'access-token' },
  };
  const context = {
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
  const guard = new AccessTokenGuard(
    authTokens as unknown as AuthTokenService,
    prisma as unknown as PrismaService,
  );

  beforeEach(() => {
    jest.clearAllMocks();
    delete (request as Partial<AuthenticatedRequest>).auth;
    authTokens.verifyAccessToken.mockResolvedValue({
      userId: 'user-id',
      userSessionId: 'user-session-id',
      tokenId: 'token-id',
    });
    prisma.userSession.findUnique.mockResolvedValue({
      userId: 'user-id',
      currentAuthSessionId: 'auth-session-id',
      revokedAt: null,
      user: {
        emailVerifiedAt: new Date(),
        status: 'active',
      },
    });
  });

  it('attaches a principal after token and server-side session validation', async () => {
    await expect(guard.canActivate(context)).resolves.toBe(true);

    expect(prisma.userSession.findUnique).toHaveBeenCalledWith({
      where: { userSessionId: 'user-session-id' },
      select: {
        userId: true,
        currentAuthSessionId: true,
        revokedAt: true,
        user: {
          select: {
            emailVerifiedAt: true,
            status: true,
          },
        },
      },
    });
    expect((request as unknown as AuthenticatedRequest).auth).toEqual({
      userId: 'user-id',
      userSessionId: 'user-session-id',
      accessTokenId: 'token-id',
    });
  });

  it('rejects a revoked user session', async () => {
    prisma.userSession.findUnique.mockResolvedValue({
      userId: 'user-id',
      currentAuthSessionId: 'auth-session-id',
      revokedAt: new Date(),
      user: {
        emailVerifiedAt: new Date(),
        status: 'active',
      },
    });

    await expect(guard.canActivate(context)).rejects.toBeInstanceOf(
      UnauthorizedException,
    );
    expect((request as Partial<AuthenticatedRequest>).auth).toBeUndefined();
  });
});
