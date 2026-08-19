import { ConfigService } from '@nestjs/config';
import { hash } from 'argon2';
import { createHash } from 'node:crypto';
import type { Request } from 'express';
import { AuditService } from '../audit/audit.service';
import { AuthTokenService } from '../auth-token/auth-token.service';
import { PrismaService } from '../database/prisma.service';
import { OAuthRateLimitService } from '../oauth-common/oauth-rate-limit.service';
import { RedisService } from '../redis/redis.service';
import { OidcSigningService } from './oidc-signing.service';
import { OAuthProviderService } from './oauth-provider.service';

describe('OAuthProviderService', () => {
  const redisClient = {
    set: jest.fn(),
    get: jest.fn(),
    getDel: jest.fn(),
  };
  const redis = { client: redisClient } as unknown as RedisService;
  const transaction = {
    oAuthGrant: { update: jest.fn() },
  };
  const prisma = {
    oAuthClient: { findUnique: jest.fn() },
    oAuthGrant: { findUnique: jest.fn(), findFirst: jest.fn() },
    userSession: { findUnique: jest.fn() },
    user: { findUnique: jest.fn() },
    $transaction: jest.fn(
      (operation: (database: typeof transaction) => unknown) =>
        operation(transaction),
    ),
  } as unknown as PrismaService;
  const authTokens = {
    verifyAccessToken: jest.fn(),
  } as unknown as AuthTokenService;
  const signing = {
    issuer: 'http://localhost:5000',
    signIdToken: jest.fn(() => 'signed-id-token'),
    jwks: jest.fn(() => ({ keys: [] })),
  } as unknown as OidcSigningService;
  const rateLimits = {
    consume: jest.fn(),
  } as unknown as OAuthRateLimitService;
  const audit = {
    record: jest.fn(),
    recordBestEffort: jest.fn(),
  } as unknown as AuditService;
  const config = {
    get: jest.fn((key: string, fallback?: string) =>
      key === 'FRONTEND_URL' ? 'http://localhost:3000' : fallback,
    ),
  } as unknown as ConfigService;
  const service = new OAuthProviderService(
    prisma,
    redis,
    authTokens,
    signing,
    rateLimits,
    audit,
    config,
  );
  const context = {
    requestMetadata: {
      requestId: 'request-id',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
      method: 'GET',
      path: '/api/oauth/authorize',
    },
    location: { city: null, region: null, country: null },
  };
  const client = {
    clientId: `auc_${'a'.repeat(32)}`,
    name: 'Example App',
    description: null,
    homepageUrl: 'https://example.com/',
    logoUrl: null,
    redirectUris: ['https://example.com/callback'],
    allowedScopes: ['openid', 'profile', 'email'],
    isActive: true,
    firstParty: false,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    redisClient.set.mockResolvedValue('OK');
    (prisma.oAuthClient.findUnique as jest.Mock).mockResolvedValue(client);
  });

  it('stores a validated interaction and sends unauthenticated users to Aurescore login', async () => {
    const result = await service.startAuthorization(
      {
        response_type: 'code',
        client_id: client.clientId,
        redirect_uri: 'https://example.com/callback',
        scope: 'openid email',
        state: 'client-state',
        nonce: 'client-nonce',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      },
      { cookies: {} } as Request,
      context,
    );

    expect(result).toMatchObject({ kind: 'redirect' });
    expect(new URL((result as { url: string }).url).pathname).toBe('/login');
    expect(redisClient.set).toHaveBeenCalledWith(
      expect.stringContaining('oauth:interaction:'),
      expect.stringContaining('"clientId"'),
      { EX: 600, NX: true },
    );
  });

  it('rejects a redirect URI that is not exactly registered', async () => {
    await expect(
      service.startAuthorization(
        {
          response_type: 'code',
          client_id: client.clientId,
          redirect_uri: 'https://evil.example/callback',
          scope: 'openid',
          state: 'state',
          nonce: 'nonce',
          code_challenge: 'a'.repeat(43),
          code_challenge_method: 'S256',
        },
        { cookies: {} } as Request,
        context,
      ),
    ).rejects.toMatchObject({ errorCode: 'invalid_request' });
    expect(redisClient.set).not.toHaveBeenCalled();
  });

  it('exchanges a code once, verifies PKCE, and issues scoped tokens', async () => {
    const clientSecret = `aus_${'s'.repeat(43)}`;
    const verifier = 'v'.repeat(43);
    const code = `auc_code_${'c'.repeat(43)}`;
    const codeValue = JSON.stringify({
      userId: 'user-id',
      grantId: 'grant-id',
      subject: 'pairwise-subject',
      clientId: client.clientId,
      redirectUri: 'https://example.com/callback',
      scopes: ['openid', 'email'],
      nonce: 'nonce',
      codeChallenge: createHash('sha256').update(verifier).digest('base64url'),
      authTime: 1_787_000_000,
    });
    (prisma.oAuthClient.findUnique as jest.Mock).mockResolvedValue({
      clientId: client.clientId,
      clientSecretHash: await hash(clientSecret),
      isActive: true,
    });
    redisClient.get.mockResolvedValue(codeValue);
    redisClient.getDel.mockResolvedValue(codeValue);
    (prisma.oAuthGrant.findFirst as jest.Mock).mockResolvedValue({
      grantId: 'grant-id',
      user: {
        name: 'User',
        avatar: null,
        email: 'user@example.com',
        emailVerifiedAt: new Date(),
      },
    });

    const result = await service.exchangeCode(
      {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://example.com/callback',
        code_verifier: verifier,
      },
      `Basic ${Buffer.from(`${client.clientId}:${clientSecret}`).toString('base64')}`,
      context,
    );

    expect(result).toMatchObject({
      token_type: 'Bearer',
      expires_in: 600,
      scope: 'openid email',
      id_token: 'signed-id-token',
    });
    expect(result.access_token).toMatch(/^aat_/);
    expect(redisClient.getDel.mock.calls).toHaveLength(1);
    expect((signing.signIdToken as jest.Mock).mock.calls).toContainEqual([
      expect.objectContaining({
        subject: 'pairwise-subject',
        clientId: client.clientId,
        email: 'user@example.com',
      }),
    ]);
  });

  it('returns only claims allowed by the access token scopes', async () => {
    redisClient.get.mockResolvedValue(
      JSON.stringify({
        userId: 'user-id',
        grantId: 'grant-id',
        subject: 'pairwise-subject',
        clientId: client.clientId,
        scopes: ['openid', 'profile'],
      }),
    );
    (prisma.oAuthGrant.findFirst as jest.Mock).mockResolvedValue({
      user: {
        name: 'User',
        avatar: 'https://example.com/avatar.png',
        username: 'user-name',
        email: 'private@example.com',
        emailVerifiedAt: new Date(),
      },
    });

    const result = await service.userInfo('Bearer aat_token', context);

    expect(result).toEqual({
      sub: 'pairwise-subject',
      name: 'User',
      picture: 'https://example.com/avatar.png',
      preferred_username: 'user-name',
    });
    expect(result).not.toHaveProperty('email');
  });
});
