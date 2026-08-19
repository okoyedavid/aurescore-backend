import { BadRequestException } from '@nestjs/common';
import { verify } from 'argon2';
import { AuditService } from '../audit/audit.service';
import { PrismaService } from '../database/prisma.service';
import { OAuthRateLimitService } from '../oauth-common/oauth-rate-limit.service';
import { OAuthClientService } from './oauth-client.service';

describe('OAuthClientService', () => {
  const createdAt = new Date('2026-08-19T09:00:00.000Z');
  const transaction = {
    oAuthClient: { create: jest.fn() },
  };
  const prisma = {
    $transaction: jest.fn(
      (operation: (database: typeof transaction) => unknown) =>
        operation(transaction),
    ),
    oAuthClient: { findMany: jest.fn(), findFirst: jest.fn() },
  } as unknown as PrismaService;
  const audit = {
    record: jest.fn(),
  } as unknown as AuditService;
  const rateLimits = {
    consume: jest.fn(),
  } as unknown as OAuthRateLimitService;
  const service = new OAuthClientService(prisma, audit, rateLimits);
  const context = {
    requestMetadata: {
      requestId: 'request-id',
      ipAddress: '127.0.0.1',
      userAgent: 'test',
      method: 'POST',
      path: '/api/developer/oauth-clients',
    },
    location: { city: null, region: null, country: null },
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('creates an owned confidential client and returns its secret only once', async () => {
    transaction.oAuthClient.create.mockImplementation(
      ({ data }: { data: Record<string, unknown> }) => ({
        clientId: data.clientId,
        name: data.name,
        slug: data.slug,
        description: null,
        homepageUrl: 'https://example.com/',
        logoUrl: null,
        clientSecretHint: data.clientSecretHint,
        secretCreatedAt: createdAt,
        redirectUris: data.redirectUris,
        allowedScopes: data.allowedScopes,
        clientType: 'CONFIDENTIAL_WEB',
        isActive: true,
        firstParty: false,
        createdAt,
        updatedAt: createdAt,
      }),
    );

    const result = await service.create(
      'owner-id',
      {
        name: 'Example App',
        homepageUrl: 'https://example.com',
        redirectUris: ['https://example.com/auth/aurescore/callback'],
        allowedScopes: ['openid', 'email'],
      },
      context,
    );
    const createCalls = transaction.oAuthClient.create.mock.calls as Array<
      [{ data: Record<string, unknown> }]
    >;
    const createInput = createCalls[0][0];

    expect(result.clientId).toMatch(/^auc_[A-Za-z0-9_-]{32}$/);
    expect(result.clientSecret).toMatch(/^aus_[A-Za-z0-9_-]{43}$/);
    expect(createInput.data.ownerUserId).toBe('owner-id');
    expect(createInput.data.redirectUris).toEqual([
      'https://example.com/auth/aurescore/callback',
    ]);
    await expect(
      verify(createInput.data.clientSecretHash as string, result.clientSecret),
    ).resolves.toBe(true);
    expect(JSON.stringify(createInput)).not.toContain(result.clientSecret);
  });

  it('rejects insecure non-local redirect URIs', async () => {
    await expect(
      service.create(
        'owner-id',
        {
          name: 'Unsafe App',
          redirectUris: ['http://example.com/callback'],
          allowedScopes: ['openid'],
        },
        context,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(transaction.oAuthClient.create.mock.calls).toHaveLength(0);
  });

  it('always scopes reads to the authenticated owner', async () => {
    (prisma.oAuthClient.findFirst as jest.Mock).mockResolvedValue(null);

    await expect(service.get('owner-id', 'auc_missing')).rejects.toThrow(
      'OAuth client not found',
    );
    expect(
      (prisma.oAuthClient.findFirst as jest.Mock).mock.calls,
    ).toContainEqual([
      expect.objectContaining({
        where: { clientId: 'auc_missing', ownerUserId: 'owner-id' },
      }),
    ]);
  });
});
