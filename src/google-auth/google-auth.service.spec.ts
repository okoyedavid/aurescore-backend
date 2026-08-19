import { ConfigService } from '@nestjs/config';
import { RedisService } from '../redis/redis.service';
import { GoogleOAuthFlowError } from './google-auth.exceptions';
import { GoogleAuthService } from './google-auth.service';

describe('GoogleAuthService', () => {
  const redisClient = {
    set: jest.fn(),
    getDel: jest.fn(),
    eval: jest.fn(),
  };
  const redis = { client: redisClient } as unknown as RedisService;
  const values: Record<string, string> = {
    GOOGLE_CLIENT_ID: 'google-client-id',
    GOOGLE_CLIENT_SECRET: 'google-client-secret',
    GOOGLE_REDIRECT_URL: 'http://localhost:3001/api/auth/google/callback',
    FRONTEND_URL: 'http://localhost:3000',
    NODE_ENV: 'development',
    RATE_LIMIT_PEPPER: 'google-rate-limit-pepper',
  };
  const config = {
    get: jest.fn((key: string, fallback?: string) => values[key] ?? fallback),
    getOrThrow: jest.fn((key: string) => {
      const value = values[key];
      if (!value) throw new Error(`Missing ${key}`);
      return value;
    }),
  } as unknown as ConfigService;

  let service: GoogleAuthService;

  beforeEach(() => {
    jest.clearAllMocks();
    redisClient.set.mockResolvedValue('OK');
    redisClient.eval.mockResolvedValue(1);
    service = new GoogleAuthService(redis, config);
  });

  it('creates one-time state, nonce and PKCE parameters', async () => {
    const authorization = await service.createAuthorizationRequest('8.8.8.8');
    const url = new URL(authorization.url);

    expect(authorization.state).toHaveLength(43);
    expect(url.searchParams.get('state')).toBe(authorization.state);
    expect(url.searchParams.get('nonce')).toBeTruthy();
    expect(url.searchParams.get('code_challenge')).toBeTruthy();
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('redirect_uri')).toBe(
      values.GOOGLE_REDIRECT_URL,
    );
    expect(redisClient.set).toHaveBeenCalledWith(
      expect.stringContaining('oauth:google:state:'),
      expect.any(String),
      { EX: GoogleAuthService.STATE_TTL_SECONDS, NX: true },
    );
  });

  it('rejects a callback not bound to the browser before consuming Redis state', async () => {
    await expect(
      service.exchangeAuthorizationCode(
        'code',
        'returned-state',
        'different-cookie-state',
      ),
    ).rejects.toEqual(expect.any(GoogleOAuthFlowError));
    expect(redisClient.getDel).not.toHaveBeenCalled();
  });

  it('consumes state even when the user denies Google consent', async () => {
    redisClient.getDel.mockResolvedValue(
      JSON.stringify({ codeVerifier: 'verifier', nonce: 'nonce' }),
    );

    await expect(
      service.exchangeAuthorizationCode(
        undefined,
        'state',
        'state',
        'access_denied',
      ),
    ).rejects.toMatchObject({ reason: 'provider_denied' });
    expect(redisClient.getDel).toHaveBeenCalledTimes(1);
  });
});
