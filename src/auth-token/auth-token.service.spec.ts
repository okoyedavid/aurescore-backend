import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { AuthTokenService } from './auth-token.service';

describe('AuthTokenService', () => {
  it('signs access and refresh tokens with the user session ID', async () => {
    const signAsync = jest
      .fn()
      .mockResolvedValueOnce('access-token')
      .mockResolvedValueOnce('refresh-token');
    const jwtService = { signAsync } as unknown as JwtService;
    const values: Record<string, string> = {
      JWT_ACCESS_SECRET: 'access-secret',
      JWT_REFRESH_SECRET: 'refresh-secret',
      JWT_ACCESS_EXPIRES: '15m',
      JWT_REFRESH_EXPIRES: '1d',
    };
    const configService = {
      getOrThrow: jest.fn((key: string) => values[key]),
      get: jest.fn((_key: string, fallback: string) => fallback),
    } as unknown as ConfigService;
    const service = new AuthTokenService(jwtService, configService);

    const result = await service.issueTokenPair('user-id', 'user-session-id');
    const calls = signAsync.mock.calls as unknown as Array<
      [Record<string, unknown>, Record<string, unknown>]
    >;
    const [accessPayload, accessOptions] = calls[0];
    const [refreshPayload, refreshOptions] = calls[1];

    expect(accessPayload).toMatchObject({
      sub: 'user-id',
      userSessionId: 'user-session-id',
      type: 'access',
    });
    expect(typeof accessPayload.iat).toBe('number');
    expect(accessPayload.jti).toEqual(expect.any(String));
    expect(accessOptions).toEqual({
      secret: 'access-secret',
      expiresIn: 900,
      algorithm: 'HS256',
      issuer: 'aurescore-api',
      audience: 'aurescore-web',
    });
    expect(refreshPayload).toMatchObject({
      sub: 'user-id',
      userSessionId: 'user-session-id',
      type: 'refresh',
    });
    expect(typeof refreshPayload.iat).toBe('number');
    expect(refreshPayload.jti).toEqual(expect.any(String));
    expect(refreshOptions).toEqual({
      secret: 'refresh-secret',
      expiresIn: 86_400,
      algorithm: 'HS256',
      issuer: 'aurescore-api',
      audience: 'aurescore-web',
    });
    expect(result.accessToken).toBe('access-token');
    expect(result.refreshToken).toBe('refresh-token');
    expect(service.hashRefreshToken('refresh-token')).toMatch(/^[a-f0-9]{64}$/);
  });

  it('verifies the access-token policy and validates its claims', async () => {
    const verifyAsync = jest.fn().mockResolvedValue({
      sub: 'user-id',
      userSessionId: 'user-session-id',
      type: 'access',
      jti: 'token-id',
    });
    const jwtService = {
      verifyAsync,
    } as unknown as JwtService;
    const values: Record<string, string> = {
      JWT_ACCESS_SECRET: 'access-secret',
      JWT_REFRESH_SECRET: 'refresh-secret',
      JWT_ACCESS_EXPIRES: '15m',
      JWT_REFRESH_EXPIRES: '1d',
    };
    const configService = {
      getOrThrow: jest.fn((key: string) => values[key]),
      get: jest.fn((_key: string, fallback: string) => fallback),
    } as unknown as ConfigService;
    const service = new AuthTokenService(jwtService, configService);

    await expect(service.verifyAccessToken('access-token')).resolves.toEqual({
      userId: 'user-id',
      userSessionId: 'user-session-id',
      tokenId: 'token-id',
    });
    expect(verifyAsync).toHaveBeenCalledWith('access-token', {
      secret: 'access-secret',
      algorithms: ['HS256'],
      issuer: 'aurescore-api',
      audience: 'aurescore-web',
    });
  });

  it('verifies refresh-token integrity while leaving expiry to the session transaction', async () => {
    const verifyAsync = jest.fn().mockResolvedValue({
      sub: 'user-id',
      userSessionId: 'user-session-id',
      type: 'refresh',
      jti: 'refresh-token-id',
      iat: 1_800_000_000,
      exp: 1_800_086_400,
    });
    const jwtService = { verifyAsync } as unknown as JwtService;
    const values: Record<string, string> = {
      JWT_ACCESS_SECRET: 'access-secret',
      JWT_REFRESH_SECRET: 'refresh-secret',
      JWT_ACCESS_EXPIRES: '15m',
      JWT_REFRESH_EXPIRES: '1d',
    };
    const configService = {
      getOrThrow: jest.fn((key: string) => values[key]),
      get: jest.fn((_key: string, fallback: string) => fallback),
    } as unknown as ConfigService;
    const service = new AuthTokenService(jwtService, configService);

    await expect(service.verifyRefreshToken('refresh-token')).resolves.toEqual({
      userId: 'user-id',
      userSessionId: 'user-session-id',
      tokenId: 'refresh-token-id',
      issuedAt: new Date(1_800_000_000 * 1_000),
      expiresAt: new Date(1_800_086_400 * 1_000),
    });
    expect(verifyAsync).toHaveBeenCalledWith('refresh-token', {
      secret: 'refresh-secret',
      algorithms: ['HS256'],
      issuer: 'aurescore-api',
      audience: 'aurescore-web',
      ignoreExpiration: true,
    });
  });
});
