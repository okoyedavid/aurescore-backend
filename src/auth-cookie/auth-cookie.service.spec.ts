import { ConfigService } from '@nestjs/config';
import type { Request, Response } from 'express';
import { AuthCookieService } from './auth-cookie.service';

describe('AuthCookieService', () => {
  it('sets host-only HTTP-only development cookies', () => {
    const config = {
      get: jest.fn().mockReturnValue('development'),
    } as unknown as ConfigService;
    const cookie = jest.fn();
    const response = { cookie } as unknown as Response;
    const service = new AuthCookieService(config);
    const accessTokenExpiresAt = new Date('2026-08-17T17:15:00.000Z');
    const refreshTokenExpiresAt = new Date('2026-08-18T17:00:00.000Z');

    service.setAuthCookies(response, {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      accessTokenExpiresAt,
      refreshTokenExpiresAt,
    });

    expect(cookie).toHaveBeenNthCalledWith(1, 'accessToken', 'access-token', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/api',
      expires: accessTokenExpiresAt,
    });
    expect(cookie).toHaveBeenNthCalledWith(2, 'refreshToken', 'refresh-token', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/api/auth',
      expires: refreshTokenExpiresAt,
    });
  });

  it('reads the refresh cookie and clears both cookie paths', () => {
    const config = {
      get: jest.fn().mockReturnValue('development'),
    } as unknown as ConfigService;
    const clearCookie = jest.fn();
    const response = { clearCookie } as unknown as Response;
    const request = {
      cookies: { refreshToken: 'refresh-token' },
    } as unknown as Request;
    const service = new AuthCookieService(config);

    expect(service.getRefreshToken(request)).toBe('refresh-token');
    service.clearAuthCookies(response);

    expect(clearCookie).toHaveBeenNthCalledWith(1, 'accessToken', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/api',
    });
    expect(clearCookie).toHaveBeenNthCalledWith(2, 'refreshToken', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/api/auth',
    });
  });

  it('binds Google OAuth state to the callback path and clears it after use', () => {
    const config = {
      get: jest.fn().mockReturnValue('development'),
    } as unknown as ConfigService;
    const cookie = jest.fn();
    const clearCookie = jest.fn();
    const expiresAt = new Date('2026-08-18T02:00:00.000Z');
    const response = { cookie, clearCookie } as unknown as Response;
    const request = {
      cookies: { googleOAuthState: 'oauth-state' },
    } as unknown as Request;
    const service = new AuthCookieService(config);

    service.setGoogleOAuthStateCookie(response, 'oauth-state', expiresAt);
    expect(service.getGoogleOAuthState(request)).toBe('oauth-state');
    service.clearGoogleOAuthStateCookie(response);

    expect(cookie).toHaveBeenCalledWith('googleOAuthState', 'oauth-state', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/api/auth/google/callback',
      expires: expiresAt,
    });
    expect(clearCookie).toHaveBeenCalledWith('googleOAuthState', {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/api/auth/google/callback',
    });
  });
});
