import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthCookieService } from '../auth-cookie/auth-cookie.service';
import { LocationService } from '../location/location.service';
import {
  RefreshAlreadyRotatedException,
  RefreshRejectedException,
} from '../session/session.exceptions';
import { AccessTokenGuard } from '../auth-guard/access-token.guard';
import { AuthTokenService } from '../auth-token/auth-token.service';
import { PrismaService } from '../database/prisma.service';

describe('AuthController', () => {
  let controller: AuthController;
  const authService = {
    registerUser: jest.fn(),
    login: jest.fn(),
    refreshAuthSession: jest.fn(),
    verifyEmail: jest.fn(),
    resendEmailVerification: jest.fn(),
    verifyLogin: jest.fn(),
    resendLoginVerification: jest.fn(),
    beginGoogleLogin: jest.fn(),
    loginWithGoogle: jest.fn(),
    googleCallbackRedirect: jest.fn(),
    isGoogleLinkCallback: jest.fn().mockResolvedValue(false),
    googleLinkCallbackRedirect: jest.fn(),
    beginGoogleLink: jest.fn(),
    linkGoogleAccount: jest.fn(),
    logout: jest.fn(),
  };
  const authCookies = {
    setAuthCookies: jest.fn(),
    getRefreshToken: jest.fn(),
    clearAuthCookies: jest.fn(),
    setGoogleOAuthStateCookie: jest.fn(),
    getGoogleOAuthState: jest.fn(),
    clearGoogleOAuthStateCookie: jest.fn(),
    getAccessToken: jest.fn(),
  };
  const locations = {
    getRequestContext: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: authService,
        },
        { provide: AuthCookieService, useValue: authCookies },
        { provide: LocationService, useValue: locations },
        { provide: AuthTokenService, useValue: {} },
        { provide: PrismaService, useValue: {} },
      ],
    })
      .overrideGuard(AccessTokenGuard)
      .useValue({ canActivate: jest.fn(() => true) })
      .compile();

    controller = module.get<AuthController>(AuthController);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('delegates registration with the request context', async () => {
    const dto = {
      email: 'user@example.com',
      name: 'User',
      password: 'a-secure-password',
    };
    const request = {
      ip: '127.0.0.1',
      socket: {},
    };
    const requestContext = { requestMetadata: {}, location: {} };
    locations.getRequestContext.mockReturnValue(requestContext);

    await controller.register(dto, request as never);

    expect(authService.registerUser).toHaveBeenCalledWith(dto, requestContext);
  });

  it('sets auth cookies without returning tokens in the response body', async () => {
    const dto = { email: 'user@example.com', password: 'password' };
    const requestContext = { requestMetadata: {}, location: {} };
    const tokens = {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
    };
    const user = { id: 'user-id', email: dto.email, name: 'User' };
    const request = {};
    const response = {};
    locations.getRequestContext.mockReturnValue(requestContext);
    authService.login.mockResolvedValue({
      status: 'authenticated',
      user,
      session: { tokens },
    });

    const result = await controller.login(
      dto,
      request as never,
      response as never,
    );

    expect(authService.login).toHaveBeenCalledWith(dto, requestContext);
    expect(authCookies.setAuthCookies).toHaveBeenCalledWith(response, tokens);
    expect(result).toEqual({ message: 'Login successful', user });
    expect(result).not.toHaveProperty('tokens');
  });

  it('starts Google authorization with a browser-bound state cookie', async () => {
    const expiresAt = new Date('2026-08-18T02:00:00.000Z');
    const response = { redirect: jest.fn() };
    const request = {};
    const requestContext = { requestMetadata: {}, location: {} };
    locations.getRequestContext.mockReturnValue(requestContext);
    authService.beginGoogleLogin.mockResolvedValue({
      state: 'oauth-state',
      expiresAt,
      url: 'https://accounts.google.com/o/oauth2/v2/auth',
    });

    await controller.beginGoogleLogin(request as never, response as never);

    expect(authService.beginGoogleLogin).toHaveBeenCalledWith(requestContext);

    expect(authCookies.setGoogleOAuthStateCookie).toHaveBeenCalledWith(
      response,
      'oauth-state',
      expiresAt,
    );
    expect(response.redirect).toHaveBeenCalledWith(
      302,
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
  });

  it('sets application cookies after the Google callback and redirects safely', async () => {
    const request = {};
    const response = { redirect: jest.fn() };
    const tokens = { accessToken: 'access', refreshToken: 'refresh' };
    const requestContext = { requestMetadata: {}, location: {} };
    authCookies.getGoogleOAuthState.mockReturnValue('oauth-state');
    locations.getRequestContext.mockReturnValue(requestContext);
    authService.loginWithGoogle.mockResolvedValue({
      status: 'authenticated',
      session: { tokens },
    });
    authService.googleCallbackRedirect.mockReturnValue(
      'http://localhost:3000/auth/callback?provider=google&status=success',
    );

    await controller.completeGoogleLogin(
      { code: 'code', state: 'oauth-state' },
      request as never,
      response as never,
    );

    expect(authCookies.clearGoogleOAuthStateCookie).toHaveBeenCalledWith(
      response,
    );
    expect(authService.loginWithGoogle).toHaveBeenCalledWith(
      {
        code: 'code',
        state: 'oauth-state',
        error: undefined,
        expectedState: 'oauth-state',
      },
      requestContext,
    );
    expect(authCookies.setAuthCookies).toHaveBeenCalledWith(response, tokens);
    expect(response.redirect).toHaveBeenCalledWith(
      302,
      'http://localhost:3000/auth/callback?provider=google&status=success',
    );
  });

  it('does not set cookies while login verification is pending', async () => {
    const request = {};
    const response = {};
    locations.getRequestContext.mockReturnValue({});
    authService.login.mockResolvedValue({
      status: 'verification-required',
      challengeId: 'challenge-id',
    });

    const result = await controller.login(
      { email: 'user@example.com', password: 'password' },
      request as never,
      response as never,
    );

    expect(authCookies.setAuthCookies).not.toHaveBeenCalled();
    expect(result).toEqual({
      message: 'A login verification code has been sent.',
      requiresTwoFactor: true,
      challengeId: 'challenge-id',
    });
  });

  it('sets cookies after successful login verification', async () => {
    const request = {};
    const response = {};
    const tokens = { accessToken: 'access', refreshToken: 'refresh' };
    const user = { id: 'user-id', email: 'user@example.com' };
    locations.getRequestContext.mockReturnValue({});
    authService.verifyLogin.mockResolvedValue({
      user,
      session: { tokens },
    });

    const result = await controller.verifyLogin(
      { challengeId: 'challenge-id', code: '123456' },
      request as never,
      response as never,
    );

    expect(authCookies.setAuthCookies).toHaveBeenCalledWith(response, tokens);
    expect(result).toEqual({ message: 'Login successful', user });
  });

  it('rotates refresh cookies without exposing tokens in JSON', async () => {
    const request = {};
    const response = {};
    const tokens = { accessToken: 'new-access', refreshToken: 'new-refresh' };
    const requestContext = { requestMetadata: {}, location: {} };
    locations.getRequestContext.mockReturnValue(requestContext);
    authCookies.getRefreshToken.mockReturnValue('old-refresh');
    authService.refreshAuthSession.mockResolvedValue(tokens);

    const result = await controller.refresh(
      request as never,
      response as never,
    );

    expect(authService.refreshAuthSession).toHaveBeenCalledWith(
      'old-refresh',
      requestContext,
    );
    expect(authCookies.setAuthCookies).toHaveBeenCalledWith(response, tokens);
    expect(result).toEqual({ message: 'Session refreshed successfully' });
    expect(result).not.toHaveProperty('tokens');
  });

  it('clears cookies only when refresh is rejected', async () => {
    const request = {};
    const response = {};
    authCookies.getRefreshToken.mockReturnValue('invalid-refresh');
    authService.refreshAuthSession.mockRejectedValue(
      new RefreshRejectedException(),
    );

    await expect(
      controller.refresh(request as never, response as never),
    ).rejects.toBeInstanceOf(RefreshRejectedException);
    expect(authCookies.clearAuthCookies).toHaveBeenCalledWith(response);
    expect(authCookies.setAuthCookies).not.toHaveBeenCalled();
  });

  it('does not clear the winner cookies when another request already rotated', async () => {
    const request = {};
    const response = {};
    authCookies.getRefreshToken.mockReturnValue('old-refresh');
    authService.refreshAuthSession.mockRejectedValue(
      new RefreshAlreadyRotatedException(),
    );

    await expect(
      controller.refresh(request as never, response as never),
    ).rejects.toBeInstanceOf(RefreshAlreadyRotatedException);
    expect(authCookies.clearAuthCookies).not.toHaveBeenCalled();
    expect(authCookies.setAuthCookies).not.toHaveBeenCalled();
  });

  it('always clears cookies during idempotent logout', async () => {
    const request = {};
    const response = {};
    authCookies.getRefreshToken.mockReturnValue(null);
    authService.logout.mockResolvedValue(undefined);
    locations.getRequestContext.mockReturnValue({});

    await expect(
      controller.logout(request as never, response as never),
    ).resolves.toEqual({ message: 'Logged out successfully' });
    expect(authCookies.clearAuthCookies).toHaveBeenCalledWith(response);
  });
});
