import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { PrismaService } from '../database/prisma.service';
import { VerificationCodeService } from '../verification-code/verification-code.service';
import { EmailService } from '../email/email.service';
import { SessionService } from '../session/session.service';
import { LoginRateLimitService } from '../rate-limit/login-rate-limit.service';
import { LoginVerificationService } from '../login-verification/login-verification.service';
import { AuditService } from '../audit/audit.service';
import { GoogleAuthService } from '../google-auth/google-auth.service';
import { GoogleAccountLinkRequiredError } from '../google-auth/google-auth.exceptions';
import { AuthTokenService } from '../auth-token/auth-token.service';

describe('AuthService', () => {
  let service: AuthService;
  const prisma = {
    $transaction: jest.fn(),
    user: {
      findUnique: jest.fn(),
    },
    authProvider: {
      findUnique: jest.fn(),
      update: jest.fn(),
      create: jest.fn(),
    },
    userSession: { findUnique: jest.fn() },
  };
  const sessions = {
    createLoginSession: jest.fn(),
    refreshSession: jest.fn(),
  };
  const loginRateLimits = {
    consumeLoginAttempt: jest.fn(),
    resetAccountLimit: jest.fn(),
  };
  const loginVerifications = {
    issueChallenge: jest.fn(),
    consumeChallenge: jest.fn(),
    resendChallenge: jest.fn(),
    invalidateChallenge: jest.fn(),
    invalidateCode: jest.fn(),
  };
  const emailService = {
    sendLoginVerification: jest.fn(),
  };
  const audit = {
    record: jest.fn(),
    recordBestEffort: jest.fn(),
  };
  const googleAuth = {
    createAuthorizationRequest: jest.fn(),
    exchangeAuthorizationCode: jest.fn(),
    frontendCallbackUrl: jest.fn(),
    exchangeLinkAuthorizationCode: jest.fn(),
  };
  const authTokens = { verifyAccessToken: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prisma },
        { provide: VerificationCodeService, useValue: {} },
        { provide: EmailService, useValue: emailService },
        { provide: SessionService, useValue: sessions },
        { provide: LoginRateLimitService, useValue: loginRateLimits },
        { provide: LoginVerificationService, useValue: loginVerifications },
        { provide: AuditService, useValue: audit },
        { provide: GoogleAuthService, useValue: googleAuth },
        { provide: AuthTokenService, useValue: authTokens },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  it('validates credentials and creates a login session', async () => {
    const context = {
      requestMetadata: {
        requestId: 'request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test-agent',
        method: 'POST',
        path: '/api/auth/login',
      },
      location: { city: null, region: null, country: 'United States' },
    };
    const session = { userSessionId: 'session-id', tokens: {} };
    prisma.user.findUnique.mockResolvedValue({
      id: 'user-id',
      email: 'user@example.com',
      name: 'User',
      username: null,
      avatar: null,
      passwordHash:
        '$argon2id$v=19$m=19456,p=1,t=2$vnqdgSXrPWJ2LQoM/KocTQ$yAo23u2KFYc+81T86cNGCfzE9LX+ylVX2F5mR09jYEQ',
      emailVerifiedAt: new Date(),
      status: 'active',
      preferences: { twoFactorEnabled: false },
    });
    sessions.createLoginSession.mockResolvedValue(session);

    const result = await service.login(
      {
        email: 'USER@EXAMPLE.COM ',
        password: 'not-a-real-user-password',
      },
      context,
    );

    expect(prisma.user.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { email: 'user@example.com' } }),
    );
    expect(loginRateLimits.consumeLoginAttempt).toHaveBeenCalledWith(
      'user@example.com',
      '8.8.8.8',
    );
    expect(loginRateLimits.resetAccountLimit).toHaveBeenCalledWith(
      'user@example.com',
    );
    expect(sessions.createLoginSession).toHaveBeenCalledWith(
      'user-id',
      context,
      'password',
    );
    expect(result).toEqual({
      status: 'authenticated',
      user: {
        id: 'user-id',
        email: 'user@example.com',
        name: 'User',
        username: null,
        avatar: null,
      },
      session,
    });
  });

  it('creates a pending challenge instead of a session when email login verification is enabled', async () => {
    const context = {
      requestMetadata: {
        requestId: 'request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test-agent',
        method: 'POST',
        path: '/api/auth/login',
      },
      location: { city: null, region: null, country: 'United States' },
    };
    prisma.user.findUnique.mockResolvedValue({
      id: 'user-id',
      email: 'user@example.com',
      name: 'User',
      username: null,
      avatar: null,
      passwordHash:
        '$argon2id$v=19$m=19456,p=1,t=2$vnqdgSXrPWJ2LQoM/KocTQ$yAo23u2KFYc+81T86cNGCfzE9LX+ylVX2F5mR09jYEQ',
      emailVerifiedAt: new Date(),
      status: 'active',
      preferences: { twoFactorEnabled: true },
    });
    loginVerifications.issueChallenge.mockResolvedValue({
      challengeId: 'challenge-id',
      code: '123456',
      deliveryId: 'delivery-id',
      userId: 'user-id',
    });

    await expect(
      service.login(
        {
          email: 'user@example.com',
          password: 'not-a-real-user-password',
        },
        context,
      ),
    ).resolves.toEqual({
      status: 'verification-required',
      challengeId: 'challenge-id',
    });
    expect(emailService.sendLoginVerification).toHaveBeenCalledWith({
      to: 'user@example.com',
      code: '123456',
      idempotencyKey: 'login-verification/delivery-id',
    });
    expect(sessions.createLoginSession).not.toHaveBeenCalled();
  });

  it('creates the session only after atomically consuming the login challenge', async () => {
    const context = {
      requestMetadata: {
        requestId: 'verification-request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test-agent',
        method: 'POST',
        path: '/api/auth/login-verification/verify',
      },
      location: { city: null, region: null, country: 'United States' },
    };
    const session = { userSessionId: 'session-id', tokens: {} };
    loginVerifications.consumeChallenge.mockResolvedValue({
      status: 'verified',
      userId: 'user-id',
      authenticationMethod: 'password',
    });
    prisma.user.findUnique.mockResolvedValue({
      id: 'user-id',
      email: 'user@example.com',
      name: 'User',
      username: null,
      avatar: null,
      emailVerifiedAt: new Date(),
      status: 'active',
    });
    sessions.createLoginSession.mockResolvedValue(session);

    const result = await service.verifyLogin(
      { challengeId: 'challenge-id', code: '123456' },
      context,
    );

    expect(loginVerifications.consumeChallenge).toHaveBeenCalledWith(
      'challenge-id',
      '123456',
    );
    expect(sessions.createLoginSession).toHaveBeenCalledWith(
      'user-id',
      context,
      'password_email_code',
    );
    expect(result.session).toBe(session);
  });

  it('logs in an already-linked Google identity through the normal session pipeline', async () => {
    const context = {
      requestMetadata: {
        requestId: 'google-request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test-agent',
        method: 'GET',
        path: '/api/auth/google/callback',
      },
      location: { city: null, region: null, country: 'United States' },
    };
    googleAuth.exchangeAuthorizationCode.mockResolvedValue({
      providerUserId: 'google-subject',
      email: 'user@example.com',
      name: 'User',
      avatar: null,
    });
    prisma.$transaction.mockImplementation(
      (operation: (transaction: typeof prisma) => unknown) => operation(prisma),
    );
    prisma.authProvider.findUnique.mockResolvedValue({
      authProviderId: 'provider-id',
      providerEmail: 'user@example.com',
      user: {
        id: 'user-id',
        email: 'user@example.com',
        emailVerifiedAt: new Date(),
        status: 'active',
        preferences: { twoFactorEnabled: false },
      },
    });
    const session = { userSessionId: 'session-id', tokens: {} };
    sessions.createLoginSession.mockResolvedValue(session);

    await expect(
      service.loginWithGoogle(
        {
          code: 'authorization-code',
          state: 'state',
          expectedState: 'state',
        },
        context,
      ),
    ).resolves.toEqual({ status: 'authenticated', session });
    expect(sessions.createLoginSession).toHaveBeenCalledWith(
      'user-id',
      context,
      'google',
    );
  });

  it('refuses to silently link Google to an existing email account', async () => {
    const context = {
      requestMetadata: {
        requestId: 'google-link-request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test-agent',
        method: 'GET',
        path: '/api/auth/google/callback',
      },
      location: { city: null, region: null, country: null },
    };
    googleAuth.exchangeAuthorizationCode.mockResolvedValue({
      providerUserId: 'unlinked-google-subject',
      email: 'existing@example.com',
      name: 'Existing User',
      avatar: null,
    });
    prisma.$transaction.mockImplementation(
      (operation: (transaction: typeof prisma) => unknown) => operation(prisma),
    );
    prisma.authProvider.findUnique.mockResolvedValue(null);
    prisma.user.findUnique.mockResolvedValue({ id: 'existing-user-id' });

    await expect(
      service.loginWithGoogle(
        { code: 'code', state: 'state', expectedState: 'state' },
        context,
      ),
    ).rejects.toBeInstanceOf(GoogleAccountLinkRequiredError);
    expect(sessions.createLoginSession).not.toHaveBeenCalled();
    expect(audit.recordBestEffort).toHaveBeenCalledWith(
      expect.objectContaining({ reason: 'google_account_link_required' }),
    );
  });

  it('returns newly rotated tokens', async () => {
    const tokens = { accessToken: 'access', refreshToken: 'refresh' };
    sessions.refreshSession.mockResolvedValue({ status: 'rotated', tokens });

    const context = {
      requestMetadata: {
        requestId: 'request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test-agent',
        method: 'POST',
        path: '/api/auth/refresh',
      },
      location: { city: null, region: null, country: null },
    };

    await expect(
      service.refreshAuthSession('old-refresh', context),
    ).resolves.toBe(tokens);
    expect(sessions.refreshSession).toHaveBeenCalledWith(
      'old-refresh',
      context,
    );
  });

  it('links Google only after a fresh flow bound to the same session', async () => {
    const context = {
      requestMetadata: {
        requestId: 'request-id',
        ipAddress: '8.8.8.8',
        userAgent: 'test',
        method: 'GET',
        path: '/api/auth/google/callback',
      },
      location: { city: null, region: null, country: null },
    };
    authTokens.verifyAccessToken.mockResolvedValue({
      userId: 'user-id',
      userSessionId: 'session-id',
      tokenId: 'token-id',
    });
    googleAuth.exchangeLinkAuthorizationCode.mockResolvedValue({
      intent: { userId: 'user-id', userSessionId: 'session-id' },
      identity: {
        providerUserId: 'google-subject',
        email: 'different-google-email@example.com',
        name: 'User',
        avatar: null,
      },
    });
    prisma.userSession.findUnique.mockResolvedValue({
      userId: 'user-id',
      currentAuthSessionId: 'auth-session-id',
      revokedAt: null,
      user: { status: 'active', emailVerifiedAt: new Date() },
    });
    prisma.authProvider.findUnique
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(null);
    prisma.authProvider.create.mockResolvedValue({});
    prisma.$transaction.mockImplementation(
      (operation: (transaction: typeof prisma) => unknown) => operation(prisma),
    );

    await service.linkGoogleAccount(
      {
        code: 'code',
        state: 'state',
        expectedState: 'state',
        accessToken: 'access-token',
      },
      context,
    );

    expect(prisma.authProvider.create.mock.calls).toHaveLength(1);
    const createCalls = prisma.authProvider.create.mock
      .calls as unknown as Array<[{ data: Record<string, unknown> }]>;
    expect(createCalls[0][0]).toEqual({
      data: {
        userId: 'user-id',
        provider: 'GOOGLE',
        providerUserId: 'google-subject',
        providerEmail: 'different-google-email@example.com',
      },
    });
  });
});
