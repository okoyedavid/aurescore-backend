import { validateEnvironment } from './environment';

describe('validateEnvironment', () => {
  const valid = {
    DATABASE_URL: 'postgresql://user:password@localhost/database',
    REDIS_URL: 'redis://localhost:6379',
    VERIFICATION_CODE_PEPPER: 'v'.repeat(32),
    AUDIT_LOG_PEPPER: 'a'.repeat(32),
    RATE_LIMIT_PEPPER: 'r'.repeat(32),
    RESEND_KEY: 'resend-key',
    RESEND_FROM_EMAIL: 'Aurescore <test@example.com>',
    JWT_ACCESS_SECRET: 'x'.repeat(32),
    JWT_REFRESH_SECRET: 'y'.repeat(32),
    JWT_ACCESS_EXPIRES: '15m',
    JWT_REFRESH_EXPIRES: '1d',
    GOOGLE_CLIENT_ID: 'client-id',
    GOOGLE_CLIENT_SECRET: 'client-secret',
    GOOGLE_REDIRECT_URL: 'https://api.example.com/api/auth/google/callback',
  };

  it('fails closed when secure production cookie/proxy configuration is absent', () => {
    expect(() =>
      validateEnvironment({
        ...valid,
        NODE_ENV: 'production',
        FRONTEND_URL: 'https://example.com',
        OIDC_ISSUER: 'https://api.example.com',
        OIDC_PRIVATE_KEY_BASE64: 'private-key',
        OIDC_KEY_ID: 'key-id',
      }),
    ).toThrow('TRUST_PROXY is required');
  });

  it('accepts explicit secure production settings', () => {
    expect(
      validateEnvironment({
        ...valid,
        NODE_ENV: 'production',
        FRONTEND_URL: 'https://example.com',
        OIDC_ISSUER: 'https://api.example.com',
        OIDC_PRIVATE_KEY_BASE64: 'private-key',
        OIDC_KEY_ID: 'key-id',
        TRUST_PROXY: '1',
        COOKIE_SECURE: 'true',
      }),
    ).toMatchObject({ COOKIE_SECURE: 'true', TRUST_PROXY: '1' });
  });
});
