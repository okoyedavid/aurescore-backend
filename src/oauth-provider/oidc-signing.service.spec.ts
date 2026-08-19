import { ConfigService } from '@nestjs/config';
import { createPublicKey, createVerify } from 'node:crypto';
import { OidcSigningService } from './oidc-signing.service';

describe('OidcSigningService', () => {
  it('publishes a public JWKS key that verifies issued ID tokens', () => {
    const values: Record<string, string> = {
      PORT: '5000',
      NODE_ENV: 'test',
      OIDC_ISSUER: 'http://localhost:5000',
      OIDC_KEY_ID: 'test-key',
    };
    const config = {
      get: jest.fn((key: string, fallback?: string) => values[key] ?? fallback),
    } as unknown as ConfigService;
    const service = new OidcSigningService(config);

    const token = service.signIdToken({
      subject: 'pairwise-subject',
      clientId: 'auc_client',
      nonce: 'client-nonce',
      authTime: 1_787_000_000,
      name: 'Aurescore User',
      email: 'user@example.com',
      emailVerified: true,
    });
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
    const header = JSON.parse(
      Buffer.from(encodedHeader, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    const payload = JSON.parse(
      Buffer.from(encodedPayload, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    const jwk = service.jwks().keys[0];
    const valid = createVerify('RSA-SHA256')
      .update(`${encodedHeader}.${encodedPayload}`)
      .end()
      .verify(
        createPublicKey({ key: jwk, format: 'jwk' }),
        encodedSignature,
        'base64url',
      );

    expect(valid).toBe(true);
    expect(header).toMatchObject({ alg: 'RS256', kid: 'test-key' });
    expect(payload).toMatchObject({
      iss: 'http://localhost:5000',
      sub: 'pairwise-subject',
      aud: 'auc_client',
      nonce: 'client-nonce',
      email: 'user@example.com',
      email_verified: true,
    });
    expect(jwk).not.toHaveProperty('d');
  });
});
