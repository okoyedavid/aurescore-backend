import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  generateKeyPairSync,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';

@Injectable()
export class OidcSigningService {
  private readonly logger = new Logger(OidcSigningService.name);
  private readonly privateKey: KeyObject;
  private readonly publicJwk: JsonWebKey & {
    kid: string;
    use: 'sig';
    alg: 'RS256';
  };
  readonly issuer: string;

  constructor(configService: ConfigService) {
    const configuredIssuer = configService.get<string>('OIDC_ISSUER');
    const port = configService.get<string>('PORT', '3001');
    this.issuer = (configuredIssuer ?? `http://localhost:${port}`).replace(
      /\/$/,
      '',
    );

    const encodedPrivateKey = configService.get<string>(
      'OIDC_PRIVATE_KEY_BASE64',
    );
    if (encodedPrivateKey) {
      this.privateKey = createPrivateKey(
        Buffer.from(encodedPrivateKey, 'base64').toString('utf8'),
      );
    } else {
      if (configService.get<string>('NODE_ENV') === 'production') {
        throw new Error('OIDC_PRIVATE_KEY_BASE64 is required in production');
      }
      this.privateKey = generateKeyPairSync('rsa', {
        modulusLength: 2048,
      }).privateKey;
      this.logger.warn(
        'Using an ephemeral OIDC signing key. Configure OIDC_PRIVATE_KEY_BASE64 before deployment.',
      );
    }

    const publicKey = createPublicKey(this.privateKey);
    const exported = publicKey.export({ format: 'jwk' });
    const thumbprint = createHash('sha256')
      .update(
        JSON.stringify({ e: exported.e, kty: exported.kty, n: exported.n }),
      )
      .digest('base64url')
      .slice(0, 16);
    this.publicJwk = {
      ...exported,
      kid: configService.get<string>('OIDC_KEY_ID', thumbprint),
      use: 'sig',
      alg: 'RS256',
    };
  }

  signIdToken(input: {
    subject: string;
    clientId: string;
    nonce: string;
    authTime: number;
    name?: string;
    picture?: string | null;
    email?: string;
    emailVerified?: boolean;
  }): string {
    const issuedAt = Math.floor(Date.now() / 1_000);
    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: this.publicJwk.kid,
    };
    const payload = {
      iss: this.issuer,
      sub: input.subject,
      aud: input.clientId,
      iat: issuedAt,
      exp: issuedAt + 10 * 60,
      auth_time: input.authTime,
      nonce: input.nonce,
      ...(input.name ? { name: input.name } : {}),
      ...(input.picture ? { picture: input.picture } : {}),
      ...(input.email ? { email: input.email } : {}),
      ...(input.email !== undefined
        ? { email_verified: input.emailVerified === true }
        : {}),
    };
    const signingInput = `${this.encode(header)}.${this.encode(payload)}`;
    const signature = createSign('RSA-SHA256')
      .update(signingInput)
      .end()
      .sign(this.privateKey)
      .toString('base64url');
    return `${signingInput}.${signature}`;
  }

  jwks() {
    return { keys: [this.publicJwk] };
  }

  private encode(value: object): string {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
  }
}
