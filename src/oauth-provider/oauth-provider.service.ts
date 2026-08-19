import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { verify } from 'argon2';
import { createHash, randomBytes } from 'node:crypto';
import type { Request } from 'express';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENTS } from '../audit/audit-event.types';
import { AuthTokenService } from '../auth-token/auth-token.service';
import { PrismaService } from '../database/prisma.service';
import { RedisService } from '../redis/redis.service';
import type { RequestLocationContext } from '../location/location.service';
import {
  isSupportedScope,
  normalizeScopes,
  OAUTH_ACCESS_TOKEN_TTL_SECONDS,
  OAUTH_CODE_TTL_SECONDS,
  OAUTH_INTERACTION_TTL_SECONDS,
  type OidcScope,
} from '../oauth-common/oauth.constants';
import { OAuthRateLimitService } from '../oauth-common/oauth-rate-limit.service';
import type { AuthorizeDto } from './dto/authorize.dto';
import type { ConsentDecisionDto } from './dto/consent-decision.dto';
import type { TokenRequestDto } from './dto/token-request.dto';
import { OAuthProtocolException } from './oauth-protocol.exception';
import type {
  OAuthAccessTokenRecord,
  OAuthAuthenticatedUser,
  OAuthAuthorizationCode,
  OAuthInteraction,
} from './oauth-provider.types';
import { OidcSigningService } from './oidc-signing.service';

export type AuthorizationPageResult =
  | { kind: 'redirect'; url: string }
  | {
      kind: 'consent';
      interaction: string;
      consentToken: string;
      client: {
        name: string;
        description: string | null;
        homepageUrl: string | null;
        logoUrl: string | null;
        firstParty: boolean;
      };
      scopes: OidcScope[];
      user: { email: string; name: string };
    };

@Injectable()
export class OAuthProviderService {
  private readonly frontendUrl: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
    private readonly authTokens: AuthTokenService,
    private readonly signing: OidcSigningService,
    private readonly rateLimits: OAuthRateLimitService,
    private readonly audit: AuditService,
    configService: ConfigService,
  ) {
    this.frontendUrl = configService.get<string>(
      'FRONTEND_URL',
      configService.get<string>('NODE_ENV') === 'production'
        ? 'https://aurescore.okoyedavid.com'
        : 'http://localhost:3000',
    );
  }

  async startAuthorization(
    input: AuthorizeDto,
    request: Request,
    context: RequestLocationContext,
  ): Promise<AuthorizationPageResult> {
    await this.rateLimits.consume(
      'authorize',
      `${context.requestMetadata.ipAddress ?? 'unknown'}:${input.client_id}`,
      30,
      15 * 60,
    );
    const client = await this.requireAuthorizationClient(
      input.client_id,
      input.redirect_uri,
    );
    let scopes: OidcScope[];
    try {
      scopes = this.validateScopes(input.scope, client.allowedScopes);
    } catch (error: unknown) {
      if (
        error instanceof OAuthProtocolException &&
        error.errorCode === 'invalid_scope'
      ) {
        const url = new URL(input.redirect_uri);
        url.searchParams.set('error', 'invalid_scope');
        url.searchParams.set('state', input.state);
        return { kind: 'redirect', url: url.toString() };
      }
      throw error;
    }
    const interaction: OAuthInteraction = {
      clientId: client.clientId,
      redirectUri: input.redirect_uri,
      scopes,
      state: input.state,
      nonce: input.nonce,
      codeChallenge: input.code_challenge,
      forceConsent: input.prompt === 'consent',
      createdAt: new Date().toISOString(),
    };
    const interactionId = this.randomValue();
    const stored = await this.redis.client.set(
      this.interactionKey(interactionId),
      JSON.stringify(interaction),
      { EX: OAUTH_INTERACTION_TTL_SECONDS, NX: true },
    );
    if (stored !== 'OK') {
      throw new OAuthProtocolException(
        'server_error',
        500,
        'Authorization could not be started',
      );
    }
    return this.advanceAuthorization(interactionId, request, interaction);
  }

  continueAuthorization(interactionId: string, request: Request) {
    return this.advanceAuthorization(interactionId, request);
  }

  async decideConsent(
    input: ConsentDecisionDto,
    request: Request,
    context: RequestLocationContext,
  ): Promise<{ url: string }> {
    await this.rateLimits.consume(
      'consent',
      `${context.requestMetadata.ipAddress ?? 'unknown'}:${input.interaction}`,
      10,
      10 * 60,
    );
    const authenticated = await this.authenticateAurescoreRequest(request);
    if (!authenticated) {
      throw new OAuthProtocolException(
        'access_denied',
        401,
        'Aurescore authentication is required',
      );
    }
    const consentBinding = await this.redis.client.getDel(
      this.consentKey(input.consent_token),
    );
    if (
      consentBinding !==
      `${this.digest(input.interaction)}:${authenticated.userId}`
    ) {
      throw new OAuthProtocolException(
        'invalid_request',
        400,
        'Consent interaction is invalid or expired',
      );
    }

    const interaction = await this.readInteraction(input.interaction);
    await this.requireAuthorizationClient(
      interaction.clientId,
      interaction.redirectUri,
    );

    if (input.decision === 'deny') {
      await this.consumeInteraction(input.interaction, interaction);
      await this.audit.recordBestEffort({
        eventType: AUDIT_EVENTS.OAUTH_AUTHORIZATION_DENIED,
        category: 'security',
        outcome: 'blocked',
        userId: authenticated.userId,
        context,
        metadata: { clientId: interaction.clientId },
      });
      return {
        url: this.authorizationRedirect(interaction, {
          error: 'access_denied',
        }),
      };
    }

    await this.consumeInteraction(input.interaction, interaction);
    const grant = await this.prisma.$transaction(async (transaction) => {
      const existing = await transaction.oAuthGrant.findUnique({
        where: {
          userId_clientId: {
            userId: authenticated.userId,
            clientId: interaction.clientId,
          },
        },
        select: { grantId: true, subject: true, scopes: true },
      });
      const scopes = normalizeScopes([
        ...(existing?.scopes ?? []),
        ...interaction.scopes,
      ]);
      const saved = existing
        ? await transaction.oAuthGrant.update({
            where: { grantId: existing.grantId },
            data: {
              scopes,
              revokedAt: null,
              grantedAt: new Date(),
              lastUsedAt: new Date(),
            },
            select: { grantId: true, subject: true },
          })
        : await transaction.oAuthGrant.create({
            data: {
              userId: authenticated.userId,
              clientId: interaction.clientId,
              subject: `ausub_${randomBytes(24).toString('base64url')}`,
              scopes,
              lastUsedAt: new Date(),
            },
            select: { grantId: true, subject: true },
          });
      await this.audit.record(
        {
          eventType: AUDIT_EVENTS.OAUTH_AUTHORIZATION_APPROVED,
          category: 'security',
          outcome: 'success',
          userId: authenticated.userId,
          context,
          metadata: {
            clientId: interaction.clientId,
            scopes: interaction.scopes.join(' '),
          },
        },
        transaction,
      );
      return saved;
    });

    return {
      url: await this.issueAuthorizationCode(
        input.interaction,
        interaction,
        authenticated,
        grant,
        true,
      ),
    };
  }

  async exchangeCode(
    input: TokenRequestDto,
    authorizationHeader: string | undefined,
    context: RequestLocationContext,
  ) {
    const credentials = this.parseClientCredentials(authorizationHeader);
    await this.rateLimits.consume(
      'token',
      `${context.requestMetadata.ipAddress ?? 'unknown'}:${credentials.clientId}`,
      60,
      60,
    );

    try {
      const client = await this.prisma.oAuthClient.findUnique({
        where: { clientId: credentials.clientId },
        select: {
          clientId: true,
          clientSecretHash: true,
          isActive: true,
        },
      });
      if (
        !client ||
        !client.isActive ||
        !(await this.verifyClientSecret(
          client.clientSecretHash,
          credentials.clientSecret,
        ))
      ) {
        throw new OAuthProtocolException(
          'invalid_client',
          401,
          'Client authentication failed',
        );
      }

      const codeValue = await this.redis.client.get(this.codeKey(input.code));
      if (!codeValue) {
        throw new OAuthProtocolException(
          'invalid_grant',
          400,
          'Authorization code is invalid or expired',
        );
      }
      const authorizationCode = this.parseAuthorizationCode(codeValue);
      const expectedChallenge = createHash('sha256')
        .update(input.code_verifier)
        .digest('base64url');
      if (
        authorizationCode.clientId !== client.clientId ||
        authorizationCode.redirectUri !== input.redirect_uri ||
        authorizationCode.codeChallenge !== expectedChallenge
      ) {
        throw new OAuthProtocolException(
          'invalid_grant',
          400,
          'Authorization code validation failed',
        );
      }

      const grant = await this.prisma.oAuthGrant.findFirst({
        where: {
          grantId: authorizationCode.grantId,
          userId: authorizationCode.userId,
          clientId: authorizationCode.clientId,
          subject: authorizationCode.subject,
          revokedAt: null,
          client: { isActive: true },
          user: { status: 'active', emailVerifiedAt: { not: null } },
        },
        select: {
          grantId: true,
          user: {
            select: {
              name: true,
              avatar: true,
              email: true,
              emailVerifiedAt: true,
            },
          },
        },
      });
      if (!grant) {
        throw new OAuthProtocolException(
          'invalid_grant',
          400,
          'Authorization grant is no longer available',
        );
      }

      const claimedCode = await this.redis.client.getDel(
        this.codeKey(input.code),
      );
      if (claimedCode !== codeValue) {
        throw new OAuthProtocolException(
          'invalid_grant',
          400,
          'Authorization code has already been used',
        );
      }

      const accessToken = `aat_${this.randomValue()}`;
      const accessRecord: OAuthAccessTokenRecord = {
        userId: authorizationCode.userId,
        grantId: authorizationCode.grantId,
        subject: authorizationCode.subject,
        clientId: authorizationCode.clientId,
        scopes: authorizationCode.scopes,
      };
      const storedAccessToken = await this.redis.client.set(
        this.accessTokenKey(accessToken),
        JSON.stringify(accessRecord),
        { EX: OAUTH_ACCESS_TOKEN_TTL_SECONDS, NX: true },
      );
      if (storedAccessToken !== 'OK') {
        throw new OAuthProtocolException(
          'server_error',
          500,
          'Access token could not be issued',
        );
      }

      const hasProfile = authorizationCode.scopes.includes('profile');
      const hasEmail = authorizationCode.scopes.includes('email');
      const idToken = this.signing.signIdToken({
        subject: authorizationCode.subject,
        clientId: authorizationCode.clientId,
        nonce: authorizationCode.nonce,
        authTime: authorizationCode.authTime,
        ...(hasProfile
          ? { name: grant.user.name, picture: grant.user.avatar }
          : {}),
        ...(hasEmail
          ? {
              email: grant.user.email,
              emailVerified: Boolean(grant.user.emailVerifiedAt),
            }
          : {}),
      });

      await this.prisma.$transaction(async (transaction) => {
        await transaction.oAuthGrant.update({
          where: { grantId: grant.grantId },
          data: { lastUsedAt: new Date() },
        });
        await this.audit.record(
          {
            eventType: AUDIT_EVENTS.OAUTH_TOKEN_ISSUED,
            category: 'security',
            outcome: 'success',
            userId: authorizationCode.userId,
            context,
            metadata: { clientId: authorizationCode.clientId },
          },
          transaction,
        );
      });

      return {
        token_type: 'Bearer',
        access_token: accessToken,
        expires_in: OAUTH_ACCESS_TOKEN_TTL_SECONDS,
        scope: authorizationCode.scopes.join(' '),
        id_token: idToken,
      };
    } catch (error: unknown) {
      await this.audit.recordBestEffort({
        eventType: AUDIT_EVENTS.OAUTH_TOKEN_REJECTED,
        category: 'security',
        outcome: 'blocked',
        severity: 'warning',
        context,
        reason:
          error instanceof OAuthProtocolException
            ? error.errorCode
            : 'token_exchange_failed',
        metadata: { clientId: credentials.clientId },
      });
      throw error;
    }
  }

  async userInfo(
    authorizationHeader: string | undefined,
    context: RequestLocationContext,
  ) {
    const accessToken = this.parseBearerToken(authorizationHeader);
    await this.rateLimits.consume(
      'userinfo',
      `${context.requestMetadata.ipAddress ?? 'unknown'}:${this.digest(accessToken)}`,
      120,
      60,
    );
    const stored = await this.redis.client.get(
      this.accessTokenKey(accessToken),
    );
    if (!stored) {
      throw new OAuthProtocolException(
        'invalid_grant',
        401,
        'Access token is invalid or expired',
      );
    }
    const token = this.parseAccessToken(stored);
    const grant = await this.prisma.oAuthGrant.findFirst({
      where: {
        grantId: token.grantId,
        userId: token.userId,
        clientId: token.clientId,
        subject: token.subject,
        revokedAt: null,
        client: { isActive: true },
        user: { status: 'active', emailVerifiedAt: { not: null } },
      },
      select: {
        user: {
          select: {
            name: true,
            avatar: true,
            username: true,
            email: true,
            emailVerifiedAt: true,
          },
        },
      },
    });
    if (!grant) {
      throw new OAuthProtocolException(
        'invalid_grant',
        401,
        'Access token is no longer valid',
      );
    }

    return {
      sub: token.subject,
      ...(token.scopes.includes('profile')
        ? {
            name: grant.user.name,
            picture: grant.user.avatar,
            preferred_username: grant.user.username,
          }
        : {}),
      ...(token.scopes.includes('email')
        ? {
            email: grant.user.email,
            email_verified: Boolean(grant.user.emailVerifiedAt),
          }
        : {}),
    };
  }

  discovery() {
    const base = this.signing.issuer;
    return {
      issuer: base,
      authorization_endpoint: `${base}/api/oauth/authorize`,
      token_endpoint: `${base}/api/oauth/token`,
      userinfo_endpoint: `${base}/api/oauth/userinfo`,
      jwks_uri: `${base}/api/oauth/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_basic'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: [
        'sub',
        'iss',
        'aud',
        'exp',
        'iat',
        'auth_time',
        'nonce',
        'name',
        'picture',
        'preferred_username',
        'email',
        'email_verified',
      ],
    };
  }

  jwks() {
    return this.signing.jwks();
  }

  private async advanceAuthorization(
    interactionId: string,
    request: Request,
    knownInteraction?: OAuthInteraction,
  ): Promise<AuthorizationPageResult> {
    const interaction =
      knownInteraction ?? (await this.readInteraction(interactionId));
    const client = await this.requireAuthorizationClient(
      interaction.clientId,
      interaction.redirectUri,
    );
    const authenticated = await this.authenticateAurescoreRequest(request);
    if (!authenticated) {
      const login = new URL('/login', this.frontendUrl);
      login.searchParams.set('oauthInteraction', interactionId);
      return { kind: 'redirect', url: login.toString() };
    }

    const grant = await this.prisma.oAuthGrant.findUnique({
      where: {
        userId_clientId: {
          userId: authenticated.userId,
          clientId: interaction.clientId,
        },
      },
      select: { grantId: true, subject: true, scopes: true, revokedAt: true },
    });
    const alreadyGranted =
      grant &&
      !grant.revokedAt &&
      interaction.scopes.every((scope) => grant.scopes.includes(scope));
    if ((client.firstParty || alreadyGranted) && !interaction.forceConsent) {
      const usableGrant =
        grant && !grant.revokedAt
          ? grant
          : await this.createFirstPartyGrant(
              authenticated.userId,
              interaction.clientId,
              interaction.scopes,
            );
      return {
        kind: 'redirect',
        url: await this.issueAuthorizationCode(
          interactionId,
          interaction,
          authenticated,
          usableGrant,
        ),
      };
    }

    const consentToken = this.randomValue();
    const storedConsent = await this.redis.client.set(
      this.consentKey(consentToken),
      `${this.digest(interactionId)}:${authenticated.userId}`,
      { EX: OAUTH_INTERACTION_TTL_SECONDS, NX: true },
    );
    if (storedConsent !== 'OK') {
      throw new OAuthProtocolException(
        'server_error',
        500,
        'Consent could not be started',
      );
    }
    const user = await this.prisma.user.findUnique({
      where: { id: authenticated.userId },
      select: { email: true, name: true },
    });
    if (!user) {
      throw new OAuthProtocolException(
        'access_denied',
        401,
        'Aurescore account is unavailable',
      );
    }
    return {
      kind: 'consent',
      interaction: interactionId,
      consentToken,
      client: {
        name: client.name,
        description: client.description,
        homepageUrl: client.homepageUrl,
        logoUrl: client.logoUrl,
        firstParty: client.firstParty,
      },
      scopes: interaction.scopes,
      user,
    };
  }

  private async createFirstPartyGrant(
    userId: string,
    clientId: string,
    scopes: OidcScope[],
  ) {
    return this.prisma.oAuthGrant.upsert({
      where: { userId_clientId: { userId, clientId } },
      update: { scopes, revokedAt: null, lastUsedAt: new Date() },
      create: {
        userId,
        clientId,
        scopes,
        subject: `ausub_${randomBytes(24).toString('base64url')}`,
        lastUsedAt: new Date(),
      },
      select: { grantId: true, subject: true },
    });
  }

  private async issueAuthorizationCode(
    interactionId: string,
    interaction: OAuthInteraction,
    authenticated: OAuthAuthenticatedUser,
    grant: { grantId: string; subject: string },
    interactionAlreadyConsumed = false,
  ): Promise<string> {
    if (!interactionAlreadyConsumed) {
      await this.consumeInteraction(interactionId, interaction);
    }
    const code = `auc_code_${this.randomValue()}`;
    const record: OAuthAuthorizationCode = {
      userId: authenticated.userId,
      grantId: grant.grantId,
      subject: grant.subject,
      clientId: interaction.clientId,
      redirectUri: interaction.redirectUri,
      scopes: interaction.scopes,
      nonce: interaction.nonce,
      codeChallenge: interaction.codeChallenge,
      authTime: authenticated.authTime,
    };
    const stored = await this.redis.client.set(
      this.codeKey(code),
      JSON.stringify(record),
      { EX: OAUTH_CODE_TTL_SECONDS, NX: true },
    );
    if (stored !== 'OK') {
      throw new OAuthProtocolException(
        'server_error',
        500,
        'Authorization code could not be issued',
      );
    }
    return this.authorizationRedirect(interaction, { code });
  }

  private async consumeInteraction(
    interactionId: string,
    expected: OAuthInteraction,
  ): Promise<void> {
    const consumed = await this.redis.client.getDel(
      this.interactionKey(interactionId),
    );
    if (!consumed || consumed !== JSON.stringify(expected)) {
      throw new OAuthProtocolException(
        'invalid_request',
        400,
        'Authorization interaction has already been completed',
      );
    }
  }

  private async readInteraction(
    interactionId: string,
  ): Promise<OAuthInteraction> {
    const stored = await this.redis.client.get(
      this.interactionKey(interactionId),
    );
    if (!stored) {
      throw new OAuthProtocolException(
        'invalid_request',
        400,
        'Authorization interaction is invalid or expired',
      );
    }
    return this.parseInteraction(stored);
  }

  private async authenticateAurescoreRequest(
    request: Request,
  ): Promise<OAuthAuthenticatedUser | null> {
    const cookies: unknown = (request as unknown as { cookies?: unknown })
      .cookies;
    if (typeof cookies !== 'object' || cookies === null) return null;
    const accessToken = (cookies as Record<string, unknown>).accessToken;
    if (typeof accessToken !== 'string' || !accessToken) return null;

    try {
      const claims = await this.authTokens.verifyAccessToken(accessToken);
      const session = await this.prisma.userSession.findUnique({
        where: { userSessionId: claims.userSessionId },
        select: {
          userId: true,
          currentAuthSessionId: true,
          revokedAt: true,
          createdAt: true,
          user: { select: { status: true, emailVerifiedAt: true } },
        },
      });
      if (
        !session ||
        session.userId !== claims.userId ||
        session.revokedAt ||
        !session.currentAuthSessionId ||
        session.user.status !== 'active' ||
        !session.user.emailVerifiedAt
      ) {
        return null;
      }
      return {
        userId: claims.userId,
        userSessionId: claims.userSessionId,
        authTime: Math.floor(session.createdAt.getTime() / 1_000),
      };
    } catch {
      return null;
    }
  }

  private async requireAuthorizationClient(
    clientId: string,
    redirectUri: string,
  ) {
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId },
      select: {
        clientId: true,
        name: true,
        description: true,
        homepageUrl: true,
        logoUrl: true,
        redirectUris: true,
        allowedScopes: true,
        isActive: true,
        firstParty: true,
      },
    });
    if (!client || !client.isActive) {
      throw new OAuthProtocolException(
        'unauthorized_client',
        400,
        'OAuth client is invalid or inactive',
      );
    }
    if (!client.redirectUris.includes(redirectUri)) {
      throw new OAuthProtocolException(
        'invalid_request',
        400,
        'Redirect URI is not registered for this client',
      );
    }
    return client;
  }

  private validateScopes(scope: string, allowed: string[]): OidcScope[] {
    const scopes = normalizeScopes(scope);
    if (
      !scopes.includes('openid') ||
      scopes.some(
        (value) => !isSupportedScope(value) || !allowed.includes(value),
      )
    ) {
      throw new OAuthProtocolException(
        'invalid_scope',
        400,
        'Requested scopes are not allowed',
      );
    }
    return scopes;
  }

  private parseClientCredentials(value: string | undefined): {
    clientId: string;
    clientSecret: string;
  } {
    if (!value || !/^Basic /i.test(value)) {
      throw new OAuthProtocolException(
        'invalid_client',
        401,
        'Client authentication is required',
      );
    }
    try {
      const decoded = Buffer.from(value.slice(6), 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      if (separator <= 0) throw new Error('invalid credentials');
      const clientId = decoded.slice(0, separator);
      const clientSecret = decoded.slice(separator + 1);
      if (!clientSecret) throw new Error('invalid credentials');
      return { clientId, clientSecret };
    } catch {
      throw new OAuthProtocolException(
        'invalid_client',
        401,
        'Client authentication is invalid',
      );
    }
  }

  private parseBearerToken(value: string | undefined): string {
    if (!value?.startsWith('Bearer ') || value.length <= 7) {
      throw new OAuthProtocolException(
        'invalid_grant',
        401,
        'Bearer access token is required',
      );
    }
    return value.slice(7);
  }

  private async verifyClientSecret(
    hash: string,
    secret: string,
  ): Promise<boolean> {
    try {
      return await verify(hash, secret);
    } catch {
      return false;
    }
  }

  private authorizationRedirect(
    interaction: OAuthInteraction,
    values: { code?: string; error?: string },
  ): string {
    const url = new URL(interaction.redirectUri);
    if (values.code) url.searchParams.set('code', values.code);
    if (values.error) url.searchParams.set('error', values.error);
    url.searchParams.set('state', interaction.state);
    return url.toString();
  }

  private parseInteraction(value: string): OAuthInteraction {
    const parsed = this.parseObject(value);
    if (
      typeof parsed.clientId !== 'string' ||
      typeof parsed.redirectUri !== 'string' ||
      !Array.isArray(parsed.scopes) ||
      !parsed.scopes.every(
        (scope) => typeof scope === 'string' && isSupportedScope(scope),
      ) ||
      typeof parsed.state !== 'string' ||
      typeof parsed.nonce !== 'string' ||
      typeof parsed.codeChallenge !== 'string' ||
      typeof parsed.forceConsent !== 'boolean' ||
      typeof parsed.createdAt !== 'string'
    ) {
      throw new OAuthProtocolException(
        'invalid_request',
        400,
        'Stored interaction is invalid',
      );
    }
    return parsed as unknown as OAuthInteraction;
  }

  private parseAuthorizationCode(value: string): OAuthAuthorizationCode {
    const parsed = this.parseObject(value);
    if (
      typeof parsed.userId !== 'string' ||
      typeof parsed.grantId !== 'string' ||
      typeof parsed.subject !== 'string' ||
      typeof parsed.clientId !== 'string' ||
      typeof parsed.redirectUri !== 'string' ||
      !Array.isArray(parsed.scopes) ||
      !parsed.scopes.every(
        (scope) => typeof scope === 'string' && isSupportedScope(scope),
      ) ||
      typeof parsed.nonce !== 'string' ||
      typeof parsed.codeChallenge !== 'string' ||
      typeof parsed.authTime !== 'number'
    ) {
      throw new OAuthProtocolException(
        'invalid_grant',
        400,
        'Stored authorization code is invalid',
      );
    }
    return parsed as unknown as OAuthAuthorizationCode;
  }

  private parseAccessToken(value: string): OAuthAccessTokenRecord {
    const parsed = this.parseObject(value);
    if (
      typeof parsed.userId !== 'string' ||
      typeof parsed.grantId !== 'string' ||
      typeof parsed.subject !== 'string' ||
      typeof parsed.clientId !== 'string' ||
      !Array.isArray(parsed.scopes) ||
      !parsed.scopes.every(
        (scope) => typeof scope === 'string' && isSupportedScope(scope),
      )
    ) {
      throw new OAuthProtocolException(
        'invalid_grant',
        401,
        'Stored access token is invalid',
      );
    }
    return parsed as unknown as OAuthAccessTokenRecord;
  }

  private parseObject(value: string): Record<string, unknown> {
    try {
      const parsed: unknown = JSON.parse(value);
      if (
        typeof parsed === 'object' &&
        parsed !== null &&
        !Array.isArray(parsed)
      ) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // A protocol-safe error is returned below.
    }
    throw new OAuthProtocolException(
      'server_error',
      500,
      'Stored OAuth state is invalid',
    );
  }

  private interactionKey(value: string): string {
    return `oauth:interaction:${this.digest(value)}`;
  }

  private consentKey(value: string): string {
    return `oauth:consent:${this.digest(value)}`;
  }

  private codeKey(value: string): string {
    return `oauth:code:${this.digest(value)}`;
  }

  private accessTokenKey(value: string): string {
    return `oauth:access:${this.digest(value)}`;
  }

  private digest(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  private randomValue(): string {
    return randomBytes(32).toString('base64url');
  }
}
