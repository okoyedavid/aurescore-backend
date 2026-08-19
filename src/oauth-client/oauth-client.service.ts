import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { argon2id, hash } from 'argon2';
import { randomBytes } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AUDIT_EVENTS } from '../audit/audit-event.types';
import { PrismaService } from '../database/prisma.service';
import type { RequestLocationContext } from '../location/location.service';
import { normalizeScopes } from '../oauth-common/oauth.constants';
import { OAuthRateLimitService } from '../oauth-common/oauth-rate-limit.service';
import type { CreateOAuthClientDto } from './dto/create-oauth-client.dto';

@Injectable()
export class OAuthClientService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly rateLimits: OAuthRateLimitService,
  ) {}

  async create(
    ownerUserId: string,
    input: CreateOAuthClientDto,
    context: RequestLocationContext,
  ) {
    await this.rateLimits.consume('client-create', ownerUserId, 5, 60 * 60);

    const redirectUris = input.redirectUris.map((value) =>
      this.validateRedirectUri(value),
    );
    if (new Set(redirectUris).size !== redirectUris.length) {
      throw new BadRequestException('Redirect URIs must be unique');
    }
    const allowedScopes = normalizeScopes(input.allowedScopes);
    if (!allowedScopes.includes('openid')) {
      throw new BadRequestException('The openid scope is required');
    }

    const homepageUrl = input.homepageUrl
      ? this.validateWebsiteUrl(input.homepageUrl, 'homepageUrl')
      : null;
    const logoUrl = input.logoUrl
      ? this.validateWebsiteUrl(input.logoUrl, 'logoUrl')
      : null;
    const clientId = `auc_${randomBytes(24).toString('base64url')}`;
    const clientSecret = this.generateSecret();
    const clientSecretHash = await this.hashSecret(clientSecret);
    const slug = `${this.slugify(input.name)}-${randomBytes(4).toString('hex')}`;

    const client = await this.prisma.$transaction(async (transaction) => {
      const created = await transaction.oAuthClient.create({
        data: {
          clientId,
          ownerUserId,
          name: input.name,
          slug,
          description: input.description || null,
          homepageUrl,
          logoUrl,
          clientSecretHash,
          clientSecretHint: clientSecret.slice(-6),
          redirectUris,
          allowedScopes,
        },
        select: this.clientSelect(),
      });
      await this.audit.record(
        {
          eventType: AUDIT_EVENTS.OAUTH_CLIENT_CREATED,
          category: 'security',
          outcome: 'success',
          userId: ownerUserId,
          context,
          metadata: { clientId, name: input.name },
        },
        transaction,
      );
      return created;
    });

    return { ...client, clientSecret };
  }

  list(ownerUserId: string) {
    return this.prisma.oAuthClient.findMany({
      where: { ownerUserId },
      orderBy: { createdAt: 'desc' },
      select: this.clientSelect(),
    });
  }

  async get(ownerUserId: string, clientId: string) {
    const client = await this.prisma.oAuthClient.findFirst({
      where: { clientId, ownerUserId },
      select: this.clientSelect(),
    });
    if (!client) throw new NotFoundException('OAuth client not found');
    return client;
  }

  async rotateSecret(
    ownerUserId: string,
    clientId: string,
    context: RequestLocationContext,
  ) {
    await this.rateLimits.consume(
      'client-secret-rotate',
      `${ownerUserId}:${clientId}`,
      5,
      24 * 60 * 60,
    );
    await this.get(ownerUserId, clientId);
    const clientSecret = this.generateSecret();
    const clientSecretHash = await this.hashSecret(clientSecret);
    const secretCreatedAt = new Date();

    await this.prisma.$transaction(async (transaction) => {
      await transaction.oAuthClient.update({
        where: { clientId },
        data: {
          clientSecretHash,
          clientSecretHint: clientSecret.slice(-6),
          secretCreatedAt,
        },
      });
      await this.audit.record(
        {
          eventType: AUDIT_EVENTS.OAUTH_CLIENT_SECRET_ROTATED,
          category: 'security',
          outcome: 'success',
          userId: ownerUserId,
          context,
          metadata: { clientId },
        },
        transaction,
      );
    });
    return { clientId, clientSecret, secretCreatedAt };
  }

  async disable(
    ownerUserId: string,
    clientId: string,
    context: RequestLocationContext,
  ) {
    await this.get(ownerUserId, clientId);
    await this.prisma.$transaction(async (transaction) => {
      await transaction.oAuthClient.update({
        where: { clientId },
        data: { isActive: false },
      });
      await transaction.oAuthGrant.updateMany({
        where: { clientId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await this.audit.record(
        {
          eventType: AUDIT_EVENTS.OAUTH_CLIENT_DISABLED,
          category: 'security',
          outcome: 'success',
          userId: ownerUserId,
          context,
          metadata: { clientId },
        },
        transaction,
      );
    });
    return { message: 'OAuth client disabled successfully' };
  }

  private clientSelect() {
    return {
      clientId: true,
      name: true,
      slug: true,
      description: true,
      homepageUrl: true,
      logoUrl: true,
      clientSecretHint: true,
      secretCreatedAt: true,
      redirectUris: true,
      allowedScopes: true,
      clientType: true,
      isActive: true,
      firstParty: true,
      createdAt: true,
      updatedAt: true,
    } as const;
  }

  private generateSecret(): string {
    return `aus_${randomBytes(32).toString('base64url')}`;
  }

  private hashSecret(secret: string): Promise<string> {
    return hash(secret, {
      type: argon2id,
      memoryCost: 19_456,
      timeCost: 2,
      parallelism: 1,
    });
  }

  private validateRedirectUri(value: string): string {
    const url = this.parseUrl(value, 'redirect URI');
    if (url.hash || url.search || url.username || url.password) {
      throw new BadRequestException(
        'Redirect URIs cannot contain credentials, query strings, or fragments',
      );
    }
    this.requireSecureUrl(url, 'redirect URI');
    return url.toString();
  }

  private validateWebsiteUrl(value: string, field: string): string {
    const url = this.parseUrl(value, field);
    if (url.username || url.password) {
      throw new BadRequestException(`${field} cannot contain credentials`);
    }
    this.requireSecureUrl(url, field);
    return url.toString();
  }

  private parseUrl(value: string, field: string): URL {
    try {
      return new URL(value);
    } catch {
      throw new BadRequestException(`${field} must be an absolute URL`);
    }
  }

  private requireSecureUrl(url: URL, field: string): void {
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
      throw new BadRequestException(
        `${field} must use HTTPS except on localhost`,
      );
    }
  }

  private slugify(value: string): string {
    const slug = value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '')
      .slice(0, 60);
    return slug || 'application';
  }
}
