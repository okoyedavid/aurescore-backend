import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../database/prisma.service';
import { AUDIT_EVENTS } from './audit-event.types';
import { AuditService } from './audit.service';

describe('AuditService', () => {
  const create = jest.fn().mockResolvedValue({});
  const findFirst = jest.fn();
  const findMany = jest.fn();
  const prisma = {
    auditEvent: {
      create,
      findFirst,
      findMany,
    },
  } as unknown as PrismaService;
  const config = {
    get: jest.fn((key: string) =>
      key === 'AUDIT_LOG_PEPPER' ? 'audit-test-pepper' : undefined,
    ),
    getOrThrow: jest.fn(),
  } as unknown as ConfigService;

  let service: AuditService;

  beforeEach(() => {
    jest.clearAllMocks();
    service = new AuditService(prisma, config);
  });

  it('records normalized context and an irreversible email fingerprint', async () => {
    await service.record({
      eventType: AUDIT_EVENTS.LOGIN_FAILED,
      category: 'authentication',
      outcome: 'failure',
      severity: 'warning',
      email: ' USER@Example.com ',
      reason: 'invalid_credentials\r\nforged-entry',
      context: {
        requestMetadata: {
          requestId: 'request-id',
          ipAddress: '8.8.8.8',
          userAgent: 'test-agent',
          method: 'POST',
          path: '/api/auth/login',
        },
        location: {
          city: 'Lagos',
          region: 'Lagos',
          country: 'Nigeria',
        },
      },
    });

    const calls = create.mock.calls as unknown as Array<
      [
        {
          data: {
            emailHash: string;
            reason: string;
            requestId: string;
            country: string;
          };
        },
      ]
    >;
    const data = calls[0][0].data;
    expect(data.emailHash).toMatch(/^[a-f0-9]{64}$/);
    expect(data.emailHash).not.toContain('user@example.com');
    expect(data.reason).toBe('invalid_credentials  forged-entry');
    expect(data.requestId).toBe('request-id');
    expect(data.country).toBe('Nigeria');
  });

  it('rejects sensitive metadata before writing it', async () => {
    await expect(
      service.record({
        eventType: AUDIT_EVENTS.LOGIN_SUCCEEDED,
        category: 'authentication',
        outcome: 'success',
        metadata: { accessToken: 'must-not-be-logged' },
      }),
    ).rejects.toThrow('Sensitive audit field is not allowed');
    expect(create).not.toHaveBeenCalled();
  });

  it('returns only the authenticated user audit projection', async () => {
    findMany.mockResolvedValue([
      { eventId: 'event-2' },
      { eventId: 'event-1' },
    ]);

    await expect(
      service.listUserEvents('user-id', { limit: 1 }),
    ).resolves.toEqual({
      items: [{ eventId: 'event-2' }],
      nextCursor: 'event-2',
    });
    const calls = findMany.mock.calls as unknown as Array<
      [{ where: { userId: string }; select: Record<string, unknown> }]
    >;
    expect(calls[0][0].where).toEqual({ userId: 'user-id' });
    expect(calls[0][0].select.emailHash).toBeUndefined();
  });
});
