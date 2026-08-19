import type { NextFunction, Request, Response } from 'express';
import { csrfOriginMiddleware } from './csrf-origin.middleware';

describe('csrfOriginMiddleware', () => {
  const middleware = csrfOriginMiddleware(
    new Set(['https://aurescore.okoyedavid.com']),
  );

  it('rejects unsafe browser requests from an untrusted origin', () => {
    const next = jest.fn();
    middleware(
      {
        method: 'POST',
        get: jest.fn(() => 'https://evil.example'),
      } as unknown as Request,
      {} as Response,
      next as NextFunction,
    );
    const calls = next.mock.calls as unknown as Array<[unknown]>;
    expect(calls[0][0]).toMatchObject({ status: 403 });
  });

  it('allows trusted browser origins and originless server requests', () => {
    const trustedNext = jest.fn();
    middleware(
      {
        method: 'PATCH',
        get: jest.fn(() => 'https://aurescore.okoyedavid.com'),
      } as unknown as Request,
      {} as Response,
      trustedNext as NextFunction,
    );
    expect(trustedNext.mock.calls[0]).toEqual([]);

    const serverNext = jest.fn();
    middleware(
      { method: 'POST', get: jest.fn(() => undefined) } as unknown as Request,
      {} as Response,
      serverNext as NextFunction,
    );
    expect(serverNext.mock.calls[0]).toEqual([]);
  });
});
