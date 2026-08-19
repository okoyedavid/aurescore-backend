import type { NextFunction, Request, Response } from 'express';
import {
  requestContextMiddleware,
  type RequestWithContext,
} from './request-context.middleware';

describe('requestContextMiddleware', () => {
  it('assigns a request ID and exposes it in the response headers', () => {
    const request = {} as Request;
    const setHeader = jest.fn();
    const response = {
      setHeader,
    } as unknown as Response;
    const next = jest.fn() as NextFunction;

    requestContextMiddleware(request, response, next);

    const requestId = (request as RequestWithContext).requestId;
    expect(requestId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
    expect(setHeader).toHaveBeenCalledWith('X-Request-ID', requestId);
    expect(next).toHaveBeenCalledTimes(1);
  });
});
