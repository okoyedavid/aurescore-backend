import {
  Body,
  Controller,
  Get,
  Headers,
  HttpException,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { LocationService } from '../location/location.service';
import { AuthorizationInteractionDto } from './dto/authorization-interaction.dto';
import { AuthorizeDto } from './dto/authorize.dto';
import { ConsentDecisionDto } from './dto/consent-decision.dto';
import { TokenRequestDto } from './dto/token-request.dto';
import { OAuthConsentRendererService } from './oauth-consent-renderer.service';
import { OAuthProtocolException } from './oauth-protocol.exception';
import {
  OAuthProviderService,
  type AuthorizationPageResult,
} from './oauth-provider.service';

@Controller('oauth')
export class OAuthProviderController {
  constructor(
    private readonly oauth: OAuthProviderService,
    private readonly renderer: OAuthConsentRendererService,
    private readonly locations: LocationService,
  ) {}

  @Get('authorize')
  async authorize(
    @Query() query: AuthorizeDto,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    try {
      const result = await this.oauth.startAuthorization(
        query,
        request,
        this.locations.getRequestContext(request),
      );
      this.sendAuthorizationResult(response, result);
    } catch (error: unknown) {
      this.sendAuthorizationError(response, error);
    }
  }

  @Get('authorize/continue')
  async continueAuthorization(
    @Query() query: AuthorizationInteractionDto,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    try {
      const result = await this.oauth.continueAuthorization(
        query.interaction,
        request,
      );
      this.sendAuthorizationResult(response, result);
    } catch (error: unknown) {
      this.sendAuthorizationError(response, error);
    }
  }

  @Post('authorize/decision')
  async consentDecision(
    @Body() input: ConsentDecisionDto,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    try {
      const result = await this.oauth.decideConsent(
        input,
        request,
        this.locations.getRequestContext(request),
      );
      response.redirect(HttpStatus.FOUND, result.url);
    } catch (error: unknown) {
      this.sendAuthorizationError(response, error);
    }
  }

  @Post('token')
  async token(
    @Body() input: TokenRequestDto,
    @Headers('authorization') authorization: string | undefined,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    this.setNoStore(response);
    try {
      const tokens = await this.oauth.exchangeCode(
        input,
        authorization,
        this.locations.getRequestContext(request),
      );
      response.status(HttpStatus.OK).json(tokens);
    } catch (error: unknown) {
      const protocol = this.asProtocolError(error);
      if (protocol.errorCode === 'invalid_client') {
        response.setHeader('WWW-Authenticate', 'Basic realm="Aurescore OAuth"');
      }
      response.status(protocol.statusCode).json({
        error: protocol.errorCode,
        error_description: protocol.description,
      });
    }
  }

  @Get('userinfo')
  async userInfo(
    @Headers('authorization') authorization: string | undefined,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    this.setNoStore(response);
    try {
      response
        .status(HttpStatus.OK)
        .json(
          await this.oauth.userInfo(
            authorization,
            this.locations.getRequestContext(request),
          ),
        );
    } catch (error: unknown) {
      const protocol = this.asProtocolError(error);
      response.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
      response.status(protocol.statusCode).json({
        error: 'invalid_token',
        error_description: protocol.description,
      });
    }
  }

  @Get('jwks')
  jwks(@Res({ passthrough: true }) response: Response) {
    response.setHeader('Cache-Control', 'public, max-age=300');
    return this.oauth.jwks();
  }

  private sendAuthorizationResult(
    response: Response,
    result: AuthorizationPageResult,
  ): void {
    if (result.kind === 'redirect') {
      response.redirect(HttpStatus.FOUND, result.url);
      return;
    }
    const page = this.renderer.renderConsent(result);
    this.setHtmlSecurityHeaders(response, page.nonce);
    response.status(HttpStatus.OK).send(page.html);
  }

  private sendAuthorizationError(response: Response, error: unknown): void {
    const protocol = this.asProtocolError(error);
    const page = this.renderer.renderError(protocol.description);
    this.setHtmlSecurityHeaders(response, page.nonce);
    response.status(protocol.statusCode).send(page.html);
  }

  private asProtocolError(error: unknown): OAuthProtocolException {
    if (error instanceof HttpException && error.getStatus() === 429) {
      return new OAuthProtocolException(
        'temporarily_unavailable',
        429,
        'Too many OAuth requests. Please try again later.',
      );
    }
    return error instanceof OAuthProtocolException
      ? error
      : new OAuthProtocolException(
          'server_error',
          500,
          'The authorization server could not complete the request',
        );
  }

  private setNoStore(response: Response): void {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');
  }

  private setHtmlSecurityHeaders(response: Response, nonce: string): void {
    this.setNoStore(response);
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader(
      'Content-Security-Policy',
      `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    );
  }
}
