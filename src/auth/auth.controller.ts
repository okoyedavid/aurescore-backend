import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { AuthCookieService } from '../auth-cookie/auth-cookie.service';
import { LocationService } from '../location/location.service';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { ResendEmailVerificationDto } from './dto/resend-email-verification.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { RefreshRejectedException } from '../session/session.exceptions';
import { VerifyLoginDto } from './dto/verify-login.dto';
import { ResendLoginVerificationDto } from './dto/resend-login-verification.dto';
import { GoogleOAuthCallbackDto } from './dto/google-oauth-callback.dto';
import { GoogleAccountLinkRequiredError } from '../google-auth/google-auth.exceptions';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly authCookies: AuthCookieService,
    private readonly locations: LocationService,
  ) {}

  @Get('google')
  async beginGoogleLogin(
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const authorization = await this.authService.beginGoogleLogin(
      this.locations.getRequestContext(request),
    );
    this.authCookies.setGoogleOAuthStateCookie(
      response,
      authorization.state,
      authorization.expiresAt,
    );
    response.redirect(HttpStatus.FOUND, authorization.url);
  }

  @Get('google/callback')
  async completeGoogleLogin(
    @Query() query: GoogleOAuthCallbackDto,
    @Req() request: Request,
    @Res() response: Response,
  ): Promise<void> {
    const expectedState = this.authCookies.getGoogleOAuthState(request);
    this.authCookies.clearGoogleOAuthStateCookie(response);

    try {
      const result = await this.authService.loginWithGoogle(
        {
          code: query.code,
          state: query.state,
          error: query.error,
          expectedState,
        },
        this.locations.getRequestContext(request),
      );

      if (result.status === 'verification-required') {
        response.redirect(
          HttpStatus.FOUND,
          this.authService.googleCallbackRedirect(
            'verification-required',
            result.challengeId,
          ),
        );
        return;
      }

      this.authCookies.setAuthCookies(response, result.session.tokens);
      response.redirect(
        HttpStatus.FOUND,
        this.authService.googleCallbackRedirect('success'),
      );
    } catch (error: unknown) {
      response.redirect(
        HttpStatus.FOUND,
        this.authService.googleCallbackRedirect(
          error instanceof GoogleAccountLinkRequiredError
            ? 'account-link-required'
            : 'failed',
        ),
      );
    }
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() loginDto: LoginDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.authService.login(
      loginDto,
      this.locations.getRequestContext(request),
    );

    if (result.status === 'verification-required') {
      return {
        message: 'A login verification code has been sent.',
        requiresTwoFactor: true,
        challengeId: result.challengeId,
      };
    }

    this.authCookies.setAuthCookies(response, result.session.tokens);

    return {
      message: 'Login successful',
      user: result.user,
    };
  }

  @Post('login-verification/verify')
  @HttpCode(HttpStatus.OK)
  async verifyLogin(
    @Body() verifyLoginDto: VerifyLoginDto,
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const result = await this.authService.verifyLogin(
      verifyLoginDto,
      this.locations.getRequestContext(request),
    );
    this.authCookies.setAuthCookies(response, result.session.tokens);

    return {
      message: 'Login successful',
      user: result.user,
    };
  }

  @Post('login-verification/resend')
  @HttpCode(HttpStatus.ACCEPTED)
  resendLoginVerification(
    @Body() resendDto: ResendLoginVerificationDto,
    @Req() request: Request,
  ) {
    return this.authService.resendLoginVerification(
      resendDto,
      this.locations.getRequestContext(request),
    );
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const tokens = await this.authService.refreshAuthSession(
        this.authCookies.getRefreshToken(request),
        this.locations.getRequestContext(request),
      );
      this.authCookies.setAuthCookies(response, tokens);

      return { message: 'Session refreshed successfully' };
    } catch (error: unknown) {
      if (error instanceof RefreshRejectedException) {
        this.authCookies.clearAuthCookies(response);
      }

      throw error;
    }
  }

  @Post('register')
  register(@Body() registerDto: RegisterDto, @Req() request: Request) {
    return this.authService.registerUser(
      registerDto,
      this.locations.getRequestContext(request),
    );
  }

  @Post('email-verification/verify')
  @HttpCode(HttpStatus.OK)
  verifyEmail(@Body() verifyEmailDto: VerifyEmailDto, @Req() request: Request) {
    return this.authService.verifyEmail(
      verifyEmailDto,
      this.locations.getRequestContext(request),
    );
  }

  @Post('email-verification/resend')
  @HttpCode(HttpStatus.ACCEPTED)
  resendEmailVerification(
    @Body() resendDto: ResendEmailVerificationDto,
    @Req() request: Request,
  ) {
    return this.authService.resendEmailVerification(
      resendDto,
      this.locations.getRequestContext(request),
    );
  }
}
