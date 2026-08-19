import {
  Body,
  Controller,
  Delete,
  Get,
  Header,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { AuthenticatedRequest } from '../auth-guard/authenticated-request';
import { AccessTokenGuard } from '../auth-guard/access-token.guard';
import { LocationService } from '../location/location.service';
import { CreateOAuthClientDto } from './dto/create-oauth-client.dto';
import { OAuthClientIdParamDto } from './dto/oauth-client-id-param.dto';
import { OAuthClientService } from './oauth-client.service';

@Controller('developer/oauth-clients')
@UseGuards(AccessTokenGuard)
export class OAuthClientController {
  constructor(
    private readonly clients: OAuthClientService,
    private readonly locations: LocationService,
  ) {}

  @Post()
  @Header('Cache-Control', 'no-store')
  create(
    @Req() request: AuthenticatedRequest,
    @Body() input: CreateOAuthClientDto,
  ) {
    return this.clients.create(
      request.auth.userId,
      input,
      this.locations.getRequestContext(request),
    );
  }

  @Get()
  @Header('Cache-Control', 'no-store')
  list(@Req() request: AuthenticatedRequest) {
    return this.clients.list(request.auth.userId);
  }

  @Get(':clientId')
  @Header('Cache-Control', 'no-store')
  get(
    @Req() request: AuthenticatedRequest,
    @Param() params: OAuthClientIdParamDto,
  ) {
    return this.clients.get(request.auth.userId, params.clientId);
  }

  @Post(':clientId/rotate-secret')
  @HttpCode(HttpStatus.OK)
  @Header('Cache-Control', 'no-store')
  rotateSecret(
    @Req() request: AuthenticatedRequest,
    @Param() params: OAuthClientIdParamDto,
  ) {
    return this.clients.rotateSecret(
      request.auth.userId,
      params.clientId,
      this.locations.getRequestContext(request),
    );
  }

  @Delete(':clientId')
  disable(
    @Req() request: AuthenticatedRequest,
    @Param() params: OAuthClientIdParamDto,
  ) {
    return this.clients.disable(
      request.auth.userId,
      params.clientId,
      this.locations.getRequestContext(request),
    );
  }
}
