import { Controller, Get, Header } from '@nestjs/common';
import { OAuthProviderService } from './oauth-provider.service';

@Controller('.well-known')
export class OidcDiscoveryController {
  constructor(private readonly oauth: OAuthProviderService) {}

  @Get('openid-configuration')
  @Header('Cache-Control', 'public, max-age=300')
  discovery() {
    return this.oauth.discovery();
  }
}
