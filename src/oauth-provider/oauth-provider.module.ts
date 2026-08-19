import { Module } from '@nestjs/common';
import { AuthTokenModule } from '../auth-token/auth-token.module';
import { LocationModule } from '../location/location.module';
import { OAuthCommonModule } from '../oauth-common/oauth-common.module';
import { OAuthConsentRendererService } from './oauth-consent-renderer.service';
import { OAuthProviderController } from './oauth-provider.controller';
import { OAuthProviderService } from './oauth-provider.service';
import { OidcDiscoveryController } from './oidc-discovery.controller';
import { OidcSigningService } from './oidc-signing.service';

@Module({
  imports: [AuthTokenModule, LocationModule, OAuthCommonModule],
  controllers: [OAuthProviderController, OidcDiscoveryController],
  providers: [
    OAuthProviderService,
    OAuthConsentRendererService,
    OidcSigningService,
  ],
})
export class OAuthProviderModule {}
