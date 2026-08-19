import { Module } from '@nestjs/common';
import { AuthGuardModule } from '../auth-guard/auth-guard.module';
import { LocationModule } from '../location/location.module';
import { OAuthCommonModule } from '../oauth-common/oauth-common.module';
import { OAuthClientController } from './oauth-client.controller';
import { OAuthClientService } from './oauth-client.service';

@Module({
  imports: [AuthGuardModule, LocationModule, OAuthCommonModule],
  controllers: [OAuthClientController],
  providers: [OAuthClientService],
  exports: [OAuthClientService],
})
export class OAuthClientModule {}
