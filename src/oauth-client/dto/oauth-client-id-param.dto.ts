import { IsString, Matches } from 'class-validator';

export class OAuthClientIdParamDto {
  @IsString()
  @Matches(/^auc_[A-Za-z0-9_-]{32}$/)
  clientId!: string;
}
