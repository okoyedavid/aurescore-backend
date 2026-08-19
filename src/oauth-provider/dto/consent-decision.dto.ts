import { IsIn, IsString, Matches } from 'class-validator';

export class ConsentDecisionDto {
  @IsString()
  @Matches(/^[A-Za-z0-9_-]{43}$/)
  interaction!: string;

  @IsString()
  @Matches(/^[A-Za-z0-9_-]{43}$/)
  consent_token!: string;

  @IsIn(['allow', 'deny'])
  decision!: 'allow' | 'deny';
}
