import {
  IsIn,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
} from 'class-validator';

export class AuthorizeDto {
  @IsIn(['code'])
  response_type!: string;

  @Matches(/^auc_[A-Za-z0-9_-]{32}$/)
  client_id!: string;

  @IsString()
  @MaxLength(500)
  redirect_uri!: string;

  @IsString()
  @MaxLength(100)
  scope!: string;

  @IsString()
  @MaxLength(256)
  state!: string;

  @IsString()
  @MaxLength(256)
  nonce!: string;

  @Matches(/^[A-Za-z0-9_-]{43,128}$/)
  code_challenge!: string;

  @IsIn(['S256'])
  code_challenge_method!: string;

  @IsOptional()
  @IsIn(['consent'])
  prompt?: string;
}
