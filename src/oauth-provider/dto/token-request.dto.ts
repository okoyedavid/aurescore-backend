import { IsIn, IsString, Matches, MaxLength } from 'class-validator';

export class TokenRequestDto {
  @IsIn(['authorization_code'])
  grant_type!: string;

  @IsString()
  @MaxLength(256)
  code!: string;

  @IsString()
  @MaxLength(500)
  redirect_uri!: string;

  @Matches(/^[A-Za-z0-9._~-]{43,128}$/)
  code_verifier!: string;
}
