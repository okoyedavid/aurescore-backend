import { IsString, MaxLength, MinLength } from 'class-validator';

export class OAuthGrantParamDto {
  @IsString()
  @MinLength(10)
  @MaxLength(64)
  grantId!: string;
}
