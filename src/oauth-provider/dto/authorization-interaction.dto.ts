import { IsString, Matches } from 'class-validator';

export class AuthorizationInteractionDto {
  @IsString()
  @Matches(/^[A-Za-z0-9_-]{43}$/)
  interaction!: string;
}
