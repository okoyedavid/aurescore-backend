import type { OidcScope } from '../oauth-common/oauth.constants';

export interface OAuthInteraction {
  clientId: string;
  redirectUri: string;
  scopes: OidcScope[];
  state: string;
  nonce: string;
  codeChallenge: string;
  forceConsent: boolean;
  createdAt: string;
}

export interface OAuthAuthorizationCode {
  userId: string;
  grantId: string;
  subject: string;
  clientId: string;
  redirectUri: string;
  scopes: OidcScope[];
  nonce: string;
  codeChallenge: string;
  authTime: number;
}

export interface OAuthAccessTokenRecord {
  userId: string;
  grantId: string;
  subject: string;
  clientId: string;
  scopes: OidcScope[];
}

export interface OAuthAuthenticatedUser {
  userId: string;
  userSessionId: string;
  authTime: number;
}
