export const OIDC_SCOPES = ['openid', 'profile', 'email'] as const;
export type OidcScope = (typeof OIDC_SCOPES)[number];

export const OAUTH_INTERACTION_TTL_SECONDS = 10 * 60;
export const OAUTH_CODE_TTL_SECONDS = 2 * 60;
export const OAUTH_ACCESS_TOKEN_TTL_SECONDS = 10 * 60;

export function normalizeScopes(value: string | string[]): OidcScope[] {
  const values = Array.isArray(value) ? value : value.split(/\s+/);
  return [...new Set(values.filter(Boolean))].sort() as OidcScope[];
}

export function isSupportedScope(value: string): value is OidcScope {
  return (OIDC_SCOPES as readonly string[]).includes(value);
}
