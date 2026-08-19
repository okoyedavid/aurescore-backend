export class OAuthProtocolException extends Error {
  constructor(
    public readonly errorCode:
      | 'invalid_request'
      | 'invalid_client'
      | 'invalid_grant'
      | 'unauthorized_client'
      | 'unsupported_grant_type'
      | 'invalid_scope'
      | 'access_denied'
      | 'temporarily_unavailable'
      | 'server_error',
    public readonly statusCode: number,
    public readonly description: string,
  ) {
    super(description);
    this.name = OAuthProtocolException.name;
  }
}
