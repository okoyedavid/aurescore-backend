# Aurescore Backend

NestJS authentication and identity API backed by PostgreSQL/Prisma, Redis, Resend, MaxMind GeoLite2, and HTTP-only cookie sessions. It also acts as an OpenID Connect provider so external applications can offer “Sign in with Aurescore.”

## Local setup

```bash
npm install
```

Copy `.env.example` to `.env`, configure PostgreSQL, Redis, Resend, Google OAuth, JWT secrets, verification/audit/rate-limit peppers, and MaxMind credentials. Then run:

```bash
npm run maxmind:download
npx prisma migrate deploy
npx prisma generate
npm run start:dev
```

The frontend defaults to `http://localhost:3000`. This API currently runs locally on the configured `PORT`—the project environment uses port `5000`. Production uses `https://api.aurescore.okoyedavid.com` for the API and `https://aurescore.okoyedavid.com` for the frontend.

## Authentication model

Aurescore issues access and refresh JWTs only through HTTP-only cookies. Access cookies cover `/api`; refresh cookies are restricted to `/api/auth`, which allows both refresh and logout while keeping them away from unrelated API routes. CORS allows only the configured frontend origin with credentials.

Each device login creates a long-lived `UserSession`. Its `currentAuthSessionId` points to the one refresh-token record currently allowed to rotate. Refresh rotation atomically claims that record, creates its replacement, and conditionally moves the pointer. A duplicate arriving within one minute receives the already-rotated response; a later replay or inconsistent relational state revokes the entire session chain.

Passwords and OAuth client secrets use Argon2id. Verification codes are six digits, HMAC-digested with a server-side pepper, stored in separate Redis namespaces, short-lived, attempt-limited, resend-limited, and consumed atomically.

## Account registration and email verification

1. `POST /api/auth/register` accepts `email`, `name`, and `password`.
2. The response is deliberately generic and a five-minute verification code is emailed when appropriate.
3. `POST /api/auth/email-verification/verify` accepts `email` and `code`.
4. `POST /api/auth/email-verification/resend` requests another code subject to cooldown and IP limits.

Registration does not create login cookies. The verified user signs in separately.

## Password login and optional email 2FA

1. `POST /api/auth/login` validates the password with account/IP rate limits.
2. When email 2FA is disabled, a `UserSession` and initial `AuthSession` are created and both cookies are returned.
3. When 2FA is enabled, no auth cookies are returned. The response includes a temporary `challengeId`.
4. `POST /api/auth/login-verification/verify` consumes the challenge and creates the session only after the code succeeds.
5. `POST /api/auth/login-verification/resend` replaces the code within the existing challenge.

## Google authentication

- Begin with a full browser navigation to `GET /api/auth/google`.
- Google returns to `GET /api/auth/google/callback`; this exact callback must be registered in Google Cloud.
- OAuth state is bound through a short-lived HTTP-only cookie.
- A new verified Google identity can create an account. An existing password account with the same email is not silently linked.
- An authenticated user can start a fresh, session-bound link flow with `POST /api/auth/google/link`; the Google identity is linked only to that authenticated account and is rejected if another user owns it.
- If Aurescore email 2FA is enabled, Google authentication must still complete the login-verification challenge before cookies are issued.

Detailed integration: [Google authentication](docs/google-authentication.md) and [frontend Google prompt](docs/frontend-google-auth-prompt.md).

## Forgot password

1. `POST /api/auth/password-reset/request` accepts `{ "email": "user@example.com" }`.
2. An accepted request returns HTTP 202, a generic message, and an opaque `challengeId`, including for unknown or ineligible accounts. Rate-limited requests return HTTP 429.
3. Eligible accounts receive a five-minute code by email. A replacement request after cooldown invalidates the previous active challenge.
4. `POST /api/auth/password-reset/confirm` accepts `challengeId`, six-digit `code`, and `newPassword`.
5. Successful confirmation changes the password in the same transaction that revokes every `UserSession` and `AuthSession`, writes the audit event, clears caller cookies, and sends a security notice.

Password reset never logs the user in. All devices must authenticate again. See the [frontend forgot-password prompt](docs/frontend-password-reset-prompt.md).

## Refresh and session management

- `POST /api/auth/refresh` rotates the refresh credential and replaces both cookies.
- `POST /api/auth/logout` idempotently revokes the identifiable current session and always clears both cookies, including when the access cookie has expired.
- `GET /api/sessions` lists the authenticated user's devices and marks the current one.
- `DELETE /api/sessions/:sessionId` revokes one owned session and clears cookies when it is the caller.
- `DELETE /api/sessions/others` revokes every session except the caller.

The access-token guard verifies JWT claims, the user/session relationship, the current auth-session pointer, revocation state, and account availability before protected handlers run.

## Account management and audit history

- `GET /api/account/me` returns the current user through an explicit password-free projection.
- `PATCH /api/account/profile` updates profile fields, including a frontend-provided avatar URL.
- `PATCH /api/account/preferences` updates supported preferences including email 2FA.
- `PATCH /api/account/password` changes the password while preserving the caller session and revoking the other sessions.
- `POST /api/account/email-change/request` verifies the current password and sends a code to the new address.
- `POST /api/account/email-change/confirm` applies the verified address and revokes other sessions.
- `GET /api/audit-events` returns cursor-paginated security/account history belonging only to the caller.

`GET /api/account/me` also reports `hasPassword` and linked provider summaries. Password-backed accounts confirm high-risk changes with their current password. Provider-only accounts request and verify a one-use email security challenge through `/api/account/security-verification`; the resulting five-minute token is bound to one session and one action (`set-password`, `change-email`, or `change-two-factor`). Sensitive password checks are rate-limited per user, session and IP.

Users can inspect and revoke third-party access with `GET /api/account/oauth-grants` and `DELETE /api/account/oauth-grants/:grantId`.

Audit metadata rejects sensitive field names and stores a keyed email hash instead of plaintext email.

## Aurescore as an OAuth/OIDC provider

External confidential web applications use Authorization Code flow with mandatory PKCE S256. Aurescore itself does not “Sign in with Aurescore”; `/api/oauth/authorize/continue` only resumes an external application's authorization request after the user finishes normal Aurescore password, Google, and optional 2FA authentication.

Supported provider endpoints:

- `GET /.well-known/openid-configuration`
- `GET /api/oauth/authorize`
- `GET /api/oauth/authorize/continue`
- `POST /api/oauth/authorize/decision`
- `POST /api/oauth/token`
- `GET /api/oauth/userinfo`
- `GET /api/oauth/jwks`

Authenticated developers manage applications through `/api/developer/oauth-clients`. Secrets are shown once, stored only as Argon2id hashes, and must be exchanged only from the relying application's backend. Tokens use pairwise subjects and claims are limited by `openid`, `profile`, and `email` scopes. Access tokens are opaque and live for ten minutes; provider refresh tokens and public clients are not supported yet.

Read [Sign in with Aurescore](docs/oauth-provider.md) and the [OAuth frontend prompt](docs/frontend-oauth-platform-prompt.md). Generate a stable production signing key with:

```bash
npm run oidc:generate-key
```

Store the output only in the deployment secret manager.

## OAuth continuation through Aurescore login

When `/login` receives `oauthInteraction`, the frontend preserves that opaque identifier through password login, Google redirect, and 2FA. After authentication is fully complete, it performs a full browser navigation—not Axios—to:

```text
${API_BASE_URL}/api/oauth/authorize/continue?interaction=...
```

The provider then loads its Redis interaction and either renders consent or returns an authorization code to the external application's exact registered redirect URI. Only the opaque interaction may temporarily use `sessionStorage` when an external Google round trip requires it; tokens, codes, secrets, passwords, and PKCE values must never use persistent browser storage.

## Supporting services and security controls

- Redis stores verification challenges, Google OAuth state, OIDC interactions/codes/access tokens, cooldowns, and rate-limit counters.
- Resend sends registration, login-2FA, password-reset, and email-change messages.
- MaxMind GeoLite2 enriches security events and sessions from public IP addresses.
- Request-context middleware assigns request IDs and captures normalized request metadata.
- Helmet provides global security headers, unsafe browser requests are checked against trusted origins for CSRF defense, and production startup requires explicit secure-cookie and trusted-proxy configuration.
- Audit events cover registration, login, verification, refresh replay, password changes/resets, email changes, session revocation, and OAuth client/consent/token activity.

## Validation and tests

```bash
npm run lint
npx tsc --noEmit
npm test -- --runInBand
npm run build
npx prisma validate
npx prisma migrate status
```

The security-focused unit tests cover cookie configuration, request metadata, access guarding, login and 2FA, refresh rotation/replay behavior, session ownership, verification-code consumption, Google state handling, password reset, audit sanitization, OAuth client ownership, PKCE code exchange, scoped UserInfo, and RSA/JWKS verification.

## Production checklist

- Use independent high-entropy JWT, verification, audit, and rate-limit secrets.
- Set `COOKIE_SECURE=true` and configure `TRUST_PROXY` to the exact deployed hop count or proxy CIDRs; production startup fails when these are missing.
- Configure a persistent `OIDC_PRIVATE_KEY_BASE64` and `OIDC_KEY_ID`; never use the development ephemeral key.
- Run `prisma migrate deploy` during deployment and `prisma generate` during build.
- Run Redis with authentication, TLS/private networking, persistence appropriate to the deployment, and eviction settings that do not unexpectedly discard security state.
- Keep `FRONTEND_URL`, `OIDC_ISSUER`, Google callback URL, cookie security, reverse-proxy trust, and CORS aligned with the deployed domains.
- Download/update the MaxMind database securely and never commit credentials.
- Use a verified Resend sender domain and monitor delivery failures.
- Terminate HTTPS at the trusted edge, restrict logs, alert on critical replay/audit events, and back up PostgreSQL.
