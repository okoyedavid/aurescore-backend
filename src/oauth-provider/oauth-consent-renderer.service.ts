import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import type { AuthorizationPageResult } from './oauth-provider.service';

@Injectable()
export class OAuthConsentRendererService {
  renderConsent(result: Extract<AuthorizationPageResult, { kind: 'consent' }>) {
    const nonce = randomBytes(18).toString('base64');
    const permissions = result.scopes
      .map((scope) => `<li>${this.scopeDescription(scope)}</li>`)
      .join('');
    const domain = result.client.homepageUrl
      ? this.escape(new URL(result.client.homepageUrl).hostname)
      : 'Unverified application';
    const badge = result.client.firstParty
      ? '<span class="badge">Aurescore application</span>'
      : '<span class="badge neutral">Third-party application</span>';

    return {
      nonce,
      html: `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Authorize ${this.escape(result.client.name)} · Aurescore</title>
  <style nonce="${nonce}">
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #09090b; color: #fafafa; padding: 24px; }
    main { width: min(100%, 520px); border: 1px solid #27272a; border-radius: 20px; background: #111113; padding: 32px; box-shadow: 0 24px 80px #0008; }
    .mark { width: 52px; height: 52px; display: grid; place-items: center; border-radius: 14px; background: #7c3aed; font-size: 22px; font-weight: 800; }
    h1 { margin: 22px 0 8px; font-size: 25px; line-height: 1.25; }
    p { color: #a1a1aa; line-height: 1.55; }
    .badge { display: inline-block; margin-top: 6px; border-radius: 999px; padding: 5px 9px; background: #4c1d95; color: #ddd6fe; font-size: 12px; }
    .badge.neutral { background: #27272a; color: #d4d4d8; }
    section { border-block: 1px solid #27272a; margin: 24px 0; padding: 20px 0; }
    ul { margin: 12px 0 0; padding-left: 22px; color: #e4e4e7; }
    li + li { margin-top: 10px; }
    .account { color: #d4d4d8; font-size: 14px; }
    form { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    button { border: 0; border-radius: 11px; padding: 13px 16px; cursor: pointer; font: inherit; font-weight: 700; }
    .deny { background: #27272a; color: #fafafa; }
    .allow { background: #7c3aed; color: white; }
    small { display: block; margin-top: 18px; color: #71717a; line-height: 1.45; }
  </style>
</head>
<body>
  <main>
    <div class="mark">${this.escape(result.client.name.slice(0, 1).toUpperCase())}</div>
    <h1>${this.escape(result.client.name)} wants to use your Aurescore account</h1>
    <div>${badge}</div>
    <p>${domain}</p>
    ${result.client.description ? `<p>${this.escape(result.client.description)}</p>` : ''}
    <section>
      <strong>This will allow the application to:</strong>
      <ul>${permissions}</ul>
    </section>
    <p class="account">Signed in as <strong>${this.escape(result.user.name)}</strong> (${this.escape(result.user.email)})</p>
    <form method="post" action="/api/oauth/authorize/decision">
      <input type="hidden" name="interaction" value="${this.escape(result.interaction)}">
      <input type="hidden" name="consent_token" value="${this.escape(result.consentToken)}">
      <button class="deny" type="submit" name="decision" value="deny">Cancel</button>
      <button class="allow" type="submit" name="decision" value="allow">Allow</button>
    </form>
    <small>Only approve applications you trust. You can revoke access later from your Aurescore account.</small>
  </main>
</body>
</html>`,
    };
  }

  renderError(message = 'The authorization request could not be completed.') {
    const nonce = randomBytes(18).toString('base64');
    return {
      nonce,
      html: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorization error · Aurescore</title><style nonce="${nonce}">:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#09090b;color:#fafafa;padding:24px}main{max-width:520px;border:1px solid #27272a;border-radius:18px;background:#111113;padding:32px}p{color:#a1a1aa;line-height:1.55}</style></head><body><main><h1>Authorization could not continue</h1><p>${this.escape(message)}</p><p>You may close this window and return to the application.</p></main></body></html>`,
    };
  }

  private scopeDescription(scope: string): string {
    switch (scope) {
      case 'openid':
        return 'Sign you in using your Aurescore identity';
      case 'profile':
        return 'View your name, username and profile image';
      case 'email':
        return 'View your email address and verification status';
      default:
        return 'Access a requested permission';
    }
  }

  private escape(value: string): string {
    return value
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }
}
