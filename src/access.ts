/**
 * Cloudflare Access check for the draft review pages (/admin/approve/*).
 *
 * In production Cloudflare Access sits in front of /admin/approve/* and only lets the identities allowed
 * by its policy through, adding a signed `Cf-Access-Jwt-Assertion` header to every request it forwards.
 * The review page no longer asks for AUTH_PASSWORD, so this module verifies that JWT as defense in depth:
 * RS256 signature against the team's published keys, issuer, audience (the Access application's AUD tag),
 * and expiry. Without a valid assertion the approval handler does nothing: no draft is shown, approved,
 * rejected or published.
 *
 * Test double (local development and e2e only): with ACCESS_TEST_DOUBLE=true and a request to
 * localhost / 127.0.0.1 / [::1], the header `X-Test-Access-Identity: <email>` stands in for the Access
 * JWT. It is ignored on every other hostname, so it cannot open a deployed Worker even if the variable is
 * set by mistake. Never set ACCESS_TEST_DOUBLE in production.
 */
import { readLimited } from './http';
import type { Env, Fetcher } from './types';

export const ACCESS_JWT_HEADER = 'Cf-Access-Jwt-Assertion';
export const TEST_IDENTITY_HEADER = 'X-Test-Access-Identity';
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const KEY_CACHE_MS = 10 * 60 * 1000;
const TIMEOUT_MS = 5000;
const CLOCK_SKEW_S = 60;

export class AccessError extends Error {
  constructor(message: string, readonly status: 403 | 503 = 403) { super(message); }
}
export interface AccessIdentity { email?: string; via: 'access' | 'test-double' }

interface Jwk { kid?: string; kty?: string; n?: string; e?: string; alg?: string }

/** The team domain as a bare hostname, or undefined when it isn't a *.cloudflareaccess.com host. */
export function teamDomain(value: string | undefined): string | undefined {
  const host = (value ?? '').trim().replace(/^https:\/\//i, '').replace(/\/+$/, '').toLowerCase();
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(host) ? host : undefined;
}

export function testDoubleEnabled(env: Env, url: URL): boolean {
  return env.ACCESS_TEST_DOUBLE === 'true' && LOCAL_HOSTS.has(url.hostname);
}

const decoder = new TextDecoder();
function base64urlBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new AccessError('Cloudflare Access token is malformed');
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function base64urlJson(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(decoder.decode(base64urlBytes(value)));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch { /* handled below */ }
  throw new AccessError('Cloudflare Access token is malformed');
}

export class AccessVerifier {
  private keys?: { team: string; fetched: number; keys: Map<string, CryptoKey> };
  constructor(private fetcher: Fetcher, private now: () => number) {}

  /** Throws AccessError unless the request carries a valid Access assertion (or the local test double). */
  async verify(request: Request, env: Env): Promise<AccessIdentity> {
    const url = new URL(request.url);
    if (testDoubleEnabled(env, url)) {
      const email = (request.headers.get(TEST_IDENTITY_HEADER) ?? '').trim();
      if (!email) throw new AccessError('Cloudflare Access sign-in required');
      return { email: email.slice(0, 200), via: 'test-double' };
    }
    const team = teamDomain(env.ACCESS_TEAM_DOMAIN);
    const aud = (env.ACCESS_AUD ?? '').trim();
    if (!team || !aud) throw new AccessError('Cloudflare Access is not configured', 503);
    const token = request.headers.get(ACCESS_JWT_HEADER) ?? '';
    if (!token) throw new AccessError('Cloudflare Access sign-in required');
    if (token.length > 16384) throw new AccessError('Cloudflare Access token is malformed');
    const parts = token.split('.');
    if (parts.length !== 3) throw new AccessError('Cloudflare Access token is malformed');
    const header = base64urlJson(parts[0]);
    const payload = base64urlJson(parts[1]);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') throw new AccessError('Cloudflare Access token is invalid');
    const key = await this.key(team, header.kid);
    const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    let valid = false;
    try { valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, base64urlBytes(parts[2]), signed); } catch { valid = false; }
    if (!valid) throw new AccessError('Cloudflare Access token is invalid');
    if (payload.iss !== `https://${team}`) throw new AccessError('Cloudflare Access token is invalid');
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(aud)) throw new AccessError('Cloudflare Access token is invalid');
    const nowS = Math.floor(this.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp + CLOCK_SKEW_S <= nowS) throw new AccessError('Cloudflare Access session expired');
    if (typeof payload.nbf === 'number' && payload.nbf - CLOCK_SKEW_S > nowS) throw new AccessError('Cloudflare Access token is invalid');
    return { email: typeof payload.email === 'string' ? payload.email.slice(0, 200) : undefined, via: 'access' };
  }

  private async key(team: string, kid: string): Promise<CryptoKey> {
    const cached = this.keys;
    const fresh = cached && cached.team === team && this.now() - cached.fetched < KEY_CACHE_MS;
    if (fresh && cached.keys.has(kid)) return cached.keys.get(kid)!;
    // Unknown kid on a fresh cache: Access may have rotated keys, so refetch once.
    const keys = await this.fetchKeys(team);
    this.keys = { team, fetched: this.now(), keys };
    const key = keys.get(kid);
    if (!key) throw new AccessError('Cloudflare Access token is invalid');
    return key;
  }

  private async fetchKeys(team: string): Promise<Map<string, CryptoKey>> {
    let body: { keys?: Jwk[] };
    try {
      const response = await this.fetcher(new Request(`https://${team}/cdn-cgi/access/certs`, { redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) }));
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      body = JSON.parse(await readLimited(response.body, 65536));
    } catch { throw new AccessError('Cloudflare Access keys are unavailable; try again later', 503); }
    const keys = new Map<string, CryptoKey>();
    for (const jwk of Array.isArray(body?.keys) ? body.keys.slice(0, 20) : []) {
      if (jwk.kty !== 'RSA' || typeof jwk.kid !== 'string' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string') continue;
      try {
        keys.set(jwk.kid, await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']));
      } catch { /* skip unusable keys */ }
    }
    return keys;
  }
}
