import type { Env } from './types';
import { readLimited } from './http';

const TTL_MS = 5 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 30;
type AccessKey = JsonWebKey & { kid?: string };
type KeySet = { keys: AccessKey[]; expires: number; lastRefresh: number };
const cache = new Map<string, KeySet>();
const pending = new Map<string, Promise<KeySet>>();
class AccessError extends Error {}
const fail = (category: string): never => { throw new AccessError(category); };

async function keysFor(issuer: string): Promise<KeySet> {
  const existing = pending.get(issuer);
  if (existing) return existing;
  const loading = (async () => {
    try {
      const response = await fetch(`${issuer}/cdn-cgi/access/certs`, { redirect: 'error', signal: AbortSignal.timeout(5000) });
      if (!response.ok) return fail('jwks_unavailable');
      const body = JSON.parse(await readLimited(response.body, 256 * 1024));
      if (!Array.isArray(body.keys) || body.keys.length > 100) return fail('jwks_invalid');
      const result = { keys: body.keys.filter((key: unknown) => key && typeof key === 'object'), expires: Date.now() + TTL_MS, lastRefresh: Date.now() };
      // Bound the cache even when several deployments/configurations share an isolate.
      if (cache.size >= 16) cache.delete(cache.keys().next().value!);
      cache.set(issuer, result);
      return result;
    } catch (error) {
      if (error instanceof AccessError) throw error;
      return fail('jwks_unavailable');
    }
  })();
  pending.set(issuer, loading);
  try { return await loading; } finally { pending.delete(issuer); }
}
function decode(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return fail('jwt_malformed');
  try { return Uint8Array.from(atob(segment.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)); }
  catch { return fail('jwt_malformed'); }
}
function object(segment: string): Record<string, unknown> {
  try {
    const value = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(decode(segment)));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return fail('jwt_malformed');
    return value;
  } catch { return fail('jwt_malformed'); }
}

/** Only the signed Access assertion is trusted; cookies and identity headers are ignored. */
export async function verifyAccess(request: Request, env: Env): Promise<boolean> {
  try {
    const domain = env.ACCESS_TEAM_DOMAIN;
    if (!domain || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.cloudflareaccess\.com$/i.test(domain) || !env.ACCESS_AUD?.trim()) return fail('configuration');
    const issuer = `https://${domain.toLowerCase()}`;
    const token = request.headers.get('Cf-Access-Jwt-Assertion');
    if (!token) return fail('missing_assertion');
    if (token.length > 16384) return fail('jwt_malformed');
    const parts = token.split('.');
    if (parts.length !== 3) return fail('jwt_malformed');
    const header = object(parts[0]);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || !header.kid || header.crit !== undefined) return fail('jwt_header');
    let set = cache.get(issuer);
    let refreshed = false;
    if (!set || set.expires <= Date.now()) { set = await keysFor(issuer); refreshed = true; }
    const select = () => set!.keys.find(key => key.kid === header.kid && key.kty === 'RSA' && (!key.alg || key.alg === 'RS256') && (!key.use || key.use === 'sig'));
    let jwk = select();
    // Refresh once for rotation; throttle unknown-kid misses to prevent fetch amplification.
    if (!jwk && !refreshed && Date.now() - set.lastRefresh >= 1000) { set = await keysFor(issuer); jwk = select(); }
    if (!jwk) return fail('unknown_kid');
    let valid = false;
    try {
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
      valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decode(parts[2]), new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
    } catch { return fail('signature'); }
    if (!valid) return fail('signature');
    const claims = object(parts[1]);
    if (claims.iss !== issuer) return fail('issuer');
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(env.ACCESS_AUD)) return fail('audience');
    const now = Date.now() / 1000;
    if (typeof claims.exp !== 'number' || !Number.isFinite(claims.exp) || claims.exp <= now - CLOCK_SKEW_SECONDS) return fail('expired');
    if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isFinite(claims.nbf) || claims.nbf > now + CLOCK_SKEW_SECONDS)) return fail('not_yet_valid');
    if (env.ACCESS_ALLOWED_EMAILS !== undefined) {
      const allowed = env.ACCESS_ALLOWED_EMAILS.split(',').map(email => email.trim().toLowerCase()).filter(Boolean);
      if (typeof claims.email !== 'string' || !allowed.includes(claims.email.toLowerCase())) return fail('email');
    }
    return true;
  } catch (error) {
    // Fixed categories only: never log assertions, claims, request URLs, or upstream errors.
    console.warn(JSON.stringify({ action: 'access_denied', category: error instanceof AccessError ? error.message : 'verification' }));
    return false;
  }
}
