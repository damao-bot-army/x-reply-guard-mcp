import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Env } from '../src/types';
import { fixture } from './support';
import { accessToken, audience, kid, mockAccessFetch, publicJwk, teamDomain } from './access-support';

let worker: typeof import('../src/index').default;
let jwksFetch: Awaited<ReturnType<typeof mockAccessFetch>>;
beforeEach(async () => {
  vi.resetModules();
  worker = (await import('../src/index')).default;
  jwksFetch = await mockAccessFetch();
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

async function admin(env: Env, token?: string, path = '/admin/dashboard', method = 'GET') {
  return worker.fetch(new Request(`https://guard.example${path}`, { method, headers: token ? { 'Cf-Access-Jwt-Assertion': token } : {} }), env);
}
describe('Cloudflare Access admin boundary', () => {
  it('accepts a signed JWT, multiple audiences, and case-insensitive allowed emails', async () => {
    const f = fixture({ ACCESS_ALLOWED_EMAILS: 'other@example.com, OWNER@EXAMPLE.COM ' });
    const d = await f.draft();
    const response = await admin(f.env, await accessToken({ aud: ['another-app', audience] }), new URL(d.approval_url).pathname + new URL(d.approval_url).search);
    expect(response.status).toBe(200);
    expect(await response.text()).not.toContain('approval_secret');
    expect(jwksFetch).toHaveBeenCalledOnce();
    expect((await admin(f.env, await accessToken())).status).toBe(404);
    expect(jwksFetch).toHaveBeenCalledOnce();
  });
  it.each([
    ['missing header', undefined, undefined],
    ['wrong audience', { aud: ['wrong'] }, undefined],
    ['wrong issuer', { iss: 'https://attacker.example' }, undefined],
    ['expired', { exp: Math.floor(Date.now() / 1000) - 60 }, undefined],
    ['missing expiration', { exp: null }, undefined],
    ['future nbf', { nbf: Math.floor(Date.now() / 1000) + 120 }, undefined],
    ['invalid nbf', { nbf: 'yesterday' }, undefined],
    ['email not allowed', { email: 'attacker@example.com' }, undefined],
    ['missing email', { email: null }, undefined],
    ['wrong algorithm', {}, { alg: 'HS256' }],
    ['unknown kid', {}, { kid: 'unknown' }],
  ])('returns a generic 403 for %s on both GET and POST', async (label, claims, header) => {
    const f = fixture({ ACCESS_ALLOWED_EMAILS: 'owner@example.com' });
    const token = label === 'missing header' ? undefined : await accessToken(claims, header);
    const audit = vi.spyOn(console, 'warn').mockImplementation(() => {});
    for (const method of ['GET', 'POST']) {
      const response = await admin(f.env, token, `/admin/approve/${'a'.repeat(32)}`, method);
      expect(response.status).toBe(403);
      expect(await response.text()).toBe('Forbidden');
      expect(response.headers.get('cache-control')).toBe('no-store');
    }
    expect(audit).toHaveBeenCalledWith(expect.stringContaining('access_denied'));
    if (token) expect(JSON.stringify(audit.mock.calls)).not.toContain(token);
  });
  it('rejects an invalid RSA signature', async () => {
    const f = fixture();
    const token = await accessToken();
    const parts = token.split('.');
    parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
    expect((await admin(f.env, parts.join('.'))).status).toBe(403);
  });
  it.each([
    { ACCESS_TEAM_DOMAIN: undefined }, { ACCESS_TEAM_DOMAIN: '' },
    { ACCESS_AUD: undefined }, { ACCESS_AUD: '' },
    { ACCESS_TEAM_DOMAIN: 'https://evil.example/path' },
    { ACCESS_ALLOWED_EMAILS: '' },
  ])('fails closed for missing or invalid configuration: %j', async config => {
    const f = fixture(config);
    expect((await admin(f.env, await accessToken())).status).toBe(403);
  });
  it('does not trust Access cookies or unsigned identity headers', async () => {
    const f = fixture();
    const response = await worker.fetch(new Request('https://guard.example/admin/', { headers: { cookie: `CF_Authorization=${await accessToken()}`, 'Cf-Access-Authenticated-User-Email': 'owner@example.com' } }), f.env);
    expect(response.status).toBe(403);
    expect(jwksFetch).not.toHaveBeenCalled();
  });
  it.each(['broken', 'a.b.c', 'e30.e30.e30'])('rejects malformed assertions: %s', async token => {
    expect((await admin(fixture().env, token)).status).toBe(403);
  });
  it('keeps old approval URLs at 404 and unknown authenticated admin routes at 404', async () => {
    const f = fixture();
    const d = await f.draft();
    expect((await worker.fetch(new Request(d.approval_url.replace('/admin/approve/', '/approve/')), f.env)).status).toBe(404);
    for (const path of ['/admin', '/admin/', '/admin/dashboard', '/admin/approve/bad']) {
      expect((await admin(f.env, await accessToken(), path)).status).toBe(404);
      expect((await admin(f.env, undefined, path)).status).toBe(403);
    }
    expect((await f.rpc('tools/list')).status).toBe(200);
  });
  it('fails closed on JWKS network failure and malformed responses', async () => {
    const token = await accessToken();
    jwksFetch.mockRejectedValueOnce(new Error('private network detail'));
    expect((await admin(fixture().env, token)).status).toBe(403);
    jwksFetch.mockResolvedValueOnce(Response.json({ keys: 'invalid' }));
    expect((await admin(fixture().env, token)).status).toBe(403);
  });
  it('refreshes once for an unknown kid and expires the five-minute cache', async () => {
    const f = fixture();
    const now = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(now);
    expect((await admin(f.env, await accessToken())).status).toBe(404);
    clock.mockReturnValue(now + 1100);
    jwksFetch.mockResolvedValueOnce(Response.json({ keys: [{ ...await publicJwk(), kid: 'rotated' }] }));
    expect((await admin(f.env, await accessToken({}, { kid: 'rotated' }))).status).toBe(404);
    expect(jwksFetch).toHaveBeenCalledTimes(2);
    clock.mockReturnValue(now + 301100);
    expect((await admin(f.env, await accessToken({}, { kid }))).status).toBe(404);
    expect(jwksFetch).toHaveBeenCalledTimes(3);
  });
  it('allows only a small clock skew', async () => {
    const f = fixture();
    const now = Math.floor(Date.now() / 1000);
    expect((await admin(f.env, await accessToken({ exp: now - 10, nbf: now + 10 }))).status).toBe(404);
  });
  it('uses only the configured team certs endpoint, never token-supplied URLs', async () => {
    const f = fixture();
    expect((await admin(f.env, await accessToken({}, { jku: 'https://evil.example/keys' }))).status).toBe(404);
    expect(jwksFetch.mock.calls.map(call => call[0])).toEqual([`https://${teamDomain}/cdn-cgi/access/certs`]);
  });
});
