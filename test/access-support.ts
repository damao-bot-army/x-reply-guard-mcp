import { vi } from 'vitest';

const algorithm = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
const pair = crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']) as Promise<CryptoKeyPair>;
export const teamDomain = 'fixture-team.cloudflareaccess.com';
export const audience = 'fixture-application-audience';
export const kid = 'fixture-key';
export async function publicJwk() {
  return { ...await crypto.subtle.exportKey('jwk', (await pair).publicKey), kid, alg: 'RS256', use: 'sig' };
}
function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export async function accessToken(claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}, privateKey?: CryptoKey) {
  const encode = (value: unknown) => base64url(new TextEncoder().encode(JSON.stringify(value)));
  const input = `${encode({ alg: 'RS256', kid, ...header })}.${encode({ iss: `https://${teamDomain}`, aud: [audience], exp: Math.floor(Date.now() / 1000) + 3600, nbf: Math.floor(Date.now() / 1000) - 5, email: 'owner@example.com', ...claims })}`;
  const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey ?? (await pair).privateKey, new TextEncoder().encode(input));
  return `${input}.${base64url(new Uint8Array(signature))}`;
}
export async function mockAccessFetch() {
  const key = await publicJwk();
  const mock = vi.fn(async (url: string) => {
    if (url !== `https://${teamDomain}/cdn-cgi/access/certs`) throw new Error('REAL NETWORK DISABLED');
    return Response.json({ keys: [key] });
  });
  vi.stubGlobal('fetch', mock);
  return mock;
}
