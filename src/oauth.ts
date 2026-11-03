import { hmac, randomHex } from './security';
import type { Env } from './types';

export function percent(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, c => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}
export interface OAuthCredentials { consumerKey: string; consumerSecret: string; token: string; tokenSecret: string }
export async function oauthSignature(method: string, url: string, credentials: OAuthCredentials, oauth: Record<string, string>, body: [string, string][] = []): Promise<string> {
  const u = new URL(url);
  const pairs = [...u.searchParams.entries(), ...body, ...Object.entries(oauth).filter(([k]) => k !== 'oauth_signature')]
    .map(([k, v]) => [percent(k), percent(v)]).sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
  const params = pairs.map(([k, v]) => `${k}=${v}`).join('&');
  const base = [method.toUpperCase(), `${u.origin}${u.pathname}`, params].map(percent).join('&');
  return hmac(`${percent(credentials.consumerSecret)}&${percent(credentials.tokenSecret)}`, base, 'SHA-1');
}
export async function authorization(method: string, url: string, env: Env): Promise<string> {
  const credentials = { consumerKey: env.X_API_KEY, consumerSecret: env.X_API_SECRET, token: env.X_ACCESS_TOKEN, tokenSecret: env.X_ACCESS_TOKEN_SECRET };
  const oauth: Record<string, string> = {
    oauth_consumer_key: credentials.consumerKey,
    oauth_token: credentials.token,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: String(Math.floor(Date.now() / 1000)),
    oauth_nonce: randomHex(),
    oauth_version: '1.0',
  };
  oauth.oauth_signature = await oauthSignature(method, url, credentials, oauth);
  return `OAuth ${Object.entries(oauth).sort().map(([k, v]) => `${percent(k)}="${percent(v)}"`).join(', ')}`;
}
