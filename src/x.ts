import { authorization } from './oauth';
import { readLimited } from './http';
import { risks, sanitize } from './security';
import type { Env, Fetcher } from './types';

type Tweet = { id: string; text: string; author_id?: string; conversation_id?: string; in_reply_to_user_id?: string; entities?: { mentions?: { username: string; id?: string }[] }; referenced_tweets?: { type: string; id: string }[] };
type User = { id: string; username: string; name: string; description?: string };
interface XResponse { data?: Tweet | Tweet[]; includes?: { users?: User[]; tweets?: Tweet[] }; meta?: { newest_id?: string; oldest_id?: string; next_token?: string; result_count?: number } }
const fields = 'tweet.fields=author_id,conversation_id,in_reply_to_user_id,referenced_tweets,entities&expansions=author_id,in_reply_to_user_id,referenced_tweets.id,referenced_tweets.id.author_id&user.fields=name,username,description';
export function id(value: unknown): string {
  if (typeof value !== 'string' || !/^\d{1,25}$/.test(value)) throw new Error('Post/user ID must be a numeric string');
  return value;
}
/** Calls the global fetch with no receiver. Storing `fetch` itself and calling it as a method
 * (`this.fetcher(...)`) throws "Illegal invocation" in workerd. */
export const globalFetch: Fetcher = (request) => fetch(request);
export class XClient {
  constructor(private env: Env, private fetcher: Fetcher = globalFetch) {}
  private async request(path: string, body?: unknown): Promise<XResponse> {
    const url = `https://api.x.com/2/${path}`;
    const method = body ? 'POST' : 'GET';
    let response: Response;
    try {
      response = await this.fetcher(new Request(url, {
        method,
        headers: { Authorization: await authorization(method, url, this.env), 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      }));
    } catch { throw new Error('X API network error or timeout; publication outcome may be unknown. Check manually; do not retry automatically'); }
    if (!response.ok) {
      if (response.status === 429) {
        const raw = response.headers.get('x-rate-limit-reset');
        const retry = response.headers.get('retry-after');
        const wait = raw && /^\d{1,12}$/.test(raw) ? Math.max(1, Number(raw) - Math.floor(Date.now() / 1000)) : retry && /^\d{1,8}$/.test(retry) ? Number(retry) : 60;
        throw new Error(`X API rate limited (429)，retry_after_seconds=${wait}`);
      }
      const labels: Record<number, string> = { 401: 'authentication failed', 403: 'insufficient permissions', 404: 'post not found or not visible' };
      throw new Error(`X API ${labels[response.status] ?? 'request failed'} (${response.status})`);
    }
    try { return JSON.parse(await readLimited(response.body, 2 * 1024 * 1024)) as XResponse; } catch { throw new Error('X API returned invalid JSON or an oversized response'); }
  }
  async mentions(since?: string, max = 10): Promise<unknown> {
    const data = await this.request(`users/${id(this.env.X_USER_ID)}/mentions?${fields}&max_results=${max}${since ? `&since_id=${id(since)}` : ''}`);
    return this.project(data);
  }
  async rawPost(postId: string): Promise<XResponse & { data: Tweet }> {
    const result = await this.request(`tweets/${id(postId)}?${fields}`);
    if (!result.data || Array.isArray(result.data) || result.data.id !== postId || typeof result.data.text !== 'string') throw new Error('X API did not return the target post');
    return result as XResponse & { data: Tweet };
  }
  async post(postId: string): Promise<unknown> { return this.project(await this.rawPost(postId)); }
  async allowedReply(postId: string): Promise<unknown> {
    const result = await this.rawPost(postId);
    const tweet = result.data;
    const mentioned = tweet.entities?.mentions?.some(m => m.id === this.env.X_USER_ID || m.username.toLowerCase() === this.env.X_USERNAME.replace(/^@/, '').toLowerCase());
    let ownedConversation = false;
    if (!mentioned && tweet.conversation_id) {
      const root = tweet.conversation_id === tweet.id ? result : await this.rawPost(tweet.conversation_id);
      ownedConversation = root.data.author_id === this.env.X_USER_ID;
    }
    if (!mentioned && !ownedConversation) throw new Error('Reply target is not allowlisted: it must mention this account or belong to a conversation started by this account');
    return this.project(result);
  }
  async publish(text: string, target?: string): Promise<{ post_id: string }> {
    const result = await this.request('tweets', { text, ...(target ? { reply: { in_reply_to_tweet_id: id(target) } } : {}) });
    const tweet = result.data;
    if (!tweet || Array.isArray(tweet)) throw new Error('X API publication outcome unknown; check manually');
    return { post_id: id(tweet.id) };
  }
  private project(result: XResponse): unknown {
    const user = (u: User) => ({ id: id(u.id), username: sanitize(u.username, 100), name: sanitize(u.name, 100), description: sanitize(u.description ?? '', 1000), ...risks(`${u.username}\n${u.name}\n${u.description ?? ''}`) });
    const tweet = (t: Tweet) => ({
      id: id(t.id), text: sanitize(t.text),
      author_id: t.author_id ? id(t.author_id) : undefined,
      conversation_id: t.conversation_id ? id(t.conversation_id) : undefined,
      in_reply_to_user_id: t.in_reply_to_user_id ? id(t.in_reply_to_user_id) : undefined,
      in_reply_to: t.referenced_tweets?.filter(r => r.type === 'replied_to').map(r => {
        const parent = result.includes?.tweets?.find(p => p.id === r.id);
        return { post_id: id(r.id), author_id: parent?.author_id ? id(parent.author_id) : undefined };
      }),
      ...risks(t.text),
    });
    return {
      posts: (Array.isArray(result.data) ? result.data : result.data ? [result.data] : []).map(tweet),
      users: (result.includes?.users ?? []).map(user),
      referenced_posts: (result.includes?.tweets ?? []).map(tweet),
      // Return only fixed, typed metadata; never pass arbitrary API fields through.
      meta: result.meta ? { newest_id: result.meta.newest_id ? id(result.meta.newest_id) : undefined, oldest_id: result.meta.oldest_id ? id(result.meta.oldest_id) : undefined, next_token: result.meta.next_token ? sanitize(result.meta.next_token, 200) : undefined } : undefined,
    };
  }
}
