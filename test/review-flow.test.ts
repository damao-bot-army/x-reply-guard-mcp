// Review click = publish (PRD docs/prd/2026-11-05-review-click-publish.md, stories S0-S4).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { GuardService } from '../src/store';
import type { StoreData } from '../src/types';
import { ACCESS_AUD, ACCESS_TEAM, ORIGIN, WAKE_URL, accessJwt, ctx, expectHtmlPage, fixture } from './support';

beforeEach(() => { vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('Real network disabled in tests'); })); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const expectError = (result: any, message: string) => { expect(result.isError).toBe(true); expect(result.content[0].text).toContain(message); };
const posts = (f: ReturnType<typeof fixture>) => f.requests.filter(r => r.method === 'POST');
/** X answers POST /tweets with `failure`; nothing else is expected. */
const failingX = (failure: () => Response | Promise<Response>) => async (request: Request) => {
  expect(new URL(request.url).origin).toBe('https://api.x.com');
  expect(request.method).toBe('POST');
  return failure();
};

describe('S0: Cloudflare Access guards every review action', () => {
  it('shows an anonymous visitor nothing about the draft, even with a valid signed link', async () => {
    const f = fixture(); const d = await f.draft('Secret launch text');
    const { html } = await expectHtmlPage(await f.open(d.approval_url, { access: false }), 403);
    expect(html).toContain('<h1>Sign-in required</h1>');
    expect(html).not.toContain('Secret launch text');
    expect(html).not.toMatch(/<form|name="decision"|guard_csrf/);
    expect(f.certFetches).toHaveLength(0);
    expect((await f.state()).audit.at(-1)).toMatchObject({ action: 'approval_view', draft_id: d.draft_id, result: 'failed: Cloudflare Access sign-in required' });
  });
  it('refuses an anonymous Approve or Reject even with a valid signature, CSRF token and Origin', async () => {
    const f = fixture(); const d = await f.draft();
    for (const decision of ['approve', 'reject']) {
      const response = await f.approve(d.approval_url, decision, headers => headers.delete('cf-access-jwt-assertion'));
      expect(response.status).toBe(403);
      expect(await response.text()).toContain('<h1>Sign-in required</h1>');
    }
    expect(f.requests).toHaveLength(0);
    expect(f.wakes).toHaveLength(0);
    expect((await f.call('get_status', { draft_id: d.draft_id })).structuredContent.state).toBe('pending');
  });
  it.each([
    ['signed with an unknown key', { foreignKey: true }],
    ['for another Access application', { claims: { aud: ['someone-elses-aud'] } }],
    ['from another team', { claims: { iss: 'https://evil.cloudflareaccess.com' } }],
    ['expired', { claims: { exp: Math.floor(Date.UTC(2026, 10, 3, 11, 0, 0) / 1000) } }],
    ['not yet valid', { claims: { nbf: Math.floor(Date.UTC(2026, 10, 3, 13, 0, 0) / 1000) } }],
    ['with an unknown key id', { header: { kid: 'rotated-away' } }],
    ['with alg none', { header: { alg: 'none' } }],
    ['with alg HS256', { header: { alg: 'HS256' } }],
  ])('rejects an Access assertion %s', async (_, options) => {
    const f = fixture(); const d = await f.draft();
    const jwt = await accessJwt(options);
    const page = await f.open(d.approval_url, { access: false, headers: { 'cf-access-jwt-assertion': jwt } });
    expect(page.status).toBe(403);
    expect(await page.text()).toContain('<h1>Sign-in required</h1>');
    const post = await f.approve(d.approval_url, 'approve', headers => headers.set('cf-access-jwt-assertion', jwt));
    expect(post.status).toBe(403);
    expect(f.requests).toHaveLength(0);
  });
  it.each(['garbage', 'a.b', 'a.b.c', '!!.??.**'])('rejects a malformed Access assertion: %s', async jwt => {
    const f = fixture(); const d = await f.draft();
    expect((await f.open(d.approval_url, { access: false, headers: { 'cf-access-jwt-assertion': jwt } })).status).toBe(403);
  });
  it('accepts a valid assertion, with audience as a string or a list, and caches the team keys', async () => {
    const f = fixture(); const d = await f.draft();
    expect((await f.open(d.approval_url)).status).toBe(200);
    const single = await accessJwt({ claims: { aud: ACCESS_AUD } });
    expect((await f.open(d.approval_url, { access: false, headers: { 'cf-access-jwt-assertion': single } })).status).toBe(200);
    expect((await f.approve(d.approval_url)).status).toBe(200);
    expect(f.certFetches).toHaveLength(1);
    expect(f.certFetches[0].url).toBe(`https://${ACCESS_TEAM}/cdn-cgi/access/certs`);
    expect(f.certFetches[0].redirect).toBe('manual');
  });
  it('fails closed (503) when Access is not configured, misconfigured or unreachable', async () => {
    for (const overrides of [{ ACCESS_TEAM_DOMAIN: '' }, { ACCESS_AUD: '' }, { ACCESS_TEAM_DOMAIN: 'evil.example.com' }, { ACCESS_TEAM_DOMAIN: 'x.cloudflareaccess.com.evil.example' }]) {
      const f = fixture(overrides); const d = await f.draft();
      const { html } = await expectHtmlPage(await f.open(d.approval_url), 503);
      expect(html).toContain('<h1>Review is unavailable</h1>');
      expect((await f.approve(d.approval_url)).status).toBe(503);
      expect(f.certFetches).toHaveLength(0);
      expect(f.requests).toHaveLength(0);
    }
    const down = fixture(); const d = await down.draft();
    down.fetcher.mockImplementationOnce(async () => new Response('down', { status: 500 }));
    expect((await down.open(d.approval_url)).status).toBe(503);
    expect((await down.open(d.approval_url)).status).toBe(200);
  });
  it('accepts an https:// team domain with a trailing slash', async () => {
    const f = fixture({ ACCESS_TEAM_DOMAIN: `https://${ACCESS_TEAM}/` }); const d = await f.draft();
    expect((await f.open(d.approval_url)).status).toBe(200);
  });
  it('honors the local test double only on localhost and only with ACCESS_TEST_DOUBLE=true', async () => {
    const f = fixture({ ACCESS_TEST_DOUBLE: 'true' }); const d = await f.draft();
    const local = d.approval_url.replace(ORIGIN, 'http://localhost:8787');
    const identity = { 'x-test-access-identity': 'reviewer@example.com' };
    const open = (url: string, headers: Record<string, string> = {}) => worker.fetch(new Request(url, { headers }), f.env, ctx);
    expect((await open(local)).status).toBe(403);
    expect((await open(local, identity)).status).toBe(200);
    expect((await open(d.approval_url.replace(ORIGIN, 'http://127.0.0.1:8787'), identity)).status).toBe(200);
    // On any other hostname the header means nothing; the real Access check applies.
    expect((await open(d.approval_url, identity)).status).toBe(403);
    expect((await open(d.approval_url.replace(ORIGIN, 'https://localhost.evil.example'), identity)).status).toBe(403);
    const off = fixture(); const e = await off.draft();
    expect((await worker.fetch(new Request(e.approval_url.replace(ORIGIN, 'http://localhost:8787'), { headers: identity }), off.env, ctx)).status).toBe(403);
    expect(f.certFetches).toHaveLength(0);
  });
  it('keeps the OAuth consent password untouched', async () => {
    const f = fixture();
    const response = await worker.fetch(new Request(`${ORIGIN}/authorize`, {
      method: 'POST', headers: { origin: ORIGIN }, body: new URLSearchParams({ decision: 'approve', handle: 'h' }),
    }), f.env, ctx);
    expect(response.status).toBe(403);
    expect(await response.text()).toContain('<h1>Incorrect password</h1>');
  });
});

describe('S1: Approve publishes immediately', () => {
  it('posts once, shows the real post link, stores post_id and wakes Echo', async () => {
    const f = fixture(); const d = await f.draft('Shipping day!');
    const page = await f.approve(d.approval_url);
    const { html } = await expectHtmlPage(page, 200);
    expect(html).toContain('<h1>Published</h1>');
    expect(html).toContain('href="https://x.com/guardbot/status/999"');
    expect(posts(f)).toHaveLength(1);
    const stored = (await f.state()).drafts[d.draft_id];
    expect(stored).toMatchObject({ state: 'published', post_id: '999' });
    expect((await f.call('get_status', { draft_id: d.draft_id })).structuredContent).toEqual({
      draft_id: d.draft_id, mode: 'approval', expires_at: '2026-11-03T12:30:00.000Z',
      state: 'published', post_id: '999', post_url: 'https://x.com/guardbot/status/999',
    });
    expect(f.wakes).toHaveLength(1);
    const [{ request, body }] = f.wakes;
    expect(request.method).toBe('POST');
    expect(request.url).toBe(WAKE_URL);
    expect(request.headers.get('authorization')).toBe(`Bearer ${f.env.ECHO_WAKE_TOKEN}`);
    expect(request.headers.get('content-type')).toBe('application/json');
    expect(request.redirect).toBe('manual');
    expect(body).toEqual({
      event: 'draft.review_result', draft_id: d.draft_id, result: 'published', draft_state: 'published',
      post_id: '999', post_url: 'https://x.com/guardbot/status/999', time: '2026-11-03T12:00:00.000Z',
    });
    expect(JSON.stringify(body)).not.toContain('Shipping day');
    expect((await f.state()).audit.at(-1)).toMatchObject({ action: 'wake', draft_id: d.draft_id, result: 'published: delivered (204)' });
  });
  it('a failed check before sending leaves the draft pending and retryable, and wakes Echo with a failure', async () => {
    const f = fixture({ MAX_POSTS_PER_DAY: '1' });
    const first = await f.draft('First'); const second = await f.draft('Second');
    expect((await f.approve(first.approval_url)).status).toBe(200);
    const blocked = await f.approve(second.approval_url);
    expect(blocked.status).toBe(409);
    const html = await blocked.text();
    expect(html).toContain('<h1>Not published</h1>');
    expect(html).toContain('Publishing rate limit exceeded');
    expect(html).not.toContain('<h1>Published</h1>');
    expect(posts(f)).toHaveLength(1);
    expect((await f.call('get_status', { draft_id: second.draft_id })).structuredContent.state).toBe('pending');
    expect((await f.call('get_status')).structuredContent.posts_today).toBe(1);
    expect(f.wakes.at(-1)!.body).toEqual({
      event: 'draft.review_result', draft_id: second.draft_id, result: 'publish_failed', draft_state: 'pending',
      reason: 'Publishing rate limit exceeded; wait for the next UTC window', retryable: true, time: '2026-11-03T12:00:00.000Z',
    });
  });
  it('a reply target that is no longer allowed blocks sending without reserving anything', async () => {
    let allowed = true;
    const f = fixture({}, async request => {
      if (request.method === 'POST') throw new Error('must not post');
      return Response.json({ data: { id: '100', text: 'hi', author_id: '77', conversation_id: '100', ...(allowed ? { entities: { mentions: [{ username: 'guardbot' }] } } : {}) } });
    });
    const d = (await f.call('draft_reply', { text: 'Thanks!', in_reply_to_post_id: '100' })).structuredContent;
    allowed = false;
    const response = await f.approve(d.approval_url);
    expect(response.status).toBe(409);
    expect(await response.text()).toContain('not allowlisted');
    expect(posts(f)).toHaveLength(0);
    expect((await f.state()).drafts[d.draft_id].state).toBe('pending');
    expect((await f.call('get_status')).structuredContent.posts_today).toBe(0);
  });
  it.each([
    ['an X error', () => new Response('nope', { status: 503 }), 'X API request failed (503)'],
    ['a network error', () => { throw new TypeError('connection reset'); }, 'publication outcome may be unknown'],
  ])('%s after the reservation marks the draft publish_failed, keeps the quota, never retries', async (_, failure, reason) => {
    const f = fixture({}, failingX(failure)); const d = await f.draft('Will fail');
    const submit = await f.prepare(d.approval_url);
    const response = await submit();
    const { html } = await expectHtmlPage(response, 502);
    expect(html).toContain('<h1>Publishing failed</h1>');
    expect(html).toContain(reason);
    expect(html).not.toContain('<h1>Published</h1>');
    expect(html).not.toContain('x.com/');
    const stored = (await f.state()).drafts[d.draft_id];
    expect(stored.state).toBe('publish_failed');
    expect(stored.post_id).toBeUndefined();
    expect(stored.failure).toContain(reason);
    const status = (await f.call('get_status', { draft_id: d.draft_id })).structuredContent;
    expect(status).toMatchObject({ state: 'publish_failed', retryable: false });
    expect(status.reason).toContain(reason);
    expect(status.post_id).toBeUndefined();
    expect((await f.call('get_status')).structuredContent.posts_today).toBe(1);
    expect(f.wakes).toHaveLength(1);
    expect(f.wakes[0].body).toMatchObject({ draft_id: d.draft_id, result: 'publish_failed', draft_state: 'publish_failed', retryable: false });
    expect(f.wakes[0].body.reason).toContain(reason);
    // No second attempt: not from the page, not from MCP, not with the same text in a new draft.
    expect((await submit()).status).toBe(403);
    expectError(await f.call('publish', { draft_id: d.draft_id }), 'already used');
    expectError(await f.call('draft_post', { text: 'Will fail' }), 'Duplicate');
    expect(posts(f)).toHaveLength(1);
  });
  it('reports a reservation whose outcome was never recorded (crash) as publish_failed', async () => {
    const f = fixture(); const d = await f.draft();
    const state = await f.state();
    state.drafts[d.draft_id].state = 'used';
    await f.storage.put('state', state);
    const status = (await f.call('get_status', { draft_id: d.draft_id })).structuredContent;
    expect(status).toMatchObject({ state: 'publish_failed', retryable: false });
    expect(status.reason).toContain('outcome is unknown');
    expectError(await f.call('publish', { draft_id: d.draft_id }), 'already used');
  });
});

describe('S2: Reject sends the draft back', () => {
  it('rejects without calling X and wakes Echo', async () => {
    const f = fixture(); const d = await f.draft('Not this one');
    const { html } = await expectHtmlPage(await f.approve(d.approval_url, 'reject'), 200);
    expect(html).toContain('<h1>Rejected</h1>');
    expect(f.requests).toHaveLength(0);
    expect((await f.call('get_status', { draft_id: d.draft_id })).structuredContent.state).toBe('rejected');
    expect(f.wakes.map(w => w.body)).toEqual([{ event: 'draft.review_result', draft_id: d.draft_id, result: 'rejected', draft_state: 'rejected', time: '2026-11-03T12:00:00.000Z' }]);
    expectError(await f.call('publish', { draft_id: d.draft_id }), 'was rejected');
  });
});

describe('S3: wake notification delivery', () => {
  it('is skipped (and audited) when ECHO_WAKE_URL is unset or not https', async () => {
    for (const [url, result] of [['', 'rejected: skipped: not configured'], ['http://echo.example/wake', 'rejected: skipped: ECHO_WAKE_URL must be an https URL'], ['https://user:pw@echo.example/', 'rejected: skipped: ECHO_WAKE_URL must be an https URL']]) {
      const f = fixture({ ECHO_WAKE_URL: url }); const d = await f.draft();
      expect((await f.approve(d.approval_url, 'reject')).status).toBe(200);
      expect(f.wakes).toHaveLength(0);
      expect(f.fetcher.mock.calls.every(([r]) => !r.url.includes('echo.example'))).toBe(true);
      expect((await f.state()).audit.at(-1)).toMatchObject({ action: 'wake', result });
    }
  });
  it('omits the Authorization header without ECHO_WAKE_TOKEN', async () => {
    const f = fixture({ ECHO_WAKE_TOKEN: '' }); const d = await f.draft();
    await f.approve(d.approval_url, 'reject');
    expect(f.wakes[0].request.headers.get('authorization')).toBeNull();
  });
  it('never changes the review result when delivery fails, and audits the failure without secrets', async () => {
    for (const [response, result] of [[() => new Response('x', { status: 500 }), 'published: failed: HTTP 500'], [() => { throw new TypeError('down'); }, 'published: failed: network error']] as const) {
      const f = fixture(); const d = await f.draft();
      f.setWakeResponse(response);
      const page = await f.approve(d.approval_url);
      expect(page.status).toBe(200);
      expect(await page.text()).toContain('<h1>Published</h1>');
      const state = await f.state();
      expect(state.drafts[d.draft_id].state).toBe('published');
      expect(state.audit.at(-1)).toMatchObject({ action: 'wake', result });
      expect(JSON.stringify(state)).not.toContain(f.env.ECHO_WAKE_TOKEN!);
    }
  });
  it('treats ECHO_WAKE_TOKEN as a secret: drafts containing it are refused and output is redacted', async () => {
    const f = fixture();
    const result = await f.call('draft_post', { text: `token ${f.env.ECHO_WAKE_TOKEN}` });
    expectError(result, 'secret');
    expect(JSON.stringify(result)).not.toContain(f.env.ECHO_WAKE_TOKEN);
  });
  it('is not sent for auto-mode MCP publishes (the caller gets the result directly)', async () => {
    const f = fixture({ PUBLISH_MODE: 'auto' }); const d = await f.draft();
    expect((await f.call('publish', { draft_id: d.draft_id })).structuredContent.post_id).toBe('999');
    expect(f.wakes).toHaveLength(0);
    expect((await f.call('get_status', { draft_id: d.draft_id })).structuredContent).toMatchObject({ state: 'published', post_id: '999' });
  });
});

describe('S4: get_status by draft_id', () => {
  it('distinguishes pending, rejected, published and expired without returning the text', async () => {
    const f = fixture({ DRAFT_TTL_MINUTES: '5' });
    const pending = await f.draft('Pending text body'); const rejected = await f.draft('Rejected text body'); const published = await f.draft('Published text body');
    await f.approve(rejected.approval_url, 'reject');
    await f.approve(published.approval_url);
    const status = async (id: string) => (await f.call('get_status', { draft_id: id }));
    const results = await Promise.all([pending, rejected, published].map(d => status(d.draft_id)));
    expect(results.map(r => r.structuredContent.state)).toEqual(['pending', 'rejected', 'published']);
    expect(results[2].structuredContent.post_id).toBe('999');
    for (const r of results) expect(JSON.stringify(r)).not.toMatch(/text body/);
    f.advance(5 * 60000);
    expect((await status(pending.draft_id)).structuredContent.state).toBe('expired');
    expect((await status(published.draft_id)).structuredContent.state).toBe('published');
  });
  it('rejects malformed and unknown ids, and keeps the summary without draft_id', async () => {
    const f = fixture(); await f.draft();
    expectError(await f.call('get_status', { draft_id: 'nope' }), 'Invalid draft_id');
    expectError(await f.call('get_status', { draft_id: '0'.repeat(32) }), 'Draft not found');
    const summary = (await f.call('get_status')).structuredContent;
    expect(Object.keys(summary)).toEqual(['mode', 'utc_hour', 'utc_day', 'posts_this_hour', 'max_posts_per_hour', 'posts_today', 'max_posts_per_day', 'count_policy', 'pending_approval', 'recent_audit']);
    expect(summary.pending_approval).toBe(1);
  });
  it('advertises the optional draft_id in the tool schema', async () => {
    const f = fixture();
    const tools = (await (await f.rpc('tools/list')).json() as any).result.tools;
    const status = tools.find((t: any) => t.name === 'get_status');
    expect(status.inputSchema.properties.draft_id).toEqual({ type: 'string', pattern: '^[a-f0-9]{32}$' });
    expect(status.inputSchema.required).toEqual([]);
    const publish = tools.find((t: any) => t.name === 'publish');
    expect(publish.description).toContain('Approval mode: this does not publish');
  });
});

describe('approval-mode MCP publish', () => {
  it('points to the approval page, is idempotent once published, and survives a restart', async () => {
    const f = fixture(); const d = await f.draft();
    expectError(await f.call('publish', { draft_id: d.draft_id }), 'Human approval required');
    expect(f.requests).toHaveLength(0);
    await f.approve(d.approval_url);
    const restarted = new GuardService(f.storage, f.env, async () => { throw new Error('MUST NOT SEND AGAIN'); }, () => Date.UTC(2026, 10, 3, 12, 0, 0));
    const response = await restarted.fetch(new Request(`${ORIGIN}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'publish', arguments: { draft_id: d.draft_id } } }) }));
    expect((await response.json() as any).result.structuredContent).toMatchObject({ post_id: '999', already_published: true });
    expect(posts(f)).toHaveLength(1);
  });
  it('never publishes a legacy approved draft from MCP', async () => {
    const f = fixture(); const d = await f.draft();
    const state = await f.state();
    state.drafts[d.draft_id].state = 'approved';
    await f.storage.put('state', state as StoreData);
    expectError(await f.call('publish', { draft_id: d.draft_id }), 'Human approval required');
    expect(f.requests).toHaveLength(0);
  });
});
