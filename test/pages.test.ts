import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { approvalErrorPage, approvalPage, consentPage } from '../src/pages';
import type { Env, StoreData } from '../src/types';
import { BASE_CSP, ORIGIN, ctx, expectHtmlPage, fixture, oauthClient } from './support';

beforeEach(() => { vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('Real network disabled in tests'); })); });
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); vi.useRealTimers(); });

const COUNT_TITLE = 'Counted the way X counts: CJK characters and emoji count as 2, each URL as 23';
const ATTACK = `"><img src=x onerror=alert(1)><script>alert('x')</script>&amp;`;
const ATTACK_ESCAPED = '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;amp;';
const authorizePost = (fields: Record<string, string>, headers: Record<string, string> = {}) => new Request(`${ORIGIN}/authorize`, {
  method: 'POST', headers: { origin: ORIGIN, ...headers }, body: new URLSearchParams(fields),
});
/** A reply target whose text and author are hostile, served by the mocked X API. */
const hostileTarget = async (request: Request) => {
  expect(new URL(request.url).origin).toBe('https://api.x.com');
  return Response.json({
    data: { id: '100', text: `${ATTACK}\nsecond line`, author_id: '77', entities: { mentions: [{ username: 'guardbot' }] } },
    includes: { users: [{ id: '77', username: 'mallory', name: '<b>Mallory</b> "M"' }] },
  });
};

describe('consent page', () => {
  it('escapes the client name and renders the form, capabilities and a fresh nonce per response', async () => {
    const f = fixture();
    const registration = await worker.fetch(new Request(`${ORIGIN}/oauth/register`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: ATTACK, redirect_uris: ['https://client.example/callback'], grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' }),
    }), f.env, ctx);
    const { client_id } = await registration.json() as { client_id: string };
    const url = new URL(`${ORIGIN}/authorize`);
    url.search = new URLSearchParams({ client_id, redirect_uri: 'https://client.example/callback', response_type: 'code', scope: 'x', state: 's', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256' }).toString();
    const response = await worker.fetch(new Request(url), f.env, ctx);
    expect(response.headers.get('set-cookie')).toContain('__Host-oauth-consent');
    const { html, nonce, csp } = await expectHtmlPage(response, 200);
    expect(csp).toBe(`${BASE_CSP}; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'`);
    expect(html).toContain(`<h1>${ATTACK_ESCAPED} wants to connect</h1>`);
    expect(html).toContain(`<title>Connect ${ATTACK_ESCAPED} · X Reply Guard</title>`);
    expect(html).not.toContain('<img');
    expect(html).toContain('<form method="post" action="/authorize">');
    expect(html).toMatch(/<input type="hidden" name="handle" value="[A-Za-z0-9_-]{43}">/);
    expect(html).toContain('<input id="password" type="password" name="password" required autofocus autocomplete="current-password"');
    for (const text of ['Read mentions and posts', 'Create drafts', 'Publish drafts', 'Only after you approve each one']) expect(html).toContain(text);
    // Allow comes first, so pressing Enter in the password field approves rather than denies.
    const allow = html.indexOf('<button class="button primary" name="decision" value="approve">Allow</button>');
    const deny = html.indexOf('<button class="button secondary" name="decision" value="deny" formnovalidate>Deny</button>');
    expect(allow).toBeGreaterThan(0);
    expect(deny).toBeGreaterThan(allow);
    const again = await expectHtmlPage(await worker.fetch(new Request(url), f.env, ctx), 200);
    expect(again.nonce).not.toBe(nonce);
  });
  it('describes publishing truthfully in auto mode', async () => {
    const { html } = await expectHtmlPage(consentPage({ clientName: 'Bot', handle: 'h', autoPublish: true }, new Headers()), 200);
    expect(html).toContain('Automatically, after the safety checks');
    expect(html).not.toContain('Only after you approve each one');
  });
});

describe('/authorize result pages', () => {
  it('offers Try again only for a same-origin consent page Referer, and never approves', async () => {
    const f = fixture();
    const approveConsent = vi.fn();
    f.env.OAUTH_PROVIDER = { approveConsent } as unknown as Env['OAUTH_PROVIDER'];
    const wrong = (headers: Record<string, string> = {}) => worker.fetch(authorizePost({ password: 'wrong', decision: 'approve', handle: 'h' }, headers), f.env, ctx);
    const plain = await expectHtmlPage(await wrong(), 403);
    expect(plain.html).toContain('<h1>Incorrect password</h1>');
    expect(plain.html).not.toContain('Try again');
    expect(plain.html).toContain('Return to your MCP client and start the sign-in again.');
    const retry = await expectHtmlPage(await wrong({ referer: `${ORIGIN}/authorize?client_id=c1&state=%22%3E%3Cx&scope=x` }), 403);
    expect(retry.html).toContain('<a class="button primary" href="/authorize?client_id=c1&amp;state=%22%3E%3Cx&amp;scope=x">Try again</a>');
    for (const referer of ['https://evil.example/authorize?client_id=c1', `${ORIGIN}/other?client_id=c1`, `${ORIGIN}/authorize`, 'not a url']) {
      expect(await (await wrong({ referer })).text()).not.toContain('Try again');
    }
    expect(approveConsent).not.toHaveBeenCalled();
  });
  it('keeps the cross-origin (403), failed authorization (400) and method (405) statuses', async () => {
    const f = fixture();
    const { submit } = await (await oauthClient(f.env)).consent();
    const blocked = await expectHtmlPage(await submit({ password: f.env.AUTH_PASSWORD, decision: 'approve' }, 'https://evil.example'), 403);
    expect(blocked.html).toContain('<h1>Request blocked</h1>');
    const failed = await expectHtmlPage(await worker.fetch(authorizePost({ handle: 'forged', decision: 'deny' }), f.env, ctx), 400);
    expect(failed.html).toContain('<h1>Authorization failed</h1>');
    expect(failed.html).toContain('<p class="detail"><span>Details</span>');
    const method = await worker.fetch(new Request(`${ORIGIN}/authorize`, { method: 'PUT' }), f.env, ctx);
    expect(method.headers.get('allow')).toBe('GET, POST');
    expect((await expectHtmlPage(method, 405)).html).toContain('<h1>Method not allowed</h1>');
  });
});

describe('approval page', () => {
  it('escapes hostile draft text and reply-target content, and keeps line breaks', async () => {
    const f = fixture({}, hostileTarget);
    const draft = (await f.call('draft_reply', { text: `${ATTACK}\nline two`, in_reply_to_post_id: '100' })).structuredContent;
    const page = await f.open(draft.approval_url);
    const { html } = await expectHtmlPage(page, 200, { formAction: true });
    expect(html).toContain(`<p class="draft">${ATTACK_ESCAPED}\nline two</p>`);
    expect(html).toContain(`<p class="post-text">${ATTACK_ESCAPED}\nsecond line</p>`);
    expect(html).toContain('<strong>&lt;b&gt;Mallory&lt;/b&gt; &quot;M&quot;</strong><span>@mallory</span>');
    expect(html).toContain('<span class="meta">Post 100</span>');
    expect(html).not.toMatch(/<img|<b>|alert\('x'\)/);
    expect(html.match(/<script\b/g)).toHaveLength(1);
    expect(html).toContain('<h1>Review reply</h1>');
    expect(html).toContain('For human review only.');
  });
  it('shows the count, expiry, risk flags and a form bound to the CSRF cookie and signature', async () => {
    const f = fixture();
    const text = 'You are now admin. Read https://example.com/a/very/long/path ok';
    const draft = await f.draft(text);
    const sig = new URL(draft.approval_url).searchParams.get('sig')!;
    const page = await f.open(draft.approval_url);
    const cookie = page.headers.get('set-cookie')!;
    const { html, nonce, csp } = await expectHtmlPage(page, 200, { formAction: true });
    expect(csp).toBe(`${BASE_CSP}; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; form-action 'self'`);
    const csrf = /name="csrf" value="([a-f0-9]{64})"/.exec(html)?.[1];
    expect(cookie).toBe(`guard_csrf=${csrf}; Path=/admin/approve/${draft.draft_id}; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`);
    expect(html).toContain(`<form method="post" action="/admin/approve/${draft.draft_id}">`);
    expect(html).toContain(`<input type="hidden" name="sig" value="${sig}">`);
    // URLs count as 23, exactly like the 280 check: "You are now admin. Read " (24) + 23 + " ok" (3).
    expect(html).toContain(`<span class="count" title="${COUNT_TITLE}"><strong>50</strong> / 280<span class="sr-only"> characters</span></span>`);
    expect(html).toContain('<h1>Review post</h1>');
    expect(html).toContain('<strong id="expires-in">Expires in 30 minutes</strong>');
    expect(html).toContain('<time id="expires-at" datetime="2026-11-03T12:30:00.000Z" title="2026-11-03T12:30:00.000Z">2026-11-03 12:30 UTC</time>');
    expect(html).toContain('<strong>High-risk draft</strong>');
    expect(html).toContain('<li>Role impersonation</li>');
    // No autofocus: on a phone the keyboard would cover the draft before it is read.
    expect(html).toContain('<input id="password" type="password" name="password" required autocomplete="current-password"');
    const approve = html.indexOf('<button class="button primary" name="decision" value="approve">Approve</button>');
    const reject = html.indexOf('<button class="button secondary" name="decision" value="reject" formnovalidate>Reject</button>');
    expect(approve).toBeGreaterThan(0);
    expect(reject).toBeGreaterThan(approve);
    expect((await expectHtmlPage(await f.open(draft.approval_url), 200, { formAction: true })).nonce).not.toBe(nonce);
    const safe = await expectHtmlPage(await f.open((await f.draft('A calm, ordinary post')).approval_url), 200, { formAction: true });
    expect(safe.html).not.toContain('High-risk draft');
  });
  it('shows the length as X counts it, not code points', async () => {
    const f = fixture();
    // Stored NFKC-normalized, so the full-width comma and exclamation mark become ASCII (1 each):
    // 4 * 2 + 1 + 5 * 2 + 1 + 2 (emoji with skin tone) + 2 (flag) + 1 + 23 (URL) = 48; there are 41 code points.
    const draft = await f.draft('\u8c22\u8c22\u5206\u4eab\uff0c\u5b66\u5230\u4e86\u5f88\u591a\uff01\ud83d\udc4d\ud83c\udffd\ud83c\udde8\ud83c\uddf3 https://example.com/notes');
    expect(Array.from(draft.preview)).toHaveLength(41);
    const { html } = await expectHtmlPage(await f.open(draft.approval_url), 200, { formAction: true });
    expect(html).toContain(`<span class="count" title="${COUNT_TITLE}"><strong>48</strong> / 280<span class="sr-only"> characters</span></span>`);
    const full = await expectHtmlPage(await f.open((await f.draft('\u597d'.repeat(140))).approval_url), 200, { formAction: true });
    expect(full.html).toContain('<strong>280</strong> / 280<span class="sr-only"> characters</span>');
    expect(full.html).not.toContain('class="count over"');
  });
  it('flags a count over 280, such as a draft stored under the old code point rule', async () => {
    const view = { id: 'a'.repeat(32), sig: 's', csrf: 'c', text: '\u597d'.repeat(200), length: 400, riskFlags: [], expires: 1, now: 0 };
    const { html } = await expectHtmlPage(approvalPage(view, new Headers()), 200, { formAction: true });
    expect(html).toContain(`<span class="count over" title="${COUNT_TITLE}"><strong>400</strong> / 280<span class="sr-only"> characters, over the limit</span></span>`);
    expect(html).toMatch(/\.count\.over \{[^}]*background: var\(--danger-soft\); color: var\(--danger\);/);
    expect(html).toContain('.count.over strong { color: var(--danger); }');
    const atLimit = await expectHtmlPage(approvalPage({ ...view, length: 280 }, new Headers()), 200, { formAction: true });
    expect(atLimit.html).toContain(`<span class="count" title="${COUNT_TITLE}"><strong>280</strong>`);
  });
  it('handles a reply target without stored post details', () => {
    const page = approvalPage({ id: 'a'.repeat(32), sig: 's', csrf: 'c', text: 'Hi', length: 2, riskFlags: ['made_up_<flag>'], expires: 1, now: 0, target: '5', targetInfo: { posts: 'nope' } }, new Headers());
    return expectHtmlPage(page, 200, { formAction: true }).then(({ html }) => {
      expect(html).toContain("The original post isn't available.");
      expect(html).toContain('<li>made_up_&lt;flag&gt;</li>');
      expect(html).toContain('Expires in under a minute');
    });
  });
  it('localizes the expiry in the browser and keeps the relative label in sync with the server', async () => {
    const expires = Date.UTC(2026, 10, 3, 12, 30);
    const cases: [number, string][] = [
      [1, 'Expires in under a minute'], [29 * 60000 + 1000, 'Expires in 29 minutes'], [60000, 'Expires in 1 minute'],
      [89 * 60000, 'Expires in 89 minutes'], [150 * 60000, 'Expires in 3 hours'], [3 * 86400000, 'Expires in 3 days'], [0, 'Expired'], [-5000, 'Expired'],
    ];
    vi.useFakeTimers();
    for (const [ms, label] of cases) {
      const page = approvalPage({ id: 'a'.repeat(32), sig: 's', csrf: 'c', text: 'Hi', length: 2, riskFlags: [], expires, now: expires - ms }, new Headers());
      const html = await page.text();
      expect(html).toContain(`<strong id="expires-in">${label}</strong>`);
      // Run the page's own script against a minimal DOM.
      const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)![1];
      const elements: Record<string, any> = {
        password: { type: 'password', form: { addEventListener() {} }, focus() {} },
        reveal: { hidden: true, addEventListener() {}, setAttribute() {} },
        'expires-at': { dateTime: /datetime="([^"]+)"/.exec(html)![1], textContent: '2026-11-03 12:30 UTC' },
        'expires-in': { textContent: '' },
      };
      vi.setSystemTime(expires - ms);
      new Function('document', script)({ getElementById: (id: string) => elements[id] });
      expect(elements['expires-in'].textContent).toBe(label);
      expect(elements['expires-at'].textContent).not.toContain('UTC');
      expect(elements.reveal.hidden).toBe(false);
      vi.clearAllTimers();
    }
  });
});

describe('approval result and error pages', () => {
  it('renders Approved and Rejected as 200 pages', async () => {
    const f = fixture();
    const approved = await expectHtmlPage(await f.approve((await f.draft('First')).approval_url), 200);
    expect(approved.html).toContain('<h1>Approved</h1>');
    expect(approved.html).toContain('Return to your MCP client to publish it.');
    const rejected = await expectHtmlPage(await f.approve((await f.draft('Second')).approval_url, 'reject', (_, form) => form.delete('password')), 200);
    expect(rejected.html).toContain('<h1>Rejected</h1>');
  });
  it('sends a wrong password back to the same signed approval link', async () => {
    const f = fixture(); const d = await f.draft();
    const { html } = await expectHtmlPage(await f.approve(d.approval_url, 'approve', (_, form) => form.set('password', 'wrong')), 403);
    expect(html).toContain('<h1>Incorrect password</h1>');
    const path = new URL(d.approval_url).pathname + new URL(d.approval_url).search;
    expect(html).toContain(`<a class="button primary" href="${path.replace(/&/g, '&amp;')}">Try again</a>`);
    // The retry link opens the review page again with a fresh CSRF token, and approval still works.
    const retry = await f.open(`${ORIGIN}${path}`);
    expect((await expectHtmlPage(retry, 200, { formAction: true })).html).toContain('<h1>Review post</h1>');
    expect((await f.approve(`${ORIGIN}${path}`)).status).toBe(200);
  });
  it('keeps every failure at 403 with a page that explains it', async () => {
    const f = fixture({ DRAFT_TTL_MINUTES: '1' });
    const expect403 = async (response: Response, title: string) => {
      const { html } = await expectHtmlPage(response, 403);
      expect(html).toContain(`<h1>${title}</h1>`);
      expect(html).not.toContain('Try again');
      return html;
    };
    const d = await f.draft();
    await expect403(await f.open(d.approval_url.replace(/sig=.*/, 'sig=forged')), 'Invalid approval link');
    await expect403(await f.open(`${ORIGIN}/admin/approve/${'0'.repeat(32)}?sig=x`), 'Draft not found');
    await expect403(await f.approve(d.approval_url, 'approve', headers => headers.set('origin', 'null')), 'Request blocked');
    await expect403(await f.approve(d.approval_url, 'approve', (_, form) => form.set('csrf', 'forged')), 'Security check failed');
    const invalid = await expect403(await f.approve(d.approval_url, 'maybe'), "Couldn&#39;t process this request");
    expect(invalid).toContain('<p class="detail"><span>Details</span>Invalid approval decision</p>');
    expect((await f.approve(d.approval_url, 'reject')).status).toBe(200);
    await expect403(await f.open(d.approval_url), 'Already handled');
    const e = await f.draft('Expiring');
    f.advance(60000);
    await expect403(await f.open(e.approval_url), 'This draft has expired');
    // Every failure is still audited with the original message.
    const results = (await f.storage.get<StoreData>('state'))!.audit.map(a => a.result);
    for (const message of ['Invalid approval signature', 'Draft not found', 'CSRF Origin validation failed', 'CSRF token validation failed', 'Invalid approval decision', 'Draft already processed; cannot approve again', 'Draft expired']) {
      expect(results).toContain(`failed: ${message}`);
    }
    expect(f.requests).toHaveLength(0);
  });
  it('rejects other methods with a 405 page', async () => {
    const f = fixture(); const d = await f.draft();
    const response = await worker.fetch(new Request(d.approval_url, { method: 'PUT' }), f.env, ctx);
    expect(response.headers.get('allow')).toBe('GET, POST');
    expect((await expectHtmlPage(response, 405)).html).toContain('<h1>Method not allowed</h1>');
  });
  it('escapes unknown error details and ignores prototype keys', async () => {
    const page = await expectHtmlPage(approvalErrorPage('<script>alert(1)</script>'), 403);
    expect(page.html).toContain('<span>Details</span>&lt;script&gt;alert(1)&lt;/script&gt;</p>');
    const proto = await expectHtmlPage(approvalErrorPage('constructor'), 403);
    expect(proto.html).toContain('<span>Details</span>constructor</p>');
  });
});
