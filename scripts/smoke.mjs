// Real local workerd/DO smoke test with dummy X credentials and the production OAuth code (no auth bypass).
// It never calls an X read tool or publishes a draft, so it makes no X requests. No Cloudflare account is required.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const dir = await mkdtemp(join(tmpdir(), 'x-guard-smoke-'));
const port = process.env.SMOKE_PORT ?? '8789';
const base = `http://127.0.0.1:${port}`;
const password = randomBytes(32).toString('base64url');
const vars = {
  AUTH_PASSWORD: password, APPROVAL_SECRET: 'smoke-only-approval-dummy',
  X_API_KEY: 'smoke-only-api-key-dummy', X_API_SECRET: 'smoke-only-api-secret-dummy',
  X_ACCESS_TOKEN: 'smoke-only-access-dummy', X_ACCESS_TOKEN_SECRET: 'smoke-only-token-secret-dummy',
  PUBLISH_MODE: 'approval',
};
const args = ['node_modules/wrangler/bin/wrangler.js', 'dev', '--local', '--ip', '127.0.0.1', '--port', port, '--inspector-port', '0', '--persist-to', dir];
for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
const child = spawn(process.execPath, args, {
  detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, WRANGLER_SEND_METRICS: 'false', BROWSER: 'none' },
});
let log = '';
for (const stream of [child.stdout, child.stderr]) stream.on('data', data => { log = (log + data).replaceAll(password, '[test-password]').slice(-16000); });
const cookies = response => response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
async function json(response) {
  const text = await response.text();
  assert.ok(response.ok, `HTTP ${response.status}: ${text}`);
  return JSON.parse(text);
}
let seq = 0;
let accessToken = '';
async function rpc(method, params = {}) {
  const response = await fetch(`${base}/mcp`, {
    method: 'POST', signal: AbortSignal.timeout(10000),
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++seq, method, params }),
  });
  assert.equal(response.status, 200);
  return (await response.json()).result;
}
/** The page's inline style/script must carry the nonce from its CSP, also after the DO's redaction pass. */
function assertNonce(response, html, suffix = '') {
  const csp = response.headers.get('Content-Security-Policy');
  const nonce = /^default-src 'none'; frame-ancestors 'none'; base-uri 'none'; style-src 'nonce-([A-Za-z0-9+/]{24})'; script-src 'nonce-\1'(.*)$/.exec(csp);
  assert.ok(nonce, `Unexpected CSP: ${csp}`);
  assert.equal(nonce[2], suffix);
  assert.ok(!csp.includes('unsafe-inline'));
  assert.ok(html.includes(`<style nonce="${nonce[1]}">`) && html.includes(`<script nonce="${nonce[1]}">`), 'Nonce mismatch between CSP and page');
}
async function approvalForm(url) {
  const page = await fetch(url);
  assert.equal(page.status, 200);
  // no-referrer would make real browsers send `Origin: null` on the form POST below.
  assert.equal(page.headers.get('referrer-policy'), 'same-origin');
  const html = await page.text();
  assertNonce(page, html, "; form-action 'self'");
  assert.match(html, /type="password" name="password"/);
  const csrf = html.match(/name="csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrf, 'Missing CSRF token');
  return (fields) => fetch(url.split('?')[0], {
    method: 'POST', headers: { Origin: base, Cookie: cookies(page), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ sig: new URL(url).searchParams.get('sig'), csrf, ...fields }),
  });
}
try {
  let ready = false;
  for (let n = 0; n < 120; n++) {
    if (child.exitCode !== null) throw new Error('Wrangler exited early');
    try { ready = (await fetch(`${base}/health`, { signal: AbortSignal.timeout(500) })).ok; } catch { /* startup */ }
    if (ready) break;
    await sleep(500);
  }
  assert.ok(ready, 'Wrangler did not start');

  // OAuth discovery.
  const unauthenticated = await fetch(`${base}/mcp`, { method: 'POST' });
  assert.equal(unauthenticated.status, 401);
  assert.match(unauthenticated.headers.get('www-authenticate'), new RegExp(`resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`));
  const resource = await json(await fetch(`${base}/.well-known/oauth-protected-resource/mcp`));
  assert.equal(resource.resource, `${base}/mcp`);
  assert.deepEqual(resource.authorization_servers, [base]);
  const server = await json(await fetch(`${base}/.well-known/oauth-authorization-server`));
  assert.equal(server.authorization_endpoint, `${base}/authorize`);
  assert.equal(server.registration_endpoint, `${base}/oauth/register`);
  assert.equal(server.client_id_metadata_document_supported, true);
  console.log('OAuth discovery: 401 challenge, protected resource and authorization server metadata (CIMD enabled)');

  // Dynamic registration, consent page with password, PKCE token exchange.
  const redirectUri = 'http://localhost:9876/callback';
  const registration = await json(await fetch(`${base}/oauth/register`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Local smoke client', redirect_uris: [redirectUri], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }),
  }));
  const verifier = randomBytes(32).toString('base64url');
  const state = randomBytes(16).toString('hex');
  const authUrl = new URL('/authorize', base);
  authUrl.search = new URLSearchParams({
    client_id: registration.client_id, redirect_uri: redirectUri, response_type: 'code', scope: 'x offline_access', state,
    resource: `${base}/mcp`, code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  });
  const consent = async () => {
    const page = await fetch(authUrl);
    assert.equal(page.status, 200, await page.clone().text());
    assert.equal(page.headers.get('Referrer-Policy'), 'same-origin');
    const html = await page.text();
    assertNonce(page, html);
    const handle = html.match(/name="handle" value="([^"]+)"/)?.[1];
    assert.ok(handle, 'Missing consent handle');
    return (fields) => fetch(`${base}/authorize`, {
      method: 'POST', redirect: 'manual', headers: { Origin: base, Cookie: cookies(page) },
      body: new URLSearchParams({ handle, ...fields }),
    });
  };
  const submit = await consent();
  assert.equal((await submit({ password: 'wrong-password', decision: 'approve' })).status, 403);
  const approved = await submit({ password, decision: 'approve' });
  assert.equal(approved.status, 302, await approved.clone().text());
  const callback = new URL(approved.headers.get('Location'));
  assert.equal(callback.searchParams.get('state'), state);
  const denied = await (await consent())({ decision: 'deny' });
  assert.equal(denied.status, 302);
  assert.equal(new URL(denied.headers.get('Location')).searchParams.get('error'), 'access_denied');
  const token = await json(await fetch(`${base}/oauth/token`, {
    method: 'POST', body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: registration.client_id, redirect_uri: redirectUri,
      code: callback.searchParams.get('code'), code_verifier: verifier, resource: `${base}/mcp`,
    }),
  }));
  assert.ok(token.access_token, 'OAuth did not issue an access token');
  accessToken = token.access_token;
  console.log('OAuth: dynamic registration, wrong password=403, deny redirect, consent + PKCE token');

  // MCP over the OAuth token.
  const init = await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'local-smoke', version: '1' } });
  assert.equal(init.protocolVersion, '2025-03-26');
  const { tools } = await rpc('tools/list');
  assert.deepEqual(tools.map(t => t.name), ['get_mentions', 'get_post', 'draft_post', 'draft_reply', 'publish', 'get_status']);
  console.log('MCP: initialize OK, tools/list: ' + tools.map(t => t.name).join(', '));

  // Approval form: approve needs AUTH_PASSWORD, reject does not.
  const first = (await rpc('tools/call', { name: 'draft_post', arguments: { text: 'Local smoke draft only. No X request.' } })).structuredContent;
  const blocked = await rpc('tools/call', { name: 'publish', arguments: { draft_id: first.draft_id } });
  assert.ok(blocked.isError);
  assert.match(blocked.content[0].text, /Human approval required/);
  assert.equal(new URL(first.approval_url).pathname, `/admin/approve/${first.draft_id}`);
  assert.equal((await fetch(first.approval_url.replace(/sig=.*/, 'sig=forged'))).status, 403);
  const decide = await approvalForm(first.approval_url);
  for (const fields of [{ decision: 'approve' }, { decision: 'approve', password: 'wrong-password' }]) {
    const response = await decide(fields);
    assert.equal(response.status, 403);
    assert.match(await response.text(), /<h1>Incorrect password<\/h1>/);
  }
  assert.match((await rpc('tools/call', { name: 'publish', arguments: { draft_id: first.draft_id } })).content[0].text, /Human approval required/);
  const rejected = await decide({ decision: 'reject' });
  assert.equal(rejected.status, 200);
  assert.match(await rejected.text(), /<h1>Rejected<\/h1>/);
  assert.match((await rpc('tools/call', { name: 'publish', arguments: { draft_id: first.draft_id } })).content[0].text, /was rejected/);
  const second = (await rpc('tools/call', { name: 'draft_post', arguments: { text: 'Second local smoke draft.' } })).structuredContent;
  const approvedDraft = await (await approvalForm(second.approval_url))({ decision: 'approve', password });
  assert.equal(approvedDraft.status, 200);
  assert.match(await approvedDraft.text(), /<h1>Approved<\/h1>/);
  assert.equal((await fetch(first.approval_url.replace('/admin/approve/', '/approve/'))).status, 404);
  const status = (await rpc('tools/call', { name: 'get_status', arguments: {} })).structuredContent;
  assert.equal(status.posts_today, 0);
  assert.equal(status.pending_approval, 0);
  assert.ok(status.recent_audit.some(a => a.action === 'approve' && a.result === 'failed: Incorrect password'));
  console.log('Approval: forged sig=403, approve without/with wrong password=403, reject without password OK, approve with password OK, old route=404, X calls=0');
} catch (error) {
  console.error(log);
  throw error;
} finally {
  try {
    if (process.platform === 'win32') child.kill('SIGTERM');
    else process.kill(-child.pid, 'SIGTERM');
  } catch { /* already stopped */ }
  await Promise.race([new Promise(resolve => child.once('exit', resolve)), sleep(3000)]);
  await rm(dir, { recursive: true, force: true });
}
