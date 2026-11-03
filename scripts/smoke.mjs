// Real local workerd/DO smoke test. Dummy credentials only; never calls an X read
// tool, approves a draft, or publishes a draft. No Cloudflare account is required.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const dir = await mkdtemp(join(tmpdir(), 'x-guard-smoke-'));
const port = process.env.SMOKE_PORT ?? '8789';
const base = `http://127.0.0.1:${port}`;
const vars = {
  MCP_BEARER_TOKEN: 'smoke-only-mcp-dummy', APPROVAL_SECRET: 'smoke-only-approval-dummy',
  X_API_KEY: 'smoke-only-api-key-dummy', X_API_SECRET: 'smoke-only-api-secret-dummy',
  X_ACCESS_TOKEN: 'smoke-only-access-dummy', X_ACCESS_TOKEN_SECRET: 'smoke-only-token-secret-dummy',
  PUBLISH_MODE: 'approval',
};
const args = ['node_modules/wrangler/bin/wrangler.js', 'dev', '--local', '--port', port, '--persist-to', dir];
for (const [key, value] of Object.entries(vars)) args.push('--var', `${key}:${value}`);
const child = spawn(process.execPath, args, {
  detached: process.platform !== 'win32', stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
});
let log = '';
for (const stream of [child.stdout, child.stderr]) stream.on('data', data => { log = (log + data).slice(-16000); });
let seq = 0;
async function rpc(method, params = {}) {
  const response = await fetch(`${base}/mcp`, {
    method: 'POST', signal: AbortSignal.timeout(10000),
    headers: { Authorization: `Bearer ${vars.MCP_BEARER_TOKEN}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++seq, method, params }),
  });
  assert.equal(response.status, 200);
  return (await response.json()).result;
}
try {
  let ready = false;
  for (let n = 0; n < 60; n++) {
    if (child.exitCode !== null) throw new Error('Wrangler exited early');
    try { ready = (await fetch(`${base}/health`, { signal: AbortSignal.timeout(500) })).ok; } catch { /* startup */ }
    if (ready) break;
    await sleep(500);
  }
  assert.ok(ready, 'Wrangler did not start');
  assert.equal((await fetch(`${base}/mcp`)).status, 401);
  const init = await rpc('initialize', { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'local-smoke', version: '1' } });
  assert.equal(init.protocolVersion, '2025-03-26');
  console.log('initialize: OK, protocolVersion=' + init.protocolVersion);
  const { tools } = await rpc('tools/list');
  assert.deepEqual(tools.map(t => t.name), ['get_mentions', 'get_post', 'draft_post', 'draft_reply', 'publish', 'get_status']);
  console.log('tools/list: 6 — ' + tools.map(t => t.name).join(', '));
  const draft = await rpc('tools/call', { name: 'draft_post', arguments: { text: 'Local smoke draft only. No X request.' } });
  assert.ok(draft.structuredContent.draft_id);
  const blocked = await rpc('tools/call', { name: 'publish', arguments: { draft_id: draft.structuredContent.draft_id } });
  assert.ok(blocked.isError);
  assert.match(blocked.content[0].text, /Human approval required/);
  const url = draft.structuredContent.approval_url;
  assert.equal(new URL(url).pathname, `/admin/approve/${draft.structuredContent.draft_id}`);
  const page = await fetch(url);
  assert.equal(page.status, 403);
  assert.equal(await page.text(), 'Forbidden');
  assert.equal((await fetch(url.split('?')[0], { method: 'POST' })).status, 403);
  assert.equal((await fetch(url.replace('/admin/approve/', '/approve/'))).status, 404);
  // No Access credentials or bypass: local smoke must never authorize approval or call X.
  const status = await rpc('tools/call', { name: 'get_status', arguments: {} });
  assert.equal(status.structuredContent.posts_today, 0);
  assert.equal(status.structuredContent.pending_approval, 1);
  assert.ok(!status.structuredContent.recent_audit.some(a => a.action === 'approve' && a.result === 'success'));
  console.log('real DO: draft persisted; unapproved publish blocked; admin GET/POST without JWT=403; old route=404; X calls=0');
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
