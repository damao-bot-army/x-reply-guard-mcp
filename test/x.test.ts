import { afterEach, describe, expect, it, vi } from 'vitest';
import { GuardService } from '../src/store';
import { XClient, cause } from '../src/x';
import { MemoryStorage, testEnv } from './support';

/** Mimics workerd: global fetch throws "Illegal invocation" when called with any other receiver. */
function strictFetch() {
  return vi.fn(function (this: unknown, request: Request) {
    if (this !== undefined && this !== globalThis) throw new TypeError('Illegal invocation');
    expect(new URL(request.url).origin).toBe('https://api.x.com');
    return Promise.resolve(Response.json({ data: [{ id: '100', text: 'hello', author_id: '77' }], includes: { users: [{ id: '77', username: 'alice', name: 'Alice' }] } }));
  });
}
afterEach(() => { vi.unstubAllGlobals(); });

describe('default fetcher (no injection)', () => {
  it('XClient calls global fetch without binding it to the client', async () => {
    const stub = strictFetch();
    vi.stubGlobal('fetch', stub);
    await expect(new XClient(testEnv()).mentions()).resolves.toBeDefined();
    expect(stub).toHaveBeenCalledTimes(1);
  });
  it('GuardService default fetcher also works with a receiver-sensitive global fetch', async () => {
    const stub = strictFetch();
    vi.stubGlobal('fetch', stub);
    const service = new GuardService(new MemoryStorage(), testEnv());
    await expect((service as unknown as { x: XClient }).x.mentions()).resolves.toBeDefined();
    expect(stub).toHaveBeenCalledTimes(1);
  });
});

describe('network error diagnostics', () => {
  const env = testEnv();
  const run = (error: unknown) => new XClient(env, async () => { throw error; }).mentions();
  it('appends the TypeError name and message', async () => {
    await expect(run(new TypeError('fetch failed: unsupported option'))).rejects.toThrow(
      'X API network error or timeout; publication outcome may be unknown. Check manually; do not retry automatically (cause: TypeError: fetch failed: unsupported option)');
  });
  it('marks AbortError and TimeoutError as timeouts', async () => {
    await expect(run(new DOMException('The operation was aborted', 'AbortError'))).rejects.toThrow('(cause: timeout after 15s, AbortError: The operation was aborted)');
    await expect(run(new DOMException('The operation timed out', 'TimeoutError'))).rejects.toThrow('(cause: timeout after 15s, TimeoutError: The operation timed out)');
  });
  it('never includes credentials, and truncates after redaction', async () => {
    const all = [env.X_API_KEY, env.X_API_SECRET, env.X_ACCESS_TOKEN, env.X_ACCESS_TOKEN_SECRET, env.AUTH_PASSWORD, env.APPROVAL_SECRET];
    const error: Error = await run(new TypeError(`Authorization: OAuth ${all.join(' ')} ${encodeURIComponent(env.X_API_SECRET)}`)).then(() => new Error('no throw'), (e: unknown) => e as Error);
    expect(error.message).toContain('(cause: TypeError: Authorization: OAuth [REDACTED]');
    for (const secret of all) expect(error.message).not.toContain(secret);
    // A secret straddling the 120-char cut must not leave an unredacted prefix.
    const straddle = cause(new Error(`${'a'.repeat(115)}${env.X_API_SECRET}`), env);
    expect(straddle).toBe(` (cause: Error: ${'a'.repeat(115)}[REDA)`);
    expect(cause(new Error(`\u0000x${'y'.repeat(300)}`), env)).toBe(` (cause: Error: x${'y'.repeat(119)})`);
  });
  it('handles non-Error throwables', () => {
    expect(cause('plain string', env)).toBe(' (cause: string)');
    expect(cause(undefined, env)).toBe(' (cause: undefined)');
  });
  it('builds a workerd-compatible request: redirect manual, timeout signal, no Content-Type on GET', async () => {
    const seen: Request[] = [];
    await new XClient(env, async request => { seen.push(request); return Response.json({ data: [] }); }).mentions();
    expect(seen[0].redirect).toBe('manual');
    expect(seen[0].signal).toBeInstanceOf(AbortSignal);
    expect(seen[0].headers.get('content-type')).toBeNull();
  });
  it('reports request-construction failures as not sent', async () => {
    vi.stubGlobal('Request', class { constructor() { throw new TypeError('Invalid redirect value'); } });
    await expect(new XClient(env, async () => { throw new Error('must not be called'); }).mentions()).rejects.toThrow(
      'X API request could not be built; nothing was sent (cause: TypeError: Invalid redirect value)');
  });
});
