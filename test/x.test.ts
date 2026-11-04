import { afterEach, describe, expect, it, vi } from 'vitest';
import { GuardService } from '../src/store';
import { XClient } from '../src/x';
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
