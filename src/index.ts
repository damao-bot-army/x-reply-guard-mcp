import type { Env } from './types';
import { constantTimeEqual, secrets } from './security';
import { GuardService } from './store';

export class GuardStore {
  private service: GuardService;
  constructor(state: DurableObjectState, env: Env) { this.service = new GuardService(state.storage, env); }
  fetch(request: Request): Promise<Response> { return this.service.fetch(request); }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/health' && request.method === 'GET') return Response.json({ ok: true });
    if (url.pathname !== '/mcp' && !/^\/approve\/[a-f0-9]{32}$/.test(url.pathname)) return new Response('Not found', { status: 404 });
    if (url.pathname === '/mcp') {
      const supplied = /^Bearer (.+)$/i.exec(request.headers.get('authorization') ?? '')?.[1] ?? '';
      if (!env.MCP_BEARER_TOKEN || !supplied || !await constantTimeEqual(supplied, env.MCP_BEARER_TOKEN)) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } });
      const origin = request.headers.get('origin');
      if (origin && origin !== url.origin) return new Response('Forbidden origin', { status: 403 });
    }
    if (secrets(env).length !== 6) return new Response('服务尚未配置完整凭据', { status: 503 });
    try {
      // One globally named DO per Worker/account. Never derive the shard from client input.
      const stub = env.GUARD_STORE.get(env.GUARD_STORE.idFromName('single-account-v1'));
      return await stub.fetch(request);
    } catch { return new Response('服务内部错误，请稍后重试', { status: 500 }); }
  },
};
