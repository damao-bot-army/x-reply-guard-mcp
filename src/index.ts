import OAuthProvider, {
  AuthorizationError,
  CimdFetchError,
  type OAuthResourceAuth,
  insufficientScope,
} from '@cloudflare/workers-oauth-provider';
import type { Env } from './types';
import { html, passwordMatches, secrets } from './security';
import { GuardService } from './store';

export class GuardStore {
  private service: GuardService;
  constructor(state: DurableObjectState, env: Env) { this.service = new GuardService(state.storage, env); }
  fetch(request: Request): Promise<Response> { return this.service.fetch(request); }
}

const SCOPE = 'x';

async function forward(request: Request, env: Env): Promise<Response> {
  if (secrets(env).length !== 6) return new Response('Service credentials are incomplete', { status: 503 });
  try {
    // One globally named DO per Worker/account. Never derive the shard from client input.
    const stub = env.GUARD_STORE.get(env.GUARD_STORE.idFromName('single-account-v1'));
    return await stub.fetch(request);
  } catch { return new Response('Internal server error; please try again later', { status: 500 }); }
}

async function authorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  try {
    const oauth = env.OAUTH_PROVIDER;
    if (request.method === 'GET') {
      const auth = await oauth.parseAuthRequest(request);
      const details = await oauth.describeConsent(auth);
      const consent = await oauth.beginConsent(auth);
      consent.headers.set('Content-Type', 'text/html; charset=utf-8');
      consent.headers.set('Cache-Control', 'no-store');
      // form-action applies to the whole redirect chain after submit, and OAuth clients may redirect further, so it is omitted here.
      consent.headers.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
      return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Authorize X Reply Guard</title>
<h1>Authorize X Reply Guard</h1>
<p>Allow ${html(details.clientName)} to read X mentions and posts, create drafts, and publish drafts?</p>
<form method="post" action="/authorize"><input type="hidden" name="handle" value="${html(consent.handle)}">
<label>Password <input type="password" name="password" required autocomplete="current-password" maxlength="1024"></label>
<button name="decision" value="approve">Allow</button><button name="decision" value="deny" formnovalidate>Deny</button></form></html>`, { headers: consent.headers });
    }
    if (request.method !== 'POST') return new Response('Use GET or POST', { status: 405 });
    if (request.headers.get('Origin') !== url.origin) return new Response('Authorization form must be submitted from this origin; restart sign-in', { status: 403 });
    const form = await request.formData();
    const handle = String(form.get('handle') ?? '');
    if (form.get('decision') === 'deny') {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    if (form.get('decision') !== 'approve' || !await passwordMatches(String(form.get('password') ?? ''), env.AUTH_PASSWORD)) {
      return new Response('Incorrect authorization password. Restart sign-in and use the AUTH_PASSWORD configured on this Worker.', { status: 403, headers: { 'Cache-Control': 'no-store' } });
    }
    const approved = await oauth.approveConsent(request, handle);
    const { redirectTo } = await oauth.completeAuthorization({
      request: approved.request, userId: 'owner', metadata: {}, scope: approved.request.scope,
      props: { userId: 'owner' },
    });
    approved.headers.set('Location', redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (error) {
    if (error instanceof AuthorizationError && error.redirectTo) return Response.redirect(error.redirectTo, 302);
    if (error instanceof AuthorizationError || error instanceof CimdFetchError) {
      return new Response(`Authorization failed: ${error.message}. Restart sign-in from your MCP client.`, { status: 400 });
    }
    throw error;
  }
}

/** Everything outside /mcp. Approval pages carry their own HMAC signature, CSRF and password checks in the DO. */
export async function publicHandler(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/health' && request.method === 'GET') return Response.json({ ok: true });
  if (url.pathname === '/authorize') return authorize(request, env);
  if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) return forward(request, env);
  return new Response('Not found', { status: 404 });
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const origin = new URL(request.url).origin;
    return new OAuthProvider<Env>({
      apiRoute: '/mcp',
      apiHandler: {
        fetch(request, env, ctx) {
          const { auth } = ctx as ExecutionContext & { auth: OAuthResourceAuth };
          if (!auth.scope.includes(SCOPE)) return insufficientScope(auth, [SCOPE]);
          const requestOrigin = request.headers.get('origin');
          if (requestOrigin && requestOrigin !== new URL(request.url).origin) return new Response('Forbidden origin', { status: 403 });
          return forward(request, env);
        },
      },
      defaultHandler: { fetch: publicHandler },
      authorizeEndpoint: '/authorize',
      tokenEndpoint: '/oauth/token',
      clientRegistrationEndpoint: '/oauth/register',
      clientIdMetadataDocumentEnabled: true,
      scopesSupported: [SCOPE, 'offline_access'],
      requiredScopes: [SCOPE],
      resourceMetadata: { resource: `${origin}/mcp`, authorization_servers: [origin] },
    }).fetch(request, env, ctx);
  },
};
