import OAuthProvider, {
  AuthorizationError,
  CimdFetchError,
  type OAuthResourceAuth,
  insufficientScope,
} from '@cloudflare/workers-oauth-provider';
import type { Env } from './types';
import { passwordMatches, secrets } from './security';
import { GuardService } from './store';
import { authorizationFailedPage, consentPage, crossOriginPage, methodNotAllowedPage, wrongPasswordPage } from './pages';

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

/**
 * The consent page a form was posted from, so a mistyped password can be retried. Opening it again
 * runs the same authorization request through parseAuthRequest with a fresh consent handle, exactly
 * like reloading the page; without a same-origin Referer the user restarts from the client instead.
 */
function consentPageUrl(request: Request, url: URL): string | undefined {
  try {
    const referer = new URL(request.headers.get('Referer') ?? '');
    if (referer.origin === url.origin && referer.pathname === '/authorize' && referer.search) return `/authorize${referer.search}`;
  } catch { /* Missing or malformed Referer. */ }
  return undefined;
}

async function authorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  try {
    const oauth = env.OAUTH_PROVIDER;
    if (request.method === 'GET') {
      const auth = await oauth.parseAuthRequest(request);
      const details = await oauth.describeConsent(auth);
      const consent = await oauth.beginConsent(auth);
      // Sets the HTML, no-store, referrer and CSP headers (see BASE_CSP for why form-action is omitted).
      return consentPage({ clientName: details.clientName, handle: consent.handle, autoPublish: env.PUBLISH_MODE === 'auto' }, consent.headers);
    }
    if (request.method !== 'POST') return methodNotAllowedPage();
    if (request.headers.get('Origin') !== url.origin) return crossOriginPage();
    const form = await request.formData();
    const handle = String(form.get('handle') ?? '');
    if (form.get('decision') === 'deny') {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    if (form.get('decision') !== 'approve' || !await passwordMatches(String(form.get('password') ?? ''), env.AUTH_PASSWORD)) {
      return wrongPasswordPage(consentPageUrl(request, url));
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
      return authorizationFailedPage(error.message);
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
