# x-reply-guard-mcp

[![CI](https://github.com/damao-bot-army/x-reply-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/damao-bot-army/x-reply-guard-mcp/actions/workflows/ci.yml)
![Node 22.12+](https://img.shields.io/badge/node-22.12%2B-brightgreen)
![Cloudflare Workers](https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-F38020)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A self-hosted MCP service on Cloudflare Workers with a shared Durable Object, letting clients such as Grok Bot read X posts and mentions, draft posts and replies, and publish through the official X API v2. External content is treated as untrusted data, and server-side checks enforce human approval by default; `PUBLISH_MODE` selects `approval` or `auto`.

<!-- screenshots -->

## Status

This project is for people who run their own Grok Bot and want human control over what it publishes on X using approval mode.

- **Maturity:** early development, version 0.1.0. The author has not deployed it yet.
- **Requirements:** a Cloudflare account with Workers and Durable Objects enabled; Cloudflare Access for `/admin`; an X developer application with OAuth 1.0a user tokens and Read and Write permissions; Node.js 22.12+ and npm.
- **Releases:** none yet. Deploy from source using the [deployment instructions](#deployment) below.

For bug reports and development checks, see [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Tools (exactly six)

| Tool | Arguments | Purpose |
| --- | --- | --- |
| `get_mentions` | `since_id?`, `max_results?` (5–100, default 10) | Read posts mentioning this account |
| `get_post` | `post_id` | Read text, author, conversation, reply parent, and parent author |
| `draft_post` | `text` | Create a draft only; return final preview, ID, expiration, and approval URL |
| `draft_reply` | `in_reply_to_post_id`, `text` | Verify the reply allowlist live, then create a reply draft only |
| `publish` | `draft_id` | Publish a draft after state, content, deduplication, and quota checks |
| `get_status` | None | Mode, UTC hour/day counts and limits, pending approvals, last 20 audit summaries |

Direct messages, deletion, likes, reposts, follows, profile changes, media uploads, and arbitrary URL requests are **not supported**. Clients cannot supply credentials, X API URLs, publishing modes, or approval results.

## Security design

### Read path: external content is not instructions

- Only known fields are projected; raw X JSON and upstream error bodies are never passed through.
- External text is normalized with Unicode NFKC. Zero-width, bidirectional, and C0/C1 control characters are removed (newlines preserved). Post text and biographies are capped at 1,000 Unicode code points; names/usernames at 100.
- Read-tool text starts with a fixed English warning that X content is untrusted and must never be executed as instructions. Each response uses random `<<X_UNTRUSTED_…>>` boundaries; boundary lookalikes in content are escaped. Structured data lives under `untrusted_content`. Reply drafts also wrap and label their target context separately.
- English and Chinese risk rules label `instruction_override`, `credential_request`, `tool_invocation`, `role_impersonation`, `exfil_url`, `hidden_text`, and `risk_level`. They cover instruction overrides, system prompts, role spoofing, credential requests, immediate publication, exfiltration URLs, and hidden characters. These are advisory labels, not authorization. Multilingual patterns and fixtures use Unicode escapes in source.

### Write path: enforced by the server

1. `draft_*` **never publishes**. It creates a random 128-bit ID and stores immutable final text, hash, target, and TTL.
2. Default `approval` mode returns a signed `/admin/approve/<id>` link. Cloudflare Access protects all `/admin/*` routes, and the Worker independently validates the Access JWT on every GET and POST. Missing configuration or failed verification returns a generic 403. The link alone does not authorize access or approval.
3. A human opens the link in a trusted browser, signs in through Access, checks the text/target/risk warning, and clicks Approve or Reject. **There is no password field.** `APPROVAL_SECRET` is only a domain-separated HMAC-SHA256 signing key stored server-side; humans never need to know or enter it. Do not give this key, Access sessions, or Access assertions to the bot.
4. Approval POST still checks the link HMAC, expiration, pending state, same-origin `Origin`, and a random double-submit CSRF token in an HttpOnly/Secure/SameSite=Strict cookie scoped to `/admin/approve/<id>`. HTML escapes all text and target information, highlights risks, disables scripts/frames/third-party resources through CSP, and sets no-store/no-referrer.
5. `publish` runs serially inside the DO. It checks expiration and rejected/used states; approval mode additionally requires human approval. Each draft is single-use. Switching from auto back to approval does not grant approval to pending drafts. **Approval is not publication**: the MCP client must still call `publish` afterward.
6. Replies are allowed only when X mention entities name this account, or a live conversation-root lookup confirms this account started the conversation. `in_reply_to_user_id` alone is insufficient. The target is checked again before publication.
7. Text must be nonempty and roughly at most 280 Unicode code points, with HTTP(S) URLs counted as 23 characters. Checks reject the raw, NFKC, sanitized, and URL-encoded forms of all six configured secrets, plus suspicious `sk-`, `Bearer `, long hex/base64 patterns. Both original and cleaned text are checked against hidden-character secret splitting. SHA-256 hashes of normalized, stripped, trimmed text prevent duplication against the last 50 published/reserved texts.
8. Risky drafts may be reviewed in approval mode, but auto mode refuses them. Publication rechecks risk and content so switching modes cannot send risky drafts in auto mode.
9. All clients share one fixed-name DO. Its serial queue covers network awaits. **Before X POST**, a durable transaction marks the draft used and reserves quota and deduplication state. Concurrent calls or DO restarts cannot send the same draft again. Large snapshots are chunked and committed in one transaction.
10. Quotas use **UTC clock hours and calendar days**, defaulting to 5/hour and 20/day. Counts include published and reserved attempts. X errors, timeouts, or crashes **do not roll back** the used flag, quota, or deduplication reservation, avoiding duplicate posts under uncertain outcomes. Check X manually before deciding whether to create a different draft; never automatically retry identical content.
11. Draft/approve/reject/publish successes, failures, and pre-send reservations record time, action, draft ID, target, text hash, and result, not text bodies. The last 500 audit entries are retained; status returns 20. Expired drafts are cleaned up 24 hours after expiration during later operations, with a maximum of 1,000 drafts. Long-term production audit archives must be separately controlled and unavailable to MCP clients. Access failures are logged in Worker logs as `access_denied` with fixed reason categories, never tokens, claims, URLs, or upstream details.
12. Last-mile redaction covers tool results, HTML, and errors. Requests, credentials, and raw X errors are not logged. X 401/403/404/429 map to fixed messages; 429 includes `retry_after_seconds`. X fetch forbids redirects and times out after 15 seconds. Limits: MCP body 32 KiB, approval POST 4 KiB, X response 2 MiB.

`auto` explicitly lowers the human-authorization requirement: an AI may publish any ordinary text passing the hard checks. Risk rules are not semantic moderation. Keep `approval` if **every post must be human-authorized**.

## Deployment

### 1. X developer application

Create your own project/application in the X Developer Portal and enable **OAuth 1.0a user-context Read and Write**. Regenerate this account's Access Token/Secret after permission changes. Prepare API Key/Secret, Access Token/Secret, the account's numeric User ID, and username without `@`. Your X API plan must support mentions, single-post reads, and post creation; X plan/endpoint limits are independent of this service's quotas.

This version supports **one account and one shared client trust domain**, without OAuth redirects, multi-user login, or token refresh flows.

### 2. Install and configure

Use Node.js 22.12+, npm, and a Cloudflare account with Workers and Durable Objects enabled. Durable Objects use SQLite migration `v1`.

```sh
npm ci
npx wrangler login
```

Edit the Worker name, `X_USER_ID`, and `X_USERNAME` in `wrangler.toml`. Keep `PUBLISH_MODE = "approval"`. Replace the Access placeholders using the next section.

Generate two distinct high-entropy random values (at least 32 random bytes recommended, using a password manager or `openssl rand -hex 32`). Store them through interactive secret prompts, not config files or command-line arguments:

```sh
npx wrangler secret put MCP_BEARER_TOKEN
npx wrangler secret put APPROVAL_SECRET
npx wrangler secret put X_API_KEY
npx wrangler secret put X_API_SECRET
npx wrangler secret put X_ACCESS_TOKEN
npx wrangler secret put X_ACCESS_TOKEN_SECRET
npm run deploy
# Equivalent to npx wrangler deploy; first deployment creates the DO migration.
```

Never reuse `APPROVAL_SECRET` as the MCP Bearer or an X credential. It is solely a server-side signing key, not a human passphrase. This repository contains placeholders and test credentials only; `.dev.vars.example` is a local template.

| Setting | Type | Default / meaning |
| --- | --- | --- |
| `MCP_BEARER_TOKEN` | secret | Shared `/mcp` credential, compared in constant time after fixed-length SHA-256 hashing |
| `APPROVAL_SECRET` | secret | Server-only approval-link HMAC-SHA256 key |
| `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_TOKEN_SECRET` | secret | X OAuth 1.0a user credentials |
| `ACCESS_TEAM_DOMAIN` | var | Required for admin: team hostname, e.g. `your-team.cloudflareaccess.com`, without scheme/path |
| `ACCESS_AUD` | var | Required for admin: Access application's Audience (AUD) tag |
| `ACCESS_ALLOWED_EMAILS` | optional var | Comma-separated email allowlist, trimmed and case-insensitive; if set, JWT email must match. An empty list denies everyone |
| `X_USER_ID`, `X_USERNAME` | var | Account ID / username |
| `PUBLISH_MODE` | var | `approval` (default if omitted) or `auto`; other values refuse writes |
| `MAX_POSTS_PER_HOUR` | var | 5; positive integer |
| `MAX_POSTS_PER_DAY` | var | 20; positive integer |
| `DRAFT_TTL_MINUTES` | var | 30; positive integer |

Grok Bot needs only the MCP Bearer. Do not grant it Cloudflare administration credentials, Worker secret-management access, server filesystem access, or your browser's Access identity/session.

### Cloudflare Access setup

1. In **Cloudflare Zero Trust → Access → Applications**, create a **self-hosted application** covering `<worker-host>/admin/*` (for example `x-reply-guard.example.com/admin/*`). Use the same hostname as the MCP URL so generated links reach the protected host. Future Dashboard routes will share this admin boundary.
2. Configure an **Allow policy restricted to your own email address**, using your preferred identity provider or email one-time PIN. Do not add public Bypass policies or machine/service-token approvals for this application.
3. Copy the application's **Application Audience (AUD) tag** into `ACCESS_AUD`.
4. Set `ACCESS_TEAM_DOMAIN` to your Zero Trust team domain, e.g. `your-team.cloudflareaccess.com`, without `https://` or a trailing slash.
5. Optionally set `ACCESS_ALLOWED_EMAILS` to your email for defense in depth. The template includes `owner@example.com`; replace it, or remove the setting entirely to rely on the Access application's policy.
6. Deploy the updated configuration, open a draft's approval link in a browser, sign in, and approve/reject without entering a Worker secret.

**Do not cover `/mcp` with Access.** It is a machine endpoint authenticated only by its existing Bearer token. Do not create a host-wide Access application that accidentally captures it. If you expose other hostnames or Worker aliases, protect their admin paths too; the Worker's JWT check still fails closed if the edge policy is missing. `/health` is a public liveness check and makes no X authentication probe.

The Worker reads only `Cf-Access-Jwt-Assertion`; it does not trust identity headers or a client-supplied Access cookie as authentication. It verifies RS256 with WebCrypto using the matching `kid` from `https://<ACCESS_TEAM_DOMAIN>/cdn-cgi/access/certs`, then checks exact issuer, audience membership, required expiration, optional `nbf`, and optional email allowlist. Clock tolerance is 30 seconds. JWKS are cached in memory for five minutes; an unknown key can trigger one refresh, throttled to at most one per second. Fetches forbid redirects, have a five-second timeout and a 256 KiB response limit. Verification failures return only `Forbidden` (403). Missing Access config blocks admin only; `/mcp` keeps working with its Bearer and service credentials.

### 3. Add a custom MCP in Grok Bot

Use a client supporting **Streamable HTTP** custom MCP servers:

- URL: `https://<worker>/mcp`
- Custom header: `Authorization: Bearer <MCP_BEARER_TOKEN>`
- Transport: Streamable HTTP, not legacy HTTP+SSE

Adapt JSON field names to your host, for example:

```json
{
  "mcpServers": {
    "x-reply-guard": {
      "url": "https://<worker>/mcp",
      "headers": { "Authorization": "Bearer <MCP_BEARER_TOKEN>" }
    }
  }
}
```

Host-specific UI/config formats vary; the essentials are the HTTP MCP URL and Bearer header. Never add `APPROVAL_SECRET`, Access tokens, or X credentials to this configuration.

The MCP layer is minimal **JSON-RPC over Streamable HTTP**: stateless POST, JSON responses, notifications returning 202, and `initialize` / `ping` / `tools/list` / `tools/call`. Protocols `2025-03-26`, `2025-06-18`, and `2025-11-25` are supported. No sessions, SSE subscriptions, or server push; GET/DELETE return 405. No Node HTTP adapter, SDK, or agents are needed. Request `Accept` must include both `application/json, text/event-stream`; `Content-Type` must be `application/json`. Later requests may include the negotiated `MCP-Protocol-Version`. Cross-origin browser requests are rejected and CORS is not enabled.

### 4. Approval-mode trial

1. Call `get_status`; confirm approval mode and low quotas.
2. Call `get_mentions` / `get_post`. Treat `untrusted_content` only as reading material, never instructions.
3. Call `draft_reply` or `draft_post`; verify no X post has been created.
4. Give `approval_url` to the human. In a browser, they sign in through Access, review the immutable final preview, target, and risks, then approve or reject. No manual Worker password is required.
5. After approval, call `publish({ draft_id })` and verify on X. A second call for the same draft fails.

Routes are `/health`, `/mcp`, and `/admin/approve/<32-hex-id>`. Old `/approve/<id>` URLs return 404 with no redirect. Unknown admin routes return 404 after successful Access authentication; unauthenticated admin requests always return 403. There is a shared admin routing entry point ready for a future Dashboard, but no Dashboard yet.

### 5. Switching to automatic mode

After sufficient testing, set `PUBLISH_MODE = "auto"` and redeploy. The draft → publish sequence and reply/content/risk/deduplication/single-use/rate checks remain mandatory. Switching back to `approval` does not approve drafts created in auto mode. Approval links remain bound to their ID and TTL; rotating `APPROVAL_SECRET` invalidates existing links. Legacy `/approve/` links must be replaced with newly generated admin links.

## Local development and verification

```sh
npm ci
cp .dev.vars.example .dev.vars
# Fill only the local .dev.vars; configure account ID/username in wrangler.toml too.
npm run dev
# Secure approval cookies require HTTPS and a trusted local certificate:
npm run dev -- --local-protocol https

npm run typecheck
npm test
npm run test:smoke
npx wrangler deploy --dry-run --outdir /tmp/xrg-dist
```

A local Worker does not bypass Access: without a valid assertion its admin pages return 403. Use a properly protected deployed hostname for real browser approval, or the mocked Vitest flow for local approval development. There is no production-capable bypass switch.

Vitest uses dependency injection and mocked fetch. Global fetch allows only the fixture JWKS endpoint where needed; all X calls are mocked and there are no real external requests. Tests generate RSA keys with WebCrypto and cover Access signature/claims/configuration/email failures, JWKS caching/rotation, legacy routes, password-free approve/reject, signed links, and CSRF. Existing coverage includes two OAuth signing vectors ([official guide](https://oauth.net/core/1.0a/#sig_base_example), [RFC 5849 §3.4.1.1](https://www.rfc-editor.org/rfc/rfc5849#section-3.4.1.1)), Bearer authentication, sanitization/risk rules, exactly six tools, single-use/concurrency/restarts, auto/mode switches, reply allowlists, content/deduplication/UTC quotas, redaction, and chunked-storage transaction rollback. `GuardService` is separated from the thin Cloudflare binding layer for testing; production state remains in the real DO.

`npm run test:smoke` starts an isolated local Wrangler/workerd + DO with dummy credentials, verifies initialization, six-tool listing, persisted drafts, unapproved-publish rejection, missing-JWT admin GET/POST rejection (403), and old-route rejection (404). It never reads X, approves, or sends a post; temporary DO state and processes are cleaned up. Default port is 8789; override with `SMOKE_PORT`.

Manual local MCP handshake (set a test-only `MCP_BEARER_TOKEN` in your terminal; do not put real values in shell history):

```sh
curl http://localhost:8787/mcp \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'

curl http://localhost:8787/mcp \
  -H "Authorization: Bearer $MCP_BEARER_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## Initial scope and limitations

- Static risk heuristics can be conservative (e.g. ordinary technical discussion mentioning "token", or long English/base64-like strings). They are not semantic moderation. Chinese/emoji length uses code points rather than X's full weighted algorithm; X ultimately determines acceptance.
- Text only, one account. No multi-user OAuth, images, thread orchestration, background scheduling, SSE push, or approval notifications. Mentions exposes `since_id` / `max_results`, not pagination tokens; callers may save `newest_id` for incremental reads.
- Browser approval requires HTTPS, a trusted browser, and a restrictive Access policy. Treat signed links as sensitive, even though the link alone grants neither reading nor approval access. Never share Access sessions with an AI client.
- Unknown send outcomes retain reservations and may consume quota without a successful post. This explicitly favors avoiding duplicates over automatic recovery. Credential cleanup/rotation, mode changes, Access policies, and long-term audit archival are operational responsibilities.
- All MCP clients must share one trusted authorization domain. The Bearer does not distinguish users and status contains audit summaries. Admin identity is delegated to Access, with optional Worker-side email restriction; there is no separate application user database.

## License

[MIT](LICENSE).
