# x-reply-guard-mcp

[![CI](https://github.com/damao-bot-army/x-reply-guard-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/damao-bot-army/x-reply-guard-mcp/actions/workflows/ci.yml)
![Node 22.12+](https://img.shields.io/badge/node-22.12%2B-brightgreen)
![Cloudflare Workers](https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-F38020)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![x-reply-guard-mcp](docs/images/banner.jpg)

A self-hosted MCP service on Cloudflare Workers with a shared Durable Object, letting clients such as Grok Bot read X posts and mentions, draft posts and replies, and publish through the official X API v2. External content is treated as untrusted data, and server-side checks enforce human approval by default; `PUBLISH_MODE` selects `approval` or `auto`.

## Status

This project is for people who connect Grok Bot or another MCP client to their own X account and want a human to approve each post in a browser before it is published. In approval mode one click on **Approve** publishes the draft right away, and one click on **Reject** sends it back to the agent for a rewrite; the review pages are protected by [Cloudflare Access](#review-pages-and-cloudflare-access) instead of a password.

- **Maturity:** early development, version 0.1.0. The author has not deployed it yet.
- **Requirements:** a Cloudflare account with Workers, Workers KV, and Durable Objects enabled; an X developer application with OAuth 1.0a user-context Read and Write permissions on an X API plan that includes mentions, post lookup, and post creation; an MCP client that supports remote Streamable HTTP servers with OAuth; Node.js 22.12+ and npm.
- **Releases:** none yet. Deploy from source using the [deployment instructions](#deployment) below.

For bug reports and development checks, see [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in [SECURITY.md](SECURITY.md).

Secret scanning: [gitleaks](https://github.com/gitleaks/gitleaks) runs in CI on every pull request and push to `main`, and as a pre-commit hook (`npm install` sets `core.hooksPath` to `.githooks`; requires `gitleaks` in `PATH`).

## Tools (exactly six)

| Tool | Arguments | Purpose |
| --- | --- | --- |
| `get_mentions` | `since_id?`, `max_results?` (5–100, default 10) | Read posts mentioning this account |
| `get_post` | `post_id` | Read text, author, conversation, reply parent, and parent author |
| `draft_post` | `text` | Create a draft only; return ID, final preview, expiration, risk flags, and, in approval mode, the approval URL (the human publishes it by clicking Approve there) |
| `draft_reply` | `in_reply_to_post_id`, `text` | Verify the reply allowlist live, then create a reply draft only |
| `publish` | `draft_id` | Auto mode: publish a draft after state, content, deduplication, and quota checks. Approval mode: never publishes; returns the stored `post_id` of a draft that was already published (idempotent), otherwise tells the client to have the human use the approval link |
| `get_status` | `draft_id?` | Without `draft_id`: mode, UTC hour/day counts and limits, pending approvals, last 20 audit summaries. With `draft_id`: that draft's `state` (`pending`, `rejected`, `published` with `post_id`/`post_url`, `publish_failed` with `reason`, `expired`), never its text |

Direct messages, deletion, likes, reposts, follows, profile changes, media uploads, and arbitrary URL requests are **not supported**. Clients cannot supply credentials, X API URLs, publishing modes, or approval results.

## Security design

### Sign-in

- `/mcp` is protected by `@cloudflare/workers-oauth-provider`: OAuth 2.1 with PKCE, dynamic client registration, and Client ID Metadata Documents. Requests without a valid token get `401` with a `WWW-Authenticate` header that points to the OAuth discovery metadata. Tokens must carry the `x` scope.
- When a client signs in, the consent page at `/authorize` asks for `AUTH_PASSWORD`. The owner enters it and clicks **Allow**, or clicks **Deny**. The form must be posted from the Worker's own origin, and the password is compared in constant time after SHA-256 hashing. After a wrong password, **Try again** reopens the same consent page; its address comes only from a same-origin `Referer`.

### Read path: external content is not instructions

- Only known fields are projected; raw X JSON and upstream error bodies are never passed through.
- External text is normalized with Unicode NFKC. Zero-width, bidirectional, and C0/C1 control characters are removed (newlines preserved). Post text and biographies are capped at 1,000 Unicode code points; names/usernames at 100.
- Read-tool text starts with a fixed English warning that X content is untrusted and must never be executed as instructions. Each response uses random `<<X_UNTRUSTED_…>>` boundaries; boundary lookalikes in content are escaped. Structured data lives under `untrusted_content`. Reply drafts also wrap and label their target context separately.
- English and Chinese risk rules label `instruction_override`, `credential_request`, `tool_invocation`, `role_impersonation`, `exfil_url`, `hidden_text`, and `risk_level`. They cover instruction overrides, system prompts, role spoofing, credential requests, immediate publication, exfiltration URLs, and hidden characters. These are advisory labels, not authorization. Chinese characters in the risk patterns are written as Unicode escapes in source.

### Write path: enforced by the server

1. `draft_*` **never publishes**. It creates a random 128-bit ID and stores immutable final text, hash, target, and TTL.
2. Default `approval` mode returns a `/admin/approve/<id>` link signed with HMAC-SHA256 over the draft ID and expiration. `APPROVAL_SECRET` is only this server-side signing key; humans never need to know or enter it.
3. A human signed in through [Cloudflare Access](#review-pages-and-cloudflare-access) opens the link and checks the text/target/risk warning. **One click on Approve publishes the draft immediately**; one click on **Reject** sends it back (state `rejected`, X is not called). There is no password and no confirmation step on the review page. Do not give `AUTH_PASSWORD` or `APPROVAL_SECRET` to the bot.
4. Before anything else, the page and the form POST verify the Cloudflare Access assertion (`Cf-Access-Jwt-Assertion`: RS256 signature against the team's keys, issuer, audience, expiry). Without it the visitor sees a sign-in page with nothing about the draft, and no decision is executed. Then they check the link HMAC, expiration, and pending state. The POST also checks same-origin `Origin` and a random double-submit CSRF token in an HttpOnly/Secure/SameSite=Strict cookie scoped to `/admin/approve/<id>`. The page shows the final text with its length as X counts it (out of 25000, highlighted if over), the reply target's author and text, the expiry, and any risk flags; all of it is HTML-escaped.

   Results of an Approve click: **Published** (200) with a **View post on X** link to `https://x.com/<X_USERNAME>/status/<post_id>`; **Not published** (409) when a check fails before sending (rate limit, duplicate, reply target no longer allowed, expiry): nothing was reserved, the draft stays `pending`, and **Try again** reopens the same signed link; **Publishing failed** (502) when X refuses or the outcome is unknown after the reservation: the draft becomes `publish_failed` and is never retried. **Rejected** (200) after Reject.

   All HTML pages (consent, review, results and errors) are self-contained: the CSP is `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` plus a per-response nonce for the one inline stylesheet and the small progressive-enhancement scripts (show password on the consent page, local expiry time on the review page); there is no `'unsafe-inline'` and nothing is loaded from elsewhere. The only external link is the published post on `x.com`. `/authorize` omits `form-action` because it would also apply to the OAuth redirect chain; the review page keeps `form-action 'self'`, since it posts to itself and never redirects. Pages set `Cache-Control: no-store` and `Referrer-Policy: same-origin` (not `no-referrer`, which makes browsers send `Origin: null` on the same-origin form POST; `Origin: null` is rejected).
5. Every publication, from MCP `publish` in auto mode or from an Approve click in approval mode, goes through the same code path, serially inside the DO: expiration and state checks, content and auto-mode risk checks, deduplication, quotas, reply-target revalidation, then the durable reservation, then POST to X. Each draft is single-use; a second click or a double submit reports **Already handled**. In approval mode MCP `publish` never sends anything: it returns the stored `post_id` of a published draft and otherwise points to the approval link. Switching from auto back to approval does not approve pending drafts.
6. Replies are allowed only when X mention entities name this account, or a live conversation-root lookup confirms this account started the conversation. `in_reply_to_user_id` alone is insufficient. The target is checked again before publication.
7. Text must be nonempty and fit X Premium's 25000-character limit as twitter-text 3.1.0 counts it (CJK and emoji 2; each URL 23, including bare domains such as `example.com` or `main.py`), measured on the text as it will be published. Published text is not NFKC-normalized (full-width punctuation and letters are kept); hidden characters are stripped as for external text. An NFKC-cleaned copy is used only for secret checks and duplicate hashing. Checks reject the raw, NFKC, sanitized, and URL-encoded forms of all six configured secrets, plus suspicious `sk-`, `Bearer `, long hex/base64 patterns. Both original and cleaned text are checked against hidden-character secret splitting. SHA-256 hashes of normalized, stripped, trimmed text prevent duplication against the last 50 published/reserved texts.
8. Risky drafts may be reviewed in approval mode, but auto mode refuses them. Publication rechecks risk and content so switching modes cannot send risky drafts in auto mode.
9. All clients share one fixed-name DO. Its serial queue covers network awaits. **Before X POST**, a durable transaction marks the draft used and reserves quota and deduplication state. Concurrent calls or DO restarts cannot send the same draft again. Large snapshots are chunked and committed in one transaction.
10. Quotas use **UTC clock hours and calendar days**, defaulting to 5/hour and 20/day. Counts include published and reserved attempts. X errors, timeouts, or crashes **do not roll back** the reservation (state `publish_failed`, quota, deduplication hash), avoiding duplicate posts under uncertain outcomes. Check X manually before deciding whether to create a different draft; never automatically retry identical content.
11. Draft/approve/reject/publish/wake successes, failures, and pre-send reservations record time, action, draft ID, target, text hash, and result, not text bodies. The last 500 audit entries are retained; status returns 20. Expired drafts are cleaned up 24 hours after expiration during later operations, with a maximum of 1,000 drafts. Long-term production audit archives must be separately controlled and unavailable to MCP clients.
12. Last-mile redaction covers tool results, HTML, and errors. Requests, credentials, and raw X errors are not logged. X 401/403/404/429 map to fixed messages; 429 includes `retry_after_seconds`. X fetch forbids redirects and times out after 15 seconds. Limits: MCP body 256 KiB, string arguments 30,000 UTF-16 code units, approval POST 4 KiB, X response 2 MiB.

### Review pages and Cloudflare Access

The review page asks for no password, so in production **`/admin/approve/*` must sit behind Cloudflare Access**. Access decides who may review (for example, only the owner's email); a reviewer with a valid Access session approves or rejects with one click, while anyone else holding a link cannot see the draft or act on it. The Worker also verifies the Access JWT itself and fails closed: with `ACCESS_TEAM_DOMAIN` or `ACCESS_AUD` unset, review pages return 503 and no decision can be made.

Set up (Cloudflare dashboard, done by the owner):

1. In **Zero Trust → Access → Applications**, add a **Self-hosted** application for the Worker's hostname with the path `admin/approve/*` (GET and POST and every result page are served under it). Do **not** protect `/mcp`, `/authorize`, `/oauth/*` or `/.well-known/*`: MCP clients cannot pass Access, and the consent page keeps its own `AUTH_PASSWORD`.
2. Add an **Allow** policy that includes only the reviewers (for example, your email). Pick a session duration that suits you; while the session is valid, review is one click.
3. Copy the application's **Application Audience (AUD) tag** into `ACCESS_AUD`, and your team domain (`<team>.cloudflareaccess.com`, under Zero Trust settings) into `ACCESS_TEAM_DOMAIN`, in `wrangler.local.jsonc`, then redeploy.

The Worker fetches the team's public keys from `https://<team>.cloudflareaccess.com/cdn-cgi/access/certs` (cached for 10 minutes, refetched once on an unknown key ID) and checks the RS256 signature, `iss`, `aud`, `exp` and `nbf`. A custom domain is the simplest setup; Access can also protect a `workers.dev` hostname.

**Test double (local development and e2e only):** with `ACCESS_TEST_DOUBLE=true` and a request to `localhost`, `127.0.0.1` or `[::1]`, the header `X-Test-Access-Identity: <email>` stands in for the Access JWT; without the header the pages refuse as an anonymous visitor. It is ignored on every other hostname, so a deployed Worker never accepts it, but still **never set `ACCESS_TEST_DOUBLE` in production**.

### Wake notifications (Echo)

When a review ends, the Worker POSTs to `ECHO_WAKE_URL` (https only) so the drafting agent can wrap up or rewrite without being pinged. With `ECHO_WAKE_TOKEN` set, the request carries `Authorization: Bearer <token>`. The body never contains the draft text or any credential:

```json
{ "event": "draft.review_result", "draft_id": "<32 hex>", "result": "published", "draft_state": "published",
  "post_id": "1890000000000000999", "post_url": "https://x.com/<X_USERNAME>/status/1890000000000000999", "time": "2026-11-05T12:00:00.000Z" }
```

`result` is `published` (with `post_id`, `post_url`), `rejected`, or `publish_failed` (with `reason` and `retryable`: `true` when a check failed before sending and the same link can be approved again, `false` after a failed send). Delivery is best effort (5-second timeout, no retries); the outcome is audited as action `wake` and never changes the review result. The agent can always confirm with `get_status({ draft_id })`. No wake is sent for auto-mode `publish`, whose caller gets the result directly. Leave `ECHO_WAKE_URL` unset to disable.

`auto` explicitly lowers the human-authorization requirement: an AI may publish any ordinary text passing the hard checks. Risk rules are not semantic moderation. Keep `approval` if **every post must be human-authorized**.

## Data storage

Everything runs in your own Cloudflare account. The Worker sends outbound requests only to `api.x.com`, to your Access team's key endpoint (`https://<team>.cloudflareaccess.com/cdn-cgi/access/certs`), to `ECHO_WAKE_URL` if set, and, when an MCP client identifies itself with a Client ID Metadata Document, to that client's metadata URL.

- **Worker secrets:** `AUTH_PASSWORD`, `APPROVAL_SECRET`, the four X credentials, and optionally `ECHO_WAKE_TOKEN`.
- **Durable Object storage:** one fixed-name `GuardStore` object (binding `GUARD_STORE`, SQLite-backed) holds all state: drafts (final text, text hash, reply target ID, sanitized target context, risk flags, state, expiration, `post_id` once published, a redacted failure summary if sending failed), the last 50 published/reserved text hashes, the current UTC hour/day counters, and the last 500 audit entries (no text bodies). Drafts are deleted 24 hours after expiration during later operations.
- **KV (`OAUTH_KV`):** OAuth clients, grants, and tokens, managed by `@cloudflare/workers-oauth-provider`. Tokens and secrets are stored only as hashes.
- **Not stored:** results of `get_mentions` and `get_post`, and raw MCP requests.

## Deployment

### 1. X developer application

Create your own project/application in the X Developer Portal and enable **OAuth 1.0a user-context Read and Write**. Regenerate this account's Access Token/Secret after permission changes. Prepare API Key/Secret, Access Token/Secret, the account's numeric User ID, and username without `@`. Your X API plan must support mentions, single-post reads, and post creation; X plan/endpoint limits are independent of this service's quotas.

This version supports **one X account and one owner**; every MCP client the owner authorizes acts for that owner.

### 2. Install and configure

Use Node.js 22.12+, npm, and a Cloudflare account with Workers, Workers KV, and Durable Objects enabled.

```sh
npm ci
npx wrangler login
npx wrangler kv namespace create OAUTH_KV   # prints the namespace ID
cp wrangler.local.jsonc.example wrangler.local.jsonc
```

The committed `wrangler.jsonc` holds placeholders only and is used for local development, tests, and CI. Put your real values in the git-ignored `wrangler.local.jsonc`: `X_USER_ID`, `X_USERNAME`, the `OAUTH_KV` namespace ID, `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` (see [Review pages and Cloudflare Access](#review-pages-and-cloudflare-access)), optionally `ECHO_WAKE_URL`, and optionally a custom domain under `routes` (remove `routes` to use `x-reply-guard-mcp.<your-subdomain>.workers.dev`). Keep `PUBLISH_MODE` at `approval`.

Choose a long random `AUTH_PASSWORD` and a different high-entropy `APPROVAL_SECRET` (for example `openssl rand -hex 32`). Store all secrets through the interactive prompts, not config files or command-line arguments, then deploy:

```sh
npx wrangler secret put AUTH_PASSWORD -c wrangler.local.jsonc
npx wrangler secret put APPROVAL_SECRET -c wrangler.local.jsonc
npx wrangler secret put X_API_KEY -c wrangler.local.jsonc
npx wrangler secret put X_API_SECRET -c wrangler.local.jsonc
npx wrangler secret put X_ACCESS_TOKEN -c wrangler.local.jsonc
npx wrangler secret put X_ACCESS_TOKEN_SECRET -c wrangler.local.jsonc
npx wrangler secret put ECHO_WAKE_TOKEN -c wrangler.local.jsonc   # optional, with ECHO_WAKE_URL
npx wrangler deploy --dry-run -c wrangler.local.jsonc --outdir dist
npm run deploy
# Runs wrangler deploy -c wrangler.local.jsonc; the first deployment applies the Durable Object migration v1.
```

This repository contains placeholders and test credentials only; `.dev.vars.example` and `wrangler.local.jsonc.example` are templates.

| Setting | Type | Default / meaning |
| --- | --- | --- |
| `AUTH_PASSWORD` | secret | Owner password for the OAuth consent page (`/authorize`), compared in constant time after SHA-256 hashing. The review page does not use it |
| `APPROVAL_SECRET` | secret | Server-only approval-link HMAC-SHA256 key |
| `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_TOKEN_SECRET` | secret | X OAuth 1.0a user credentials |
| `X_USER_ID`, `X_USERNAME` | var | Account ID / username |
| `PUBLISH_MODE` | var | `approval` (default if omitted) or `auto`; any other value makes `draft_*`, `publish`, and `get_status` fail with a configuration error |
| `MAX_POSTS_PER_HOUR` | var | 5; positive integer |
| `MAX_POSTS_PER_DAY` | var | 20; positive integer |
| `DRAFT_TTL_MINUTES` | var | 30; positive integer |
| `ACCESS_TEAM_DOMAIN` | var | Required for review pages: your Access team domain, `<team>.cloudflareaccess.com` |
| `ACCESS_AUD` | var | Required for review pages: Application Audience (AUD) tag of the Access application protecting `/admin/approve/*` |
| `ACCESS_TEST_DOUBLE` | var | Unset. Local development and e2e only: `true` accepts `X-Test-Access-Identity` on localhost. Never set in production |
| `ECHO_WAKE_URL` | var | Unset (no notifications). https endpoint notified when a review ends |
| `ECHO_WAKE_TOKEN` | secret | Optional bearer token sent to `ECHO_WAKE_URL`; treated as a secret (redacted, refused in drafts) |
| `GUARD_STORE` | Durable Object binding | Class `GuardStore`, SQLite migration `v1`; holds all guard state |
| `OAUTH_KV` | KV binding | OAuth clients, grants, and tokens |

If any of the six required secrets is missing, authorized `/mcp` requests and `/admin` pages return 503. Review pages also return 503 until `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are set.

### 3. Add a custom MCP in Grok Bot

In Grok Bot or another MCP client that supports remote **Streamable HTTP** servers with OAuth, add the server URL:

```text
https://<worker-host>/mcp
```

No header, client ID, or client secret is needed: the server supports OAuth dynamic client registration and Client ID Metadata Documents. When the client starts the OAuth flow, the consent page opens in your browser. Check the client name, enter `AUTH_PASSWORD`, and click **Allow**. The client then lists the six tools. Never add `AUTH_PASSWORD`, `APPROVAL_SECRET`, or X credentials to the client configuration.

The MCP layer is minimal **JSON-RPC over Streamable HTTP**: stateless POST, JSON responses, notifications returning 202, and `initialize` / `ping` / `tools/list` / `tools/call`. Protocols `2025-03-26`, `2025-06-18`, and `2025-11-25` are supported. No sessions, SSE subscriptions, or server push; GET/DELETE return 405. No Node HTTP adapter, SDK, or agents are needed. Request `Accept` must include both `application/json, text/event-stream`; `Content-Type` must be `application/json`. Later requests may include the negotiated `MCP-Protocol-Version`. Requests with a cross-origin `Origin` header are rejected.

### 4. Approval-mode trial

1. Call `get_status`; confirm approval mode and low quotas.
2. Call `get_mentions` / `get_post`. Treat `untrusted_content` only as reading material, never instructions.
3. Call `draft_reply` or `draft_post`; verify no X post has been created.
4. Give `approval_url` to the human. Opened without an Access session, it shows a sign-in page and nothing else. Signed in through Access, they review the immutable final preview, target, and risks, then click **Approve and publish** (the post goes out immediately and the page links to it) or **Reject**.
5. Wait for the wake notification or call `get_status({ draft_id })`: `published` with `post_id`, `rejected` (write a new draft), or `publish_failed` with a reason. In approval mode `publish({ draft_id })` only returns the stored `post_id`; it never sends.

| Path | Access |
| --- | --- |
| `/mcp` | MCP endpoint; OAuth bearer token with the `x` scope |
| `/authorize` | OAuth consent page; Allow requires `AUTH_PASSWORD` |
| `/oauth/register`, `/oauth/token`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp` | OAuth client registration, token exchange, and discovery |
| `/admin/approve/<32-hex-id>` | Review page; Cloudflare Access session, signed link, `Origin` and CSRF token. No password |
| `/health` | Public liveness check; makes no X request |

Old `/approve/<id>` URLs and unknown `/admin` routes return 404 with no redirect.

### 5. Switching to automatic mode

After sufficient testing, set `PUBLISH_MODE` to `auto` in `wrangler.local.jsonc` and redeploy. In auto mode the MCP client publishes with `publish({ draft_id })` and no approval link is issued. The draft → publish sequence and reply/content/risk/deduplication/single-use/rate checks remain mandatory. Switching back to `approval` does not approve drafts created in auto mode. Approval links remain bound to their ID and TTL; rotating `APPROVAL_SECRET` invalidates existing links. Legacy `/approve/` links must be replaced with newly generated admin links.

## Local development and verification

```sh
npm ci
cp .dev.vars.example .dev.vars
# Fill only the local .dev.vars.
npm run dev
# Secure approval cookies require HTTPS and a trusted local certificate:
npm run dev -- --local-protocol https

npm run typecheck
npm test
npm run test:smoke
npm run test:e2e   # needs Google Chrome; set CHROME_PATH if it is not /usr/bin/google-chrome
npx wrangler deploy --dry-run --outdir /tmp/xrg-dist
```

Local development uses the placeholder `wrangler.jsonc`. To read your real account locally, also set `X_USER_ID` and `X_USERNAME` in `.dev.vars`; they override the placeholders. Point an MCP client that supports OAuth at `http://localhost:8787/mcp`; the consent page asks for the `AUTH_PASSWORD` from `.dev.vars`. To open review pages locally, set `ACCESS_TEST_DOUBLE=true` in `.dev.vars` and send `X-Test-Access-Identity: <email>` (for example with a header-editing browser extension or `curl -H`); remember that Approve really publishes with real X credentials. The dry run above checks the committed config; add `-c wrangler.local.jsonc` to check your own.

Vitest uses dependency injection and mocked fetch; all X calls are mocked and any other global fetch fails, so there are no real external requests. OAuth tests run the real `OAuthProvider` against an in-memory KV: discovery metadata, 401 challenges, dynamic registration, the consent page and its CSP, correct/wrong/missing password, deny, cross-origin and forged consent submissions, and PKCE token exchange; every MCP test uses a token obtained through that flow. Approval tests cover signed links, CSRF, `Origin` (including `Origin: null`), the `same-origin` referrer policy, expiration, single use, legacy routes, and the absence of any password field. Review-flow tests (`test/review-flow.test.ts`, mapped to PRD stories S0–S4) sign real RS256 Access JWTs against a served JWKS and cover: anonymous, forged, expired, wrong-audience, wrong-issuer and `alg` confusion assertions (no draft shown, no decision executed), fail-closed 503 without Access config, the localhost-only test double, one-click Approve publishing with the post link and stored `post_id`, pre-send check failures that keep the draft pending and retryable, X failures after the reservation (`publish_failed`, no retry), Reject without calling X, wake notifications (payload without text, bearer token, skipped/failed delivery), `get_status({ draft_id })`, and idempotent approval-mode `publish`. Page tests check that hostile draft text, client names and reply-target content are escaped, that every page's CSP nonce matches its inline style and script with no `'unsafe-inline'`, and that every result and error page keeps its status code. Existing coverage includes two OAuth 1.0a signing vectors ([official guide](https://oauth.net/core/1.0a/#sig_base_example), [RFC 5849 §3.4.1.1](https://www.rfc-editor.org/rfc/rfc5849#section-3.4.1.1)), sanitization/risk rules, exactly six tools, single-use/concurrency/restarts, auto/mode switches, reply allowlists, X's weighted length (expected values agree with the official `twitter-text` 3.1.0 library), content/deduplication/UTC quotas, redaction, and chunked-storage transaction rollback. `GuardService` is separated from the thin Cloudflare binding layer for testing; production state remains in the real DO.

`npm run test:smoke` starts an isolated local Wrangler/workerd + DO with dummy X credentials and a random `AUTH_PASSWORD`, and runs the production OAuth code: the 401 challenge, discovery metadata (including Client ID Metadata Document support), dynamic registration, wrong password, deny, and consent + PKCE token. With that token it checks initialization, six-tool listing, persisted drafts, unapproved-publish rejection, the review page refused without the Access test double (403), forged-signature rejection, a review page with no password field, Reject, `get_status({ draft_id })`, and old-route rejection (404). It never reads X or clicks Approve (which publishes), so it makes no X requests; temporary DO state and processes are cleaned up. Default port is 8789; override with `SMOKE_PORT`.

`npm run test:e2e` drives headless Chrome (`puppeteer-core`, using the installed Chrome at `CHROME_PATH`, default `/usr/bin/google-chrome`) through the real pages on Wrangler's local dev server with the committed `wrangler.jsonc`: consent with a wrong password, **Try again**, the correct password and **Allow**, then the PKCE token; a reply draft's review link refused without Access (no draft, no form), then opened with the Access test double (no password field) and **Reject**ed; a post draft published by one click on **Approve and publish**, with the **View post on X** link, **Already handled** on reopening, and MCP `publish` returning the same `post_id`; and a draft the fake X refuses, showing **Publishing failed** and `publish_failed`. Wake notifications are captured and checked (rejected, published, publish_failed; bearer token; no draft text). Every outbound request from the Worker is intercepted: `api.x.com` is answered by a fake X API and `ECHO_WAKE_URL` by a fake wake endpoint inside the script, and anything else fails the test, so it never contacts X. It fails on any CSP violation, script error, horizontal overflow, or form POST whose `Origin` is not the page's own origin. It picks a free port (override with `E2E_PORT`); `E2E_SCREENSHOTS=<dir>` saves a screenshot of each step.

## Initial scope and limitations

- Static risk heuristics can be conservative (e.g. ordinary technical discussion mentioning "token", or long English/base64-like strings). They are not semantic moderation. The length check follows twitter-text 3.1.0, including where URLs start and end; emoji sequences missing from its emoji table (Emoji 12 and later with a skin tone, such as 🤏🏽, and emoji followed by a redundant U+FE0F, such as ♾️ or 😀️) count as 2 here where twitter-text counts 4. Like twitter-text, counting is quadratic on some pathological inputs (long runs such as `中.` repeated). Text whose published form (hidden characters stripped, no NFKC) is longer than 25,000 UTF-16 code units is refused before it is counted, and MCP string arguments are capped at 30,000 UTF-16 code units. Within that cap a pathological draft can still take about 5 s to count in Node (12,500 × `中.`) and about 8 s on workerd, during which the Durable Object handles no other request; an accepted pathological draft (such as `😀.` × 8,333) is recounted when drafted, each time its approval page is opened, and on `publish`, about 7.5 s each. The cap can also refuse a legitimate post that exceeds 25,000 code units even though X would count it as 25,000 or fewer (very long URLs, or many multi-code-point emoji). Tabs, carriage returns and other hidden characters (including U+200D, so emoji ZWJ sequences lose their joiners) are stripped from the published text and add the `hidden_text` risk flag, so `auto` mode refuses such drafts. X ultimately determines acceptance.
- Text only, one account. No multi-user OAuth, images, thread orchestration, background scheduling, or SSE push; review results are pushed only to the optional `ECHO_WAKE_URL`. `get_mentions` accepts `since_id` / `max_results` but no pagination token; callers may save `newest_id` for incremental reads.
- Browser review requires HTTPS, a trusted browser and a Cloudflare Access session. Anyone allowed by the Access policy who holds a signed link can approve (and so publish) or reject it with one click; keep the policy to the reviewers only. Drafts approved under the old two-step flow (state `approved`) are not published by `publish`; let them expire and draft again.
- Unknown send outcomes retain reservations and may consume quota without a successful post. This explicitly favors avoiding duplicates over automatic recovery. Credential cleanup/rotation, mode changes, and long-term audit archival are operational responsibilities.
- Every authorized MCP client acts as the single owner; clients are not separated, and status contains audit summaries. Changing `AUTH_PASSWORD` does not revoke issued OAuth tokens; to revoke all grants, use a fresh `OAUTH_KV` namespace and redeploy.

## License

[MIT](LICENSE). `src/post-urls.ts` includes code ported from:

- [twitter-text](https://github.com/twitter/twitter-text) 3.1.0 — Copyright Twitter, Inc., Apache License 2.0.
- [punycode.js](https://github.com/mathiasbynens/punycode.js) — Copyright Mathias Bynens, MIT License.

Their copyright notices and full license texts are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
