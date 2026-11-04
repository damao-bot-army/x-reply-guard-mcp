# Security policy

This service holds X write credentials, passes untrusted content from X to an AI client, and serves an OAuth consent page at `/authorize` and a browser approval page under `/admin`. A vulnerability can let someone publish from the connected X account or approve posts without authorization.

## Report a vulnerability privately

Use **Security → Report a vulnerability** on GitHub:

https://github.com/damao-bot-army/x-reply-guard-mcp/security/advisories/new

Include:

- Steps to reproduce the issue and the observed result.
- The commit you tested.
- Relevant configuration with all secrets removed.

You will get an answer within a week. Fixes land on `main`; there are no maintained release branches.

## In scope

- Publishing in `approval` mode without a human approval, including through prompt injection in X content.
- Bypassing OAuth on `/mcp`, the `AUTH_PASSWORD` check on the consent page, or the `x` scope check.
- Forging approval links signed with `APPROVAL_SECRET`, approving a draft without `AUTH_PASSWORD`, or cross-site request forgery against the consent or approval forms.
- Open redirects or other flaws in the OAuth authorization redirect and consent page.
- Publishing a draft more than once, changing its text or reply target after approval, or exceeding the configured hourly and daily limits.
- Bypassing the reply allowlist or the content checks applied at draft and publish time.
- Exposure of `AUTH_PASSWORD`, `APPROVAL_SECRET`, OAuth tokens, or the X credentials (`X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_TOKEN_SECRET`) through tool results, approval pages, errors, or logs.

## Out of scope

- Issues in X, Cloudflare, Grok Bot, or other MCP clients rather than this repository.
- Posts published in `auto` mode that pass the server-side checks; that mode does not require human approval by design.
- Attacks that require access to the Cloudflare account, Worker secrets, or `AUTH_PASSWORD`.
- Deployment errors caused by ignoring the README's setup instructions.
