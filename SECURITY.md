# Security policy

This service holds X write credentials, processes untrusted external content, and provides a human approval interface. Security issues can affect what is published from the connected X account and who can authorize it.

## Report a vulnerability privately

Use **Security → Report a vulnerability** on GitHub:

https://github.com/damao-bot-army/x-reply-guard-mcp/security/advisories/new

Include:

- Steps to reproduce the issue and the observed result.
- The commit you tested.
- Relevant configuration with all secrets removed.

You will get an answer within a week. Fixes land on `main`; there are no maintained release branches.

## In scope

- Bypassing required human approval.
- Prompt injection that causes a write without required approval.
- Authentication bypass on `/mcp` or `/admin`.
- Exposure of X credentials, the MCP Bearer token, or the approval signing secret.
- Bypassing server-side publishing checks or altering a draft after approval.

## Out of scope

- Issues in X, Cloudflare, or Grok Bot itself rather than this repository.
- Deployment errors caused by ignoring the README's setup instructions.
