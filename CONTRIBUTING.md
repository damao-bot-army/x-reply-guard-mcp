# Contributing

This is a small project. Bug reports and fixes are welcome. Open an issue to discuss new ideas before implementing them.

## Report issues

Report bugs using the GitHub [new issue form](https://github.com/damao-bot-army/x-reply-guard-mcp/issues/new). Include reproduction steps, expected and actual behavior, and the commit you tested.

Report security issues privately using [SECURITY.md](SECURITY.md), not a public issue.

## Development

Use Node.js 22.12+ and npm. Clone the repository, enter its directory, and install dependencies:

```sh
npm ci
```

Install [gitleaks](https://github.com/gitleaks/gitleaks) 8.x locally and make sure `gitleaks` is in your `PATH`. `npm ci` sets `core.hooksPath` to `.githooks`, and the pre-commit hook blocks commits when gitleaks is missing. The hook and the `prepare` script require a POSIX shell.

See the README's [local development instructions](README.md#local-development-and-verification) for local Worker configuration and execution.

Before submitting a pull request, run the same checks as CI:

```sh
npm ci
npm run typecheck
npm test
npx wrangler deploy --dry-run
```

Open pull requests against `main`. Describe the change, link the relevant issue, and include your check results.
