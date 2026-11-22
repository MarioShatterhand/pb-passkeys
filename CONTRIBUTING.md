# Contributing

Thanks for your interest. This project is on the login path of other people's applications, so we value careful, well-tested changes over fast ones.

## Before you start

- **Security issues: do not open a public issue.** See [SECURITY.md](SECURITY.md).
- For anything bigger than a small fix, open an issue first and describe the problem. Check that it fits the module boundary in [docs/architecture.md](docs/architecture.md#2-the-boundary): application-specific policy belongs in hooks, not in the module.

## Development setup

- Go (version in `go.mod`), Node.js 22+ for the client, and Chromium via Playwright for E2E.
- See the commands in [CLAUDE.md](CLAUDE.md#commands-once-code-exists).

## Pull requests

1. Fork, create a branch from `main`.
2. Add or update tests. Changes to ceremony, recovery or storage code must include tests for the affected invariants in [docs/security.md](docs/security.md).
3. Run `go test -race ./...`, `golangci-lint run`, and the client tests if you touched `client/`.
4. Update docs and `CHANGELOG.md` (`Unreleased`) for user-visible changes.
5. Use [Conventional Commits](https://www.conventionalcommits.org/) and sign off every commit (`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org/).
6. Keep PRs focused. One feature or fix per PR.

New dependencies need a justification in the PR description. We prefer the standard library.

## Using AI assistants

You may use AI tools. You are responsible for every line you submit: you must understand it and be able to explain it in review. [CLAUDE.md](CLAUDE.md) contains the rules we give to Claude Code, and they apply to human contributors too.

## Reporting bugs

Include the pocketauthn version, PocketBase version, Go version, browser and authenticator (e.g. "Chrome 140 on Android 15, Google Password Manager"), and the steps to reproduce. Never paste real tokens, recovery codes or database files.

## Code of conduct

Be respectful and constructive. Maintainers may remove comments or contributions that are abusive. [Placeholder: adopt the Contributor Covenant 2.1 as `CODE_OF_CONDUCT.md` before announcing the project.]
