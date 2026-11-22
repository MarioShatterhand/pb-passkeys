# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`pocketauthn` (working name): an open-source Go module that adds passkey (WebAuthn) authentication to PocketBase applications, plus a small TypeScript client. It is a **generic library**. It must stay usable by anyone, for any app.

Read before changing anything substantial:
- `docs/architecture.md`: module boundary, data model, flows
- `docs/api.md`: config, routes, hooks, client
- `docs/security.md`: threat model and invariants (authoritative when documents disagree)
- `docs/versioning.md`: PocketBase compatibility policy
- `docs/open-questions.md`: assumptions not yet verified

## Hard rules

1. **No application-specific logic.** No references to any particular product, domain, language, country or workflow. If a feature needs to know *why* a user enrolls or *how* they were verified, it is a hook, not module code. Examples and tests use neutral data (`alice@example.com`, `example.com`).
2. **No home-made cryptography.** WebAuthn verification goes through `github.com/go-webauthn/webauthn`. Hashing through the Go standard library and `golang.org/x/crypto/argon2`. Randomness only from `crypto/rand`. Comparisons of secrets with `crypto/subtle`.
3. **Never store or log secrets in plaintext**: recovery codes, enrollment tokens, step-up tokens, `sessionData`, raw client data. Logs use allow-listed fields only.
4. **Public endpoints return generic errors.** Do not leak whether an account, credential or code exists. Secrets travel only in JSON bodies, never in URL paths or query strings.
5. **New collections start with all API rules `null`.** Open them deliberately and add rule tests.
6. **Do not trust your memory of the PocketBase API.** PocketBase is pre-1.0 and changes between minors. Before using any PocketBase function, read it in the module cache for the version pinned in `go.mod` (`go env GOMODCACHE`). The same for go-webauthn. If something in `docs/open-questions.md` turns out different, update that file in the same PR.
7. **Every security invariant marked (T) in `docs/security.md` needs a test.** A PR that touches `ceremony/`, `recovery/` or `store/` without tests is incomplete.
8. Keep dependencies minimal. Adding a Go or npm dependency needs a sentence in the PR explaining why.

## Layout (planned)

```
/                 Go module root (package pocketauthn: Register, Config validation, hooks)
internal/ceremony go-webauthn wrapper
internal/store    collections, migrations, queries, cleanup jobs
internal/recovery recovery codes, enrollment tokens, step-up
internal/routes   HTTP handlers
internal/testauthn software authenticator for tests (ES256, "none" attestation)
client/           TypeScript client (npm package), Vitest tests
examples/minimal  example app, target of Playwright E2E
docs/             design documents
```

## Commands (once code exists)

```sh
go test -race ./...                     # unit + integration (in-process PocketBase with a temp data dir)
go vet ./... && golangci-lint run
govulncheck ./...
go get github.com/pocketbase/pocketbase@v0.X.Y && go mod tidy   # test against another PocketBase version

cd client && npm ci && npm test && npm run typecheck
cd examples/minimal && go run . serve --dir ./pb_data           # manual check on http://localhost:8090
npx playwright test --trace off                                  # E2E (Chromium virtual authenticator)
```

## Testing approach

- Go integration tests start a real PocketBase app in-process (`tests.NewTestApp` or equivalent in the pinned version, to verify) with a temporary data directory and exercise the HTTP routes.
- `internal/testauthn` generates real WebAuthn responses, so tests cover actual signature verification, not mocks.
- E2E uses Chromium's CDP `WebAuthn.addVirtualAuthenticator`, with both resident-key/UV and non-UV authenticators.
- Each failing test re-run: only the failing tests while fixing; the full suite before pushing.

## Conventions

- Go: standard formatting, errors wrapped with `%w`, exported API documented with examples. Hooks use `github.com/pocketbase/pocketbase/tools/hook` and must call `e.Next()`.
- TypeScript: strict mode, ES2022, no runtime dependencies.
- Commits: Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), signed off (`git commit -s`, DCO).
- User-visible changes go in `CHANGELOG.md` under `Unreleased`.
- English everywhere in the repository.
