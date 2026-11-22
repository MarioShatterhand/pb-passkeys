# Roadmap and compatibility

## 1. Versioning

- Semantic versioning for both the Go module and the npm client, released together with the same version number.
- `v0.x`: breaking changes are allowed in minor releases and are listed under **Breaking** in `CHANGELOG.md`.
- `v1.0.0` after the security checklist in [security.md](security.md#7-before-10) is done. Not tied to PocketBase reaching 1.0.

## 2. PocketBase compatibility

PocketBase is pre-1.0 and changes its Go API between minor releases. Policy:

- Each pb-passkeys minor release supports a stated **range of PocketBase minor versions**. The first release (0.1) supports only the PocketBase minor that is current at that time. From then on, when a new PocketBase minor appears, the previous one stays supported, so the range is at least the **current and previous** minor.
- `go.mod` requires the lowest supported PocketBase version. Users may upgrade PocketBase within the supported range without upgrading this module.
- CI runs the full Go test suite against the lowest supported patch and the latest patch of every supported minor (matrix in `.github/workflows/ci.yml`).
- A scheduled CI job (weekly) tests against the newest PocketBase release and opens an issue when it fails, so breakage is found before users report it.
- The README has a compatibility table:

| pb-passkeys | PocketBase | Go | go-webauthn |
|---|---|---|---|
| 0.1.x (planned) | 0.40.x (from v0.40.6) | 1.27+ | 0.18.x |

`go.mod` pins PocketBase **v0.40.6** (the latest release as of 2026-11-22, requires Go 1.27) and go-webauthn **v0.18.2**. PocketBase 0.39 is not supported: nothing was released for it, so supporting it would only double the work of verifying every assumption in [open-questions.md](open-questions.md) against two versions of a pre-1.0 API.

## 3. Roadmap

| Version | Scope |
|---|---|
| **0.1** | Config validation, collections + migrations, registration and discoverable login, many credentials per user, list/rename/delete via collection API, stored authenticator hints and `CredentialKind`, standard auth response, Go tests with a software authenticator |
| **0.2** | Recovery codes, enrollment tokens (invite, admin reset, recovery, optional binding to the first device), step-up (including `ForCredentialDelete`), all hooks, cleanup job, passwordless `Warn`/`Enforce` |
| **0.3** | TypeScript client, `examples/minimal`, Playwright E2E with Chromium's virtual authenticator, conditional UI (autofill) |
| **0.4** | Android origins (`android:apk-key-hash`) documented and tested, AAGUID → authenticator name lookup (optional, embedded list), prebuilt "PocketBase + pb-passkeys" binaries via GoReleaser |
| **0.5** | Fuzzing, docs site, migration guide from other PocketBase passkey add-ons |
| **1.0** | External security review, stable API |
| Later | JSVM (`pb_hooks`) bindings, attestation via FIDO MDS, PRF extension helpers |

## 4. Release process

1. All CI green on `main`, including the PocketBase matrix.
2. Update `CHANGELOG.md` and the compatibility table.
3. Signed tag `vX.Y.Z`; the release workflow publishes the npm package with provenance and attaches binaries (from 0.4).
4. Security fixes: patch release for the latest minor; backport to the previous minor while it is still listed as supported.
