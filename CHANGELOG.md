# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## Unreleased

### Added
- Design documents: architecture, API, threat model, versioning, open questions.
- Design: step-up ceremony routes and `passkey_step_ups` collection; recovery codes with selector + verifier (one Argon2id check per redeem); global caps `MaxPendingChallenges` and `RecoveryCodes.MaxConcurrentHashes`; `OnSignCountAnomaly` hook.
- Design: optional step-up for deleting a credential (`StepUp.ForCredentialDelete`: `Off` / `AnyCredential` / `OtherCredential`) with a `credentials/delete` route.
- Design: optional binding of an enrollment token to the first browser that uses it (`bindToFirstDevice`) and the `OnEnrollmentBindingMismatch` hook.
- Design: `authenticatorAttachment` stored with each credential; `CredentialKind` helper (`synced` / `device` / `security_key` / `unknown`) for display.
- Go module `github.com/MarioShatterhand/pb-passkeys` (package `passkeys`), pinned to PocketBase v0.40.6 and go-webauthn v0.18.2. No functionality yet.
- Secret scanning with gitleaks: pre-commit hook in `.githooks/` and a CI workflow.
- `passkeys.Register` and `MustRegister` with `Config`: defaults, validation of the relying party settings and options, and startup checks of the configured auth collections. The module does not serve any route yet.
- The module creates its collections `passkey_credentials` and `passkey_challenges` on the first start, with API rules that let users list, rename and delete only their own passkeys. Startup fails when the collection names in the configuration were changed afterwards.
- `internal/testauthn`: a software authenticator for tests (ES256, `none` attestation) that produces real WebAuthn registration and assertion responses.
- Design: PocketBase MFA behaviour is kept for passkey logins (MFA should be off for passkey collections); the names of the module's collections are fixed after the first start.
- Design: assumptions about PocketBase v0.40.6 and go-webauthn v0.18.2 verified in source and recorded in `docs/open-questions.md`; the challenge lifetime is set on the go-webauthn session explicitly; passwordless users get `Record.SetRandomPassword()`.

### Changed
- Project renamed from the working name `pocketauthn` to `pb-passkeys`.
- Design: enrollment status moved from `GET .../enrollment/{token}` to `POST .../enrollment/status`; secrets are never sent in URLs.
- Design: non-discoverable login with `identity` removed from v0.x (account enumeration); `ResidentKey` is `Required` only.
- Design: `Passwordless` is a three-value setting (`Off` / `Warn` / `Enforce`) everywhere.
