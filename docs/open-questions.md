# Open questions and assumptions

Each item must be resolved (verified in the pinned PocketBase source, or decided by a maintainer) before the related feature is implemented. Update this file when an item is closed: move it to "Resolved" with the answer and the PocketBase version it was checked against.

## Assumptions to verify in PocketBase and go-webauthn source

1. **Migrations from a library.** Go migrations registered by an imported module (`core.AppMigrations`) run alongside the app's own migrations, and ordering is predictable.
2. **Auth response.** `apis.RecordAuthResponse(e, record, authMethod, meta)` is the public way to issue a token for a custom method, triggers `OnRecordAuthRequest`, and records `_authOrigins`.
3. **MFA interplay.** How PocketBase MFA treats a custom auth method name such as `"passkey"`. Expected recommendation: MFA off for passkey-only collections, because a UV passkey is already multi-factor.
4. **Session revocation.** Rotating the record's `tokenKey` invalidates all existing tokens for that record.
5. **Passwordless users.** Auth records always have a `password` field; creating invited users with a random unknown password is acceptable and does not weaken anything when password auth is disabled.
6. **Rate limiter.** Built-in rate limit rules can target custom route prefixes, and the module can read the configured rules at startup (to warn when none cover `{prefix}/*`).
7. **Token age.** PocketBase JWTs carry no usable issued-at claim, hence the explicit step-up token.
8. **Argon2id cost.** 64 MiB / t=3 is fast enough on a 1 vCPU VPS (target: under 300 ms per verification; thanks to the selector, one verification per redeem), and a default `MaxConcurrentHashes` of 2 keeps peak memory acceptable.
9. **BE flag (go-webauthn).** Whether go-webauthn rejects an assertion whose backup-eligible flag differs from the stored credential, or whether the module must check it (security.md, threat 23).
10. **Request logs (PocketBase).** Which request data PocketBase writes to `_logs` (URL, headers, body?), to confirm that secrets in JSON bodies are not logged.

## Decisions open for maintainers

1. **Project name** and GitHub owner (personal account or organisation). Changes the Go module path.
2. **Client dependency.** Proposed zero dependencies. Alternative: depend on `@simplewebauthn/browser` (mature, but another package on the login path).
3. **Route prefix.** Proposed `/api/passkeys/{collection}/...`. Alternative `/api/collections/{collection}/passkey/...` mirrors built-in auth routes but risks clashing with future PocketBase routes.
4. **User handle.** Proposed: the PocketBase record ID (random, not personal data). Alternative: a separate random 64-byte handle per user, which allows rotation.
5. **Non-discoverable login.** Logging in with an `identity` returns that user's `allowCredentials`, which reveals whether the account exists and how many keys it has. Proposed for v0.x: not supported; `ResidentKey` only accepts `Required`. Later option: for unknown identities return deterministic fake `allowCredentials` derived with HMAC from a server secret, which needs a stored per-installation key.

## Resolved

- **License: MIT**, matching PocketBase. `LICENSE` is in the repository. (Decided by the maintainer, initial commit.)
- **Contributor sign-off: DCO** (`Signed-off-by`), no CLA. Required in CONTRIBUTING.md and CLAUDE.md.
