# Threat model and security invariants

This module sits on the login path. A bug here is an account takeover. This document lists what we defend against, the invariants the code must keep, and what is explicitly the deploying application's job. Every invariant marked **(T)** must have an automated test before 1.0.

## 1. Assets

1. The ability to obtain a PocketBase auth token for a user.
2. The set of credentials bound to an account (adding one is equivalent to permanent access).
3. Recovery codes and enrollment tokens (each is a path to item 2).
4. Privacy: whether an account exists, which authenticators a user owns.

## 2. Trust assumptions

- TLS terminates correctly and the RP ID domain is controlled by the deployer.
- go-webauthn correctly implements WebAuthn verification. We track its releases and advisories, and we add regression tests for any bypass reported upstream.
- The PocketBase superuser is trusted. A superuser can always edit the database; this module does not try to protect against them (see section 6).
- The user's authenticator and platform (Google Password Manager, Windows Hello, iCloud Keychain, security key) are trusted for user verification.

## 3. Attackers

| Attacker | Capability |
|---|---|
| A1 Remote anonymous | Calls any public route, at volume, from many IPs |
| A2 Phisher | Runs a look-alike domain and relays traffic |
| A3 Signed-in user | Has a valid token for their own account and calls the API directly |
| A4 XSS on the RP origin | Runs script in a victim's session |
| A5 Link interceptor | Reads messages that carry enrollment links (messenger, email) |
| A6 Database reader | Gets a copy of the SQLite file or a backup |
| A7 Malicious contribution | Submits a PR or a compromised dependency |

## 4. Threats and mitigations

| # | Threat | Mitigation | Invariant |
|---|---|---|---|
| 1 | Phishing / relay (A2) | Origin and RP ID hash checked by go-webauthn against an exact allow-list; no wildcards | Origin not in `RPOrigins` is rejected **(T)** |
| 2 | Challenge replay | Challenges stored server-side, consumed atomically on first use, TTL 5 min, bound to ceremony type (`registration`/`login`/`step_up`), collection and (for registration and step-up) user | Second use of a challenge fails, including two concurrent uses **(T)**; a challenge cannot finish a ceremony of another type **(T)** |
| 3 | Credential ID takeover | `credentialId` unique index; registration of an existing ID is rejected even for the same user | **(T)** |
| 4 | Assertion for another user | On login, `userHandle` is required and must match the credential's owner; the credential must belong to the route's collection | Missing or mismatched `userHandle` rejected **(T)**; credential of collection A cannot log in through collection B **(T)** |
| 5 | Weak user verification | UV required by default; the UV flag is checked server-side, not only requested | UV=0 rejected when policy is Required **(T)** |
| 6 | Cloned authenticator | Sign count stored. Synced passkeys always report 0, so default policy is **warn and fire `OnSignCountAnomaly`**, not reject. `Reject` available for security-key-only deployments | Counter regression triggers the configured policy and the hook **(T)** |
| 7 | Account enumeration (A1) | Discoverable login needs no identity; no identity-based login in v0.x; public endpoints return one generic error and similar timing; `recovery/redeem` verifies a dummy hash for unknown users or selectors | Same status/body for unknown vs known user **(T)**; `recovery/redeem` runs one Argon2id verification on every path **(T)** |
| 8 | Brute force of recovery codes (A1) | 50-bit verifier, Argon2id hashes, required rate limits, generic errors, `OnLoginFailed` hook for fail2ban/CrowdSec | Used code cannot be reused **(T)** |
| 9 | Recovery code used as a login bypass | Redeeming a code yields only a short-lived enrollment token, never an auth token | **(T)** |
| 10 | Enrollment link leaked (A5) | Token is 256-bit random, stored as SHA-256 hash, single use, TTL, attempt limit, optional app factor via `OnEnrollmentVerify`; viewing status never consumes it | Expired/consumed/revoked tokens rejected **(T)**; `maxAttempts` failed hooks revoke the token **(T)** |
| 11 | Signed-in attacker adds a credential (A3 with stolen token, A4) | Step-up assertion required for recovery codes and, by default, for additional credentials (`StepUp.ForNewCredential`); the step-up assertion must come from the same user's credential; `OnCredentialRegistered` lets the app notify the user | Without step-up the request fails **(T)**; a step-up token of user A is rejected for user B **(T)**; an assertion by user B's credential cannot produce a step-up token for user A **(T)** |
| 12 | User edits stored credential data (A3) | `create` rule `null`; on update only `name` is writable, enforced in a Go hook as well as by rules | Changing `publicKey`/`recordRef` through the API fails **(T)** |
| 13 | Self-lockout | Deleting the last credential is refused unless explicitly allowed; check and delete in one transaction | **(T)**, including two concurrent deletes of the last two credentials |
| 14 | Stale sessions after reset | `revokeExisting` deletes credentials and codes and rotates the user's `tokenKey` in one transaction | Old token rejected after reset **(T)** **[Assumption]** `tokenKey` rotation invalidates existing JWTs in the pinned version |
| 15 | Database leak (A6) | Only public keys, hashes and non-secret metadata are stored; no plaintext codes or tokens | Schema review in CI (test asserts no plaintext columns) |
| 16 | CSRF | JSON bodies, bearer tokens in `Authorization` header, no cookies set by the module | — |
| 17 | Secrets in logs | Tokens, codes, `sessionData` and raw client data never logged; log fields are allow-listed; secrets travel only in JSON bodies, never in URL paths or query strings (PocketBase and proxies log URLs); enrollment links put the token in the URL fragment | Log capture test **(T)**; no route takes a secret as a path or query parameter **(T)** |
| 18 | Timing attacks on comparisons | Hash comparisons use `crypto/subtle` | Code review rule |
| 19 | Superuser takeover via passkeys | Module refuses to register routes for `_superusers` | Startup error **(T)** |
| 20 | Supply chain (A7) | Minimal dependencies (PocketBase, go-webauthn, `golang.org/x/crypto`); `govulncheck` and Dependabot in CI; actions pinned by SHA; signed tags; two-person review for `ceremony/`, `recovery/`, `store/` once there are two maintainers | — |
| 21 | Resource exhaustion on public routes (A1) | `login/options` writes a row and `recovery/redeem` runs Argon2id. Per-IP rate limits are required; a global cap on pending challenges (`MaxPendingChallenges`, 429 above it); Argon2id behind a global concurrency limit; one hash per redeem thanks to the selector | Above the cap, `login/options` returns 429 and writes nothing **(T)**; parallel redeems never exceed `MaxConcurrentHashes` **(T)** |
| 22 | Enrollment token used twice in parallel | Registration challenge bound to the enrollment; `register/verify` re-checks and consumes the enrollment in the same transaction | Two ceremonies started with one token: only the first to finish succeeds **(T)** |
| 23 | Synced credential swapped for a device-bound one, or the reverse | The backup-eligible (BE) flag is fixed at registration; an assertion with a different BE value is rejected | **(T)** **[Assumption]** whether go-webauthn already enforces this |
| 24 | Forwarded or intercepted enrollment link used on another device (A5) | Optional `bindToFirstDevice`: the first use binds the token to a 256-bit secret kept in that browser's `sessionStorage` (stored as SHA-256); later calls without it fail and fire `OnEnrollmentBindingMismatch`; never re-bound. Does not help when the attacker opens the link first; then the legitimate user's attempt is what the hook reports | Bound token without the secret, or with a wrong one, is rejected with the generic error and does not change `attempts` **(T)**; the binding secret is returned only once **(T)**; binding happens once under concurrent first calls **(T)** |
| 25 | Credential removed with a stolen session token (A3, A4) | Optional `StepUp.ForCredentialDelete`; with `OtherCredential` the step-up must come from a different credential of the same user, which also proves that another key still works | With the option on, collection API delete fails and `credentials/delete` without a valid step-up fails **(T)**; with `OtherCredential`, a step-up signed by the credential being deleted is rejected **(T)** |
| 26 | Authenticator type trusted for security | `authenticatorAttachment`, `transports` and the AAGUID are unsigned client hints under `none` attestation; `CredentialKind` is display only | Code review rule: no policy branches on these fields |

## 5. Cryptographic parameters

- Random values: `crypto/rand` only.
- Enrollment and step-up tokens: 32 bytes, base64url; stored as SHA-256 (high entropy, so a slow hash is not needed).
- Recovery codes: 16 characters of Crockford base32, shown as `SSSSSS-VVVVV-VVVVV`. The first 6 characters are the **selector** (30 bits, stored in plaintext with a unique index, regenerated on collision; it only locates the row and is not secret). The last 10 characters are the **verifier** (50 bits), stored as Argon2id `m=64 MiB, t=3, p=1` (tunable), PHC-encoded. **[Assumption]** 64 MiB is acceptable on small VPS instances; to benchmark.
- Dummy hash for unknown users or selectors: computed once at startup with the same parameters, so the failure path costs the same as a real check.
- Algorithms accepted from authenticators: ES256, EdDSA, RS256.

## 6. Out of scope (the deploying application's responsibility)

- Verifying a person's identity before issuing an enrollment token, and guarding against a malicious administrator. The module provides the audit hooks; the app decides what to record and who gets notified.
- CSP, XSS prevention and security headers on the RP origin. XSS on the origin defeats any WebAuthn deployment.
- Network controls (geo-blocking, WAF, fail2ban), backups, server hardening.
- Account recovery that does not go through this module (e.g. leaving email OTP enabled).

## 7. Before 1.0

- Independent review of the ceremony, recovery and storage code by someone other than the author.
- Fuzz tests for all JSON decoders on public routes (`go test -fuzz`).
- Property tests for the enrollment token state machine (issued → consumed | expired | revoked).
- Concurrency tests (`-race`, parallel requests) for every "single use" invariant: challenges, enrollment tokens, step-up tokens, recovery codes, last-credential delete.
