# Architecture and module boundary

Status: draft for v0.1. Items marked **[Assumption]** must be checked against the source code of the pinned PocketBase version before they are implemented. They are collected in [open-questions.md](open-questions.md).

## 1. Goals

1. Anyone running PocketBase as a Go framework can add passkey login with a few lines of code, without forking anything.
2. The module is **generic**: it knows nothing about any particular application. Application policy enters only through configuration and hooks.
3. After login, everything is plain PocketBase: the same token, the same `authStore`, the same API rules.
4. Security-sensitive logic (WebAuthn verification) is delegated to [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn). This module adds storage, routing, lifecycle and policy, never its own cryptography.

## 2. The boundary

| In the module (generic) | Outside the module (your application) |
|---|---|
| Registration and login ceremonies (WebAuthn L3) | Who may get an invitation or a reset |
| Many credentials per user, limits, naming | How a person proves who they are (phone call, ID, video) |
| Recovery codes (generate, hash, redeem) | Extra secret factors, e.g. a 6-digit code read aloud |
| Enrollment tokens (single-use, TTL, attempt limit, revoke-existing option) | Delivering links or QR codes (email, messenger, print) |
| Issuing the standard PocketBase auth response | Email/push notifications to the user or others |
| Optional passwordless mode checks | Geo-blocking, IP reputation, CAPTCHA |
| Hooks before/after every state change | Admin UI, audit log UI |
| Default API rules for its own collections | Rules for your own collections |
| Cleanup of expired challenges and tokens | Backups, deployment, reverse proxy, CSP |
| TypeScript client (thin wrapper on `navigator.credentials`) | Your UI and UX copy |

Rule of thumb for contributors: if a feature needs to know *why* a user is enrolling, it belongs in a hook, not in the module.

## 3. Components

```
your main.go
  └── pocketauthn.MustRegister(app, cfg)
        ├── config     validation at startup, fails fast on unsafe values      (root package)
        ├── hooks      typed hook.Hook[*Event] values, PocketBase style         (root package)
        ├── store      collections + migrations (credentials, challenges,       internal/store
        │              step-up tokens, recovery codes, enrollments)
        ├── ceremony   wraps go-webauthn: begin/finish registration and login   internal/ceremony
        ├── recovery   recovery codes, enrollment tokens, step-up tokens        internal/recovery
        ├── routes     HTTP handlers bound in app.OnServe()                     internal/routes
        └── jobs       cron cleanup of expired rows                             internal/store

client/  (npm package)  base64url <-> ArrayBuffer, calls routes via pb.send(), saves into pb.authStore
examples/minimal       main.go + one static HTML page, used by E2E tests
```

The Go module lives at the repository root so the import path stays short. The TypeScript client lives in `client/` with its own `package.json`.

### Integration with PocketBase

- Routes are registered in `app.OnServe().BindFunc(...)` on `se.Router`, the documented way to add custom routes.
- Collections are created by Go migrations shipped with the module and applied automatically (`migratecmd` is not required). **[Assumption]** Migrations registered by a library through `core.AppMigrations` run together with the app's own migrations; to verify, including ordering.
- Successful login returns `apis.RecordAuthResponse(e, record, "passkey", meta)`, so PocketBase's `OnRecordAuthRequest` hooks, `_authOrigins` tracking and new-login alerts behave as for built-in methods. **[Assumption]** Exact function name and MFA interplay to verify in the pinned version.
- Hook types reuse `github.com/pocketbase/pocketbase/tools/hook`, so the API feels native.

## 4. Data model

All collection names are configurable (`Config.Collections`). Defaults below. Every collection is created with **all API rules set to `null` (superuser only)** except where listed. Credentials and codes reference users with `collectionRef` + `recordRef` text fields, the same pattern PocketBase uses for `_mfas` and `_externalAuths`, so one module instance can serve several auth collections.

### `passkey_credentials`

| Field | Type | Notes |
|---|---|---|
| `collectionRef`, `recordRef` | text, indexed | Owner |
| `credentialId` | text, **unique** | base64url |
| `publicKey` | text, hidden | COSE key, base64url |
| `signCount` | number | Stored, see security.md for policy |
| `aaguid` | text | Authenticator model, optional display name lookup |
| `transports` | json | Hints for later logins, e.g. `internal`, `hybrid`, `usb`, `nfc` |
| `authenticatorAttachment` | text | `platform`, `cross-platform` or empty, as reported by the browser at registration |
| `backupEligible`, `backupState` | bool | Synced ("passkey") vs device-bound |
| `attestationFormat` | text | `none` by default |
| `name` | text, max 64 | User-chosen label |
| `lastUsedAt` | date | |
| `created`, `updated` | autodate | |

Default rules: list/view `recordRef = @request.auth.id && collectionRef = @request.auth.collectionId`; update the same, with only `name` writable (enforced in a hook, not only in rules); delete the same, guarded by the "last credential" policy; create `null` (only through the ceremony). The "last credential" check and the delete run in the same transaction, so two parallel deletes cannot remove the last two credentials. When `StepUp.ForCredentialDelete` is not `Off`, the delete rule is `null` and deletion goes only through the module route (5.6).

#### Authenticator type

So that users can see which kind of authenticator each passkey lives on (and that their passkeys are independent of each other), the module stores what the browser and authenticator report and nothing more: `aaguid`, `transports`, `authenticatorAttachment`, `backupEligible`, `backupState`. It derives a coarse `kind`, exposed as a helper in Go (`pocketauthn.CredentialKind(record)`) and in the client (`credentialKind(record)`), not as a stored field:

| `kind` | Rule (first match) |
|---|---|
| `synced` | `backupEligible = true` (copied between devices by a passkey provider) |
| `security_key` | `authenticatorAttachment = cross-platform`, or `transports` contains `usb`/`nfc`/`ble` without `internal` |
| `device` | `authenticatorAttachment = platform`, or `transports` contains `internal` |
| `unknown` | anything else |

Display names for known models (from the AAGUID) come in 0.4. These values are **unsigned hints** with `none` attestation: `authenticatorAttachment` and `transports` come from the client, and some platforms send an all-zero AAGUID. They are for display only and are never used in a security decision.

### `passkey_challenges`

Server-side ceremony state:

| Field | Notes |
|---|---|
| `type` | `registration`, `login` or `step_up`; a challenge can only finish the ceremony type it was created for |
| `collectionRef` | Always set: the auth collection from the route |
| `recordRef` | Set for registration and step-up; empty for discoverable login |
| `enrollmentRef` | Set when registration was started with an enrollment token |
| `sessionData` | json, hidden |
| `expiresAt` | Default 5 min |

A challenge is consumed atomically (read and delete in one transaction) on first use, success or failure. No API access. Because `login/options` is public, the number of unexpired challenges is capped (`Config.MaxPendingChallenges`); above the cap, new public ceremonies are refused with 429 until cleanup or expiry frees space.

### `passkey_step_ups`

`collectionRef`, `recordRef`, `credentialRef` (the credential that produced the assertion), `tokenHash` (SHA-256 of a 256-bit random token), `expiresAt` (default 5 min). Created by a successful step-up assertion, deleted on first use. No API access.

### `passkey_recovery_codes`

`collectionRef`, `recordRef`, `selector` (unique, indexed), `codeHash` (Argon2id of the verifier part, PHC string), `usedAt`. Regenerating deletes all previous codes of that user. No API access.

A code has two parts: a short random **selector** used only to find the row, and the secret **verifier** that is hashed. Redeeming a code therefore costs at most one Argon2id verification, no matter how many codes a user has (see security.md, threat 8).

### `passkey_enrollments`

| Field | Notes |
|---|---|
| `collectionRef`, `recordRef` | Target user (the user record may be inactive or newly created) |
| `tokenHash` | SHA-256 of a 256-bit random token; the plaintext is returned once |
| `purpose` | `invite`, `recovery_code`, `admin_reset`, or a custom string |
| `expiresAt` | Required |
| `attempts`, `maxAttempts` | Failed hook verifications count; reaching the limit revokes the token |
| `revokeExisting` | On success: delete all credentials and recovery codes and rotate the user's `tokenKey` |
| `createdBy` | Optional reference for audit |
| `consumedAt` | Set on success; the row is kept for audit until cleanup |
| `bindToFirstDevice` | If true, the token works only in the browser that first used it (see 5.3) |
| `bindingHash`, `boundAt` | SHA-256 of the binding secret and the time of binding; empty until the first use |
| `meta` | json, hidden; application data for hooks (e.g. a hash of a phone code) |

No API access. Applications create enrollments through the Go API (`pa.IssueEnrollment`) from their own routes or admin tooling.

## 5. Flows

### 5.1 Registration (signed-in user adds a passkey)

1. `POST .../register/options` with the user's PocketBase token (and a `stepUpToken` when `Config.StepUp.ForNewCredential` is on and the user already has a credential). The module checks the credential limit, creates a challenge, and returns `PublicKeyCredentialCreationOptions` with `excludeCredentials` set to the user's existing credentials.
2. Browser calls `navigator.credentials.create()`.
3. `POST .../register/verify` with the response. go-webauthn verifies origin, RP ID hash, challenge, flags and attestation. The module rejects a `credentialId` that already exists, stores the credential and fires `OnCredentialRegistered`.

### 5.2 Login (discoverable, no username)

1. `POST .../login/options` (public). Returns options with an empty `allowCredentials` and `mediation` hints for conditional UI (autofill).
2. `navigator.credentials.get()`.
3. `POST .../login/verify`. The module:
   - looks up the credential by ID **within the route's collection** (`collectionRef` must equal `{c}`);
   - requires `userHandle` (always present for discoverable credentials) and checks that it matches the credential's owner;
   - verifies the assertion and rejects a change of the backup-eligible (BE) flag, which must never change after registration;
   - updates `signCount`/`backupState`/`lastUsedAt` and applies `SignCountPolicy` (firing `OnSignCountAnomaly` on regression);
   - fires `OnBeforeLogin` (may reject) and returns the standard auth response.

Non-discoverable login with an `identity` is not part of v0.x, see [open-questions.md](open-questions.md) (decision 5).

### 5.3 Enrollment token (invitation, admin reset, recovery)

1. The application calls `pa.IssueEnrollment(...)` and delivers the token however it wants. Links should carry the token in the URL **fragment** (`https://example.com/enroll#token=...`): fragments are not sent to servers, so the token does not end up in access logs, PocketBase request logs or `Referer` headers. The token is never part of a request path or query string.
2. `POST .../enrollment/status` with `{ token }` returns only non-sensitive status (valid/expired, purpose). **Opening a link never consumes it**, so messenger link previews do not burn tokens. Link previews also never see the token, because it sits in the fragment and they do not run the page's script.
3. `POST .../register/options` with `enrollmentToken` and optional `extra` data (e.g. `{ "phoneCode": "123456" }`). `OnEnrollmentVerify` runs: the app checks its own factors. A returned error increments `attempts`. On success the new challenge is bound to the enrollment (`enrollmentRef`).

**Binding to the first device** (`bindToFirstDevice`, per token, default from `Config.Enrollment.BindToFirstDevice`). It limits a token that was forwarded or intercepted (A5) to the browser that opened it first:

- The first `enrollment/status` or `register/options` call with a valid, unbound token binds it. The module generates a 256-bit binding secret, stores its SHA-256 in `bindingHash`, sets `boundAt`, and returns the secret once in the response. The client keeps it in `sessionStorage`.
- Every later call with that token must also send `bindingSecret`. A missing or wrong secret gets the generic error, does **not** count towards `attempts`, and fires `OnEnrollmentBindingMismatch` with allow-listed request data (time, IP, user agent). The application can show these attempts to an administrator or revoke the token with `pa.RevokeEnrollment`.
- If the legitimate user loses the binding (other browser, closed tab), they need a new token. Binding is one-way: the module never re-binds a token.
4. `POST .../register/verify`. In one transaction: consume the challenge, re-check that the bound enrollment is still unconsumed, unexpired and unrevoked, optionally revoke existing credentials, codes and sessions, store the new credential, mark the token consumed, fire `OnEnrollmentCompleted`. If two registrations were started with the same token, only the first to finish succeeds. The response is a normal auth response, issued after any `tokenKey` rotation, so the user is signed in.

### 5.4 Recovery code

`POST .../recovery/redeem` with an identity (email or username) and a code. The module finds the code row by its selector and checks that it belongs to that identity, then runs one Argon2id verification. When the user or selector does not exist, it verifies against a fixed dummy hash instead, so the response time does not reveal which part was wrong. Argon2id verifications run behind a global concurrency limit (`Config.RecoveryCodes.MaxConcurrentHashes`), so a flood of requests queues instead of exhausting memory.

On success the code is marked used and the module returns a short-lived enrollment token (`purpose = recovery_code`, default 15 min, `revokeExisting = false`). It **does not** return a session token. The client immediately continues with 5.3, so a recovery code can only be used to add a new passkey.

### 5.5 Step-up

1. `POST .../step-up/options` with the user's PocketBase token. Creates a `step_up` challenge bound to that user, with `allowCredentials` set to the user's credentials.
2. `navigator.credentials.get()`.
3. `POST .../step-up/verify` with the user's token. The assertion must come from a credential owned by the **same** signed-in user; an assertion from another account is rejected even if valid. On success the module returns a one-time `stepUpToken` (stored hashed in `passkey_step_ups` together with the credential that signed, default TTL 5 min).

### 5.6 Deleting a credential

With `StepUp.ForCredentialDelete: Off` (default), users delete their credentials through the collection API, as in section 4. With `AnyCredential` or `OtherCredential`, the collection delete rule is `null` and the only way is:

1. Step-up (5.5). With `OtherCredential`, the client asks for an assertion from a credential other than the one being deleted (`allowCredentials` excludes it). This proves the user still has another working passkey before one is removed.
2. `POST .../credentials/delete` with the user's token and `{ id, stepUpToken }`. In one transaction: consume the step-up token, check that it belongs to the same user and, with `OtherCredential`, that `credentialRef` differs from `id`, apply the "last credential" policy, delete, fire `OnCredentialDeleted`.

## 6. Passwordless mode

`Config.Passwordless` has three values. `PasswordlessOff` (default) does no checks. `PasswordlessEnforce` checks at startup that password auth and OTP are disabled on the configured collections and refuses to start otherwise. `PasswordlessWarn` runs the same checks but only logs a warning. The module never changes collection settings silently. **[Assumption]** PocketBase auth records always carry a `password` field; invited users are created with a random 32-byte password that nobody knows. To verify that this is the cleanest option in the pinned version.

## 7. Non-goals for 1.0

- JSVM (`pb_hooks`) bindings. Possible later, see versioning.md.
- Attestation verification against the FIDO Metadata Service (enterprise use). The config field exists, but only `none` is supported at first.
- WebAuthn PRF / largeBlob extensions. The client will pass extension results through untouched.
