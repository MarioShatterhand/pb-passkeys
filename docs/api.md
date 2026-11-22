# API and configuration

Status: draft. Names and signatures are proposals and may change before v0.1.0. Breaking changes are allowed until 1.0 but must be listed in `CHANGELOG.md`.

## 1. Go configuration

```go
pa := pocketauthn.MustRegister(app, pocketauthn.Config{
	// Relying party
	RPID:          "example.com",                 // required; registrable domain, no scheme/port
	RPDisplayName: "Example",                     // required
	RPOrigins:     []string{"https://example.com"}, // required; exact origins
	// Android apps using Credential Manager send "android:apk-key-hash:<base64url sha256>".
	// Add them here and publish /.well-known/assetlinks.json on the RP ID domain.

	AuthCollections: []string{"users"},           // auth collections that get passkey routes

	// Ceremony policy
	UserVerification: pocketauthn.UVRequired,     // Required (default) | Preferred | Discouraged
	ResidentKey:      pocketauthn.ResidentKeyRequired, // only Required in v0.x, see open-questions.md (decision 5)
	Attestation:      "none",                     // only "none" in v0.x
	Algorithms:       nil,                        // default: ES256, EdDSA, RS256
	ChallengeTTL:     5 * time.Minute,
	Timeout:          2 * time.Minute,            // hint sent to the browser
	MaxPendingChallenges: 10000,                  // cap on unexpired challenges; above it public ceremonies get 429

	// Step-up (fresh passkey assertion before sensitive actions)
	StepUp: pocketauthn.StepUpConfig{
		TTL:              5 * time.Minute,         // lifetime of a stepUpToken
		ForNewCredential: true,                    // require step-up to add a credential when one already exists
		ForCredentialDelete: pocketauthn.StepUpDeleteOff, // Off (default) | AnyCredential | OtherCredential
	},

	// Credentials
	MaxCredentialsPerUser: 10,
	AllowDeleteLastCredential: false,             // default false: prevents self-lockout
	SignCountPolicy: pocketauthn.SignCountWarn,   // Warn (default) | Reject | Ignore

	// Recovery
	RecoveryCodes: pocketauthn.RecoveryCodesConfig{
		Enabled: true,
		Count:   8,
		EnrollmentTTL: 15 * time.Minute,           // token returned after redeeming a code
		MaxConcurrentHashes: 2,                    // global cap on parallel Argon2id verifications
	},
	Enrollment: pocketauthn.EnrollmentConfig{
		DefaultTTL:         24 * time.Hour,
		DefaultMaxAttempts: 3,
		BindToFirstDevice:  false,                 // default for tokens that do not set it; see architecture.md 5.3
	},

	// Mode
	Passwordless: pocketauthn.PasswordlessOff,    // Off (default) | Warn | Enforce

	// Routing and storage
	RoutePrefix: "/api/passkeys",                 // routes: {prefix}/{collection}/...
	Collections: pocketauthn.CollectionNames{},   // zero value = defaults from architecture.md
})
```

Startup validation fails (returns an error from `Register`, panics in `MustRegister`) when:

- `RPID` is empty, has a scheme, or is not a suffix of every `https` origin host;
- an origin uses `http` on anything other than `localhost`/`127.0.0.1`;
- a configured collection does not exist, is not an auth collection, or is `_superusers`;
- `Passwordless: Enforce` and password or OTP auth is enabled on a configured collection.

A helper `pocketauthn.ConfigFromEnv(prefix string)` may be added for people who prefer environment variables (`PA_RP_ID`, `PA_RP_ORIGINS`, ...). Not in v0.1.

## 2. HTTP routes

All bodies are JSON. WebAuthn binary fields use base64url (WebAuthn L3 JSON serialization). `{c}` is the auth collection name or ID.

Secrets (enrollment tokens, binding secrets, step-up tokens, recovery codes) are only ever sent in JSON bodies, never in a path or query string, because URLs are written to PocketBase request logs and proxy access logs.

| Method & path | Auth | Purpose |
|---|---|---|
| `POST {prefix}/{c}/register/options` | user token (+ `stepUpToken`, see below) **or** `enrollmentToken` (+ `bindingSecret` when the token is bound) | Start registration; may return `bindingSecret` (first use of a token with `bindToFirstDevice`) |
| `POST {prefix}/{c}/register/verify` | same as above | Finish registration; returns the credential, or an auth response when an enrollment token was used |
| `POST {prefix}/{c}/login/options` | public | Start a discoverable login |
| `POST {prefix}/{c}/login/verify` | public | Finish login; returns the **standard PocketBase auth response** |
| `POST {prefix}/{c}/step-up/options` | user token | Start a step-up assertion for the signed-in user |
| `POST {prefix}/{c}/step-up/verify` | user token | Finish step-up; `{ stepUpToken, expiresAt }` |
| `POST {prefix}/{c}/recovery-codes` | user token + `stepUpToken` | Generate a new set; plaintext codes returned **once**; old codes deleted |
| `GET  {prefix}/{c}/recovery-codes/status` | user token | `{ total, remaining }` only |
| `POST {prefix}/{c}/recovery/redeem` | public | `{ identity, code }` → `{ enrollmentToken, expiresAt }` |
| `POST {prefix}/{c}/enrollment/status` | public | `{ token, bindingSecret? }` → `{ valid, purpose, expiresAt, bindingSecret? }`; never consumes; `bindingSecret` is returned only when this call binds the token |
| `POST {prefix}/{c}/credentials/delete` | user token + `stepUpToken` | `{ id, stepUpToken }`; only when `StepUp.ForCredentialDelete` is not `Off` |

Listing and renaming credentials use the normal collection API on `passkey_credentials` (`pb.collection("passkey_credentials").getFullList()`), governed by the default rules in architecture.md. Deleting does too, unless `StepUp.ForCredentialDelete` is on, in which case the collection delete rule is `null` and `credentials/delete` is the only way.

### Error responses

Errors use PocketBase's standard error shape (`{ status, message, data }`). Public endpoints return **the same generic 400** for "no such user", "wrong code", "unknown credential" and "verification failed", so they cannot be used to enumerate accounts. Detailed reasons go only to the server log at debug level and to hooks.

### Rate limiting

The module does not implement a per-IP limiter. Rate limiting the public routes is **required** for a production deployment, not optional: `login/*` creates a database row per call and `recovery/redeem` runs Argon2id. The docs give recommended PocketBase rate limit rules for `{prefix}/*` (e.g. 10 requests/min per IP for `login/*`, `recovery/*`, `enrollment/*`), and the module logs a startup warning when none is configured. **[Assumption]** PocketBase's built-in limiter can target custom route paths by prefix, and its settings can be read at startup; to verify.

Independent of per-IP limits, two global caps protect the server from distributed floods: `MaxPendingChallenges` and `RecoveryCodes.MaxConcurrentHashes`.

### Step-up

Sensitive actions require a fresh passkey assertion: generating recovery codes always, adding a credential when one already exists if `StepUp.ForNewCredential` is on (default), and deleting a credential if `StepUp.ForCredentialDelete` is `AnyCredential` or `OtherCredential`. With `OtherCredential`, the assertion must come from a credential other than the one being deleted. The client calls `step-up/options` and `step-up/verify` with the user's token and passes the resulting one-time `stepUpToken` in the body of the sensitive request. The step-up assertion must come from a credential of the same signed-in user. **[Assumption]** PocketBase JWTs carry no issued-at claim usable for "recent login" checks, so the module cannot rely on token age.

## 3. Go API

```go
// Enrollment tokens: the generic recovery/invitation primitive.
tok, err := pa.IssueEnrollment(ctx, pocketauthn.EnrollmentRequest{
	Record:         userRecord,          // *core.Record from an auth collection
	Purpose:        "admin_reset",       // free-form string, passed to hooks
	TTL:            24 * time.Hour,
	MaxAttempts:    3,
	RevokeExisting: true,                // delete old credentials + codes, rotate tokenKey
	CreatedBy:      adminRecord.Id,
	BindToFirstDevice: pocketauthn.Bool(true), // nil = Config.Enrollment.BindToFirstDevice
	Meta:           map[string]any{"phoneCodeHash": h},
})
// tok.Token is plaintext, returned only here. tok.ExpiresAt, tok.Id.

pa.RevokeEnrollment(ctx, id)
pa.RevokeAllCredentials(ctx, userRecord)   // also deletes codes, rotates tokenKey
pa.ListCredentials(ctx, userRecord)

pocketauthn.CredentialKind(credRecord)     // "synced" | "device" | "security_key" | "unknown"; display only
```

## 4. Hooks

All hooks are `*hook.Hook[*Event]` from `github.com/pocketbase/pocketbase/tools/hook`. Handlers must call `e.Next()`; returning an error aborts the operation and the client gets a generic error.

| Hook | When | Typical use |
|---|---|---|
| `OnRegistrationOptions` | Before options are returned | Custom limits |
| `OnCredentialRegistered` | After a credential is stored (in transaction) | Notify the user, audit log |
| `OnBeforeLogin` | Assertion verified, before the token is issued | Block disabled accounts, geo rules |
| `OnLoginFailed` | Any failed login verification | Alerting, fail2ban log line |
| `OnSignCountAnomaly` | Sign counter did not increase for a credential that reports one; fires under `Warn` and `Reject` | Alert, flag the credential for review |
| `OnCredentialDeleted` | After delete through the API or Go | Notify the user |
| `OnRecoveryCodesGenerated` | After a new set is created | Notify the user |
| `OnRecoveryCodeRedeemed` | After a code is used | Notify the user, alert when few remain |
| `OnEnrollmentVerify` | Before an enrollment token is accepted; `e.Extra` holds client data | Check a phone code from `e.Enrollment.Meta` |
| `OnEnrollmentBindingMismatch` | A bound token was used without its binding secret; `e.Request` holds allow-listed request data | Show the attempt to an administrator, revoke the token |
| `OnEnrollmentCompleted` | After successful enrollment (in transaction) | Notify the user or an administrator, audit |

Example of an application-specific factor, which stays in the application:

```go
pa.OnEnrollmentVerify().BindFunc(func(e *pocketauthn.EnrollmentVerifyEvent) error {
	if e.Enrollment.Purpose == "admin_reset" {
		code, _ := e.Extra["phoneCode"].(string)
		if !checkPhoneCode(e.Enrollment.Meta, code) {
			return pocketauthn.ErrEnrollmentVerificationFailed // counts as a failed attempt
		}
	}
	return e.Next()
})
```

## 5. TypeScript client (`client/`)

- No runtime dependencies. `pocketbase` JS SDK is a peer dependency; all requests go through `pb.send()`, and logins end with `pb.authStore.save(token, record)`.
- Uses `PublicKeyCredential.parseCreationOptionsFromJSON` / `toJSON()` when available, with a small base64url fallback.
- Typed errors: `PasskeyCancelledError` (user dismissed the dialog), `PasskeyNotSupportedError`, `PasskeyServerError`.

```ts
const pk = passkeys(pb, { collection: "users" });

await pk.isSupported();                         // boolean
await pk.register({ name: "Phone" });          // signed-in user adds a passkey
await pk.login();                               // modal
await pk.login({ mediation: "conditional" });   // autofill in an <input autocomplete="username webauthn">
const codes = await pk.generateRecoveryCodes(); // runs step-up first
const status = await pk.enrollmentStatus(enrollmentToken); // token read from location.hash
const { enrollmentToken } = await pk.redeemRecoveryCode(identity, code);
await pk.enroll(enrollmentToken, { name: "New phone", extra: { phoneCode } });
await pk.deleteCredential(id);                  // runs step-up first when the server requires it
credentialKind(record);                         // same rules as the Go helper; display only
```

The client stores a `bindingSecret` it receives in `sessionStorage` (keyed by a hash of the token) and sends it automatically on later `enrollmentStatus` and `enroll` calls for the same token.

## 6. Example application (`examples/minimal`)

A `main.go` with one auth collection and a single static HTML page: sign up by invitation, add a second passkey, log in, generate and use a recovery code. It is the target of the Playwright E2E tests and doubles as living documentation. It must not grow into a product.
