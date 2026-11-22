# Security policy

## Supported versions

Until 1.0, only the latest minor release receives security fixes. The previous minor receives fixes while it is listed as supported in [docs/versioning.md](docs/versioning.md).

| Version | Supported |
|---|---|
| 0.x latest | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request.**

Use GitHub's private vulnerability reporting: the **Security** tab of this repository → **Report a vulnerability**. [Maintainer: enable it under Settings → Code security → Private vulnerability reporting.]

Please include:
- affected version(s) and configuration,
- a description of the impact (e.g. login as another user, bypass of user verification, enrollment token reuse),
- steps or a proof of concept, using test data only.

## What to expect

- Acknowledgement within **7 days**.
- An initial assessment within **14 days**.
- A fix and coordinated disclosure, normally within **90 days**. We will credit you in the advisory unless you prefer otherwise.

This is a volunteer project; timelines are goals, not guarantees.

## Scope

In scope: this repository's Go module, TypeScript client and example app.

Out of scope, please report upstream:
- PocketBase itself → https://github.com/pocketbase/pocketbase/security
- go-webauthn → https://github.com/go-webauthn/webauthn/security
- Browser or authenticator bugs → the respective vendor.

Misconfiguration of a deploying application (missing CSP, `http` origins, password auth left enabled) is not a vulnerability in this module, but we welcome suggestions for safer defaults or startup checks.
