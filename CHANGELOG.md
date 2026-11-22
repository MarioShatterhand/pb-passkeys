# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## Unreleased

### Added
- Design documents: architecture, API, threat model, versioning, open questions.
- Design: step-up ceremony routes and `passkey_step_ups` collection; recovery codes with selector + verifier (one Argon2id check per redeem); global caps `MaxPendingChallenges` and `RecoveryCodes.MaxConcurrentHashes`; `OnSignCountAnomaly` hook.

### Changed
- Design: enrollment status moved from `GET .../enrollment/{token}` to `POST .../enrollment/status`; secrets are never sent in URLs.
- Design: non-discoverable login with `identity` removed from v0.x (account enumeration); `ResidentKey` is `Required` only.
- Design: `Passwordless` is a three-value setting (`Off` / `Warn` / `Enforce`) everywhere.
