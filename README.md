# pb-passkeys

> Passkey (WebAuthn) authentication for [PocketBase](https://pocketbase.io), as a Go module you add to your own PocketBase build.
>
> **Status: design phase.** There is no code yet. The documents in `docs/` describe what will be built. Feedback via issues is welcome.

pb-passkeys is an independent, community project. It is **not affiliated with or endorsed by PocketBase** or its author.

## What it does

- Register and sign in with passkeys (Android, Windows Hello, iCloud Keychain, password managers, security keys such as YubiKey).
- Many passkeys per account. Users list, rename and delete their own passkeys through the normal PocketBase collection API.
- One-time recovery codes, stored only as Argon2id hashes.
- **Enrollment tokens**: a generic, single-use primitive for invitations, admin-assisted account recovery and "lost all my keys" flows, with hooks so your app can add its own checks (a code read over the phone, geo rules, notifications).
- After a successful passkey login it returns the **standard PocketBase auth response** (token + record), so the official JS/Dart SDKs, API rules and realtime keep working unchanged.
- Optional passkey-only (passwordless) mode.
- A small, dependency-free TypeScript client that works with the official `pocketbase` JS SDK.

## What it deliberately does not do

- It does not decide *who* may recover an account or *how* a person is verified. It gives you the primitive and the hooks.
- It does not send emails, block countries or provide an admin UI. Your app does that, using the hooks.
- It does not touch PocketBase superuser (`_superusers`) authentication.

See [docs/architecture.md](docs/architecture.md) for the exact module boundary.

## Quick look (planned API, subject to change)

```go
package main

import (
	"log"

	"github.com/pocketbase/pocketbase"
	passkeys "github.com/MarioShatterhand/pb-passkeys"
)

func main() {
	app := pocketbase.New()

	passkeys.MustRegister(app, passkeys.Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		RPOrigins:       []string{"https://example.com"},
		AuthCollections: []string{"users"},
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
```

```ts
import PocketBase from "pocketbase";
import { passkeys } from "pb-passkeys";

const pb = new PocketBase("https://example.com");
const pk = passkeys(pb, { collection: "users" });

await pk.login();            // discoverable credential, no email needed
console.log(pb.authStore.record);
```

## Requirements

- PocketBase used **as a Go framework** (a custom `main.go`). The prebuilt PocketBase binary cannot load Go modules. We plan to publish prebuilt "PocketBase + pb-passkeys" binaries for people who do not want to write Go (see [docs/versioning.md](docs/versioning.md)).
- HTTPS (WebAuthn requires a secure context; `localhost` is allowed for development).

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Module boundary, components, data model, ceremonies |
| [docs/api.md](docs/api.md) | Go configuration, HTTP routes, hooks, TS client |
| [docs/security.md](docs/security.md) | Threat model and security invariants |
| [docs/versioning.md](docs/versioning.md) | Roadmap, PocketBase compatibility policy |
| [docs/open-questions.md](docs/open-questions.md) | Assumptions to verify and open decisions |

## Contributing and security

- [CONTRIBUTING.md](CONTRIBUTING.md)
- Report vulnerabilities privately, see [SECURITY.md](SECURITY.md). Please do not open public issues for security problems.

## License

[MIT](LICENSE)
