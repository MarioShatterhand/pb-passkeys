//go:build deps

// This file pins the module's direct dependencies in go.mod before any real
// code imports them, so "go mod tidy" keeps them. It is never compiled into
// a build. Delete it once the packages below are imported by real code.

package passkeys

import (
	_ "github.com/go-webauthn/webauthn/webauthn"
	_ "github.com/pocketbase/pocketbase"
	_ "golang.org/x/crypto/argon2"
)
