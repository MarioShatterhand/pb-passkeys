package passkeys_test

import (
	"log"

	"github.com/pocketbase/pocketbase"

	passkeys "github.com/MarioShatterhand/pb-passkeys"
)

// A minimal main function: PocketBase with passkeys for the "users" collection.
func ExampleRegister() {
	app := pocketbase.New()

	_, err := passkeys.Register(app, passkeys.Config{
		RPID:            "example.com",
		RPDisplayName:   "Example",
		RPOrigins:       []string{"https://example.com"},
		AuthCollections: []string{"users"},
	})
	if err != nil {
		log.Fatal(err)
	}

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}
