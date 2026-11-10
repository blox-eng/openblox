package preview_test

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/blox-eng/openblox/pkg/preview"
)

// A token authorises one port of one sandbox until it expires. Checking it
// needs only the key, so any process that holds the key can verify it.
func ExampleSigner() {
	// In production the key is preview.MinKeyBytes of random data, kept secret.
	key := bytes.Repeat([]byte("k"), preview.MinKeyBytes)
	signer, err := preview.NewSigner(key)
	if err != nil {
		log.Fatal(err)
	}

	minted := time.Date(2026, 1, 2, 15, 0, 0, 0, time.UTC)
	token, err := signer.Sign("session-1", 8000, minted.Add(10*time.Minute))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("same sandbox and port:", signer.Verify(token, "session-1", 8000, minted))
	fmt.Println("another sandbox:", signer.Verify(token, "session-2", 8000, minted))
	fmt.Println("another port:", signer.Verify(token, "session-1", 9000, minted))
	fmt.Println("after expiry:", signer.Verify(token, "session-1", 8000, minted.Add(11*time.Minute)))

	// Output:
	// same sandbox and port: <nil>
	// another sandbox: invalid preview token
	// another port: invalid preview token
	// after expiry: invalid preview token
}
