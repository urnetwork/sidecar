//go:build darwin && !ios && !sdk_mobile_bind

// The Secure Enclave provider's plumbing, read-only: its frameworks and constants load, a lookup of a key that does not
// exist finds none, and an assertion of one creates its LAContext and refuses before anything signs. Nothing here
// makes a key, so no test leaves anything in this host's keychain; making and using one needs the signed bundle and a
// person (MCP-M3-09's review phase).

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestSecureEnclaveLookupOfNoKey(t *testing.T) {
	provider := urPlatformPresenceProvider(t.TempDir(), sidecar.DefaultSidecarSettings().Ingest, sidecar.NewNoopLogger())
	if provider == nil {
		t.Skip("Security or LocalAuthentication does not load on this host")
	}
	keyId := make([]byte, 16)
	if _, err := rand.Read(keyId); err != nil {
		t.Fatal(err)
	}
	if provider.Holds(keyId) {
		t.Fatal("a random key id is held")
	}
	if _, err := provider.Assert(context.Background(), keyId, []byte("message")); !errors.Is(err, sidecar.ErrPresenceNoKey) && !errors.Is(err, sidecar.ErrPresenceUnavailable) {
		t.Errorf("an assertion of no key: %v", err)
	}
	// an unsigned test binary reaches no data protection keychain, as keychain_darwin_test.go's round trip finds
	if err := provider.Remove(keyId); err != nil && !strings.Contains(err.Error(), fmt.Sprint(errSecMissingEntitlement)) {
		t.Errorf("removing no key: %v", err)
	}
}
