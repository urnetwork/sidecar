//go:build darwin && !ios && !sdk_mobile_bind

package main

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/urnetwork/sidecar"
)

// §4.17's Keychain round trip through purego. An unsigned test binary has no keychain-access-groups entitlement, so
// the data protection keychain answers errSecMissingEntitlement: that proves the purego path loaded and called
// Security.framework, and the test skips, the signed bundle's run being external.
func TestKeychainDarwinRoundTrip(t *testing.T) {
	security, err := loadDarwinSecurity()
	if err != nil {
		t.Fatalf("Security.framework through purego: %v", err)
	}
	calls := &darwinPuregoKeychain{security: security}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "urnetwork-sidecar-test/" + hex.EncodeToString(suffix)
	status := calls.add(name, []byte("synthetic"))
	if status == errSecMissingEntitlement {
		t.Skip("unsigned test binary: errSecMissingEntitlement from the data protection keychain; the signed run is external")
	}
	defer calls.remove(name)
	if status != errSecSuccess {
		t.Fatalf("add: %d", status)
	}
	store := &darwinKeychainStore{calls: calls}
	if value, got := store.GetSecret(name); got != sidecar.SidecarKeyStorePresent || string(value) != "synthetic" {
		t.Fatalf("get: %d", got)
	}
	if got := store.PutSecret(name, []byte("replaced")); got != sidecar.SidecarKeyStoreOk {
		t.Fatalf("replace: %d", got)
	}
	if value, got := store.GetSecret(name); got != sidecar.SidecarKeyStorePresent || string(value) != "replaced" {
		t.Fatalf("get after replace: %d", got)
	}
	if got := store.DeleteSecret(name); got != sidecar.SidecarKeyStoreOk {
		t.Fatalf("delete: %d", got)
	}
	if _, got := store.GetSecret(name); got != sidecar.SidecarKeyStoreAbsent {
		t.Fatalf("after delete: %d", got)
	}
}
