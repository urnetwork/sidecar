//go:build sidecar_testhooks

package sidecar

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Each key reaches the privacy harness where it is made and where it is read back from the keychain, so S1's scan
// finds an identity seed or a ClientKey seed wherever one leaks (§22.7), and persisting passes its barriers.
func TestIdentityKeysReachTheSecretHook(t *testing.T) {
	recorder := recordHooks(t)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := testBindingFields()
	_, secrets := newIdentityTestSecrets(t, binding.NetworkId)
	signedBinding, err := NewSidecarIdentityBinding(binding, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	record, err := loadSidecarIdentity(secrets)
	if err != nil {
		t.Fatal(err)
	}
	defer record.keys.erase()

	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, kind := range []string{"identity_key", "ClientKey"} {
		if !recorder.kinds[kind] {
			t.Errorf("no %s reached the hook", kind)
		}
	}
	for _, want := range [][]byte{keys.identitySeed, keys.clientKeySeed} {
		count := 0
		for _, secret := range recorder.secrets {
			if bytes.Equal(secret, want) {
				count += 1
			}
		}
		// once made, once read back
		if count < 2 {
			t.Errorf("a seed reached the hook %d times", count)
		}
	}
	for _, name := range []string{"identity.persist.before", "identity.persist.after"} {
		if !recorder.barriers[name] {
			t.Errorf("no barrier %s", name)
		}
	}
}
