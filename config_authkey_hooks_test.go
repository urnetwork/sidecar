//go:build sidecar_testhooks

package sidecar

import (
	"bytes"
	"testing"
)

// Both seeds and the bearer reach the privacy harness as ParseAuthKey decodes them, so §22.7's canaries
// find either seed wherever it leaks.
func TestAuthKeySeedsReachTheSecretHook(t *testing.T) {
	recorder := recordHooks(t)
	text, err := formatAuthKey(testAuthKeyBearer(), testAuthKeyBundle())
	if err != nil {
		t.Fatal(err)
	}
	recorder.stateLock.Lock()
	recorder.secrets = nil
	recorder.kinds = map[string]bool{}
	recorder.stateLock.Unlock()
	if _, err := ParseAuthKey(text); err != nil {
		t.Fatal(err)
	}
	bundle := testAuthKeyBundle()
	recorder.stateLock.Lock()
	defer recorder.stateLock.Unlock()
	for _, kind := range []string{"auth_key", "delegation_signing_seed", "delegation_reader_seed"} {
		if !recorder.kinds[kind] {
			t.Errorf("no %s reached the hook", kind)
		}
	}
	for _, want := range [][]byte{bundle.DelegationSigningSeed, bundle.DelegationReaderSeed, []byte(testAuthKeyBearer())} {
		found := false
		for _, secret := range recorder.secrets {
			if bytes.Equal(secret, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("a secret did not reach the hook")
		}
	}
}
