//go:build sidecar_testhooks

// Under the tag, each of §9's keys reaches the privacy harness's hook, under the name of what it is,
// so §22.7's scan looks for the very bytes these derive.

package sidecar

import (
	"bytes"
	"slices"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSocketKeysReachTheHook(t *testing.T) {
	kindSecrets := map[string][][]byte{}
	t.Cleanup(func() { SetTestHooks(nil) })
	SetTestHooks(&TestHooks{
		Secret: func(kind string, secret []byte) {
			kindSecrets[kind] = append(kindSecrets[kind], secret)
		},
	})
	keys := testSocketKeys(t, testSocketNetworkId, testSocketKey)
	SetTestHooks(nil)

	hooked := func(kind string, secret []byte) bool {
		return slices.ContainsFunc(kindSecrets[kind], func(candidate []byte) bool {
			return bytes.Equal(candidate, secret)
		})
	}
	if !hooked("K_sock", testSocketKey) {
		t.Error("K_sock did not reach the hook")
	}
	if !hooked("K_tok", keys.tokenKey) {
		t.Error("K_tok did not reach the hook")
	}
	if len(kindSecrets["K_seal"]) != 1 {
		t.Fatalf("%d K_seal", len(kindSecrets["K_seal"]))
	}
	// K_seal lives only inside the AEAD, so what was hooked is proved by the tags it makes
	sealAead, err := chacha20poly1305.NewX(kindSecrets["K_seal"][0])
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, sealAead.NonceSize())
	if !bytes.Equal(sealAead.Seal(nil, nonce, nil, nil), keys.sealAead.Seal(nil, nonce, nil, nil)) {
		t.Error("what was hooked as K_seal is not the key")
	}
}
