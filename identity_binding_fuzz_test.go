//go:build !js

// Off the js leg, whose tests run in a Worker with no file system, where a fuzz target cannot read its
// seed corpus.

package sidecar

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// No input panics, and anything accepted is canonical: its body and wrapper re-encode to the same bytes, so one
// binding has one byte string.
func FuzzVerifySidecarIdentityBinding(f *testing.F) {
	identitySeed, clientKeySeed := testBindingSeeds()
	signedBinding, _ := NewSidecarIdentityBinding(testBindingFields(), identitySeed, clientKeySeed)
	f.Add(signedBinding)
	f.Add([]byte{})
	f.Add(signedBinding[:len(signedBinding)/2])
	f.Add(append(bytes.Clone(signedBinding), 0x78, 0x01))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		binding, err := VerifySidecarIdentityBinding(encoded)
		if err != nil {
			if binding != nil {
				t.Fatal("a binding beside an error")
			}
			return
		}
		signed := &bridge.SignedSidecarIdentityBinding{}
		if proto.Unmarshal(encoded, signed) != nil {
			t.Fatal("accepted bytes that do not decode")
		}
		canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil || !bytes.Equal(canonical, encoded) {
			t.Fatal("accepted a wrapper that is not canonical")
		}
		if bytes.Equal(binding.ClientPublicKey, binding.IdentityPublicKey) {
			t.Fatal("accepted one key as both")
		}
	})
}
