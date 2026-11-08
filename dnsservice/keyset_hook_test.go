//go:build sidecar_testhooks

package dnsservice_test

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The ZSK reaches the privacy harness the moment its bytes exist, so §22.7's scan looks for it.
func TestLoadZskHandsTheScalarToTheHarness(t *testing.T) {
	key := keysetTestKey(t)
	type secretCall struct {
		kind   string
		secret []byte
	}
	calls := []secretCall{}
	remove, err := sidecartest.InstallTestHooks(func(kind string, secret []byte) {
		calls = append(calls, secretCall{kind: kind, secret: bytes.Clone(secret)})
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if _, err := dnsservice.LoadZsk([]byte(keysetTestFile(key))); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0].kind != "dns_zsk" || !bytes.Equal(calls[0].secret, key.D.FillBytes(make([]byte, 32))) {
		t.Errorf("calls %v", calls)
	}
}
