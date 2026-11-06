//go:build !sidecar_http

// sdk and server link connect's packages beside sidecar's, and a duplicate path or name panics at init
// (§4.9). This binary links both, as they do, so running it at all is the check that no init panics.
// sidecar_http links no connect, so there is nothing here for that leg to prove.

package sidecar

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/urnetwork/connect/protocol"
	_ "github.com/urnetwork/sidecar/protocol"
	_ "github.com/urnetwork/sidecar/protocol/bridge"
)

// connect registers bare file names in package bringyour, and sidecar root-relative paths in
// urnetwork.sidecar, so the two never meet.
func TestProtocolRegistersBesideConnect(t *testing.T) {
	cases := []struct {
		path        string
		packageName string
	}{
		{path: "transfer.proto", packageName: "bringyour"},
		{path: "protocol/types.proto", packageName: "urnetwork.sidecar"},
		{path: "protocol/bridge/signed.proto", packageName: "urnetwork.sidecar"},
	}
	for _, c := range cases {
		file, err := protoregistry.GlobalFiles.FindFileByPath(c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if string(file.Package()) != c.packageName {
			t.Errorf("%s is in package %q, want %q", c.path, file.Package(), c.packageName)
		}
	}
}
