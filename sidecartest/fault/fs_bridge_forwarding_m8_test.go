//go:build !sidecar_http && !ios_extension

// BRIDGE-M8-07's forwarding rows on T2 (fs_bridge_forwarding_m8.go): FS-38's forwarding twin, its refusals beside it,
// and its forged case, each schedule on a Net of its own; server/controller/connect_bridge_forwarding_test.go runs the
// same builders on T3.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs builder's schedule on a Net of its own on T2, failing t with its trace.
func fsForwardingRun(t *testing.T, name string, builder Builder) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	if result := Run(t.Context(), builder(net), net); result.Err != nil {
		t.Fatalf("%s: %s", name, result)
	}
}

func TestFs38ForwardingDelegation(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding twin", Fs38ForwardingDelegation)
}

func TestFs38ForwardingRefusals(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding refusals", Fs38ForwardingCase)
}

func TestFs38ForwardingForged(t *testing.T) {
	fsForwardingRun(t, "FS-38's forwarding forged case", Fs38ForwardingForgedCase)
}
