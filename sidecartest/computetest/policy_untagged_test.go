//go:build !sidecar_testhooks

package computetest

import (
	"errors"
	"testing"
)

// Without sidecar_testhooks no build pins the test release key: the fake's verifier and device say so by name.
func TestFakeComputePolicyNeedsTestHooks(t *testing.T) {
	fake, _ := newTestFakeComputePolicy(t, "")
	if verifier, err := fake.Verifier(false); verifier != nil || !errors.Is(err, ErrFakeComputePolicyUnlinked) {
		t.Fatalf("the untagged build's verifier: %v, %v", verifier, err)
	}
	if device, err := fake.NewDevice(nil); device != nil || !errors.Is(err, ErrFakeComputePolicyUnlinked) {
		t.Fatalf("the untagged build's device: %v, %v", device, err)
	}
}
