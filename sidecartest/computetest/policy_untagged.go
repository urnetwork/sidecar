//go:build !sidecar_testhooks

// The untagged build's half of policy_testhooks.go: no seam into ATTEST's verifier is linked, so no build without the
// tag pins the test release key, and Verifier and NewDevice fail with a named error rather than hand back a verifier
// that refuses everything.

package computetest

import (
	"github.com/urnetwork/sidecar"
)

// ErrFakeComputePolicyUnlinked: this build links no seam into ATTEST's verifier.
func (self *FakeComputePolicy) Verifier(staging bool) (*sidecar.ComputePolicyVerifier, error) {
	return nil, ErrFakeComputePolicyUnlinked
}

// ErrFakeComputePolicyUnlinked, as Verifier.
func (self *FakeComputePolicy) NewDevice(args *FakePolicyDeviceArgs) (*FakePolicyDevice, error) {
	return nil, ErrFakeComputePolicyUnlinked
}
