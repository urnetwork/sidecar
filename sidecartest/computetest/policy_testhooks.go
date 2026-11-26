//go:build sidecar_testhooks

// The fake's verifier and a device over it (DESIGN-COMPUTE §5.4, §18): ATTEST's verifier pinning the test release key
// through the seam only the sidecar_testhooks build has (sidecar.NewComputePolicyVerifierForTest), and a device's
// store, gate and fetcher over it, as a Sidecar's attest component wires them. policy_untagged.go is the untagged
// build's half.

package computetest

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// ATTEST's verifier with the test release key pinned, for a production build's namespace or, with staging, a staging
// build's, under the fake's AttestSettings.
func (self *FakeComputePolicy) Verifier(staging bool) (*sidecar.ComputePolicyVerifier, error) {
	return sidecar.NewComputePolicyVerifierForTest(self.settings.Attest, []ssh.PublicKey{self.keys.Release.PublicKey()}, staging), nil
}

// A device's policy store, gate and fetcher over args, verifying under the test release key: the store's release copy
// is args.Release, or none; the gate's refresh is the fetcher's pass over args.Sources; its early-ticket alarms are
// kept (FakePolicyDevice.Alarms).
func (self *FakeComputePolicy) NewDevice(args *FakePolicyDeviceArgs) (*FakePolicyDevice, error) {
	if args == nil {
		args = &FakePolicyDeviceArgs{}
	}
	store := args.Store
	if store == nil {
		store = sidecartest.NewFakeStore().Root()
	}
	clock := args.Clock
	if clock == nil {
		clock = self.clock
	}
	verifier, err := self.Verifier(args.Staging)
	if err != nil {
		return nil, err
	}
	storeArgs := &sidecar.ComputePolicyStoreArgs{
		Store:    store,
		Verifier: verifier,
		Settings: self.settings.Attest,
		Clock:    clock,
		Log:      args.Log,
	}
	if args.Release != nil {
		storeArgs.SetReleaseCopyForTest(args.Release.Document, args.Release.Signature)
	} else {
		storeArgs.SetReleaseCopyForTest(nil, nil)
	}
	policyStore, err := sidecar.NewComputePolicyStore(storeArgs)
	if err != nil {
		return nil, err
	}
	device := &FakePolicyDevice{Verifier: verifier, Store: policyStore}
	gate, err := sidecar.NewComputePolicyGate(&sidecar.ComputePolicyGateArgs{
		Store:    policyStore,
		Verifier: verifier,
		Settings: self.settings.Attest,
		Log:      args.Log,
		Alarm:    device.alarm,
		Refresh: func(ctx context.Context) error {
			return device.Fetcher.Fetch(ctx)
		},
	})
	if err != nil {
		return nil, err
	}
	fetcher, err := sidecar.NewComputePolicyFetcher(&sidecar.ComputePolicyFetcherArgs{
		Store:    policyStore,
		Gate:     gate,
		Sources:  args.Sources,
		Settings: self.settings.Attest,
		Log:      args.Log,
	})
	if err != nil {
		return nil, err
	}
	device.Gate = gate
	device.Fetcher = fetcher
	return device, nil
}
