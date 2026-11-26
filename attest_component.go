//go:build !ios_extension && !sidecar_http

// Attestation's compute component on a Sidecar (DESIGN-COMPUTE §3.3, §5; CARCH's registerComputeComponent): the
// compute policy store over the Sidecar's own sealed attest directory and this build's verifier, which every reader of
// the policy reaches through Sidecar.ComputePolicyStore; the remote-work gate over it, which every remote operation
// calls through Sidecar.ComputePolicyGate; and the fetcher, from the serving paths AttestSettings.FetchBaseUrls names,
// which the gate asks when remote work lapses and which keeps its own schedule once remote work has been asked for,
// so a device that never uses remote compute fetches nothing. The directory is the enrolled network's, resolved at
// each call, since a Sidecar constructs its components before it may have enrolled: until then the store serves the
// release's copy alone and takes nothing new.
//
// The gate's early-ticket alarm is logged: no SidecarEventKind carries it to the apps yet.

package sidecar

import (
	"context"
	"io"
	"time"
)

// The name attestation registers its component under.
const computeAttestComponentName = "attest"

// Registers attestation's component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(computeAttestComponentName, newComputeAttest, nil)
}

// Attestation's parts on one Sidecar.
type ComputeAttest struct {
	store   *ComputePolicyStore
	gate    *ComputePolicyGate
	fetcher *ComputePolicyFetcher
}

// The parts over sidecar's settings, clock, log and store. Reads nothing of the network: the store's file is read at
// its first use that can.
func newComputeAttest(sidecar *Sidecar) (*ComputeAttest, error) {
	settings := sidecar.settings.Attest
	if settings == nil {
		settings = DefaultAttestSettings()
	}
	store, err := NewComputePolicyStore(&ComputePolicyStoreArgs{
		Store:    &computeAttestSidecarStore{sidecar: sidecar},
		Verifier: NewComputePolicyVerifier(settings),
		Settings: settings,
		Clock:    sidecar.clock,
		Log:      sidecar.log,
	})
	if err != nil {
		return nil, err
	}
	sources := []ComputePolicySource{}
	for _, base := range settings.FetchBaseUrls {
		source, err := NewComputePolicyHttpSource(base, nil, settings)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	attest := &ComputeAttest{store: store}
	gate, err := NewComputePolicyGate(&ComputePolicyGateArgs{
		Store:    store,
		Verifier: store.verifier,
		Settings: settings,
		Log:      sidecar.log,
		Alarm: func(alarm *ComputePolicyAlarm) {
			sidecar.log.Errorf("[attest]a freshness ticket of batch %s arrived before its start at %s", alarm.BatchId, alarm.NotBefore.Format(time.RFC3339))
		},
		Refresh: func(ctx context.Context) error {
			return attest.fetcher.Fetch(ctx)
		},
	})
	if err != nil {
		return nil, err
	}
	attest.gate = gate
	attest.fetcher, err = NewComputePolicyFetcher(&ComputePolicyFetcherArgs{
		Store:    store,
		Gate:     gate,
		Sources:  sources,
		Settings: settings,
		Log:      sidecar.log,
	})
	if err != nil {
		return nil, err
	}
	// the schedule ends with the Sidecar; one built with no lifetime keeps none
	if sidecar.ctx != nil {
		go attest.fetcher.run(sidecar.ctx, sidecar.clock)
	}
	return attest, nil
}

// This Sidecar's compute policy store, or an error wrapping ErrComputeComponentUnavailable that says why there is none.
func (self *Sidecar) ComputePolicyStore() (*ComputePolicyStore, error) {
	attest, err := sidecarComputeComponent[ComputeAttest](self, computeAttestComponentName)
	if err != nil {
		return nil, err
	}
	return attest.store, nil
}

// This Sidecar's remote-work gate, or an error wrapping ErrComputeComponentUnavailable that says why there is none:
// with none, no remote operation runs.
func (self *Sidecar) ComputePolicyGate() (*ComputePolicyGate, error) {
	attest, err := sidecarComputeComponent[ComputeAttest](self, computeAttestComponentName)
	if err != nil {
		return nil, err
	}
	return attest.gate, nil
}

// The Sidecar's attest directory, resolved at each call from the network it has enrolled in: before that, and while
// its keychain is locked, every call answers ErrSidecarStoreLocked.
type computeAttestSidecarStore struct {
	sidecar *Sidecar
}

// The directory now.
func (self *computeAttestSidecarStore) directory() (SidecarStore, error) {
	return self.sidecar.LocalStore().Directory(computePolicyStoreDirectory, computePolicyStoreClass)
}

// See SidecarStore.
func (self *computeAttestSidecarStore) Open(name string) (io.ReadCloser, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.Open(name)
}

// See SidecarStore.
func (self *computeAttestSidecarStore) Create(name string) (SidecarStoreWriter, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.Create(name)
}

// See SidecarStore.
func (self *computeAttestSidecarStore) Remove(name string) error {
	directory, err := self.directory()
	if err != nil {
		return err
	}
	return directory.Remove(name)
}

// See SidecarStore.
func (self *computeAttestSidecarStore) List(prefix string) ([]SidecarStoreEntry, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.List(prefix)
}

// See SidecarStore.
func (self *computeAttestSidecarStore) Directory(name string, class string) (SidecarStore, error) {
	directory, err := self.directory()
	if err != nil {
		return nil, err
	}
	return directory.Directory(name, class)
}
