// A VPN component's config head reader on T2 (sidecar.NewForwardingConfigHeads; SDK-M8-16; DESIGN-DETAILS 4.2.5's
// Compile, step 3; QD-814): built as a forwarding role builds it, with no config state, no identity key, the config's
// keys from a function as the Forwarder's store answers them and its pin in a store of the role's, against an
// evsservice.EvsEngine whose config repo's main ref holds the heads a writer saved.
//
//	reads     each head at its version, at the anchor its base gives, the pin kept under the evs- names
//	refusals  an ordinary read, which judges each push at a pin this reader holds no state for, withholds; a chain
//	          value no version holds is a mismatch; a generation the keys lack is a missing key, which the Forwarder
//	          lists gkm for

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

// A forwarding role's head reader for the reader r's sidecar over the world, its keys r's device's but for the
// generation lacking names, and its store store.
func (self *configHeadWorld) forwardingHeads(store sidecar.ForwarderStore, lacking *atomic.Uint64) *sidecar.EvsConfigHeadReader {
	self.t.Helper()
	signer := self.signers["r"]
	keyDevice := self.device("r", nil)
	heads, err := sidecar.NewForwardingConfigHeads(&sidecar.ForwardingConfigHeadsArgs{
		NetworkId:    self.networkId,
		SidecarId:    signer.SidecarId,
		ConfigRepoId: self.repoId,
		RepoKeyAt: func(generation uint64) *sidecar.EvsRepoKey {
			if lacking != nil && generation == lacking.Load() {
				return nil
			}
			key, err := keyDevice.gkm.RepoKey(self.ctx, self.repoId, generation)
			if err != nil {
				return nil
			}
			return key
		},
		Store:     store,
		EvsUrl:    "https://evs.example",
		Transport: &epochTransport{world: self.epochWorld, device: keyDevice},
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			connectSidecarId := connect.Id(signer.SidecarId)
			return self.host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.clock.Now(), ExpiresAt: self.clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Settings: sidecar.DefaultForwardingConfigHeadsSettings(sidecar.DefaultForwarderSettings(sidecar.ForwarderHostAndroid)),
		Clock:    &epochDeviceClock{clock: self.clock},
		Log:      sidecar.NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return heads
}

// The forwarding reader reads each head at the anchor the base gives, keeps its pin in the role's store under the evs-
// names, and refuses what a reader of no config state cannot judge.
func TestForwardingConfigHeadsReadEachHeadAtTheAnchor(t *testing.T) {
	world := newConfigHeadWorld(t)
	world.saveWith(world.writer, map[string][]byte{
		sidecar.ConfigHeadPolicyPath: []byte(`{"acls": [{"action": "accept"}]}`),
		sidecar.ConfigHeadNamesPath:  []byte("names at 2"),
	})
	// S(1), as a Forwarder holds it after restoring at base 1
	anchor := world.bootstrap.State
	store := NewFakeStore().Root()
	heads := world.forwardingHeads(store, nil)
	for version := uint64(1); version <= 2; version += 1 {
		head, err := heads.ReadConfigHeadAtAnchor(world.ctx, version, world.chains[version][:], anchor)
		if err != nil {
			t.Fatalf("the head at %d at the anchor: %v", version, err)
		}
		if !maps.EqualFunc(head.Files(), world.heads[version].Files(), bytes.Equal) {
			t.Fatalf("the head at %d holds %v, not %v", version, head.Paths(), world.heads[version].Paths())
		}
	}
	entries, err := store.List("")
	if err != nil || len(entries) == 0 {
		t.Fatalf("the role's store holds %v, %v", entries, err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name, "evs-") || 1 < strings.Count(entry.Name, "/") {
			t.Errorf("a record named %q, outside the evs- names or past two segments", entry.Name)
		}
	}

	// a chain value no version holds is a mismatch, judged at the anchor as any read is
	if _, err := heads.ReadConfigHeadAtAnchor(world.ctx, 2, world.chains[1][:], anchor); !errors.Is(err, sidecar.ErrConfigHeadMismatch) {
		t.Errorf("another chain value at 2: %v", err)
	}

	// a reader with no pin judges each push at its own pin, for which it holds no state: withheld
	fresh := world.forwardingHeads(NewFakeStore().Root(), nil)
	if _, err := fresh.ReadConfigHead(world.ctx, 2, world.chains[2][:]); !errors.Is(err, sidecar.ErrConfigHeadUnavailable) {
		t.Errorf("an ordinary read with no state: %v", err)
	}
}

// A generation the role's keys lack withholds the head as a missing key, which the Forwarder takes as a generation to
// list from gkm at its next compile.
func TestForwardingConfigHeadsLackingAGenerationIsAMissingKey(t *testing.T) {
	world := newConfigHeadWorld(t)
	lacking := &atomic.Uint64{}
	lacking.Store(1)
	heads := world.forwardingHeads(NewFakeStore().Root(), lacking)
	_, err := heads.ReadConfigHeadAtAnchor(world.ctx, 1, world.chains[1][:], world.bootstrap.State)
	if !errors.Is(err, sidecar.ErrConfigHeadUnavailable) || !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Fatalf("a read lacking generation 1: %v", err)
	}
	lacking.Store(0)
	if _, err := heads.ReadConfigHeadAtAnchor(world.ctx, 1, world.chains[1][:], world.bootstrap.State); err != nil {
		t.Errorf("the read once the generation is held: %v", err)
	}
}
