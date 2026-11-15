// The daemon's scim_signer (QD-829) as ur daemon composes it beside each network's follower (startUrConfigFollower), on
// sidecartest's Net: real Sidecars on one instance, each admitted in an admission world's log by its real identity key,
// following that log through the Net's fake api. Of two Sidecars, each the invited first device of a member outside the
// AdminSet, only the one ServiceSettings.scim_signer names makes SCIM's queue source, here the test's in place of GET
// /sidecar/scim-changes (urDaemonScimSource), and its pass signs the queued removal of a member outside the AdminSet,
// which lands in the log, the member's device revoked, while an AdminSet member's queued removal is left to admin
// devices; the other Sidecar never makes a source. Every wait is on a monitor or the log, bounded by a real-time guard
// only a broken wiring reaches.

package main

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A queue the test scripts.
type testUrScimSource struct {
	memberIds []sidecar.Id
}

func (self *testUrScimSource) ScimMemberRevokes(ctx context.Context) ([]sidecar.Id, error) {
	return slices.Clone(self.memberIds), nil
}

// The sources the daemon's scim_signers made, and the api each was made over.
type testUrScimSources struct {
	source    sidecar.ScimChangeSource
	stateLock sync.Mutex
	apis      []*sidecar.SidecarApi
}

func (self *testUrScimSources) newSource(api *sidecar.SidecarApi) sidecar.ScimChangeSource {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.apis = append(self.apis, api)
	return self.source
}

func (self *testUrScimSources) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.apis)
}

// startUrConfigFollower starts the network's scim_signer beside the follower, one a Sidecar.
func TestDaemonStartsAScimSignerBesideEachFollower(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	scimSigner := running.ScimSigner()
	if scimSigner == nil {
		t.Fatal("the daemon started no scim_signer beside the follower")
	}
	if _, err := running.RunScimSigner(nil); err == nil {
		t.Error("a second scim_signer started on one Sidecar")
	}
	if running.ScimSigner() != scimSigner {
		t.Error("the first scim_signer stopped")
	}
}

func TestDaemonInstallsTheScimSourceOnlyOnTheDesignatedIndexer(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	owner := network.Owner()
	leaver, leaverDevice := network.ConsentedMember("scim leaver")
	adminMember := network.AdmitMember(owner, "scim admin", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	network.MustLand(network.Sign(owner, bridge.SignedType_SIGNED_ADMIN_SET, network.AdminSet([]sidecar.Id{owner.MemberId}, []sidecar.Id{adminMember}, 0)))
	sources := &testUrScimSources{source: &testUrScimSource{memberIds: []sidecar.Id{adminMember, leaver}}}
	previousSource := urDaemonScimSource
	t.Cleanup(func() { urDaemonScimSource = previousSource })
	urDaemonScimSource = sources.newSource

	// a second device's daemon, composed as the world's is
	otherInstance, err := world.net.StartInstance("other daemon", &sidecartest.TestInstanceArgs{
		Start: func(running *sidecar.Sidecar) error {
			if startUrConfigFollower(running, sidecar.NewNoopLogger()) == nil {
				return errors.New("no follower started")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherInstance.Close)
	// each the invited first device of a member outside the AdminSet, admitted by its real identity key
	host := func(instance *sidecartest.TestInstance, label string) *sidecar.Sidecar {
		t.Helper()
		memberId := network.AdmitMember(owner, label, bridge.MemberRole_MEMBER_ROLE_MEMBER)
		running, err := instance.AddSidecarIn(network.NetworkId(), nil)
		if err != nil {
			t.Fatal(err)
		}
		network.AdmitSidecar(owner, running.Identity(), memberId, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		return running
	}
	indexer := host(world.instance, "scim indexer member")
	other := host(otherInstance, "scim other member")
	network.SetServiceSettings(&protocol.ServiceSettings{ScimSigner: indexer.Identity().SidecarId.Bytes()})
	world.standing(indexer, network)
	world.standing(other, network)
	designatedAt := network.Tip().GetVersion()

	ctx, cancel := context.WithTimeout(world.ctx, urTestTimeout)
	defer cancel()
	status, err := indexer.ScimSigner().WaitStatus(ctx, func(status *sidecar.SidecarScimSignerStatus) bool {
		return status.Installed && 1 <= status.PassCount
	})
	if err != nil {
		t.Fatalf("the designated indexer's scim_signer: %v", err)
	}
	if !slices.Equal(status.Signed, []sidecar.Id{leaver}) || status.PassErr != "" {
		t.Fatalf("the indexer's pass: %+v", status)
	}

	// the removal is in the log: every reader of the world applies it, the leaver gone and its device revoked, and the
	// AdminSet member still a member
	network.Sync()
	state := network.State()
	if state.Member(leaver) != nil || state.SidecarRow(leaverDevice.SidecarId).GetRevokedAt() <= designatedAt || state.Member(adminMember) == nil {
		t.Fatalf("after the indexer's pass at %d: the leaver a member %t, its device revoked at %d", state.Pin().GetVersion(),
			state.Member(leaver) != nil, state.SidecarRow(leaverDevice.SidecarId).GetRevokedAt())
	}

	// the other Sidecar, which followed the log through the removal, looked and never made a source
	world.standing(other, network)
	otherStatus, err := other.ScimSigner().WaitStatus(ctx, func(status *sidecar.SidecarScimSignerStatus) bool { return 2 <= status.LookCount })
	if err != nil {
		t.Fatalf("the other Sidecar's scim_signer: %v", err)
	}
	if otherStatus.Installed || otherStatus.PassCount != 0 || sources.count() != 1 {
		t.Fatalf("the other Sidecar's scim_signer: %+v, %d sources made", otherStatus, sources.count())
	}
}
