//go:build !ios_extension && !sidecar_http

// The daemon's scim_signer component (QD-829) on the act harness's sidecar over the test network: it makes SCIM's queue
// source only once the verified state names this sidecar as scim_signer, signs the queue's removal of a member outside
// the AdminSet at once, and drops the source when the designation goes. Each look is woken by an entry the installed
// authority applies; the harness's clock never fires, so no pass runs on the interval.

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The sources a component made, and the api each was made over.
type testScimSourceFactory struct {
	source    ScimChangeSource
	stateLock sync.Mutex
	apis      []*SidecarApi
}

func (self *testScimSourceFactory) newSource(api *SidecarApi) ScimChangeSource {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.apis = append(self.apis, api)
	return self.source
}

func (self *testScimSourceFactory) made() []*SidecarApi {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.apis)
}

func TestTheScimSignerComponentInstallsItsSourceOnlyWhileDesignated(t *testing.T) {
	net := newTestConfigNet(t)
	leaver, _ := net.consentedMember("component leaver")
	admin := net.admitAdmin("component admin")
	sidecar, authority, deltaApi, _ := newTestMemberRemoveSidecar(t, net)
	identity := sidecar.currentIdentity()
	// the harness's sidecar admitted under its own identity key, the first device of a member outside the AdminSet, so
	// it stands as the verifier asks of a scim_signer
	indexerMember := testConfigId("component indexer member")
	net.admitMember(net.owner, indexerMember, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	admit := net.admission(testConfigDevice{sidecarId: identity.SidecarId, memberId: indexerMember, key: testConfigDeviceKey("component indexer")},
		nil, false, 0, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
	admit.IdentityPublicKey = bytes.Clone(identity.IdentityPublicKey)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
	factory := &testScimSourceFactory{source: &testScimChangeSource{memberIds: []Id{admin.memberId, leaver}}}
	settings := DefaultConfigScimSignerSettings()
	component := &SidecarScimSigner{sidecar: sidecar, settings: settings, newSource: factory.newSource, changes: NewMonitorValue[uint64](0)}

	// a real-time bound only a broken wiring reaches
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	generationCtx, endGeneration := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		component.run(generationCtx, identity.SidecarId, sidecar.sidecarApi)
	}()
	wake := func() {
		state := net.log.State()
		authority.setState(state)
		authority.apply(&SidecarAuthorityEntry{Pin: state.Pin(), TimeMs: net.timeMs, Kind: bridge.AuthEntryKindBase, Applied: true})
	}

	status, err := component.WaitStatus(ctx, func(status *SidecarScimSignerStatus) bool { return 1 <= status.LookCount })
	if err != nil {
		t.Fatal(err)
	}
	if status.Installed || status.PassCount != 0 || len(factory.made()) != 0 || len(deltaApi.postsSoFar()) != 0 {
		t.Fatalf("before any designation: %+v, %d sources", status, len(factory.made()))
	}

	// another sidecar named: still no source
	net.designateScimSigner(testConfigId("another indexer"), 2)
	looks := status.LookCount
	wake()
	status, err = component.WaitStatus(ctx, func(status *SidecarScimSignerStatus) bool { return looks < status.LookCount })
	if err != nil || status.Installed || len(factory.made()) != 0 {
		t.Fatalf("with another sidecar named: %+v %v, %d sources", status, err, len(factory.made()))
	}

	// this sidecar named: the source over its api, and a pass at once that signs the member outside the AdminSet
	net.designateScimSigner(identity.SidecarId, 3)
	wake()
	status, err = component.WaitStatus(ctx, func(status *SidecarScimSignerStatus) bool { return status.Installed && 1 <= status.PassCount })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(status.Signed, []Id{leaver}) || status.PassErr != "" {
		t.Errorf("the pass: %+v", status)
	}
	if made := factory.made(); len(made) != 1 || made[0] != sidecar.sidecarApi {
		t.Errorf("%d sources made", len(made))
	}
	posts := deltaApi.postsSoFar()
	signed := &bridge.Signed{}
	revoke := &bridge.MemberRevoke{}
	if len(posts) != 1 || proto.Unmarshal(posts[0], signed) != nil || bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_MEMBER_REVOKE ||
		proto.Unmarshal(signed.GetBody(), revoke) != nil {
		t.Fatalf("posted %d statements", len(posts))
	}
	if revokedId, err := IdFromBytes(revoke.GetMemberId()); err != nil || revokedId != leaver {
		t.Errorf("the MemberRevoke names %x", revoke.GetMemberId())
	}

	// the designation goes: so does the source, and no pass runs without one
	net.designateScimSigner(testConfigId("a later indexer"), 4)
	wake()
	status, err = component.WaitStatus(ctx, func(status *SidecarScimSignerStatus) bool { return !status.Installed })
	if err != nil || status.PassCount != 1 || len(deltaApi.postsSoFar()) != 1 {
		t.Fatalf("undesignated: %+v %v", status, err)
	}

	endGeneration()
	<-done
	if component.Status().Installed {
		t.Error("the source outlived its generation")
	}
}
