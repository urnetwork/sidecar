//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §5.8's idle rule (CORE-M2-09): an auto-spawned daemon idles out unless a component serves or its device stands as
// an indexer, asked of each component and of the verified state, never a list of names; a unit-run daemon never idles
// out; and the device's designations retire by its own IndexerSet{retire}.

// A component that serves while active is set: mail, as far as the idle rule can tell.
type testActiveComponent struct {
	name   string
	active atomic.Bool
}

func (self *testActiveComponent) Name() string {
	return self.name
}

func (self *testActiveComponent) Attach(env *SidecarEnv) error {
	return nil
}

func (self *testActiveComponent) Close() {}

func (self *testActiveComponent) Active() bool {
	return self.active.Load()
}

// An act authority that also stands devices as indexers.
type testIndexerAuthority struct {
	*testActAuthority
	designations map[Id][]SidecarIndexerDesignation
}

func (self *testIndexerAuthority) IndexerDesignations(sidecarId Id) []SidecarIndexerDesignation {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]SidecarIndexerDesignation{}, self.designations[sidecarId]...)
}

// An auto-spawned daemon on a clock the test moves, hosting one running Sidecar with components.
func startIdleTestDaemon(t *testing.T, autoSpawned bool, components ...SidecarComponent) (*testDaemon, *tokenTestClock, *Sidecar, *testEnrollment) {
	t.Helper()
	clock := newTokenTestClock()
	started := startTestDaemon(t, func(settings *DaemonSettings) {
		settings.AutoSpawned = autoSpawned
		settings.Clock = clock
	})
	instance, enrollment := newTestEnrolledInstance(t)
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(newTestSidecarPlatform()), components...)
	awaitSidecarStatus(t, sidecar, func(status SidecarStatus) bool { return status.State != SidecarStateLocked })
	if err := started.daemon.AddSidecar(enrollment.networkId, sidecar); err != nil {
		t.Fatal(err)
	}
	return started, clock, sidecar, enrollment
}

// A component that serves, mail here, keeps an idle auto-spawned daemon up, and once it stops the daemon may go.
func TestIdleExitBlockedByMail(t *testing.T) {
	mail := &testActiveComponent{name: "mail"}
	mail.active.Store(true)
	started, clock, _, _ := startIdleTestDaemon(t, true, mail, &testActiveComponent{name: "evs"})
	if started.daemon.ShouldIdleExit() {
		t.Fatal("exits before its idle time")
	}
	clock.Advance(11 * time.Minute)
	if started.daemon.ShouldIdleExit() {
		t.Fatal("idles out while mail serves")
	}
	mail.active.Store(false)
	if !started.daemon.ShouldIdleExit() {
		t.Fatal("stays up with nothing serving")
	}
}

// A device the network stands as an indexer keeps its auto-spawned daemon up, and a retired one does not.
func TestIdleExitBlockedByIndexer(t *testing.T) {
	started, clock, sidecar, enrollment := startIdleTestDaemon(t, true)
	authority := &testIndexerAuthority{testActAuthority: newTestActAuthority(), designations: map[Id][]SidecarIndexerDesignation{
		enrollment.sidecarId: {{Scope: protocol.IndexerScope_INDEXER_SCOPE_NETWORK}},
	}}
	t.Cleanup(sidecar.InstallAuthority(authority))
	clock.Advance(11 * time.Minute)
	if started.daemon.ShouldIdleExit() {
		t.Fatal("an indexer idles out")
	}
	func() {
		authority.stateLock.Lock()
		defer authority.stateLock.Unlock()
		delete(authority.designations, enrollment.sidecarId)
	}()
	if !started.daemon.ShouldIdleExit() {
		t.Fatal("a retired indexer stays up")
	}
}

// A unit-run daemon never idles out, busy or not, and its idle loop arms no wait.
func TestUnitRunNeverIdles(t *testing.T) {
	started, clock, _, _ := startIdleTestDaemon(t, false)
	clock.Advance(24 * time.Hour)
	if started.daemon.ShouldIdleExit() {
		t.Fatal("a unit-run daemon idles out")
	}
	select {
	case <-started.ran:
		t.Fatal("a unit-run daemon exited")
	default:
	}
}

// The device's own IndexerSet{retire} for each designation that stands, in one act; none with no designation, and a
// refusal with no verified state rather than a guess of none.
func TestRetireIndexerSignsEachDesignation(t *testing.T) {
	sidecar, actAuthority, deltaApi := newActTestSidecar(t)
	identity := sidecar.currentIdentity()
	authority := &testIndexerAuthority{testActAuthority: actAuthority, designations: map[Id][]SidecarIndexerDesignation{}}
	t.Cleanup(sidecar.InstallAuthority(authority))
	if retired, err := sidecar.RetireIndexer(context.Background()); err != nil || retired != 0 || len(deltaApi.postsSoFar()) != 0 {
		t.Fatalf("no designation: %d %v", retired, err)
	}
	authority.designations[identity.SidecarId] = []SidecarIndexerDesignation{
		{Scope: protocol.IndexerScope_INDEXER_SCOPE_NETWORK},
		{Scope: protocol.IndexerScope_INDEXER_SCOPE_MEMBER},
	}
	if retired, err := sidecar.RetireIndexer(context.Background()); err != nil || retired != 2 {
		t.Fatalf("retire: %d %v", retired, err)
	}
	posts := deltaApi.postsSoFar()
	if len(posts) != 2 {
		t.Fatalf("%d posts", len(posts))
	}
	for index, post := range posts {
		signed := &bridge.Signed{}
		indexerSet := &protocol.IndexerSet{}
		if err := proto.Unmarshal(post, signed); err != nil || proto.Unmarshal(signed.GetBody(), indexerSet) != nil {
			t.Fatal(err)
		}
		subjectId, _ := IdFromBytes(indexerSet.GetSidecarId())
		if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_INDEXER_SET || subjectId != identity.SidecarId ||
			!indexerSet.GetRetire() || indexerSet.GetScope() != authority.designations[identity.SidecarId][index].Scope {
			t.Errorf("post %d: %+v", index, indexerSet)
		}
	}
	unverified, _, _ := newActTestSidecar(t)
	removeAuthority := unverified.InstallAuthority(nil)
	defer removeAuthority()
	if _, err := unverified.RetireIndexer(context.Background()); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("no verified state: %v", err)
	}
}
