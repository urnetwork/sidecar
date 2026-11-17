//go:build !ios_extension

// MCP-M8-01: §16.6's host table for apps on the approver tests' world (record_approval_decide_test.go): an app in local
// mode signs others' requests by device and its own by presence; a remote-mode desktop app signs other sidecars' by
// device and lists its daemon's own with no decision, refusing it whatever check it is given (D-SDK-9); an app host
// lists a template with deny alone; a page Worker, a quick burner and a tagged sidecar list and sign nothing on any
// host; an installed approver log stands in for the record's. Then the phone's approval part on a fake leaser: it
// leases each approval log, raises approval_pending once for each request newly waiting, renews a lease at its age and
// reads a lapsed one's log again, releases nothing at Close, and on a device that is not approval-capable leases and
// raises nothing.

package sidecar

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §16.6's host table, row by row: the channel each host signs another sidecar's request and its own on.
func TestApprovalHostChannelTable(t *testing.T) {
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	presence := protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE
	none := protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED
	for _, row := range []struct {
		host   ApprovalHost
		others protocol.ApprovalChannel
		own    protocol.ApprovalChannel
	}{
		{host: ApprovalHostDaemon, others: device, own: presence},
		{host: ApprovalHostAppLocal, others: device, own: presence},
		{host: ApprovalHostAppRemote, others: device, own: none},
		// a host the table does not know signs nothing
		{host: ApprovalHost(99), others: none, own: none},
	} {
		if channel := ApprovalHostChannel(row.host, false); channel != row.others {
			t.Errorf("host %d, another's request: %s", row.host, channel)
		}
		if channel := ApprovalHostChannel(row.host, true); channel != row.own {
			t.Errorf("host %d, its own request: %s", row.host, channel)
		}
	}
}

// A desktop app in remote mode signs other sidecars' requests by device after the app's confirmation, and lists its
// daemon's own request with no decision, refusing it with or without a presence check, nothing filed (D-SDK-9); the
// same request on the daemon's own host takes presence.
func TestRemoteAppSignsNoOwnRequest(t *testing.T) {
	world := newTestApproverWorld(t)
	identity := world.sidecar.currentIdentity()
	own := world.put(identity.SidecarId, testApproverDnsSet(t, "198.51.100.7"), "")
	other := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.8"), "")
	remote := world.approver.ForHost(ApprovalHostAppRemote)
	if remote.Host() != ApprovalHostAppRemote || world.approver.Host() != ApprovalHostDaemon {
		t.Fatalf("hosts %d and %d", remote.Host(), world.approver.Host())
	}
	items, err := remote.Pending(t.Context())
	if err != nil || len(items) != 2 {
		t.Fatalf("%d items, %v", len(items), err)
	}
	for _, item := range items {
		switch item.ApprovalId {
		case own.ApprovalId():
			if item.Render == nil || item.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED || len(item.Decisions) != 0 {
				t.Errorf("the daemon's own request on the app: %+v", item)
			}
		case other.ApprovalId():
			if item.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE || !slices.Equal(item.Decisions, []string{SidecarDecisionApprove, SidecarDecisionDeny}) {
				t.Errorf("another sidecar's request on the app: %+v", item)
			}
		}
	}
	approve := &SidecarRequestDecision{Decision: SidecarDecisionApprove}
	key, keyId := addTestPresenceKey(t, world.authority)
	world.authority.stateLock.Lock()
	world.authority.liveKeys[len(world.authority.liveKeys)-1].MemberId = world.memberId.Bytes()
	world.authority.stateLock.Unlock()
	seen := []byte{}
	check := testPresenceCheck(t, key, keyId, &seen)
	for _, given := range []SidecarPresenceCheck{nil, check} {
		err := remote.Decide(t.Context(), own.ApprovalId(), approve, SidecarActConfirmed, given)
		if !errors.Is(err, ErrApprovalRemoteOwnRequest) || !errors.Is(err, ErrSidecarApprovalNotEligible) {
			t.Errorf("the app decided its daemon's own request: %v", err)
		}
	}
	if err := remote.Decide(t.Context(), own.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionDeny}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalRemoteOwnRequest) {
		t.Errorf("the app denied its daemon's own request: %v", err)
	}
	if world.decisionCount() != 0 || len(seen) != 0 {
		t.Fatalf("%d decisions filed, presence asked over %d bytes", world.decisionCount(), len(seen))
	}
	// an unconfirmed call signs nothing on the app's path either
	if err := remote.Decide(t.Context(), other.ApprovalId(), approve, SidecarActUnconfirmed, nil); !errors.Is(err, ErrSidecarActMode) {
		t.Errorf("an unconfirmed decision: %v", err)
	}
	if err := remote.Decide(t.Context(), other.ApprovalId(), approve, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	decision := world.lastDecision()
	if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) || !decision.Binds(other) {
		t.Errorf("the app's decision: %+v", decision.Decision)
	}
	if err := decision.Verify(bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey); err != nil {
		t.Errorf("the app's decision does not verify under the daemon's identity key: %v", err)
	}
	// twin: the daemon's own host signs the same own request by presence
	if err := world.approver.Decide(t.Context(), own.ApprovalId(), approve, SidecarActConfirmed, check); err != nil {
		t.Fatal(err)
	}
	if channel := world.lastDecision().Decision.GetChannel(); channel != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE) {
		t.Errorf("the daemon's own decision's channel %d", channel)
	}
}

// An iOS or Android app in local mode signs another sidecar's request by device and its own by presence through the
// app's check over the decision's §6.9 bytes; with no check, or a check the person refused, its own request signs
// nothing.
func TestLocalAppSignsOwnByPresenceOthersByDevice(t *testing.T) {
	world := newTestApproverWorld(t)
	identity := world.sidecar.currentIdentity()
	local := world.approver.ForHost(ApprovalHostAppLocal)
	own := world.put(identity.SidecarId, testApproverDnsSet(t, "198.51.100.7"), "")
	other := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.8"), "")
	approve := &SidecarRequestDecision{Decision: SidecarDecisionApprove}
	refused := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		return nil, errors.New("the person said no")
	}
	if err := local.Decide(t.Context(), own.ApprovalId(), approve, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalOwnRequest) {
		t.Errorf("its own request with no presence signer: %v", err)
	}
	if err := local.Decide(t.Context(), own.ApprovalId(), approve, SidecarActConfirmed, refused); !errors.Is(err, ErrSidecarActPresence) {
		t.Errorf("its own request on a refused check: %v", err)
	}
	if world.decisionCount() != 0 {
		t.Fatalf("%d decisions filed", world.decisionCount())
	}
	key, keyId := addTestPresenceKey(t, world.authority)
	world.authority.stateLock.Lock()
	world.authority.liveKeys[len(world.authority.liveKeys)-1].MemberId = world.memberId.Bytes()
	row := proto.Clone(world.authority.liveKeys[len(world.authority.liveKeys)-1]).(*bridge.KeyRow)
	world.authority.stateLock.Unlock()
	seen := []byte{}
	if err := local.Decide(t.Context(), own.ApprovalId(), approve, SidecarActConfirmed, testPresenceCheck(t, key, keyId, &seen)); err != nil {
		t.Fatal(err)
	}
	decision := world.lastDecision()
	if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE) {
		t.Errorf("its own decision's channel %d", decision.Decision.GetChannel())
	}
	if err := VerifyPresenceUse(decision.Signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, nil); err != nil {
		t.Errorf("the presence decision does not verify: %v", err)
	}
	if err := local.Decide(t.Context(), other.ApprovalId(), approve, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if channel := world.lastDecision().Decision.GetChannel(); channel != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) {
		t.Errorf("another's decision's channel %d", channel)
	}
}

// An app's Decide carries no uses, so an app host lists a template with deny alone and refuses its approval, nothing
// filed, while ur approve on the daemon approves it with 2 or more.
func TestAppHostTemplateTakesDenyAlone(t *testing.T) {
	world := newTestApproverWorld(t)
	template, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionDnsSet), DnsName: "app.example", DnsType: "A", DnsValue: "198.51.100.7", DnsTtl: 300, Scope: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := world.put(world.requesterId, template, "")
	for _, host := range []ApprovalHost{ApprovalHostAppLocal, ApprovalHostAppRemote} {
		approver := world.approver.ForHost(host)
		items, err := approver.Pending(t.Context())
		if err != nil || len(items) != 1 || !slices.Equal(items[0].Decisions, []string{SidecarDecisionDeny}) {
			t.Fatalf("host %d lists %+v, %v", host, items, err)
		}
		for _, uses := range []uint32{0, 2} {
			err := approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove, Uses: uses}, SidecarActConfirmed, nil)
			if !errors.Is(err, ErrSidecarApprovalDecision) {
				t.Errorf("host %d approved a template with uses %d: %v", host, uses, err)
			}
		}
	}
	if world.decisionCount() != 0 {
		t.Fatalf("%d decisions filed", world.decisionCount())
	}
	if err := world.approver.ForHost(ApprovalHostAppLocal).Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionDeny}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	// twin: the daemon's host approves it with uses
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove, Uses: 2}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if uses := world.lastDecision().Decision.GetUses(); uses != 2 {
		t.Errorf("the daemon's template approval has %d uses", uses)
	}
}

// A page Worker (read_only), a quick burner (ephemeral) and a tagged sidecar list and sign nothing on any host
// (D-MCP-14); the twin, an untagged consented device, lists the request on each.
func TestNoAppHostOfANonCapableDeviceSigns(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	identity := world.sidecar.currentIdentity()
	hosts := []ApprovalHost{ApprovalHostDaemon, ApprovalHostAppLocal, ApprovalHostAppRemote}
	for _, device := range []struct {
		name string
		set  func(admission *AclSidecar)
	}{
		{name: "a page Worker", set: func(admission *AclSidecar) {
			admission.Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
		}},
		{name: "a quick burner", set: func(admission *AclSidecar) { admission.Ephemeral = true }},
		{name: "a tagged sidecar", set: func(admission *AclSidecar) { admission.TagIds = []Id{NewId()} }},
	} {
		world.authority.stateLock.Lock()
		admission := world.authority.sidecars[identity.SidecarId]
		saved := *admission
		savedRow := proto.Clone(admission.Row).(*bridge.SidecarRow)
		device.set(admission)
		world.authority.stateLock.Unlock()
		for _, host := range hosts {
			approver := world.approver.ForHost(host)
			if items, err := approver.Pending(t.Context()); err != nil || len(items) != 0 {
				t.Errorf("%s on host %d lists %d, %v", device.name, host, len(items), err)
			}
			if err := approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
				t.Errorf("%s on host %d decided: %v", device.name, host, err)
			}
		}
		world.authority.stateLock.Lock()
		*admission = saved
		admission.Row = savedRow
		world.authority.stateLock.Unlock()
	}
	if world.decisionCount() != 0 {
		t.Fatalf("%d decisions filed", world.decisionCount())
	}
	for _, host := range hosts {
		if items, err := world.approver.ForHost(host).Pending(t.Context()); err != nil || len(items) != 1 {
			t.Errorf("the consented device on host %d lists %d, %v", host, len(items), err)
		}
	}
}

// An installed approver log is what Sidecar.ApprovalApprover reads, until its removal; a removal another install
// replaced removes nothing.
func TestInstalledApproverLogStandsInForTheRecord(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	remove := world.sidecar.InstallApproverLog(world.log)
	approver, err := world.sidecar.ApprovalApprover()
	if err != nil {
		t.Fatal(err)
	}
	items, err := approver.Pending(t.Context())
	if err != nil || len(items) != 1 || items[0].ApprovalId != request.ApprovalId() {
		t.Fatalf("the installed log lists %+v, %v", items, err)
	}
	other := &testApproverLog{}
	removeOther := world.sidecar.InstallApproverLog(other)
	remove()
	if world.sidecar.installedApproverLog() != other {
		t.Fatal("a stale removal removed the newer log")
	}
	removeOther()
	if world.sidecar.installedApproverLog() != nil {
		t.Fatal("the log stayed installed")
	}
}

// A fake leaser: each log's lease, its callbacks and its renewals, and what a commit to a log hints.
type testApprovalPhoneLeaser struct {
	stateLock sync.Mutex
	// the lease count each log's leases took, renewals included, and the callbacks live on each
	leaseCalls   map[Id]int
	callbacks    map[Id]map[int]func(logId Id)
	nextCallback int
	releases     int
	// refuses every lease while set
	refuse bool
}

func newTestApprovalPhoneLeaser() *testApprovalPhoneLeaser {
	return &testApprovalPhoneLeaser{leaseCalls: map[Id]int{}, callbacks: map[Id]map[int]func(logId Id){}}
}

func (self *testApprovalPhoneLeaser) Lease(logId Id, callback func(logId Id)) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.refuse {
		return nil, errors.New("evs is unreachable")
	}
	self.leaseCalls[logId] += 1
	if self.callbacks[logId] == nil {
		self.callbacks[logId] = map[int]func(logId Id){}
	}
	self.nextCallback += 1
	callbackId := self.nextCallback
	self.callbacks[logId][callbackId] = callback
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.callbacks[logId], callbackId)
			self.releases += 1
		})
	}, nil
}

// A commit to logId: each live callback, with no lock held.
func (self *testApprovalPhoneLeaser) commit(logId Id) {
	callbacks := func() []func(logId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		callbacks := []func(logId Id){}
		for _, callback := range self.callbacks[logId] {
			callbacks = append(callbacks, callback)
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback(logId)
	}
}

func (self *testApprovalPhoneLeaser) counts(logId Id) (int, int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.leaseCalls[logId], len(self.callbacks[logId]), self.releases
}

// The approver world's sidecar as a phone: the world's log installed as its approver log, its phone part bound over
// leaser, leasing the world's vault, each hint counted.
func newTestApprovalPhone(t *testing.T, world *testApproverWorld, leaser *testApprovalPhoneLeaser) (*ApprovalPhone, *alarmTestEvents, *int) {
	t.Helper()
	t.Cleanup(world.sidecar.InstallApproverLog(world.log))
	events := &alarmTestEvents{}
	t.Cleanup(world.sidecar.AddEventCallback(events.add))
	hints := 0
	var hintLock sync.Mutex
	phone, err := world.sidecar.BindApprovalPhone(&ApprovalPhoneArgs{
		Leaser: leaser,
		Logs:   func() ([]Id, error) { return []Id{world.vaultId}, nil },
		Hinted: func() {
			hintLock.Lock()
			defer hintLock.Unlock()
			hints += 1
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(phone.Close)
	return phone, events, &hints
}

// A phone leases its approval log at its first resync; a request filed there hints it and, at the resync the hint
// cues, raises approval_pending once with the request's ids; a second resync raises nothing more; a second request
// raises once more; a request decided elsewhere leaves the pending list.
func TestPhoneLeasesItsApprovalLogAndRaisesOnce(t *testing.T) {
	world := newTestApproverWorld(t)
	leaser := newTestApprovalPhoneLeaser()
	phone, events, hints := newTestApprovalPhone(t, world, leaser)
	if world.sidecar.ApprovalPhone() != phone {
		t.Fatal("the sidecar does not hold its phone part")
	}
	resynced, err := phone.Resync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if resynced.LeasesTaken != 1 || !slices.Equal(resynced.Leased, []Id{world.vaultId}) || len(resynced.Pending) != 0 || len(resynced.Raised) != 0 ||
		!slices.Equal(resynced.Due, []Id{world.vaultId}) {
		t.Fatalf("the first resync: %+v", resynced)
	}
	first := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	leaser.commit(world.vaultId)
	if *hints != 1 {
		t.Fatalf("%d hints for one commit", *hints)
	}
	resynced, err = phone.Resync(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(resynced.Raised, []Id{first.ApprovalId()}) || !slices.Equal(resynced.Due, []Id{world.vaultId}) || resynced.LeasesTaken+resynced.LeasesRenewed != 0 {
		t.Fatalf("the hinted resync: %+v", resynced)
	}
	raised := events.of(SidecarEventApprovalPending)
	if len(raised) != 1 || *raised[0].ApprovalId != first.ApprovalId() || raised[0].SidecarId == nil || *raised[0].SidecarId != world.requesterId {
		t.Fatalf("approval_pending: %+v", raised)
	}
	if resynced, err := phone.Resync(t.Context()); err != nil || len(resynced.Raised) != 0 || len(resynced.Pending) != 1 {
		t.Fatalf("a second resync: %+v, %v", resynced, err)
	}
	second := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.8"), "")
	if resynced, err := phone.Resync(t.Context()); err != nil || !slices.Equal(resynced.Raised, []Id{second.ApprovalId()}) {
		t.Fatalf("a second request: %+v, %v", resynced, err)
	}
	if count := len(events.of(SidecarEventApprovalPending)); count != 2 {
		t.Fatalf("%d approval_pending events for two requests", count)
	}
	// decided elsewhere: the log no longer lists it as waiting
	world.log.stateLock.Lock()
	world.log.pending = slices.DeleteFunc(world.log.pending, func(waiting *RecordPendingApproval) bool {
		return waiting.Request.ApprovalId() == first.ApprovalId()
	})
	world.log.stateLock.Unlock()
	if resynced, err := phone.Resync(t.Context()); err != nil || !slices.Equal(resynced.Pending, []Id{second.ApprovalId()}) || len(resynced.Raised) != 0 {
		t.Fatalf("after a decision: %+v, %v", resynced, err)
	}
}

// A lease is renewed once ApprovalPhoneLeaseRenewAge old, the new one taken before the old goes, and one held past
// ApprovalPhoneLeaseExpiry had lapsed, so its log is due; a lease evs refused is taken at the next resync.
func TestPhoneLeaseRenewsAtItsAgeAndLapses(t *testing.T) {
	world := newTestApproverWorld(t)
	leaser := newTestApprovalPhoneLeaser()
	phone, _, _ := newTestApprovalPhone(t, world, leaser)
	clock := world.sidecar.clock.(*identityTestClock)
	settings := world.sidecar.settings.Mcp

	leaser.refuse = true
	if resynced, err := phone.Resync(t.Context()); err != nil || resynced.LeasesTaken != 0 || len(resynced.Leased) != 0 {
		t.Fatalf("a refused lease: %+v, %v", resynced, err)
	}
	leaser.refuse = false
	if resynced, err := phone.Resync(t.Context()); err != nil || resynced.LeasesTaken != 1 {
		t.Fatalf("the lease taken at the next resync: %+v, %v", resynced, err)
	}
	clock.advance(settings.ApprovalPhoneLeaseRenewAge - time.Minute)
	if resynced, err := phone.Resync(t.Context()); err != nil || resynced.LeasesRenewed != 0 || len(resynced.Due) != 0 {
		t.Fatalf("a young lease: %+v, %v", resynced, err)
	}
	clock.advance(time.Minute)
	resynced, err := phone.Resync(t.Context())
	if err != nil || resynced.LeasesRenewed != 1 || len(resynced.Due) != 0 {
		t.Fatalf("a lease at its renewal age: %+v, %v", resynced, err)
	}
	if calls, live, releases := leaser.counts(world.vaultId); calls != 2 || live != 1 || releases != 1 {
		t.Fatalf("leases taken %d, live %d, released %d", calls, live, releases)
	}
	clock.advance(settings.ApprovalPhoneLeaseExpiry)
	if resynced, err := phone.Resync(t.Context()); err != nil || resynced.LeasesRenewed != 1 || !slices.Equal(resynced.Due, []Id{world.vaultId}) {
		t.Fatalf("a lapsed lease: %+v, %v", resynced, err)
	}
}

// Close releases nothing, so evs keeps the lease and a closed app is still woken; the closed part neither resyncs nor
// cues the host, and the next process's part takes the lease again.
func TestPhoneCloseReleasesNothing(t *testing.T) {
	world := newTestApproverWorld(t)
	leaser := newTestApprovalPhoneLeaser()
	phone, _, hints := newTestApprovalPhone(t, world, leaser)
	if _, err := phone.Resync(t.Context()); err != nil {
		t.Fatal(err)
	}
	phone.Close()
	if calls, live, releases := leaser.counts(world.vaultId); calls != 1 || live != 1 || releases != 0 {
		t.Fatalf("after Close: leases taken %d, live %d, released %d", calls, live, releases)
	}
	leaser.commit(world.vaultId)
	if *hints != 0 {
		t.Errorf("a closed part cued the host %d times", *hints)
	}
	if _, err := phone.Resync(t.Context()); !errors.Is(err, ErrApprovalPhoneClosed) {
		t.Errorf("a closed part resynced: %v", err)
	}
	if world.sidecar.ApprovalPhone() != nil {
		t.Error("the sidecar still holds a closed part")
	}
	next, err := world.sidecar.BindApprovalPhone(&ApprovalPhoneArgs{Leaser: leaser, Logs: func() ([]Id, error) { return []Id{world.vaultId}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if resynced, err := next.Resync(t.Context()); err != nil || resynced.LeasesTaken != 1 {
		t.Fatalf("the next process's part: %+v, %v", resynced, err)
	}
}

// A device that is no approval-capable device of its member, a page Worker here, leases no approval log and raises
// nothing; one that becomes one releases what it held.
func TestNonCapablePhoneLeasesNothing(t *testing.T) {
	world := newTestApproverWorld(t)
	leaser := newTestApprovalPhoneLeaser()
	phone, events, _ := newTestApprovalPhone(t, world, leaser)
	world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	if resynced, err := phone.Resync(t.Context()); err != nil || len(resynced.Leased) != 1 || len(resynced.Raised) != 1 {
		t.Fatalf("the consented phone: %+v, %v", resynced, err)
	}
	identity := world.sidecar.currentIdentity()
	world.authority.stateLock.Lock()
	world.authority.sidecars[identity.SidecarId].Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	world.authority.stateLock.Unlock()
	resynced, err := phone.Resync(t.Context())
	if err != nil || len(resynced.Leased) != 0 || resynced.LeasesReleased != 1 || len(resynced.Pending) != 0 || len(resynced.Raised) != 0 {
		t.Fatalf("a read_only device: %+v, %v", resynced, err)
	}
	if count := len(events.of(SidecarEventApprovalPending)); count != 1 {
		t.Errorf("%d approval_pending events", count)
	}
}
