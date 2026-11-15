package sidecar

// CORE-M6-04: §7.10's cleanup on an admin device. Most tests run on a real log (testConfigClientWorld): this Sidecar is
// the owner's second device there, installs its ConfigClient's authority, reads config_admissions from a scripted GET
// /sidecar/limits, and posts what it signs to the net, which judges and sequences it. From 90% of the cap the device
// raises admissions_near_cap with one cleanup item; the list shows each member's page Workers but its newest, oldest
// first, each with its admission time from the rows and its leaf's last change from the group view; a revoke signs
// SidecarRevoke{removed} of exactly what was shown, and refuses as stale a list it did not show; below 90% the item
// closes. A last test, on the act authority, puts the whole revoke under one presence check.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// GET /sidecar/limits and POST /network/config/delta as the cleanup tests script them: the limits answer
// config_admissions at admissionCap, and each posted statement is sequenced on the world's net and served.
type testCleanupApi struct {
	world *testConfigClientWorld

	stateLock    sync.Mutex
	admissionCap int64
	// whether the limits route answers at all
	limitsDown  bool
	limitsReads int
	posts       [][]byte
}

func (self *testCleanupApi) RoundTrip(request *http.Request) (*http.Response, error) {
	respond := func(status int, value any) *http.Response {
		encoded, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(encoded)), Header: http.Header{"Content-Type": {"application/json"}}, Request: request}
	}
	switch {
	case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/sidecar/limits"):
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.limitsReads += 1
		if self.limitsDown {
			return nil, errors.New("api is unreachable")
		}
		return respond(http.StatusOK, map[string]any{"tier": "team", "limits": map[string]int64{sidecarAdmissionsLimitKey: self.admissionCap}}), nil
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/network/config/delta"):
		body, err := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil {
			return nil, err
		}
		wire := &sidecarConfigDeltaWire{}
		if err := json.Unmarshal(body, wire); err != nil {
			return nil, err
		}
		self.stateLock.Lock()
		self.posts = append(self.posts, wire.Signed)
		self.stateLock.Unlock()
		net := self.world.net
		verdict := net.push(net.makeEntry(bridge.AuthEntryKindStatement, wire.Signed))
		self.world.publish()
		if !verdict.Accepted() {
			return respond(http.StatusForbidden, map[string]any{"error": "The statement fails at the tip.", "code": "config_refused"}), nil
		}
		return respond(http.StatusOK, &sidecarConfigPinReply{N: verdict.Pin.GetVersion(), Chain: verdict.Pin.GetChain()}), nil
	}
	return respond(http.StatusNotFound, map[string]any{"error": "no such route"}), nil
}

// Each statement posted so far, decoded.
func (self *testCleanupApi) postedSigned(t *testing.T) []*bridge.Signed {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	signed := []*bridge.Signed{}
	for _, posted := range self.posts {
		decoded := &bridge.Signed{}
		if err := proto.Unmarshal(posted, decoded); err != nil {
			t.Fatal(err)
		}
		signed = append(signed, decoded)
	}
	return signed
}

func (self *testCleanupApi) postCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.posts)
}

// The world: the net, the client this Sidecar follows it by, and this Sidecar as the owner's second device.
type testCleanupWorld struct {
	t       *testing.T
	world   *testConfigClientWorld
	net     *testConfigNet
	client  *ConfigClient
	sidecar *Sidecar
	api     *testCleanupApi
	events  *alarmTestEvents
	// this Sidecar as the net names it
	device testConfigDevice
}

// A Sidecar whose identity is sidecarId in networkId, enrolled and Offline, so the device calls run.
func newTestCleanupSidecar(t *testing.T, networkId Id, sidecarId Id) *Sidecar {
	t.Helper()
	binding := testBindingFields()
	binding.NetworkId = networkId
	binding.SidecarId = sidecarId
	_, secrets := newIdentityTestSecrets(t, networkId)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedBinding, err := NewSidecarIdentityBinding(binding, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	settings := cheapKeychainSettings()
	// background reads of the cap race nothing here: each test reads it when it means to
	settings.Alarms.AdmissionCapTimeout = 0
	settings.StatementTimeout = time.Hour
	sidecar := newSidecarBase(nil, settings)
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled}) {
		t.Fatal("no move to unenrolled")
	}
	if err := sidecar.adoptIdentity(secrets); err != nil {
		t.Fatal(err)
	}
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1}) {
		t.Fatal("no move to offline")
	}
	return sidecar
}

// The world at admissionCap: the owner's genesis device admits this Sidecar, the owner's member holding the AdminSet's
// one seat, so this device is an admin's. Its authority is installed once the client stands, and setup, which runs on
// the net before, has its entries delivered to no callback, as a device's first read of a log does.
func newTestCleanupWorld(t *testing.T, admissionCap int64, setup func(world *testCleanupWorld)) *testCleanupWorld {
	t.Helper()
	configWorld := newTestConfigClientWorld(t)
	net := configWorld.net
	self := &testCleanupWorld{
		t:      t,
		world:  configWorld,
		net:    net,
		api:    &testCleanupApi{world: configWorld, admissionCap: admissionCap},
		events: &alarmTestEvents{},
		// its key only shapes the admission, which then names the Sidecar's own identity key
		device: net.device("cleanup admin device", net.ownerMemberId),
	}
	self.sidecar = newTestCleanupSidecar(t, net.networkId, self.device.sidecarId)
	self.sidecar.clock = &identityTestClock{current: time.UnixMilli(net.timeMs).UTC()}
	api, err := newSidecarApi(self.sidecar.settings, self.api, self.sidecar.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt("a-synthetic-client-token-for-the-cleanup-tests")
	self.sidecar.sidecarApi = api
	admit := net.admission(self.device, nil, false, 0, 0)
	admit.IdentityPublicKey = bytes.Clone(self.sidecar.currentIdentity().IdentityPublicKey)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
	if setup != nil {
		setup(self)
	}
	self.client = configWorld.client(nil)
	self.catchUp()
	t.Cleanup(self.sidecar.InstallAuthority(self.client.Authority()))
	t.Cleanup(self.sidecar.AddEventCallback(self.events.add))
	return self
}

// Serves what the net sequenced and waits for the client, and so the watcher, to have applied it.
func (self *testCleanupWorld) catchUp() *ConfigState {
	self.t.Helper()
	self.world.publish()
	return self.world.caughtUp(self.client)
}

// The open cleanup items PendingApprovals lists.
func (self *testCleanupWorld) cleanupItems() []*SidecarApprovalItem {
	self.t.Helper()
	items, err := self.sidecar.PendingApprovals()
	if err != nil {
		self.t.Fatal(err)
	}
	return slices.DeleteFunc(items, func(item *SidecarApprovalItem) bool { return item.Kind != SidecarApprovalCleanup })
}

// The one open cleanup item, failing the test unless there is exactly one.
func (self *testCleanupWorld) cleanupItem() *SidecarApprovalItem {
	self.t.Helper()
	items := self.cleanupItems()
	if len(items) != 1 {
		self.t.Fatalf("%d open cleanup items", len(items))
	}
	return items[0]
}

// Reads the cap now, failing the test on an error.
func (self *testCleanupWorld) refreshCap() {
	self.t.Helper()
	if _, err := self.sidecar.RefreshAdmissionCap(context.Background()); err != nil {
		self.t.Fatal(err)
	}
}

// A member outside the AdminSet with its consented laptop and count page Workers, the laptop admitting each; the
// member, its laptop, and its Workers with their admission positions, oldest first.
func (self *testCleanupWorld) memberWithWorkers(label string, count int) (Id, testConfigDevice, []testConfigDevice, []uint64) {
	self.t.Helper()
	memberId, laptop := self.net.consentedMember(label)
	workers, positions := []testConfigDevice{}, []uint64{}
	for i := 0; i < count; i += 1 {
		worker, at := self.net.admitWorker(laptop, label+" worker "+string(rune('a'+i)), memberId)
		workers = append(workers, worker)
		positions = append(positions, at)
	}
	return memberId, laptop, workers, positions
}

// A Worker as the list shows it: its admission position and that entry's time, api's, from the rows.
func (self *testCleanupWorld) listed(worker testConfigDevice, admittedAt uint64) SidecarCleanupWorker {
	self.t.Helper()
	return SidecarCleanupWorker{
		SidecarId:    worker.sidecarId,
		AdmittedAt:   admittedAt,
		AdmittedTime: time.UnixMilli(self.net.entryTimeMs(admittedAt)).UTC(),
		Signatures:   1,
	}
}

// Whether device stands admitted at the net's tip.
func (self *testCleanupWorld) admitted(device testConfigDevice) bool {
	row := self.net.log.State().SidecarRow(device.sidecarId)
	return row != nil && row.GetRevokedAt() == 0
}

// From 90% of config_admissions the admin device lists, per member in id order, its page Workers but its newest, oldest
// first, each with its admission position and its entry's time from the rows, never this device's clock, and its
// leaf's last change where a group of this device shows one; a member with one Worker is left out. The revoke signs
// SidecarRevoke{removed} of exactly those, one statement each in the list's order, all landing, and the newest Worker of
// each member stands.
func TestCleanupListsAllButNewest(t *testing.T) {
	var memberM, memberN Id
	var laptopN testConfigDevice
	var workersM, workersN, workersO []testConfigDevice
	var atM, atN []uint64
	world := newTestCleanupWorld(t, 12, func(world *testCleanupWorld) {
		memberM, _, workersM, atM = world.memberWithWorkers("m", 3)
		memberN, laptopN, workersN, atN = world.memberWithWorkers("n", 1)
		_, _, workersO, _ = world.memberWithWorkers("o", 1)
	})
	// a group of this device shows one of m's Workers' leaves
	view := newTestStaleGroupView()
	groupId := NewId()
	view.set(groupId, workersM[0].sidecarId, SidecarStaleLeafLive, true)
	t.Cleanup(world.sidecar.InstallStaleGroupView(view))
	world.refreshCap()
	if count := world.net.log.State().AdmissionCount(); count != 10 || 0 < len(world.cleanupItems()) {
		t.Fatalf("count %d before n's second Worker", count)
	}
	// n's second Worker, applied by the watcher, takes the count to 11 of 12: past 90%
	newestN, _ := world.net.admitWorker(laptopN, "n worker b", memberN)
	world.catchUp()
	if count := world.net.log.State().AdmissionCount(); count != 11 {
		t.Fatalf("count %d", count)
	}

	if raised := world.events.of(SidecarEventAdmissionsNearCap); len(raised) != 1 || raised[0].ApprovalId == nil {
		t.Fatalf("admissions_near_cap raised %d times: %+v", len(raised), raised)
	}
	item := world.cleanupItem()
	if !slices.Equal(item.Decisions, []string{SidecarDecisionRevoke, SidecarDecisionDeny}) {
		t.Fatalf("decisions %v", item.Decisions)
	}
	list, err := world.sidecar.PreviewCleanup(context.Background(), item.ApprovalId)
	if err != nil {
		t.Fatal(err)
	}
	firstM := world.listed(workersM[0], atM[0])
	firstM.LastChange = time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC)
	want := []SidecarCleanupMember{
		{MemberId: memberM, Workers: []SidecarCleanupWorker{firstM, world.listed(workersM[1], atM[1])}},
		{MemberId: memberN, Workers: []SidecarCleanupWorker{world.listed(workersN[0], atN[0])}},
	}
	slices.SortFunc(want, func(a SidecarCleanupMember, b SidecarCleanupMember) int { return a.MemberId.Cmp(b.MemberId) })
	if !testCleanupMembersEqual(list.Members, want) {
		t.Fatalf("listed %+v, want %+v", list.Members, want)
	}
	if list.AdmissionCount != 11 || list.AdmissionCap != 12 || list.Presence {
		t.Fatalf("count %d of %d, presence %t", list.AdmissionCount, list.AdmissionCap, list.Presence)
	}
	// the times are the entries', which this device's clock is not
	for _, member := range list.Members {
		for _, worker := range member.Workers {
			if worker.AdmittedTime.Equal(world.sidecar.clock.Now()) {
				t.Fatal("a Worker's admission time is this device's clock")
			}
		}
	}

	revocation, err := world.sidecar.RevokeCleanup(context.Background(), item.ApprovalId, SidecarActConfirmed, nil)
	if err != nil {
		t.Fatal(err)
	}
	world.catchUp()
	wantRevoked := []Id{}
	for _, member := range want {
		for _, worker := range member.Workers {
			wantRevoked = append(wantRevoked, worker.SidecarId)
		}
	}
	if !slices.Equal(revocation.Revoked, wantRevoked) || len(revocation.Proposals) != 0 || revocation.Pending {
		t.Fatalf("revoked %v, want %v; proposals %v", revocation.Revoked, wantRevoked, revocation.Proposals)
	}
	posted := world.api.postedSigned(t)
	if len(posted) != len(wantRevoked) {
		t.Fatalf("%d statements posted", len(posted))
	}
	for i, signed := range posted {
		revoke := &bridge.SidecarRevoke{}
		if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || proto.Unmarshal(signed.GetBody(), revoke) != nil ||
			!bytes.Equal(revoke.GetSidecarId(), wantRevoked[i].Bytes()) || revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED ||
			signed.GetWebauthn() != nil {
			t.Fatalf("statement %d: type %d, %+v", i, signed.GetType(), revoke)
		}
	}
	for _, worker := range []testConfigDevice{workersM[0], workersM[1], workersN[0]} {
		if world.admitted(worker) {
			t.Errorf("a listed Worker stands after the revoke")
		}
	}
	for _, worker := range []testConfigDevice{workersM[2], newestN, workersO[0]} {
		if !world.admitted(worker) {
			t.Errorf("a member's newest or only Worker was revoked")
		}
	}
	world.net.everyReaderAgrees()
}

// Whether two lists name the same members and Workers with the same facts.
func testCleanupMembersEqual(a []SidecarCleanupMember, b []SidecarCleanupMember) bool {
	return slices.EqualFunc(a, b, func(x SidecarCleanupMember, y SidecarCleanupMember) bool {
		return x.MemberId == y.MemberId && slices.EqualFunc(x.Workers, y.Workers, func(v SidecarCleanupWorker, w SidecarCleanupWorker) bool {
			return v.SidecarId == w.SidecarId && v.AdmittedAt == w.AdmittedAt && v.AdmittedTime.Equal(w.AdmittedTime) &&
				v.LastChange.Equal(w.LastChange) && v.Signatures == w.Signatures
		})
	})
}

// Below 90% of the cap nothing is raised and no item opens, whatever the count was before the cap was read; at 90%
// one item opens; a deny dismisses it until the count rises, which opens a new one; once the revoke takes the count
// below 90% the item closes and its preview answers unknown, and a rise past 90% again raises again.
func TestCleanupClearsBelowNinetyPercent(t *testing.T) {
	var memberM Id
	var laptopM testConfigDevice
	world := newTestCleanupWorld(t, 10, func(world *testCleanupWorld) {
		memberM, laptopM = world.net.consentedMember("m")
		world.net.admitWorker(laptopM, "m worker a", memberM)
		world.net.admitWorker(laptopM, "m worker b", memberM)
	})
	// 6 of 10 once m's third Worker lands
	world.refreshCap()
	world.net.admitWorker(laptopM, "m worker c", memberM)
	world.catchUp()
	if count := world.net.log.State().AdmissionCount(); count != 6 {
		t.Fatalf("count %d", count)
	}
	if raised := world.events.of(SidecarEventAdmissionsNearCap); len(raised) != 0 || len(world.cleanupItems()) != 0 {
		t.Fatal("raised below 90%")
	}
	// 9 of 10: one item
	for _, label := range []string{"m worker d", "m worker e", "m worker f"} {
		world.net.admitWorker(laptopM, label, memberM)
	}
	world.catchUp()
	if raised := world.events.of(SidecarEventAdmissionsNearCap); len(raised) != 1 {
		t.Fatalf("%d raised at 9 of 10", len(raised))
	}
	first := world.cleanupItem()
	// deny dismisses it, signing nothing, and nothing reopens at the same count
	if err := world.sidecar.DecideApproval(context.Background(), first.ApprovalId, SidecarDecisionDeny, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	world.refreshCap()
	if len(world.cleanupItems()) != 0 || world.api.postCount() != 0 {
		t.Fatal("a dismissed item reopened at the same count, or a deny signed")
	}
	// a rise past it raises again with a new item
	world.net.admitWorker(laptopM, "m worker g", memberM)
	world.catchUp()
	second := world.cleanupItem()
	if second.ApprovalId == first.ApprovalId || len(world.events.of(SidecarEventAdmissionsNearCap)) != 2 {
		t.Fatal("the rise to 10 did not raise a new item")
	}
	list, err := world.sidecar.PreviewCleanup(context.Background(), second.ApprovalId)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Members) != 1 || len(list.Members[0].Workers) != 6 {
		t.Fatalf("listed %+v", list.Members)
	}
	if err := world.sidecar.DecideApproval(context.Background(), second.ApprovalId, SidecarDecisionRevoke, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	world.catchUp()
	if count := world.net.log.State().AdmissionCount(); count != 4 {
		t.Fatalf("count %d after the revoke", count)
	}
	if len(world.cleanupItems()) != 0 {
		t.Fatal("an item stays open below 90%")
	}
	if _, err := world.sidecar.PreviewCleanup(context.Background(), second.ApprovalId); !errors.Is(err, ErrSidecarApprovalUnknown) {
		t.Fatalf("a closed item's preview: %v", err)
	}
	// back at 90%: raised again
	for _, label := range []string{"m worker h", "m worker i", "m worker j", "m worker k", "m worker l"} {
		world.net.admitWorker(laptopM, label, memberM)
	}
	world.catchUp()
	if len(world.events.of(SidecarEventAdmissionsNearCap)) != 3 || len(world.cleanupItems()) != 1 {
		t.Fatal("back at 9 of 10 nothing was raised")
	}
}

// A revoke signs only the list this device showed for the item: with none shown, and after a Worker admitted since
// changes it, it answers ErrSidecarCleanupStale with nothing posted and the item open; shown again, it signs what it
// lists then. A cap api cannot read now falls back to the one read before.
func TestCleanupRevokeSignsOnlyTheListShown(t *testing.T) {
	var memberM Id
	var laptopM testConfigDevice
	world := newTestCleanupWorld(t, 10, func(world *testCleanupWorld) {
		memberM, laptopM = world.net.consentedMember("m")
		for _, label := range []string{"m worker a", "m worker b", "m worker c", "m worker d", "m worker e"} {
			world.net.admitWorker(laptopM, label, memberM)
		}
	})
	world.refreshCap()
	world.net.admitWorker(laptopM, "m worker f", memberM)
	world.catchUp()
	item := world.cleanupItem()
	ctx := context.Background()
	if _, err := world.sidecar.RevokeCleanup(ctx, item.ApprovalId, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarCleanupStale) {
		t.Fatalf("a list never shown: %v", err)
	}
	if err := world.sidecar.DecideApproval(ctx, item.ApprovalId, SidecarDecisionRevoke, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarCleanupStale) {
		t.Fatalf("a decision on a list never shown: %v", err)
	}
	shown, err := world.sidecar.PreviewCleanup(ctx, item.ApprovalId)
	if err != nil {
		t.Fatal(err)
	}
	// another Worker lands: the shown list's newest is listed now
	world.net.admitWorker(laptopM, "m worker g", memberM)
	world.catchUp()
	if _, err := world.sidecar.RevokeCleanup(ctx, item.ApprovalId, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarCleanupStale) {
		t.Fatalf("a list that changed: %v", err)
	}
	if world.api.postCount() != 0 || world.cleanupItem().ApprovalId != item.ApprovalId {
		t.Fatal("a stale revoke posted, or closed the item")
	}
	// api down: the preview and the revoke read the cap read before
	world.api.stateLock.Lock()
	world.api.limitsDown = true
	world.api.stateLock.Unlock()
	again, err := world.sidecar.PreviewCleanup(ctx, item.ApprovalId)
	if err != nil {
		t.Fatal(err)
	}
	if again.ListId == shown.ListId || len(shown.Members[0].Workers) != 5 || len(again.Members) != 1 || len(again.Members[0].Workers) != 6 ||
		again.AdmissionCap != 10 {
		t.Fatalf("shown again: %+v", again)
	}
	revocation, err := world.sidecar.RevokeCleanup(ctx, item.ApprovalId, SidecarActConfirmed, nil)
	if err != nil || len(revocation.Revoked) != 6 || revocation.ListId != again.ListId {
		t.Fatalf("the revoke of the list shown again: %v %+v", err, revocation)
	}
	world.catchUp()
	if world.api.postCount() != 6 || len(world.cleanupItems()) != 0 {
		t.Fatalf("%d posted", world.api.postCount())
	}
}

// The revoke is a person's confirmation on an admin's approval-capable device alone: MCP, a hook and an unconfirmed
// control call are refused with nothing posted, and a device of a member outside the AdminSet, or a read-only one, may
// only dismiss the item.
func TestCleanupRevokeOnlyAnAdminsConfirmation(t *testing.T) {
	var memberM Id
	var laptopM testConfigDevice
	world := newTestCleanupWorld(t, 10, func(world *testCleanupWorld) {
		memberM, laptopM = world.net.consentedMember("m")
		for _, label := range []string{"m worker a", "m worker b", "m worker c", "m worker d", "m worker e"} {
			world.net.admitWorker(laptopM, label, memberM)
		}
	})
	world.refreshCap()
	world.net.admitWorker(laptopM, "m worker f", memberM)
	world.catchUp()
	item := world.cleanupItem()
	ctx := context.Background()
	if _, err := world.sidecar.PreviewCleanup(ctx, item.ApprovalId); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if _, err := world.sidecar.RevokeCleanup(ctx, item.ApprovalId, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("RevokeCleanup from origin %d: %v", origin, err)
		}
		if err := world.sidecar.DecideApproval(ctx, item.ApprovalId, SidecarDecisionRevoke, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("DecideApproval from origin %d: %v", origin, err)
		}
	}
	if world.api.postCount() != 0 {
		t.Fatal("a refused origin posted")
	}

	// the same item as a device of m, outside the AdminSet, and a read-only device of the owner would hold it
	for name, capabilities := range map[string]uint32{"a member's device": 0, "a read-only device": testConfigReadOnly} {
		memberId := world.net.ownerMemberId
		signer := world.net.owner
		if name == "a member's device" {
			memberId, signer = memberM, laptopM
		}
		other := newTestCleanupSidecar(t, world.net.networkId, testConfigId("cleanup "+name))
		admit := world.net.admission(world.net.device("cleanup "+name, memberId), nil, false, 0, capabilities)
		admit.IdentityPublicKey = bytes.Clone(other.currentIdentity().IdentityPublicKey)
		world.net.mustPost(signer, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
		world.catchUp()
		t.Cleanup(other.InstallAuthority(world.client.Authority()))
		// an entry the watcher applies, so it knows the AdminSet
		world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, world.net.memberAdmitStatement("later "+name))
		world.catchUp()
		record := &sidecarApprovalRecord{ItemId: item.ApprovalId, Kind: SidecarApprovalCleanup, Position: item.Position}
		if decisions := sidecarCleanupEligible(other, world.client.Authority(), record); !slices.Equal(decisions, []string{SidecarDecisionDeny}) {
			t.Errorf("%s may answer %v", name, decisions)
		}
	}
}

// An authority as the act tests fake it, which also answers the page Workers and a revocation's signatures: a fixed
// cleanup list, so the act's presence rule is the test's to set.
type testCleanupActAuthority struct {
	*testActAuthority
	members []ConfigCleanupMember
	count   int
}

func (self *testCleanupActAuthority) PageWorkers(memberId Id) []ConfigPageWorker {
	return nil
}

func (self *testCleanupActAuthority) AdmissionCount() int {
	return self.count
}

func (self *testCleanupActAuthority) CleanupList(admissionCap int) []ConfigCleanupMember {
	if !configAdmissionsNearCap(self.count, admissionCap) {
		return nil
	}
	return self.members
}

func (self *testCleanupActAuthority) ApprovalCapable(sidecarId Id) bool {
	return true
}

func (self *testCleanupActAuthority) Suspended(sidecarId Id) bool {
	return false
}

func (self *testCleanupActAuthority) RevokeSignatures(targetId Id) int {
	return 1
}

func (self *testCleanupActAuthority) RegisteredKeys(sidecarId Id) []*bridge.KeyRow {
	return nil
}

func (self *testCleanupActAuthority) EntryTime(n uint64) (time.Time, bool) {
	return time.Time{}, false
}

// With a live presence key the log covers a revocation by, the whole revoke asks one presence check, every statement
// carrying that check's countersignature; a refused check, and none given, sign and post nothing, the item staying
// open.
func TestCleanupRevokeTakesOnePresenceCheck(t *testing.T) {
	sidecar, base, deltaApi := newActTestSidecar(t)
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1}) {
		t.Fatal("no move to offline")
	}
	identity := sidecar.currentIdentity()
	memberId, otherId := NewId(), NewId()
	authority := &testCleanupActAuthority{testActAuthority: base, count: 9}
	workers := []ConfigPageWorker{{SidecarId: NewId(), AdmittedAt: 3}, {SidecarId: NewId(), AdmittedAt: 5}}
	authority.members = []ConfigCleanupMember{{MemberId: otherId, Workers: workers}}
	base.stateLock.Lock()
	base.sidecars[identity.SidecarId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: identity.SidecarId.Bytes(), MemberId: memberId.Bytes(), AdmittedAt: 1}, MemberId: memberId}
	base.consents[[2]Id{identity.SidecarId, memberId}] = true
	base.stateLock.Unlock()
	key, keyId := addTestPresenceKey(t, base)
	base.stateLock.Lock()
	base.covered[bridge.SignedType_SIGNED_SIDECAR_REVOKE] = true
	base.stateLock.Unlock()
	t.Cleanup(sidecar.InstallAuthority(authority))
	sidecar.settings.Alarms.AdmissionCapTimeout = 0
	limits := &testCleanupLimitsApi{deltaApi: deltaApi, admissionCap: 10}
	api, err := newSidecarApi(sidecar.settings, limits, sidecar.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt("a-synthetic-client-token-for-the-cleanup-tests")
	sidecar.sidecarApi = api
	// an entry naming this device's member in the AdminSet, at 9 of 10
	if _, err := sidecar.RefreshAdmissionCap(context.Background()); err != nil {
		t.Fatal(err)
	}
	chain := bytes.Repeat([]byte{0x07}, 32)
	base.apply(&SidecarAuthorityEntry{Pin: &bridge.AuthPin{Version: 41, Chain: chain}, AdmissionCount: 9, AdminMemberIds: []Id{memberId}})

	items, err := sidecar.PendingApprovals()
	if err != nil || len(items) != 1 || items[0].Kind != SidecarApprovalCleanup {
		t.Fatalf("items %v %v", items, err)
	}
	approvalId := items[0].ApprovalId
	ctx := context.Background()
	list, err := sidecar.PreviewCleanup(ctx, approvalId)
	if err != nil || !list.Presence || len(list.Members) != 1 || len(list.Members[0].Workers) != 2 {
		t.Fatalf("the list: %v %+v", err, list)
	}
	if _, err := sidecar.RevokeCleanup(ctx, approvalId, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarActPresence) {
		t.Fatalf("no check given: %v", err)
	}
	refused := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		return nil, errors.New("the person refused")
	}
	if _, err := sidecar.RevokeCleanup(ctx, approvalId, SidecarActConfirmed, refused); !errors.Is(err, ErrSidecarActPresence) {
		t.Fatalf("a refused check: %v", err)
	}
	if 0 < len(deltaApi.postsSoFar()) {
		t.Fatal("a revoke with no passing check posted")
	}
	checks := 0
	seen := []byte{}
	check := testPresenceCheck(t, key, keyId, &seen)
	counted := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		checks += 1
		return check(countersignedBytes)
	}
	revocation, err := sidecar.RevokeCleanup(ctx, approvalId, SidecarActConfirmed, counted)
	if err != nil || len(revocation.Revoked) != 2 {
		t.Fatalf("the revoke: %v %+v", err, revocation)
	}
	posts := deltaApi.postsSoFar()
	if checks != 1 || len(posts) != 2 {
		t.Fatalf("%d checks, %d posts", checks, len(posts))
	}
	for i, posted := range posts {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(posted, signed); err != nil {
			t.Fatal(err)
		}
		revoke := &bridge.SidecarRevoke{}
		if signed.GetWebauthn() == nil || proto.Unmarshal(signed.GetBody(), revoke) != nil || !bytes.Equal(revoke.GetSidecarId(), workers[i].SidecarId.Bytes()) {
			t.Fatalf("post %d carries no countersignature, or revokes another Worker", i)
		}
	}
	if items, _ := sidecar.PendingApprovals(); 0 < len(items) {
		t.Fatal("the item stays open after its revoke signed")
	}
}

// The act tests' delta route, with GET /sidecar/limits answering config_admissions beside it.
type testCleanupLimitsApi struct {
	deltaApi     *testDeltaApi
	admissionCap int64
}

func (self *testCleanupLimitsApi) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/sidecar/limits") {
		encoded, _ := json.Marshal(map[string]any{"tier": "team", "limits": map[string]int64{sidecarAdmissionsLimitKey: self.admissionCap}})
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(encoded)), Header: http.Header{"Content-Type": {"application/json"}}, Request: request}, nil
	}
	return self.deltaApi.RoundTrip(request)
}

// An AdminSet member's Worker at k = 2 goes as an AuthorityProposal of its own, which the revoke answers by its
// proposal_id; another admin's cosign completes it, and the Worker is revoked.
func TestCleanupAdminSetMembersWorkerGoesAsProposal(t *testing.T) {
	var team *testConfigTeam
	var workerB testConfigDevice
	// 6 admissions before b's third Worker, 7 after: from 90% of 7
	world := newTestCleanupWorld(t, 7, func(world *testCleanupWorld) {
		// the team's AdminSet comes after this device's admission, while one signer still admits
		team = &testConfigTeam{testConfigNet: world.net}
		memberB, memberC := testConfigId("admin b"), testConfigId("admin c")
		world.net.admitMember(world.net.owner, memberB, bridge.MemberRole_MEMBER_ROLE_MEMBER)
		world.net.admitMember(world.net.owner, memberC, bridge.MemberRole_MEMBER_ROLE_MEMBER)
		team.adminB = world.net.device("admin b laptop", memberB)
		team.adminC = world.net.device("admin c laptop", memberC)
		world.net.admitDevice(world.net.owner, team.adminB, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		world.net.admitDevice(world.net.owner, team.adminC, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED))
		workerB, _ = world.net.admitWorker(team.adminB, "admin b worker a", memberB)
		world.net.admitWorker(team.adminB, "admin b worker b", memberB)
		world.net.mustPost(world.net.owner, bridge.SignedType_SIGNED_ADMIN_SET, team.adminSet(0))
	})
	if k, n := world.net.log.State().Threshold(); k != 2 || n != 3 {
		t.Fatalf("k %d of n %d", k, n)
	}
	world.refreshCap()
	// an AdminSet member's Worker at k = 2 is admitted by a proposal of its own: b's third takes the count to 7 of 7
	team.admitWorkerByProposal(team.adminB, team.adminC, "admin b worker c")
	world.catchUp()
	item := world.cleanupItem()
	ctx := context.Background()
	list, err := world.sidecar.PreviewCleanup(ctx, item.ApprovalId)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Members) != 1 || len(list.Members[0].Workers) != 2 || list.Members[0].Workers[0].Signatures != 2 {
		t.Fatalf("listed %+v", list.Members)
	}
	revocation, err := world.sidecar.RevokeCleanup(ctx, item.ApprovalId, SidecarActConfirmed, nil)
	if err != nil || len(revocation.Proposals) != 2 {
		t.Fatalf("the revoke: %v %+v", err, revocation)
	}
	world.catchUp()
	if !world.admitted(workerB) {
		t.Fatal("a proposal short of k revoked the Worker")
	}
	proposalId := revocation.Proposals[workerB.sidecarId]
	if verdict := team.cosign(team.adminC, proposalId); !verdict.Accepted() || !bytes.Equal(verdict.CompletedProposalId, proposalId) {
		t.Fatalf("the cosign: %v", verdict.Refusal)
	}
	if world.admitted(workerB) {
		t.Fatal("the Worker stands after the k-th signature")
	}
	posted := world.api.postedSigned(t)
	for _, signed := range posted {
		proposal := &protocol.AuthorityProposal{}
		if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL || proto.Unmarshal(signed.GetBody(), proposal) != nil ||
			proposal.GetStatementType() != uint32(bridge.SignedType_SIGNED_SIDECAR_REVOKE) {
			t.Fatalf("a statement that is no proposal of a revocation: type %d", signed.GetType())
		}
	}
}
