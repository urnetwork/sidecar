package fault

// FS-97's M4 cases (§22.8; §7.10's stale row and §22.7's stale rows, D-TEAM-29; TEAM-M4-01) on T2, run on CORE-M4-02's
// act: a personal network's owner re-enrolls a page Worker weekly for a year, and the owner's consented device, a
// running sidecar.Sidecar, admits each in an act that also revokes, as removed, each of the owner's Workers that §10.9
// removed as stale from every group the device is a leaf of that seated it, so the Workers it holds stop growing after
// 13 weeks; a Worker back by KF5's resync or KF2's re-add is never revoked, nor one no group of the device seated; a
// kill between an act's revocations and its admission lands each statement once after the restart; and a Worker that
// resyncs after the act's decision, or while the act waits on a retry, is not revoked. The cleanup list is the same at
// two devices at one pin.
//
// The world: the admission suite's network (sidecartest.AdmissionNet), every verifier of it compared after each entry,
// on the Net's FakeApi, where the owner's device enrolls and posts its acts as any sidecar does. The device's
// authority is the suite's reference state, read through fs97Authority as TEAM-M2-10's ConfigAuthority reads a
// follower's, since no host here runs a ConfigClient for the device. Its group view is sidecartest.FakeStaleGroupView
// until a host installs KEYS-M4-01's; the groups' calendar is a fake clock of its own that moves a week each
// re-enrollment and judges §10.9's 90 days plus the day a writer leaf waits past them. The Net's clock, which api and
// the sidecar read, does not move by weeks: the sidecar would then run a year of token refreshes and key upkeep that
// no part of this row is about, and nothing the log or the act decides here reads that clock beyond a statement's
// not_after.
//
// Team cases (self_admit off, an admin's device admitting another member's Worker, Workers past the config and
// directory groups' first 1,000, k = 2 proposals) are CORE-M6-04's and TEAM-M6-12's. These are plain T2 tests, not a
// Register'd builder: the plan places this row in a test file, which server's T3 run cannot import, so a gate sweep
// reports FS-97 missing until a non-test fs97.go holds the builder.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	// How long, in real time, one of these schedules may run before it fails: only a failure's bound, since every
	// wait is a call's or a monitor's.
	fs97Timeout = 5 * time.Minute
	// A week of the groups' calendar.
	fs97Week = 7 * 24 * time.Hour
	// §10.9: a leaf is due for its stale Remove stale_leaf_days (90) after its last change, and a writer leaf commits
	// one a day past that.
	fs97StaleAfter = 91 * 24 * time.Hour
)

// A page Worker's capability bits (§18.8).
const fs97ReadOnly = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)

// The owner's device's authority: the suite's reference state, answered as ConfigAuthority answers its follower's.
type fs97Authority struct {
	suite *sidecartest.AdmissionNet
}

var _ sidecar.SidecarAuthority = fs97Authority{}

func (self fs97Authority) Pin() *bridge.AuthPin {
	return self.suite.State().Pin()
}

// A copy of an admission, sharing nothing with the state.
func fs97CloneAdmission(admission *sidecar.AclSidecar) *sidecar.AclSidecar {
	if admission == nil {
		return nil
	}
	clone := *admission
	clone.TagIds = slices.Clone(admission.TagIds)
	if admission.Row != nil {
		clone.Row = proto.Clone(admission.Row).(*bridge.SidecarRow)
	}
	return &clone
}

func (self fs97Authority) Admission(sidecarId sidecar.Id) *sidecar.AclSidecar {
	return fs97CloneAdmission(self.suite.State().Sidecar(sidecarId))
}

func (self fs97Authority) MemberDevices(memberId sidecar.Id) []*sidecar.AclSidecar {
	state := self.suite.State()
	devices := []*sidecar.AclSidecar{}
	for _, sidecarId := range state.SidecarIds() {
		if admission := state.Sidecar(sidecarId); admission != nil && len(admission.TagIds) == 0 && admission.MemberId == memberId {
			devices = append(devices, fs97CloneAdmission(admission))
		}
	}
	return devices
}

func (self fs97Authority) Consented(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	acl, err := self.suite.State().Acl()
	return err == nil && acl.ConsentedFor(sidecarId, memberId)
}

func (self fs97Authority) CurrentBinding(memberId sidecar.Id) *bridge.RecoveryBindingRow {
	binding := self.suite.State().CurrentBinding(memberId)
	if binding == nil {
		return nil
	}
	return proto.Clone(binding).(*bridge.RecoveryBindingRow)
}

func (self fs97Authority) PresenceRequired(statement *sidecar.SidecarStatement) bool {
	return self.suite.State().PresenceRequired(statement)
}

func (self fs97Authority) LiveKeys(sidecarId sidecar.Id) []*bridge.KeyRow {
	keys := []*bridge.KeyRow{}
	for _, key := range self.suite.State().LiveKeys(sidecarId) {
		keys = append(keys, proto.Clone(key).(*bridge.KeyRow))
	}
	return keys
}

func (self fs97Authority) Cascade(targetId sidecar.Id, sinceN uint64) ([]sidecar.DeviceRevokeItem, error) {
	plan, err := self.suite.State().CascadePlan(targetId, sinceN)
	if err != nil {
		return nil, err
	}
	return plan.Items(), nil
}

// No retained entries are read here: nothing in this row revokes for a loss time.
func (self fs97Authority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	return 0, time.Time{}, false
}

// No entries are reported: the alarms this row does not test watch none.
func (self fs97Authority) AddEntryCallback(callback sidecar.SidecarAuthorityEntryFunction) func() {
	return func() {}
}

// One statement the log took: its position, type and signer, and the sidecar it admits or revokes.
type fs97Landed struct {
	n          uint64
	signedType bridge.SignedType
	signerId   sidecar.Id
	sidecarId  sidecar.Id
	reason     bridge.SidecarRevokeReason
}

// The world: the suite's network on the Net's api, the owner's device enrolled there and admitted, its group view, and
// the groups' calendar.
type fs97World struct {
	t      *testing.T
	ctx    context.Context
	net    *sidecartest.Net
	api    *sidecartest.FakeApi
	suite  *sidecartest.AdmissionNet
	device *sidecartest.TestSidecar
	view   *sidecartest.FakeStaleGroupView
	groups *sidecartest.FakeClock
	// the owner, whose Workers these are
	memberId sidecar.Id
	// the groups the device is a leaf of, each seating every Worker this world seats: a records repo's and the
	// config group
	groupIds []sidecar.Id
	epoch    uint64
}

func newFs97World(t *testing.T) *fs97World {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), fs97Timeout)
	t.Cleanup(cancel)
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	// the suite appends through the api the owner's device posts to, so both see one log
	tier.NewApi = func(clock sidecar.Clock, cluster sidecar.BlobCluster) sidecartest.AdmissionApi {
		return sidecartest.FakeApiAdmission(api)
	}
	settings := sidecartest.DefaultAdmissionSuiteSettings()
	settings.RowTimeout = fs97Timeout
	tier.Settings = settings
	suite := sidecartest.NewAdmissionNet(t, tier)
	t.Cleanup(suite.Close)

	device, err := net.AddSidecarIn("owner desktop", suite.NetworkId(), nil)
	if err != nil {
		t.Fatal(err)
	}
	identity := device.Sidecar().Identity()
	owner := suite.Owner()
	// the owner's first device admits its second, the owner's consented device by §8.5's scoped clause
	suite.MustLand(suite.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		Header:            suite.Header(),
		NetworkId:         suite.NetworkId().Bytes(),
		SidecarId:         identity.SidecarId.Bytes(),
		IdentityPublicKey: identity.IdentityPublicKey,
		IdentityAlg:       "ed25519",
		MemberId:          owner.MemberId.Bytes(),
	}))
	world := &fs97World{
		t:        t,
		ctx:      ctx,
		net:      net,
		api:      api,
		suite:    suite,
		device:   device,
		view:     sidecartest.NewFakeStaleGroupView(),
		groups:   sidecartest.NewFakeClock(net.Clock().Now()),
		memberId: owner.MemberId,
		groupIds: []sidecar.Id{suite.Id("records group"), suite.Id("config group")},
	}
	world.install()
	return world
}

// Installs the authority and the group view on the device's running Sidecar, as its host does at each start.
func (self *fs97World) install() {
	self.t.Helper()
	running := self.device.Sidecar()
	self.t.Cleanup(running.InstallAuthority(fs97Authority{suite: self.suite}))
	self.t.Cleanup(running.InstallStaleGroupView(self.view))
}

// Sets a Worker's leaf in every group the device is a leaf of.
func (self *fs97World) setLeaves(workerId sidecar.Id, state sidecar.SidecarStaleLeafState, lastChange time.Time) {
	self.epoch += 1
	for _, groupId := range self.groupIds {
		self.view.SetLeaf(groupId, workerId, self.epoch, state, true, lastChange)
	}
}

// The owner's device admits worker, a page Worker of the owner, by ur approve's path: the act that carries its stale
// revocations; then every verifier applies what landed. The act's error.
func (self *fs97World) admit(worker *sidecartest.AdmissionDevice) error {
	self.t.Helper()
	running := self.device.Sidecar()
	approvalId, err := running.OpenAdmission(&sidecar.SidecarAdmissionRequest{
		SidecarId:         worker.SidecarId,
		MemberId:          self.memberId,
		IdentityPublicKey: worker.PublicKey(),
		Capabilities:      fs97ReadOnly,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	err = running.DecideApproval(self.ctx, approvalId, sidecar.SidecarDecisionApprove, sidecar.SidecarActConfirmed, nil)
	self.suite.Sync()
	return err
}

// admit, failing the test unless the act lands, then the Worker seated live in each group from now.
func (self *fs97World) enroll(label string) *sidecartest.AdmissionDevice {
	self.t.Helper()
	worker := self.suite.Device(label, self.memberId)
	if err := self.admit(worker); err != nil {
		self.t.Fatalf("%s's admission: %v", label, err)
	}
	self.setLeaves(worker.SidecarId, sidecar.SidecarStaleLeafLive, self.groups.Now())
	return worker
}

// Every statement the log took after position after, in order, as api's store holds them, each judged by every
// verifier the suite runs.
func (self *fs97World) landedAfter(after uint64) []fs97Landed {
	self.t.Helper()
	landed := []fs97Landed{}
	for {
		read, err := self.api.ReadProjection(self.ctx, self.suite.NetworkId(), after, false)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, entryBytes := range read.Entries {
			entry := &bridge.AuthEntry{}
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				self.t.Fatal(err)
			}
			after = entry.GetN()
			if entry.GetKind() != bridge.AuthEntryKindStatement {
				continue
			}
			if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
				self.t.Fatal(err)
			}
			if verdict := self.suite.VerdictAt(entry.GetN()); !verdict.Accepted() {
				self.t.Fatalf("the entry at %d is refused: %v", entry.GetN(), verdict.Refusal)
			}
			statement := fs97Landed{n: entry.GetN(), signedType: bridge.SignedType(signed.GetType())}
			statement.signerId, _ = sidecar.IdFromBytes(signed.GetSignerId())
			switch statement.signedType {
			case bridge.SignedType_SIGNED_SIDECAR_ADMIT:
				admit := &protocol.SidecarAdmit{}
				if err := proto.Unmarshal(signed.GetBody(), admit); err != nil {
					self.t.Fatal(err)
				}
				statement.sidecarId, _ = sidecar.IdFromBytes(admit.GetSidecarId())
			case bridge.SignedType_SIGNED_SIDECAR_REVOKE:
				revoke := &bridge.SidecarRevoke{}
				if err := proto.Unmarshal(signed.GetBody(), revoke); err != nil {
					self.t.Fatal(err)
				}
				statement.sidecarId, _ = sidecar.IdFromBytes(revoke.GetSidecarId())
				statement.reason = revoke.GetReason()
			}
			landed = append(landed, statement)
		}
		if !read.More || len(read.Entries) == 0 {
			return landed
		}
	}
}

// Fails unless landed is the device's revocations, as removed, of exactly revokedIds in some order, then its admission
// of admittedId; or, for a zero admittedId, the revocations alone.
func (self *fs97World) requireAct(label string, landed []fs97Landed, revokedIds []sidecar.Id, admittedId sidecar.Id) {
	self.t.Helper()
	deviceId := self.device.Sidecar().Identity().SidecarId
	want := len(revokedIds)
	if admittedId != (sidecar.Id{}) {
		want += 1
	}
	if len(landed) != want {
		self.t.Fatalf("%s: the log took %d statements, want %d: %+v", label, len(landed), want, landed)
	}
	revoked := []sidecar.Id{}
	for _, statement := range landed[:len(revokedIds)] {
		if statement.signedType != bridge.SignedType_SIGNED_SIDECAR_REVOKE ||
			statement.reason != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED || statement.signerId != deviceId {
			self.t.Fatalf("%s: %+v where a revocation as removed by the owner's device goes", label, statement)
		}
		revoked = append(revoked, statement.sidecarId)
	}
	slices.SortFunc(revoked, sidecar.Id.Cmp)
	wantRevoked := slices.SortedFunc(slices.Values(revokedIds), sidecar.Id.Cmp)
	if !slices.Equal(revoked, wantRevoked) {
		self.t.Fatalf("%s: revoked %v, want %v", label, revoked, wantRevoked)
	}
	if admittedId != (sidecar.Id{}) {
		last := landed[len(landed)-1]
		if last.signedType != bridge.SignedType_SIGNED_SIDECAR_ADMIT || last.sidecarId != admittedId || last.signerId != deviceId {
			self.t.Fatalf("%s: last %+v, want the admission of %s", label, last, admittedId)
		}
	}
}

// The owner's page Workers in the suite's reference state, as ids.
func (self *fs97World) pageWorkerIds() []sidecar.Id {
	ids := []sidecar.Id{}
	for _, worker := range self.suite.State().PageWorkers(self.memberId) {
		ids = append(ids, worker.SidecarId)
	}
	return ids
}

// A second device's state at the tip: a rows-only reader of its own, walked from the genesis on what api serves.
func (self *fs97World) secondDevice() *sidecar.ConfigState {
	self.t.Helper()
	logSettings := sidecar.DefaultConfigLogSettings()
	logSettings.Log = sidecar.NewNoopLogger()
	var log *sidecar.ConfigLog
	rows := map[[32]byte][]byte{}
	source := sidecar.ConfigRowsOnlySource(func(networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
		found, ok := rows[[32]byte(rowsSha256)]
		if !ok {
			return nil, sidecar.ErrConfigRowsUnavailable
		}
		return found, nil
	})
	after := uint64(0)
	for {
		read, err := self.api.ReadProjection(self.ctx, self.suite.NetworkId(), after, true)
		if err != nil {
			self.t.Fatal(err)
		}
		if log == nil {
			if log, err = sidecar.NewConfigLogRowsOnly(logSettings, read.SignedGenesis); err != nil {
				self.t.Fatal(err)
			}
		}
		for rowsSha256, found := range read.Rows {
			rows[rowsSha256] = found
		}
		if _, err := log.ApplyRun(read.Entries, source); err != nil {
			self.t.Fatal(err)
		}
		if !read.More || len(read.Entries) == 0 {
			return log.State()
		}
		after = read.Tip.GetVersion()
	}
}

// One of the year's Workers: its device, the week it enrolled, its leaf's last change and whether the log revoked it.
type fs97Worker struct {
	device     *sidecartest.AdmissionDevice
	week       int
	lastChange time.Time
	revoked    bool
}

// FS-97's main case: a page Worker re-enrolled every week for a year. Each evicted Worker's leaf last changes at its
// eviction, the next week's enrollment, and §10.9 removes it as stale 91 days on: another member's leaf committed that
// Remove first for an odd week's Worker, while an even week's is due and the owner's device, a writer leaf, commits it
// itself after the person's confirmation and before the revocation posts. Each admission's act revokes, before it
// admits, exactly the Workers stale in every group that seated them, so the owner's admitted Workers stop growing at
// 14 after 13 weeks and stay there through a base mid-year, the count every verifier agrees on. At the year's end the
// cleanup list from 90% of the cap is each but the newest, oldest first, and the same at a second device at one pin.
func TestFs97WeeklyReEnrollmentForAYearStopsGrowingAfterThirteenWeeks(t *testing.T) {
	world := newFs97World(t)
	workers := []*fs97Worker{}
	counts := []int{}
	for week := range 52 {
		if 0 < week {
			world.groups.Advance(fs97Week)
			// this week's enrollment evicts last week's Worker: its leaf's last change
			evicted := workers[week-1]
			evicted.lastChange = world.groups.Now()
			world.setLeaves(evicted.device.SidecarId, sidecar.SidecarStaleLeafLive, evicted.lastChange)
		}
		wantRevoked := []sidecar.Id{}
		for _, worker := range workers {
			if worker.revoked || world.groups.Now().Sub(worker.lastChange) < fs97StaleAfter {
				continue
			}
			state := sidecar.SidecarStaleLeafRemoved
			if worker.week%2 == 0 {
				state = sidecar.SidecarStaleLeafDue
			}
			world.setLeaves(worker.device.SidecarId, state, worker.lastChange)
			wantRevoked = append(wantRevoked, worker.device.SidecarId)
		}

		tip := world.suite.Tip().GetVersion()
		worker := &fs97Worker{device: world.enroll(fmt.Sprintf("owner page worker %d", week)), week: week}
		worker.lastChange = world.groups.Now()
		workers = append(workers, worker)
		world.requireAct(fmt.Sprintf("week %d", week), world.landedAfter(tip), wantRevoked, worker.device.SidecarId)
		for _, other := range workers {
			if slices.Contains(wantRevoked, other.device.SidecarId) {
				other.revoked = true
			}
		}
		count := len(world.pageWorkerIds())
		if want := min(week+1, 14); count != want {
			t.Fatalf("week %d: %d page Workers, want %d", week, count, want)
		}
		counts = append(counts, count)
		if week == 26 {
			// a base mid-year: a new device and a gate start at it from rows alone, and agree from then on
			world.suite.Fold(true)
		}
	}
	if slices.Max(counts) != 14 || slices.Index(counts, 14) != 13 {
		t.Errorf("the admitted Workers by week: %v", counts)
	}

	// every due Remove the device committed: in each group, for each even week's revoked Worker, before its revocation
	commits := world.view.Commits()
	wantCommits := 0
	for _, worker := range workers {
		if worker.revoked && worker.week%2 == 0 {
			wantCommits += len(world.groupIds)
		}
	}
	if len(commits) != wantCommits {
		t.Errorf("%d stale Removes committed, want %d", len(commits), wantCommits)
	}

	state := world.suite.State()
	// the owner's two devices and fourteen Workers
	if count := state.AdmissionCount(); count != 16 {
		t.Fatalf("%d admissions", count)
	}
	list := sidecar.CleanupList(state, 17)
	if len(list) != 1 || list[0].MemberId != world.memberId || len(list[0].Workers) != 13 {
		t.Fatalf("the cleanup list %+v", list)
	}
	for i, listed := range list[0].Workers {
		if listed.SidecarId != workers[38+i].device.SidecarId {
			t.Errorf("listed %d: %s, want week %d's Worker", i, listed.SidecarId, 38+i)
		}
	}
	second := world.secondDevice()
	if !proto.Equal(second.Pin(), state.Pin()) {
		t.Fatalf("the second device stands at %v, the first at %v", second.Pin(), state.Pin())
	}
	if secondList := sidecar.CleanupList(second, 17); !slices.EqualFunc(secondList, list, func(a sidecar.ConfigCleanupMember, b sidecar.ConfigCleanupMember) bool {
		return a.MemberId == b.MemberId && slices.Equal(a.Workers, b.Workers)
	}) {
		t.Errorf("the second device lists %+v", secondList)
	}
	if below := sidecar.CleanupList(state, 18); len(below) != 0 {
		t.Errorf("below 90%% of the cap: %+v", below)
	}
	world.suite.CheckAgreement()
}

// A Worker back in its groups is never revoked: one that resynced by an external commit (KF5) holds its leaf in each
// again, and one a writer re-added by a late Add (KF2) holds one in a group again though another still shows it
// removed, so neither is stale in every group that seated it. Once each goes 91 days unchanged again, the next
// admission revokes both.
func TestFs97AWorkerBackByAResyncOrAReAddIsNeverRevoked(t *testing.T) {
	world := newFs97World(t)
	resynced := world.enroll("owner page worker resynced")
	readded := world.enroll("owner page worker re-added")
	world.groups.Advance(fs97StaleAfter)
	world.setLeaves(resynced.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	world.setLeaves(readded.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))

	world.setLeaves(resynced.SidecarId, sidecar.SidecarStaleLeafLive, world.groups.Now())
	world.view.SetLeaf(world.groupIds[0], readded.SidecarId, 99, sidecar.SidecarStaleLeafLive, true, world.groups.Now())
	tip := world.suite.Tip().GetVersion()
	next := world.enroll("owner page worker next")
	world.requireAct("after the resync and the re-add", world.landedAfter(tip), nil, next.SidecarId)

	world.groups.Advance(fs97StaleAfter)
	world.setLeaves(resynced.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	world.setLeaves(readded.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	tip = world.suite.Tip().GetVersion()
	last := world.enroll("owner page worker last")
	world.requireAct("91 days after", world.landedAfter(tip), []sidecar.Id{resynced.SidecarId, readded.SidecarId}, last.SidecarId)
	if ids := world.pageWorkerIds(); !slices.Equal(ids, []sidecar.Id{next.SidecarId, last.SidecarId}) {
		t.Errorf("page Workers %v", ids)
	}
}

// D-TEAM-29's "at least one": a Worker no group of the admitting device seated, such as one reading by wraps alone, is
// never revoked in an act, however old; the member's device offers it instead, which the log never sees.
func TestFs97AWorkerNoGroupOfTheDeviceSeatedIsNeverRevoked(t *testing.T) {
	world := newFs97World(t)
	unseated := world.suite.Device("owner page worker unseated", world.memberId)
	if err := world.admit(unseated); err != nil {
		t.Fatal(err)
	}
	world.groups.Advance(400 * 24 * time.Hour)
	tip := world.suite.Tip().GetVersion()
	next := world.enroll("owner page worker next")
	world.requireAct("400 days on", world.landedAfter(tip), nil, next.SidecarId)
	if ids := world.pageWorkerIds(); !slices.Contains(ids, unseated.SidecarId) {
		t.Errorf("page Workers %v", ids)
	}
}

// A kill between an act's revocations and its admission: the second revocation lands but its answer is lost, so the act
// stops there with the admission unposted; the daemon starts again from its durable state alone, re-checks each
// revocation and posts the same statements, and the log holds each once.
func TestFs97AKillBetweenTheRevocationsAndTheAdmissionLandsEachOnce(t *testing.T) {
	world := newFs97World(t)
	first := world.enroll("owner page worker 1")
	second := world.enroll("owner page worker 2")
	world.groups.Advance(fs97StaleAfter)
	world.setLeaves(first.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	world.setLeaves(second.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))

	tip := world.suite.Tip().GetVersion()
	if _, err := world.net.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpHttp, KeyPrefix: "/network/config/delta", Nth: 2, Result: sidecartest.ApplyThenDrop,
	}); err != nil {
		t.Fatal(err)
	}
	next := world.suite.Device("owner page worker 3", world.memberId)
	if err := world.admit(next); !errors.Is(err, sidecar.ErrSidecarActPending) {
		t.Fatalf("a lost answer: %v", err)
	}
	world.requireAct("before the kill", world.landedAfter(tip), []sidecar.Id{first.SidecarId, second.SidecarId}, sidecar.Id{})

	if err := world.device.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := world.device.AwaitState(world.ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	world.install()
	// the start's own repost may run beside this one: api answers a statement it holds with its entry, so either way
	// each lands once
	if err := world.device.Sidecar().PostPendingStatements(world.ctx); err != nil {
		t.Fatal(err)
	}
	world.suite.Sync()
	world.requireAct("after the restart", world.landedAfter(tip), []sidecar.Id{first.SidecarId, second.SidecarId}, next.SidecarId)
	if ids := world.pageWorkerIds(); !slices.Equal(ids, []sidecar.Id{next.SidecarId}) {
		t.Errorf("page Workers %v", ids)
	}
}

// A Worker that resyncs after the act decided to revoke it is not revoked: once between the decision and the first
// post, which re-checks at each group's current epoch, and once while the act waits on a retry after a post that never
// reached api. Each time the revocation is dropped unposted and the admission goes.
func TestFs97AWorkerThatResyncsBeforeThePostOrDuringARetryIsNotRevoked(t *testing.T) {
	world := newFs97World(t)
	early := world.enroll("owner page worker early")
	world.groups.Advance(fs97StaleAfter)
	world.setLeaves(early.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	// the act's first answer decides; the post's re-check, its second, finds the Worker resynced (KF5)
	answers := 0
	world.view.SetBeforeAnswer(func() {
		answers += 1
		if answers == 2 {
			world.setLeaves(early.SidecarId, sidecar.SidecarStaleLeafLive, world.groups.Now())
		}
	})
	tip := world.suite.Tip().GetVersion()
	second := world.enroll("owner page worker second")
	world.view.SetBeforeAnswer(nil)
	world.requireAct("resynced before the post", world.landedAfter(tip), nil, second.SidecarId)

	world.groups.Advance(fs97StaleAfter)
	world.setLeaves(early.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	world.setLeaves(second.SidecarId, sidecar.SidecarStaleLeafLive, world.groups.Now())
	tip = world.suite.Tip().GetVersion()
	if _, err := world.net.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpHttp, KeyPrefix: "/network/config/delta", Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	third := world.suite.Device("owner page worker third", world.memberId)
	if err := world.admit(third); !errors.Is(err, sidecar.ErrSidecarActPending) {
		t.Fatalf("a post that never reached api: %v", err)
	}
	if landed := world.landedAfter(tip); len(landed) != 0 {
		t.Fatalf("landed %+v before the retry", landed)
	}
	world.setLeaves(early.SidecarId, sidecar.SidecarStaleLeafLive, world.groups.Now())
	if err := world.device.Sidecar().PostPendingStatements(world.ctx); err != nil {
		t.Fatal(err)
	}
	world.suite.Sync()
	world.requireAct("resynced during the retry", world.landedAfter(tip), nil, third.SidecarId)
	if ids := world.pageWorkerIds(); len(ids) != 3 {
		t.Errorf("page Workers %v", ids)
	}
}
