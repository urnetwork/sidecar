package evsservice

// EVS2-M10-09's DROP push on evs (§11.7's action, boundary and refused rows, §11.8's 5c and 5h; FS-95's push-side
// rows; DESIGN-DETAILS 10.6's push_parts_test.go and drop_table_test.go rows), each refusal with a passing twin: a
// drop committing at its written boundary with window bit 5 and its table entry appended at step 8 with seen_ms read
// after step 7's 200; DROP_KIND in a config repo, REF_MODE on a git-mode ref, 403 below admin; DROP_PATH on a
// directory and a versioning-2 head, VERSIONING on a versionless head and under a lock; DROP_CONSENT with the owner's
// device accepted and another refused; the boundary rules and a list without its base; a cancel within its window
// committing and moving the table, one past not_before less the margin refused and answered again to a late attempt
// (I-EVS-3); a cancel passing at the storage limit and past evs_drops_per_day while the next drop gets 429; and a DROP
// in parts whose parts run no body or list check and whose seal checks both over slices cut mid-value.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The push fixture with format 2's own rules, an admin, a day's drops, and path x written at versions 1 to n, each
// version's entry hash kept.
type dropTestFixture struct {
	*pushFixture
	x sidecar.EvsTokenPath
	// x's versions' entry hashes, by path version
	hashes map[uint64][]byte
	// x's newest path version
	newest uint64
	seq    int
}

func newDropTestFixture(t *testing.T, versions int) *dropTestFixture {
	fixture := &dropTestFixture{pushFixture: newPushFixture(t, nil), x: checkTestPath("x"), hashes: map[uint64][]byte{}}
	fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	fixture.setDropsPerDay(10)
	for range versions {
		fixture.writeX()
	}
	return fixture
}

// The network's evs_drops_per_day.
func (self *dropTestFixture) setDropsPerDay(limit int64) {
	self.host.Quota.SetLimits(connect.Id(self.check.networkId), &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"evs_drops_per_day": limit}})
}

// x's next version, committed by a plain push.
func (self *dropTestFixture) writeX() uint64 {
	self.t.Helper()
	plan := self.plan()
	entry := self.check.fileEntry(plan, self.newest+1, []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte(fmt.Sprintf("x content %d", self.newest+1))}})
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: self.x, BaseEntryVersion: self.newest, EntryVersion: entry})
	self.requireCommitted(self.push(plan), plan.BaseVersion+1)
	self.awaitStepEights()
	self.newest += 1
	digest := sha256.Sum256(entry)
	self.hashes[self.newest] = digest[:]
	return self.newest
}

// x's listed hashes below through.
func (self *dropTestFixture) listedBelow(through uint64) [][]byte {
	listed := [][]byte{}
	for version := uint64(1); version < through; version += 1 {
		if hash, ok := self.hashes[version]; ok {
			listed = append(listed, hash)
		}
	}
	return listed
}

// A drop of x at a written boundary: its plan, writing through as an inline record on base through - 1, with now's
// window or the week's, listing listed.
func (self *dropTestFixture) dropPlan(now bool, listed [][]byte) (*sidecar.EvsPushPlan, *protocol.EvsDropHistory) {
	self.t.Helper()
	self.seq += 1
	plan := self.plan()
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	through := self.newest + 1
	notBeforeMs := plan.TimeMs + sidecar.DefaultEvsFormatSettings().DropWindowMs()
	if now {
		notBeforeMs = plan.TimeMs
	}
	history := &protocol.EvsDropHistory{
		DropId: testId(fmt.Sprintf("drop %d", self.seq)).Bytes(), Action: 1, NotBeforeMs: notBeforeMs,
		Paths: []*protocol.EvsDropPath{{
			Lineage:        []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: self.x.Components()}},
			ThroughVersion: through,
			Boundary:       1,
		}},
	}
	self.setDropBody(plan, history, [][][]byte{listed})
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: self.x, BaseEntryVersion: through - 1,
		EntryVersion: self.check.fileEntry(plan, through, []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("kept head")}}),
	})
	return plan, history
}

// plan's DROP body and lists from history and the values listed per path.
func (self *dropTestFixture) setDropBody(plan *sidecar.EvsPushPlan, history *protocol.EvsDropHistory, listed [][][]byte) {
	self.t.Helper()
	if history.GetAction() == 1 {
		lists, err := sidecar.EvsBuildDropLists(history.GetPaths(), listed)
		if err != nil {
			self.t.Fatal(err)
		}
		plan.DropLists = lists
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
	if err != nil {
		self.t.Fatal(err)
	}
	plan.DropBody = body
}

// A cancel of the drop committed at version.
func (self *dropTestFixture) cancelPlan(dropId []byte, version uint64) *sidecar.EvsPushPlan {
	self.seq += 1
	plan := self.plan()
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	self.setDropBody(plan, &protocol.EvsDropHistory{
		DropId: testId(fmt.Sprintf("cancel %d", self.seq)).Bytes(), Action: 2, CancelsDropId: dropId, CancelsVersion: version,
	}, nil)
	return plan
}

// plan posted under the admin token.
func (self *dropTestFixture) postDrop(plan *sidecar.EvsPushPlan) *httptest.ResponseRecorder {
	return self.post(self.adminToken(), self.bodyFormat2(plan))
}

// A drop plan committed at version, x's kept head then its newest with its hash.
func (self *dropTestFixture) commitDrop(plan *sidecar.EvsPushPlan, version uint64) {
	self.t.Helper()
	self.requireCommitted(self.postDrop(plan), version)
	self.awaitStepEights()
	for _, change := range plan.Changes {
		if change.TokenPath.Equal(self.x) && change.EntryVersion != nil {
			self.newest += 1
			digest := sha256.Sum256(change.EntryVersion)
			self.hashes[self.newest] = digest[:]
		}
	}
}

// The drop table as the cluster holds it.
func (self *dropTestFixture) table() *DropTableState {
	self.t.Helper()
	read, err := self.engine.drops.Read(self.ctx, self.cluster, self.check.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	return read.State
}

// A drop commits at its written boundary: the head's window entry carries bit 5, and step 8 appends its table entry
// pending, seen_ms the clock after step 7's 200; a cancel inside its window commits, moving the entry to cancelled.
func TestPushDropCommitsAndAppendsItsTableEntry(t *testing.T) {
	fixture := newDropTestFixture(t, 3)
	plan, history := fixture.dropPlan(false, fixture.listedBelow(4))
	committedAt := fixture.clock.Now()
	fixture.requireCommitted(fixture.postDrop(plan), 4)
	fixture.awaitStepEights()
	if entry := fixture.windowEntryAt(4); !entry.Drop() {
		t.Fatal("a committed DROP's window entry lacks bit 5")
	}
	entry := fixture.table().Drop(sidecar.Id(history.GetDropId()))
	if entry == nil || entry.State != DropStatePending || entry.Version != 4 || entry.NotBeforeMs != history.GetNotBeforeMs() {
		t.Fatalf("the table holds %+v, want the drop pending at version 4", entry)
	}
	if entry.SeenMs < committedAt.UnixMilli() {
		t.Fatalf("seen_ms %d before the commit's %d", entry.SeenMs, committedAt.UnixMilli())
	}

	// a cancel inside the window commits and moves the entry; the cancel itself is never counted against the day
	fixture.setDropsPerDay(1)
	cancel := fixture.cancelPlan(history.GetDropId(), 4)
	fixture.requireCommitted(fixture.postDrop(cancel), 5)
	fixture.awaitStepEights()
	if entry := fixture.table().Drop(sidecar.Id(history.GetDropId())); entry == nil || entry.State != DropStateCancelled {
		t.Fatalf("after its cancel the table holds %+v", entry)
	}
	if !fixture.windowEntryAt(5).Drop() {
		t.Fatal("a cancel's window entry lacks bit 5")
	}
}

// 5c's final refusals: a config repo's DROP_KIND and a git-mode ref's REF_MODE, neither recorded; their twin, a drop
// in a general repo on a file-mode ref, commits.
func TestPushDropKindAndRefModeAreFinal(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	gitPlan, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	gitPlan.RefMode = protocol.EvsRefMode_EVS_REF_GIT
	before := fixture.head()
	requireRefusal(t, fixture.postDrop(gitPlan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE)
	if after := fixture.head(); after.Etag != before.Etag {
		t.Error("a REF_MODE refusal was recorded: it is final")
	}

	fixture.putRepo(protocol.RepoKind_REPO_KIND_CONFIG, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	configPlan, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	requireRefusal(t, fixture.postDrop(configPlan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_KIND)
	if after := fixture.head(); after.Etag != before.Etag {
		t.Error("a DROP_KIND refusal was recorded: it is final")
	}

	fixture.putRepo(protocol.RepoKind_REPO_KIND_GENERAL, protocol.EvsRepoState_EVS_REPO_ACTIVE)
	twin, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	fixture.requireCommitted(fixture.postDrop(twin), 2)
}

// 403 below admin, recorded; the same statement answered again to a late attempt with recorded set; its twin under
// admin commits.
func TestPushDropBelowAdminIsRefusedAndRecorded(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	plan, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	body := fixture.bodyFormat2(plan)
	writer := fixture.token(fixture.check.signerId)
	requireRefusal(t, fixture.post(writer, body), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if head := fixture.head(); len(head.Head.GetRefused()) == 0 {
		t.Fatal("a SCOPE refusal of a DROP was not recorded")
	}
	// a late attempt of the same push, even under admin, is answered the recorded refusal (I-EVS-3)
	late := fixture.post(fixture.adminToken(), body)
	requireRefusal(t, late, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	if !refusalOf(t, late).GetRecorded() {
		t.Error("a late attempt was not answered the recorded refusal")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	twin, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	fixture.requireCommitted(fixture.postDrop(twin), 2)
}

// A cancel: refused DROP_STATE past not_before_ms less the margin, recorded and answered again; refused when no drop
// committed at its version; and a week's drop's cancel committing at the storage limit and past evs_drops_per_day,
// while the next drop gets 429 refusing nothing.
func TestPushDropCancelWindowAndLimits(t *testing.T) {
	fixture := newDropTestFixture(t, 2)
	// a now drop: its window is already closed for a cancel
	now, nowHistory := fixture.dropPlan(true, fixture.listedBelow(3))
	fixture.commitDrop(now, 3)
	late := fixture.cancelPlan(nowHistory.GetDropId(), 3)
	lateBody := fixture.bodyFormat2(late)
	requireRefusal(t, fixture.post(fixture.adminToken(), lateBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE)
	again := fixture.post(fixture.adminToken(), lateBody)
	requireRefusal(t, again, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE)
	if !refusalOf(t, again).GetRecorded() {
		t.Error("a refused cancel's late attempt was not answered the recorded refusal")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	// a cancel of a version that holds no drop
	nothing := fixture.cancelPlan(nowHistory.GetDropId(), 2)
	requireRefusal(t, fixture.postDrop(nothing), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE)
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	// a week's drop, then the day's limit spent and the network at its storage limit
	week, weekHistory := fixture.dropPlan(false, fixture.listedBelow(4))
	fixture.commitDrop(week, 4)
	fixture.setDropsPerDay(2)
	fixture.check.quota.atLimit(connect.Id(fixture.check.networkId))
	next, _ := fixture.dropPlan(false, fixture.listedBelow(5))
	refused := fixture.postDrop(next)
	requireRefusal(t, refused, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
	if refusalOf(t, refused).GetQuota().GetLimitKey() != "evs_drops_per_day" {
		t.Errorf("the 429 names %q", refusalOf(t, refused).GetQuota().GetLimitKey())
	}
	if head := fixture.head(); head.Version() != 4 {
		t.Fatalf("a drop past evs_drops_per_day moved the head to %d", head.Version())
	}
	cancel := fixture.cancelPlan(weekHistory.GetDropId(), 4)
	fixture.requireCommitted(fixture.postDrop(cancel), 5)
}

// A drop past the table's admit bound gets 429 refusing nothing; a cancel never asks.
func TestPushDropPastTheTablesBoundIsRefused429(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	fixture.settings.Drop.TableAdmitByteCount = dropTableEntryByteCount
	plan, _ := fixture.dropPlan(false, fixture.listedBelow(2))
	fixture.commitDrop(plan, 2)
	next, _ := fixture.dropPlan(false, fixture.listedBelow(3))
	requireRefusal(t, fixture.postDrop(next), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED)
	if head := fixture.head(); len(head.Head.GetRefused()) != 0 {
		t.Error("the table's 429 recorded a refusal")
	}
}

// The boundary rules: a written lineage with no change, one writing another version, a change no lineage names, and a
// list without the base each refused, recorded; the plain drop commits.
func TestPushDropBoundaryAndListRefusals(t *testing.T) {
	fixture := newDropTestFixture(t, 2)
	listed := fixture.listedBelow(3)
	cases := []struct {
		name   string
		mutate func(plan *sidecar.EvsPushPlan, history *protocol.EvsDropHistory)
		code   protocol.EvsRefusalCode
	}{
		{name: "no change", code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, mutate: func(plan *sidecar.EvsPushPlan, history *protocol.EvsDropHistory) {
			plan.Changes = nil
		}},
		{name: "another version", code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, mutate: func(plan *sidecar.EvsPushPlan, history *protocol.EvsDropHistory) {
			history.Paths[0].ThroughVersion = 2
			fixture.setDropBody(plan, history, [][][]byte{listed[:1]})
		}},
		{name: "a change no lineage names", code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY, mutate: func(plan *sidecar.EvsPushPlan, history *protocol.EvsDropHistory) {
			plan.Changes = append(plan.Changes, fixture.check.change(plan, checkTestPath("y"), 0, 3))
		}},
		{name: "a list without its base", code: protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST, mutate: func(plan *sidecar.EvsPushPlan, history *protocol.EvsDropHistory) {
			fixture.setDropBody(plan, history, [][][]byte{listed[:1]})
		}},
	}
	for _, c := range cases {
		plan, history := fixture.dropPlan(false, listed)
		c.mutate(plan, history)
		recorder := fixture.postDrop(plan)
		if recorder.Code == http.StatusOK {
			t.Fatalf("%s: committed", c.name)
		}
		if got := refusalOf(t, recorder).GetCode(); got != c.code {
			t.Fatalf("%s: %s, want %s", c.name, got, c.code)
		}
		if head := fixture.head(); head.Version() != 2 {
			t.Fatalf("%s: the head moved to %d", c.name, head.Version())
		}
		fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	}
	plan, _ := fixture.dropPlan(false, listed)
	fixture.requireCommitted(fixture.postDrop(plan), 3)
}

// A list whose hash its count does not meet, and a drop whose not_before_ms is neither of its values: 409 DROP_LIST and
// DROP_STATE, recorded after 5a.
func TestPushDropPayloadRefusalsAreRecorded(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	plan, history := fixture.dropPlan(false, fixture.listedBelow(2))
	history.Paths[0].ListedSha256 = bytes.Repeat([]byte{9}, 32)
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(history)
	if err != nil {
		t.Fatal(err)
	}
	plan.DropBody = body
	requireRefusal(t, fixture.postDrop(plan), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST)
	if head := fixture.head(); len(head.Head.GetRefused()) == 0 {
		t.Fatal("DROP_LIST was not recorded")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	state, stateHistory := fixture.dropPlan(false, fixture.listedBelow(2))
	stateHistory.NotBeforeMs += 1
	fixture.setDropBody(state, stateHistory, [][][]byte{fixture.listedBelow(2)})
	requireRefusal(t, fixture.postDrop(state), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE)
}

// A consent stand-in: the owner's device may drop, any other is unconsented.
type dropTestConsentAuth struct {
	sidecar.GkmAuthView
	ownerDeviceId sidecar.Id
}

func (self *dropTestConsentAuth) MayDrop(subjectId sidecar.Id, repoId sidecar.Id, now time.Time) sidecar.AclDecision {
	if subjectId == self.ownerDeviceId {
		return sidecar.AclDecision{Allowed: true}
	}
	return sidecar.AclDecision{Reason: sidecar.AclReasonUnconsented}
}

// A drop view of a one-part DROP on a written boundary over x at version 2, its head and reads as step 4 gives them.
func dropTestView(t *testing.T, fixture *checkFixture, mutate func(plan *sidecar.EvsPushPlan, base []byte) []byte) *PushView {
	t.Helper()
	x := checkTestPath("x")
	plan := fixture.plan()
	plan.BaseVersion = 2
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
	base := fixture.fileEntry(plan, 2, nil)
	if mutate != nil {
		base = mutate(plan, base)
	}
	baseHash := sha256.Sum256(base)
	history := &protocol.EvsDropHistory{
		DropId: testId("view drop").Bytes(), Action: 1, NotBeforeMs: plan.TimeMs + sidecar.DefaultEvsFormatSettings().DropWindowMs(),
		Paths: []*protocol.EvsDropPath{{Lineage: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: x.Components()}}, ThroughVersion: 3, Boundary: 1}},
	}
	lists, err := sidecar.EvsBuildDropLists(history.GetPaths(), [][][]byte{{baseHash[:]}})
	if err != nil {
		t.Fatal(err)
	}
	plan.DropLists = lists
	marshal := proto.MarshalOptions{Deterministic: true}
	if plan.DropBody, err = marshal.Marshal(history); err != nil {
		t.Fatal(err)
	}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 2, EntryVersion: fixture.fileEntry(plan, 3, nil)}}
	view := fixture.viewFormat2(plan, nil)
	view.Head = checkTestHead(view, 2)
	view.Rights |= sidecar.AclEvsAdmin
	read := &PathRead{Newest: &EvsNewest{Exists: true, Version: 2, CommitVersion: 2, IndexVersion: &protocol.EvsIndexVersion{EntryVersion: base, CommitVersion: 2}}}
	if entry, err := parseEvsEntryVersion(base); err == nil && entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
		read.Newest.Directory = true
	}
	view.Paths[x.KeyString()] = read
	view.Drop = &PushDropReads{ListSlices: [][]byte{lists}, Removed: map[int]*DropRemovedRead{}, CancelMargin: time.Minute}
	return view
}

// DROP_PATH for a directory and a versioning-2 head, VERSIONING for a versionless one and under a lock; each twin passes.
func TestCheckDropPathAndVersioning(t *testing.T) {
	fixture := newCheckFixture(t)
	requireCheckPass(t, "a kept file", CheckDrop(dropTestView(t, fixture, nil)))
	requireCheckPass(t, "its boundary", CheckDropBoundary(dropTestView(t, fixture, nil)))
	for _, c := range []struct {
		name       string
		versioning protocol.EvsVersioning
		reason     EvsCheckReason
	}{
		{name: "a versionless head", versioning: protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, reason: EvsCheckReasonDropVersioning},
		{name: "an index head", versioning: protocol.EvsVersioning_EVS_VERSIONING_INDEX, reason: EvsCheckReasonDropPath},
	} {
		view := dropTestView(t, fixture, func(plan *sidecar.EvsPushPlan, base []byte) []byte {
			return fixture.versionedEntry(plan, 2, c.versioning, checkTestKind5Locator(sha256.Sum256([]byte(c.name)), false))
		})
		requireCheckRefusal(t, c.name, CheckDrop(view), c.reason)
	}
	directory := dropTestView(t, fixture, func(plan *sidecar.EvsPushPlan, base []byte) []byte {
		return fixture.directoryEntry(plan, 2, nil, nil)
	})
	requireCheckRefusal(t, "a directory", CheckDrop(directory), EvsCheckReasonDropPath)
	locked := dropTestView(t, fixture, nil)
	locked.Auth = &checkLockedAuth{GkmAuthView: locked.Auth}
	requireCheckRefusal(t, "under a lock", CheckDrop(locked), EvsCheckReasonDropVersioning)
	if evsCheckReasonRows[EvsCheckReasonDropPath].fate != EvsRefusalRecorded || evsCheckReasonRows[EvsCheckReasonDropVersioning].fate != EvsRefusalRecorded {
		t.Error("DROP_PATH and a DROP's VERSIONING are recorded")
	}
}

// D-ACL-25 in an owner-bound repo: the owner's consented device passes, any other signer is DROP_CONSENT, and a state
// that answers no consent refuses 503; a general repo asks none.
func TestCheckDropConsent(t *testing.T) {
	fixture := newCheckFixture(t)
	view := dropTestView(t, fixture, nil)
	requireCheckPass(t, "a general repo", CheckDrop(view))
	view.Repo.Kind = protocol.RepoKind_REPO_KIND_VAULT
	requireCheckRefusal(t, "no consent answer", CheckDrop(view), EvsCheckReasonUnchecked)
	view.Auth = &dropTestConsentAuth{GkmAuthView: fixture.auth, ownerDeviceId: fixture.signerId}
	requireCheckPass(t, "the owner's device", CheckDrop(view))
	view.Auth = &dropTestConsentAuth{GkmAuthView: fixture.auth, ownerDeviceId: fixture.otherId}
	requireCheckRefusal(t, "another admin", CheckDrop(view), EvsCheckReasonDropConsent)
}

// A removed boundary passes when step 4 read the standing removal at through_version, is refused when the path stands
// or its removal is another version, and is left to resolve when step 4 could not judge it.
func TestCheckDropRemovedBoundary(t *testing.T) {
	fixture := newCheckFixture(t)
	view := dropTestView(t, fixture, nil)
	history := view.Payload.Drop.History
	history.Paths[0].Boundary = 2
	view.Payload.Changes = nil
	view.Drop.Removed[0] = &DropRemovedRead{Known: true, RemovalVersion: 3}
	requireCheckPass(t, "the standing removal", CheckDropBoundary(view))
	view.Drop.Removed[0] = &DropRemovedRead{Known: true, Exists: true}
	requireCheckRefusal(t, "a standing path", CheckDropBoundary(view), EvsCheckReasonDropBoundary)
	view.Drop.Removed[0] = &DropRemovedRead{Known: true, RemovalVersion: 5}
	requireCheckRefusal(t, "another removal", CheckDropBoundary(view), EvsCheckReasonDropBoundary)
	view.Drop.Removed[0] = &DropRemovedRead{}
	requireCheckPass(t, "left to resolve", CheckDropBoundary(view))
}

// A written boundary's records: one record of this push's upload passes and one the base names does not; chunks each
// this push's upload or the base's own kind-1 chunk, all but the last whole, pass, and a short middle chunk or another
// chunk is refused.
func TestCheckDropWrittenChunks(t *testing.T) {
	fixture := newCheckFixture(t)
	whole := uint32(sidecar.EvsRecordByteCount(sidecar.EvsChunkByteCount))
	baseChunk := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: bytes.Repeat([]byte{1}, 32), Length: whole}
	for _, c := range []struct {
		name   string
		chain  func(uploadId [32]byte) []*protocol.EvsLocator
		passes bool
	}{
		{name: "one record of this push's upload", passes: true, chain: func(uploadId [32]byte) []*protocol.EvsLocator {
			return []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: uploadId[:], Length: 100}}
		}},
		{name: "one record the base names", chain: func(uploadId [32]byte) []*protocol.EvsLocator {
			return []*protocol.EvsLocator{baseChunk}
		}},
		{name: "the base's chunk and an upload", passes: true, chain: func(uploadId [32]byte) []*protocol.EvsLocator {
			return []*protocol.EvsLocator{baseChunk, {Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: uploadId[:], Length: 100}}
		}},
		{name: "a short middle chunk", chain: func(uploadId [32]byte) []*protocol.EvsLocator {
			short := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: uploadId[:], Length: 100}
			return []*protocol.EvsLocator{short, baseChunk}
		}},
		{name: "another segment", chain: func(uploadId [32]byte) []*protocol.EvsLocator {
			other := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT), Id: bytes.Repeat([]byte{2}, 32), Length: whole}
			return []*protocol.EvsLocator{other, baseChunk}
		}},
	} {
		uploadId, object, _ := fixture.upload("chunk "+c.name, fixture.now.Add(-time.Minute), fixture.signerId)
		view := dropTestView(t, fixture, func(plan *sidecar.EvsPushPlan, base []byte) []byte {
			plan.NewObjects = []*sidecar.EvsNewObject{object}
			return fixture.fileEntry(plan, 2, []*protocol.EvsLocator{baseChunk, baseChunk})
		})
		entry, err := parseEvsEntryVersion(view.Payload.Changes[0].EntryVersion)
		if err != nil {
			t.Fatal(err)
		}
		entry.Chain = c.chain(uploadId)
		entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		view.Payload.Changes[0].EntryVersion = entryBytes
		refusal := checkDropWrittenBoundary(view, view.Payload.Drop.History.GetPaths()[0], view.Payload.Changes[0])
		if c.passes {
			requireCheckPass(t, c.name, refusal)
		} else {
			requireCheckRefusal(t, c.name, refusal, EvsCheckReasonDropBoundary)
		}
	}
}

// The lists' search over slices cut anywhere, a value split across two: each value found at its path's range, none
// found at another's.
func TestDropListSlicesSearchAcrossCuts(t *testing.T) {
	values := [][]byte{}
	for i := range 40 {
		digest := sha256.Sum256([]byte(fmt.Sprintf("value %d", i)))
		values = append(values, digest[:])
	}
	first, second := values[:25], values[25:]
	paths := []*protocol.EvsDropPath{{}, {}}
	whole, err := sidecar.EvsBuildDropLists(paths, [][][]byte{first, second})
	if err != nil {
		t.Fatal(err)
	}
	slices := [][]byte{whole[:17], whole[17:400], whole[400:401], whole[401:]}
	lists := newEvsDropListSlices(slices)
	for _, value := range first {
		if !lists.contains(0, 25, value) || lists.contains(25, 15, value) {
			t.Fatalf("a first path's value placed wrong")
		}
	}
	for _, value := range second {
		if !lists.contains(25, 15, value) || lists.contains(0, 25, value) {
			t.Fatalf("a second path's value placed wrong")
		}
	}
	if lists.contains(0, 40, bytes.Repeat([]byte{0xff}, 32)) {
		t.Fatal("found a value no path lists")
	}
}

// A DROP in parts: 80 written boundaries whose kept heads ride inline at 14 KiB pass one part's 1 MiB, so the
// builder cuts it; each part runs no body or list check and answers its place, and the seal checks every lineage's
// list over the parts' slices and commits. Its twin, one list lacking its base, is refused DROP_LIST at the seal,
// recorded, after its parts were taken.
func TestPushDropInPartsChecksAtTheSeal(t *testing.T) {
	fixture := newDropTestFixture(t, 1)
	token := fixture.adminToken()
	const pathCount = 80
	create := fixture.plan()
	paths := make([]sidecar.EvsTokenPath, pathCount)
	hashes := make([][]byte, pathCount)
	for i := range pathCount {
		paths[i] = checkTestPath(fmt.Sprintf("pp%02d", i))
		change := fixture.check.change(create, paths[i], 0, create.BaseVersion+1)
		create.Changes = append(create.Changes, change)
		digest := sha256.Sum256(change.EntryVersion)
		hashes[i] = digest[:]
	}
	fixture.requireCommitted(fixture.push(create), 2)
	fixture.awaitStepEights()
	pathVersion := create.BaseVersion + 1

	build := func(label string, lacking int) *sidecar.EvsBuiltPush {
		plan := fixture.plan()
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP)
		history := &protocol.EvsDropHistory{DropId: testId("parts drop " + label).Bytes(), Action: 1, NotBeforeMs: plan.TimeMs + sidecar.DefaultEvsFormatSettings().DropWindowMs()}
		order := make([]int, pathCount)
		for i := range order {
			order[i] = i
		}
		slices.SortFunc(order, func(a int, b int) int { return bytes.Compare(paths[a].Bytes(), paths[b].Bytes()) })
		listed := [][][]byte{}
		for _, i := range order {
			history.Paths = append(history.Paths, &protocol.EvsDropPath{
				Lineage: []*protocol.EvsSourcePath{{Epoch: 1, TokenPath: paths[i].Components()}}, ThroughVersion: pathVersion + 1, Boundary: 1,
			})
			value := hashes[i]
			if i == lacking {
				other := sha256.Sum256([]byte("not the base"))
				value = other[:]
			}
			listed = append(listed, [][]byte{value})
			kept := bytes.Repeat([]byte{byte(i)}, 14*1024)
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
				TokenPath: paths[i], BaseEntryVersion: pathVersion,
				EntryVersion: fixture.check.fileEntry(plan, pathVersion+1, []*protocol.EvsLocator{{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: kept}}),
			})
		}
		fixture.setDropBody(plan, history, listed)
		built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.check.signingKey, fixture.check.signerId)).BuildFormat2(plan)
		if err != nil {
			t.Fatal(err)
		}
		if len(built.Parts) < 2 {
			t.Fatalf("a DROP of %d 14 KiB kept heads in %d parts", pathCount, len(built.Parts))
		}
		return built
	}
	missing := build("missing", pathCount/2)
	places := fixture.postParts(token, missing)
	requireRefusal(t, fixture.seal(token, missing, places), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST)
	if head := fixture.head(); head.Version() != 2 || len(head.Head.GetRefused()) == 0 {
		t.Fatal("a seal's DROP_LIST was not recorded, or it committed")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	built := build("listed", -1)
	places = fixture.postParts(token, built)
	fixture.requireCommitted(fixture.seal(token, built, places), 3)
	if !fixture.windowEntryAt(3).Drop() {
		t.Fatal("a sealed DROP's window entry lacks bit 5")
	}
}
