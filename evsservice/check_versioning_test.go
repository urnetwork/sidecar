package evsservice

// EVS2-M10-06's 5c and 5h for a format-2 push, each refusal with a passing twin (§22.8's twins rule): VERSIONING
// final on a git-mode ref, a creates-only ref (deposit, erasure, a record-class stream) and in config and mailcfg
// repos; recorded for versioning 1 under a lock in the state evs validates against, versioning 2 passing it and an
// unlocked twin committing; a DROP and a CUT waiting on their own tasks' rules (503); and the citation rule over what
// step 4 read (FS-64's evs clauses): a kind-5 locator naming this push's versionless upload passes, one naming an
// unmarked upload, another path's kind-5 content or a reuse source's is VERSIONING, a staged segment of this push
// passes and cited again by a later version is refused, and an inline record in a versionless version is refused.

import (
	"crypto/sha256"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A format-2 view of plan: built and checked by format 2's codecs, at a format-2 instance, the gate admitting it.
func (self *checkFixture) viewFormat2(plan *sidecar.EvsPushPlan, staged [][]byte) *PushView {
	self.t.Helper()
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(self.signingKey, self.signerId)).BuildFormat2(plan)
	if err != nil {
		self.t.Fatal(err)
	}
	payload, err := sidecar.EvsCheckPayloadFormat2(built.Statement, built.Payload, sidecar.EvsEncodeStaged(staged))
	if err != nil {
		self.t.Fatal(err)
	}
	// a format-1 view's fields, its statement and payload then this plan's
	view := self.view(self.plan())
	view.Statement, view.Payload = built.Statement, payload
	view.Repo.Format = sidecar.EvsRepoFormat2
	view.InstanceFormat = sidecar.EvsRepoFormat2
	view.NeedsFormat2 = sidecar.EvsPushNeedsFormat2(built.Statement, payload)
	view.Format2Admitted = true
	view.Paths = map[string]*PathRead{}
	for _, change := range payload.Changes {
		view.Paths[change.TokenPath.KeyString()] = &PathRead{Newest: &EvsNewest{}}
	}
	return view
}

// A file entry version of versioning at version naming locators.
func (self *checkFixture) versionedEntry(plan *sidecar.EvsPushPlan, version uint64, versioning protocol.EvsVersioning, locators ...*protocol.EvsLocator) []byte {
	self.t.Helper()
	entry := &protocol.EvsEntryVersion{
		Version: version, PushId: plan.PushId.Bytes(), BaseVersion: plan.BaseVersion, TimeMs: plan.TimeMs,
		Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), PaddedSize: 4096, SealedFields: []byte("sealed fields"),
		Versioning: uint32(versioning), Chain: locators,
	}
	entryBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return entryBytes
}

// A kind-5 locator of id, staged or not.
func checkTestKind5Locator(id [32]byte, staged bool) *protocol.EvsLocator {
	return &protocol.EvsLocator{
		Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: id[:],
		Offset: sidecar.EvsKind5SegmentHeaderByteCount, Length: uint32(sidecar.EvsRecordByteCount(100)), Staged: staged,
	}
}

// A versionless upload of this push: its id, its new-objects item and its receipt marked versionless.
func (self *checkFixture) versionlessUpload(label string) ([32]byte, *sidecar.EvsNewObject, *protocol.EvsUploadReceipt) {
	self.t.Helper()
	segmentId := sha256.Sum256([]byte("check kind-5 segment " + label))
	uploadTime := self.now.Add(-time.Minute)
	receipt, err := IssueUploadReceipt(self.receiptKeys, self.repoId, segmentId, 4096, uploadTime, self.signerId, true, self.now)
	if err != nil {
		self.t.Fatal(err)
	}
	object := &sidecar.EvsNewObject{
		Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT, Id: segmentId[:], PaddedSize: 4096,
		UploadDay: uint32(uploadTime.UnixMilli() / evsUploadDayMs),
	}
	return segmentId, object, receipt
}

// A staged segment of the plan's push: a kind-5 header of this repo naming the push, padded to a Padmé length.
func checkTestStaged(t *testing.T, plan *sidecar.EvsPushPlan, label string) ([]byte, *sidecar.EvsStagedSegment) {
	t.Helper()
	size := int(sidecar.EvsPadme(1000))
	segment := make([]byte, size)
	copy(segment, "URvs")
	segment[4] = 2
	copy(segment[8:24], plan.RepoId[:])
	segment[31] = 1
	copy(segment[32:48], plan.PushId[:])
	copy(segment[48:], []byte("staged "+label))
	staged, err := sidecar.EvsStagedSegmentOf(segment, plan.RepoId, plan.PushId)
	if err != nil {
		t.Fatal(err)
	}
	return segment, staged
}

// The newest version step 4 read of path in view: entry at version, committed in the window.
func checkTestNewest(view *PushView, path sidecar.EvsTokenPath, entryBytes []byte, version uint64) {
	view.Paths[path.KeyString()] = &PathRead{Newest: &EvsNewest{
		Exists: true, Version: version, CommitVersion: version, FromWindow: true,
		Change: &EvsCommittedChange{TokenPath: path, BaseEntryVersion: version - 1, EntryVersion: entryBytes},
	}}
}

// A gate view that holds the repo locked.
type checkLockedAuth struct {
	sidecar.GkmAuthView
}

func (self *checkLockedAuth) Repo(repoId sidecar.Id) *protocol.AclRepo {
	row := self.GkmAuthView.Repo(repoId)
	if row == nil {
		row = &protocol.AclRepo{RepoId: repoId.Bytes()}
	}
	row.Lock = protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED
	return row
}

func TestCheckVersioningRefusesByRefAndRepoKind(t *testing.T) {
	fixture := newCheckFixture(t)
	for _, c := range []struct {
		name   string
		mutate func(plan *sidecar.EvsPushPlan, view *PushView)
	}{
		{name: "a git-mode ref", mutate: func(plan *sidecar.EvsPushPlan, view *PushView) { plan.RefMode = protocol.EvsRefMode_EVS_REF_GIT }},
		{name: "a deposit ref", mutate: func(plan *sidecar.EvsPushPlan, view *PushView) {
			plan.RefKind, plan.RefId, plan.OwnerSidecarId = protocol.EvsRefKind_EVS_REF_DEPOSIT, sidecar.EvsDepositRefId(fixture.repoId, fixture.signerId), &fixture.signerId
		}},
		{name: "the erasure ref", mutate: func(plan *sidecar.EvsPushPlan, view *PushView) {
			plan.RefKind, plan.RefId = protocol.EvsRefKind_EVS_REF_ERASURE, sidecar.EvsErasureRefId(fixture.repoId)
		}},
		{name: "a record-class stream", mutate: func(plan *sidecar.EvsPushPlan, view *PushView) {
			plan.RefKind, plan.OwnerSidecarId = protocol.EvsRefKind_EVS_REF_OWNED, &fixture.signerId
			view.Repo.Kind = protocol.RepoKind_REPO_KIND_RECORD
		}},
		{name: "a config repo", mutate: func(plan *sidecar.EvsPushPlan, view *PushView) { view.Repo.Kind = protocol.RepoKind_REPO_KIND_CONFIG }},
		{name: "a mailcfg repo", mutate: func(plan *sidecar.EvsPushPlan, view *PushView) { view.Repo.Kind = protocol.RepoKind_REPO_KIND_MAILCFG }},
	} {
		for _, versioning := range []protocol.EvsVersioning{protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, protocol.EvsVersioning_EVS_VERSIONING_INDEX, protocol.EvsVersioning_EVS_VERSIONING_KEPT} {
			plan := fixture.plan()
			c.mutate(plan, &PushView{Repo: &protocol.EvsRepoObject{}})
			inline := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline")}
			plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: checkTestPath("a"), EntryVersion: fixture.versionedEntry(plan, 1, versioning, inline)}}
			view := fixture.viewFormat2(plan, nil)
			c.mutate(plan, view)
			refusal := CheckVersioning(view)
			if versioning == protocol.EvsVersioning_EVS_VERSIONING_KEPT {
				requireCheckPass(t, c.name+", versioned", refusal)
				continue
			}
			requireCheckRefusal(t, c.name, refusal, EvsCheckReasonVersioningRef)
			if refusal != nil && (len(refusal.Paths) != 1 || !refusal.Paths[0].Equal(checkTestPath("a"))) {
				t.Errorf("%s: paths %v", c.name, refusal.Paths)
			}
		}
	}
	// the twin: a general repo's file-mode shared ref takes either
	plan := fixture.plan()
	inline := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline")}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: checkTestPath("a"), EntryVersion: fixture.versionedEntry(plan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, inline)}}
	requireCheckPass(t, "a general repo's shared file-mode ref", CheckVersioning(fixture.viewFormat2(plan, nil)))
}

// §11.7's refused row's lock: versioning 1 is refused, recorded, under a lock in the state evs validates against, and
// versioning 2 passes; the unlocked twin passes; with no state the check answers 503.
func TestCheckVersioningUnderALock(t *testing.T) {
	fixture := newCheckFixture(t)
	build := func(versioning protocol.EvsVersioning) *PushView {
		plan := fixture.plan()
		inline := &protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline")}
		plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: checkTestPath("a"), EntryVersion: fixture.versionedEntry(plan, 1, versioning, inline)}}
		return fixture.viewFormat2(plan, nil)
	}
	locked := build(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	locked.Auth = &checkLockedAuth{GkmAuthView: locked.Auth}
	requireCheckRefusal(t, "versioning 1 under a lock", CheckVersioning(locked), EvsCheckReasonVersioningLocked)
	index := build(protocol.EvsVersioning_EVS_VERSIONING_INDEX)
	index.Auth = &checkLockedAuth{GkmAuthView: index.Auth}
	requireCheckPass(t, "versioning 2 under a lock", CheckVersioning(index))
	requireCheckPass(t, "versioning 1 unlocked", CheckVersioning(build(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)))
	unknown := build(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
	unknown.Auth = nil
	requireCheckRefusal(t, "no state", CheckVersioning(unknown), EvsCheckReasonGateUnknown)
}

// A DROP's and a CUT's rules are other tasks': each waits 503, refusing nothing, so none commits unchecked.
func TestCheckFormat2WaitsOnDropAndCutRules(t *testing.T) {
	fixture := newCheckFixture(t)
	plan := fixture.plan()
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: checkTestPath("a"), EntryVersion: fixture.versionedEntry(plan, 1, protocol.EvsVersioning_EVS_VERSIONING_KEPT,
		&protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline")})}}
	plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	built, err := sidecar.NewEvsStatementBuilder(checkTestSign(fixture.signingKey, fixture.signerId)).BuildFormat2(plan)
	if err != nil {
		t.Fatal(err)
	}
	view := fixture.view(fixture.plan())
	view.Statement = built.Statement
	view.InstanceFormat, view.NeedsFormat2 = sidecar.EvsRepoFormat2, true
	requireCheckRefusal(t, "a CUT", checkFormat2Refs(view), EvsCheckReasonUnchecked)
	drop := proto.Clone(built.Statement.Push).(*protocol.EvsPush)
	drop.Flags, drop.DropSha256 = uint32(protocol.EvsPushFlag_EVS_PUSH_DROP), make([]byte, 32)
	view.Statement = &sidecar.EvsStatement{Push: drop}
	requireCheckRefusal(t, "a DROP", checkFormat2Refs(view), EvsCheckReasonUnchecked)
}

// 5h's citation rule over step 4's reads (FS-64's evs clauses).
func TestCheckCitationOverStep4sReads(t *testing.T) {
	fixture := newCheckFixture(t)
	x, y := checkTestPath("x"), checkTestPath("y")

	// a creation naming this push's versionless upload passes; the same id under an unmarked receipt does not
	plan := fixture.plan()
	uploadId, object, receipt := fixture.versionlessUpload("x1")
	plan.NewObjects = []*sidecar.EvsNewObject{object}
	plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.versionedEntry(plan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(uploadId, false))}}
	view := fixture.viewFormat2(plan, nil)
	view.Receipts = []*protocol.EvsUploadReceipt{receipt}
	requireCheckPass(t, "a versionless upload of this push", CheckCitation(view))
	requireCheckPass(t, "its whole check", CheckPush(view))
	unmarked, err := IssueUploadReceipt(fixture.receiptKeys, fixture.repoId, uploadId, 4096, fixture.now.Add(-time.Minute), fixture.signerId, false, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	view.Receipts = []*protocol.EvsUploadReceipt{unmarked}
	requireCheckRefusal(t, "an unmarked upload as kind 5", CheckCitation(view), EvsCheckReasonCitation)
	requireCheckRefusal(t, "an unmarked upload as kind 5, whole", CheckPush(view), EvsCheckReasonCitation)

	// k+1 of x cites k's unstaged kind-5 segment as kind 5: its base's, so it passes
	k := fixture.plan()
	kEntry := fixture.versionedEntry(k, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(uploadId, false))
	next := fixture.plan()
	next.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.versionedEntry(next, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(uploadId, false))}}
	view = fixture.viewFormat2(next, nil)
	checkTestNewest(view, x, kEntry, 1)
	requireCheckPass(t, "a next version citing its base's kind-5 segment", CheckCitation(view))

	// a copy: y's creation cites x's kind-5 segment, x staying: VERSIONING
	copyPlan := fixture.plan()
	copyPlan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: y, EntryVersion: fixture.versionedEntry(copyPlan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(uploadId, false))}}
	view = fixture.viewFormat2(copyPlan, nil)
	requireCheckRefusal(t, "a copy citing another path's kind-5 segment", CheckCitation(view), EvsCheckReasonCitation)

	// the rename twin: the push that removes x creates y citing x's segment: passes
	rename := fixture.plan()
	rename.Changes = []*sidecar.EvsPlannedChange{
		{TokenPath: x, BaseEntryVersion: 1},
		{TokenPath: y, EntryVersion: fixture.versionedEntry(rename, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(uploadId, false))},
	}
	view = fixture.viewFormat2(rename, nil)
	checkTestNewest(view, x, kEntry, 1)
	requireCheckPass(t, "a rename citing the removed path's segment", CheckCitation(view))

	// re-uploaded bytes for k+2: a kind-5 locator naming a segment no version read names and no marked receipt of
	// this push covers
	reupload := fixture.plan()
	stranger := sha256.Sum256([]byte("another push's segment"))
	reupload.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 2, EntryVersion: fixture.versionedEntry(reupload, 3, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(stranger, false))}}
	view = fixture.viewFormat2(reupload, nil)
	requireCheckRefusal(t, "a kind-5 locator of no upload of this push", CheckCitation(view), EvsCheckReasonCitation)

	// a staged segment of this push passes; an inline record in a versionless version does not
	stagedPlan := fixture.plan()
	segment, staged := checkTestStaged(t, stagedPlan, "s")
	stagedPlan.NewObjects = []*sidecar.EvsNewObject{staged.NewObject()}
	stagedPlan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.versionedEntry(stagedPlan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true))}}
	view = fixture.viewFormat2(stagedPlan, [][]byte{segment})
	requireCheckPass(t, "a staged segment of this push", CheckCitation(view))
	requireCheckPass(t, "a staged push's whole check", CheckPush(view))
	inline := fixture.plan()
	inline.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.versionedEntry(inline, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS,
		&protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("inline")})}}
	requireCheckRefusal(t, "an inline record in a versionless version", CheckCitation(fixture.viewFormat2(inline, nil)), EvsCheckReasonCitation)

	// a staged segment cited again by the next version: refused, the next version re-staging its bytes
	stagedEntry := fixture.versionedEntry(stagedPlan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true))
	again := fixture.plan()
	again.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 1, EntryVersion: fixture.versionedEntry(again, 2, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true))}}
	view = fixture.viewFormat2(again, nil)
	checkTestNewest(view, x, stagedEntry, 1)
	requireCheckRefusal(t, "a staged segment past its introducing version", CheckCitation(view), EvsCheckReasonCitation)
}
