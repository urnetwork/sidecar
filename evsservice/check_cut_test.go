package evsservice

// EVS2-M10-11's CUT and index_epoch on evs (§11.12's cut row, §11.8's 5c and 5d; I-EVS-16, I-EVS-17, FI-19, FS-111's
// evs clause), each refusal with a passing twin (§22.8's twins rule): I-EVS-17 as a table, a CUT, a merge-shaped push,
// a CLOSURE and a settings push each at, below and above the head's epoch; a CUT's shape, one staged file of
// versioning 2 and nothing else; and through the push route, a CUT creating its ref and moving the head's index_epoch
// to its own version, an index push built before it refused 409 INDEX_EPOCH after it with its rebuilt twin
// committing, a CUT below admin refused before any write, and the epoch standing across a page-out.

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A plan's index file: versioning 2, one staged record of the plan's push, at version on base.
func cutTestIndexFile(t *testing.T, fixture *checkFixture, plan *sidecar.EvsPushPlan, path sidecar.EvsTokenPath, base uint64, version uint64, label string) []byte {
	t.Helper()
	segment, staged := checkTestStaged(t, plan, label)
	plan.NewObjects = append(plan.NewObjects, staged.NewObject())
	plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{
		TokenPath: path, BaseEntryVersion: base,
		EntryVersion: fixture.versionedEntry(plan, version, protocol.EvsVersioning_EVS_VERSIONING_INDEX, checkTestKind5Locator(staged.Id, true)),
	})
	return segment
}

// I-EVS-17 as a table: which pushes 5d holds to the head's index_epoch, and how each refusal lives.
func TestCheckIndexEpochTable(t *testing.T) {
	fixture := newCheckFixture(t)
	x := checkTestPath("x")
	const headEpoch = 5
	for _, c := range []struct {
		name string
		// builds the push's plan at epoch, and what the view needs beside it
		build func(plan *sidecar.EvsPushPlan) [][]byte
		// whether 5d holds it to the epoch
		held bool
	}{
		{name: "a CUT", held: true, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
			return [][]byte{cutTestIndexFile(t, fixture, plan, x, 0, 8, "cut")}
		}},
		{name: "a merge-shaped push", held: true, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			// a merge replaces one index file and creates another, both versioning 2
			first := cutTestIndexFile(t, fixture, plan, x, 0, 8, "merge a")
			second := cutTestIndexFile(t, fixture, plan, checkTestPath("y"), 0, 8, "merge b")
			return [][]byte{first, second}
		}},
		{name: "a CLOSURE", held: false, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
			return [][]byte{cutTestIndexFile(t, fixture, plan, x, 0, 8, "closure")}
		}},
		{name: "a settings push", held: false, build: func(plan *sidecar.EvsPushPlan) [][]byte {
			// the index's settings file is versioning 0, so it needs no epoch
			plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.versionedEntry(plan, 8, protocol.EvsVersioning_EVS_VERSIONING_KEPT,
				&protocol.EvsLocator{Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_INLINE), Inline: []byte("settings")})}}
			return nil
		}},
	} {
		for _, at := range []struct {
			name   string
			epoch  uint64
			reason EvsCheckReason
		}{
			{name: "at the epoch", epoch: headEpoch},
			{name: "below the epoch", epoch: headEpoch - 1, reason: EvsCheckReasonIndexEpochBelow},
			{name: "above the epoch", epoch: headEpoch + 1, reason: EvsCheckReasonIndexEpochAbove},
		} {
			name := c.name + " " + at.name
			plan := fixture.plan()
			plan.IndexEpoch = at.epoch
			staged := c.build(plan)
			view := fixture.viewFormat2(plan, staged)
			view.Head = checkTestHead(view, 7)
			view.Head.IndexEpoch = headEpoch
			refusal := CheckIndexEpoch(view)
			if !c.held || at.reason == 0 {
				requireCheckPass(t, name, refusal)
				continue
			}
			requireCheckRefusal(t, name, refusal, at.reason)
			if refusal != nil && refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH {
				t.Errorf("%s: code %s", name, refusal.Code)
			}
		}
	}

	// below is final and above recorded (§11.8's refuse row)
	if evsCheckReasonRows[EvsCheckReasonIndexEpochBelow].fate != EvsRefusalFinal || evsCheckReasonRows[EvsCheckReasonIndexEpochAbove].fate != EvsRefusalRecorded {
		t.Error("an index_epoch below the head's is final and one above it recorded")
	}

	// a ref with no head holds epoch 0: a CUT naming 0 passes and one naming 1 is above it
	create := fixture.plan()
	create.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	staged := cutTestIndexFile(t, fixture, create, x, 0, 1, "first")
	requireCheckPass(t, "a CUT creating its ref", CheckIndexEpoch(fixture.viewFormat2(create, [][]byte{staged})))
	ahead := fixture.plan()
	ahead.Flags, ahead.IndexEpoch = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT), 1
	staged = cutTestIndexFile(t, fixture, ahead, x, 0, 1, "ahead")
	requireCheckRefusal(t, "a CUT ahead of no head", CheckIndexEpoch(fixture.viewFormat2(ahead, [][]byte{staged})), EvsCheckReasonIndexEpochAbove)

	// the commit's epoch: a CUT's own version, any other push's the head's
	prior := &protocol.EvsHead{Version: 7, IndexEpoch: 5}
	if got := committedIndexEpoch(prior, &protocol.EvsPush{Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)}); got != 8 {
		t.Errorf("a CUT's head carries index_epoch %d, want its version 8", got)
	}
	if got := committedIndexEpoch(prior, &protocol.EvsPush{Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE), IndexEpoch: 9}); got != 5 {
		t.Errorf("a CLOSURE's head carries index_epoch %d, want the head's 5", got)
	}
}

// §11.12's cut row at 5c: admin, one file created or replaced as one staged record of versioning 2, nothing else.
func TestCheckCutShapeAndScope(t *testing.T) {
	fixture := newCheckFixture(t)
	x, y := checkTestPath("x"), checkTestPath("y")
	cut := func(mutate func(plan *sidecar.EvsPushPlan) [][]byte) *PushView {
		plan := fixture.plan()
		plan.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
		view := fixture.viewFormat2(plan, mutate(plan))
		view.Rights |= sidecar.AclEvsAdmin
		return view
	}
	one := func(plan *sidecar.EvsPushPlan) [][]byte {
		return [][]byte{cutTestIndexFile(t, fixture, plan, x, 0, 1, "set")}
	}

	requireCheckPass(t, "a CUT creating the set", CheckCut(cut(one)))
	requireCheckPass(t, "a CUT's whole check", CheckPush(cut(one)))
	replacing := cut(func(plan *sidecar.EvsPushPlan) [][]byte {
		return [][]byte{cutTestIndexFile(t, fixture, plan, x, 3, 4, "set again")}
	})
	requireCheckPass(t, "a CUT replacing the set", CheckCut(replacing))
	withDirectory := cut(func(plan *sidecar.EvsPushPlan) [][]byte {
		staged := one(plan)
		rows := []*protocol.EvsName{{Token: x[len(x)-1][:], Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), SealedName: []byte("sealed name")}}
		plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: sidecar.EvsTokenPath{}, EntryVersion: fixture.directoryEntry(plan, 1, rows, nil)})
		return staged
	})
	requireCheckPass(t, "a CUT with its creation's directory delta", CheckCut(withDirectory))

	below := cut(one)
	below.Rights = sidecar.AclEvsWrite | sidecar.AclEvsRead
	requireCheckRefusal(t, "a CUT below admin", CheckCut(below), EvsCheckReasonScope)
	requireCheckRefusal(t, "a CUT below admin, whole", CheckPush(below), EvsCheckReasonScope)

	for name, mutate := range map[string]func(plan *sidecar.EvsPushPlan) [][]byte{
		"a second file": func(plan *sidecar.EvsPushPlan) [][]byte {
			return [][]byte{cutTestIndexFile(t, fixture, plan, x, 0, 1, "set"), cutTestIndexFile(t, fixture, plan, y, 0, 1, "other")}
		},
		"a removal beside the set": func(plan *sidecar.EvsPushPlan) [][]byte {
			staged := one(plan)
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: y, BaseEntryVersion: 2})
			return staged
		},
		"no file": func(plan *sidecar.EvsPushPlan) [][]byte {
			plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: y, BaseEntryVersion: 2}}
			return nil
		},
		"a file of versioning 1": func(plan *sidecar.EvsPushPlan) [][]byte {
			segment, staged := checkTestStaged(t, plan, "versionless")
			plan.NewObjects = []*sidecar.EvsNewObject{staged.NewObject()}
			plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.versionedEntry(plan, 1, protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, checkTestKind5Locator(staged.Id, true))}}
			return [][]byte{segment}
		},
		"an uploaded set": func(plan *sidecar.EvsPushPlan) [][]byte {
			uploadId, object, _ := fixture.versionlessUpload("cut upload")
			plan.NewObjects = []*sidecar.EvsNewObject{object}
			plan.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, EntryVersion: fixture.versionedEntry(plan, 1, protocol.EvsVersioning_EVS_VERSIONING_INDEX, checkTestKind5Locator(uploadId, false))}}
			return nil
		},
		"a directory delta removing a name": func(plan *sidecar.EvsPushPlan) [][]byte {
			staged := one(plan)
			plan.Changes = append(plan.Changes, &sidecar.EvsPlannedChange{TokenPath: sidecar.EvsTokenPath{}, BaseEntryVersion: 1,
				EntryVersion: fixture.directoryEntry(plan, 2, nil, [][]byte{y[len(y)-1][:]})})
			return staged
		},
	} {
		refusal := CheckCut(cut(mutate))
		requireCheckRefusal(t, name, refusal, EvsCheckReasonCutShape)
		if refusal != nil && len(refusal.Paths) == 0 {
			t.Errorf("%s: a CUT off its shape names no path", name)
		}
	}

	// a CUT in parts, and one carrying another push kind's flag
	part := cut(one)
	part.Stage = PushStagePart
	requireCheckRefusal(t, "a CUT in parts", CheckCut(part), EvsCheckReasonCutShape)
	closure := fixture.plan()
	closure.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT | protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
	closureView := fixture.viewFormat2(closure, one(closure))
	closureView.Rights |= sidecar.AclEvsAdmin
	requireCheckRefusal(t, "a CUT that is also a CLOSURE", CheckCut(closureView), EvsCheckReasonCutShape)

	// a push that is no CUT passes these rules whatever it changes
	plain := fixture.plan()
	plain.Changes = []*sidecar.EvsPlannedChange{{TokenPath: x, BaseEntryVersion: 2}, {TokenPath: y, BaseEntryVersion: 2}}
	requireCheckPass(t, "no CUT", CheckCut(fixture.viewFormat2(plain, nil)))
}

// The fixture's admin token, which implies rw.
func (self *pushFixture) adminToken() string {
	return self.token(self.check.signerId, "admin")
}

// A push's body with its staged bytes.
func (self *pushFixture) bodyStaged(plan *sidecar.EvsPushPlan, staged [][]byte) *protocol.EvsPushRequest {
	body := self.bodyFormat2(plan)
	body.Staged = sidecar.EvsEncodeStaged(staged)
	return body
}

// FS-111's evs clause through the push route: a CUT creates its ref and moves the head's index_epoch to its own
// version; an index push built before the CUT is refused after it, final, and its rebuilt twin commits; a second CUT
// moves the epoch again; and nothing but a CUT moves it.
func TestPushCutMovesTheIndexEpochAndFencesIndexPushes(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	admin := fixture.adminToken()
	writer := fixture.token(fixture.check.signerId)
	set, shard := checkTestPath("set"), checkTestPath("shard")

	// an index push built on the ref's empty head, held back until after the CUT
	stale := fixture.plan()
	staleStaged := cutTestIndexFile(t, fixture.check, stale, shard, 0, 1, "stale shard")
	staleBody := fixture.bodyStaged(stale, [][]byte{staleStaged})

	// the CUT creates the ref, naming the epoch of a ref with no head
	cut := fixture.plan()
	cut.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	cutStaged := cutTestIndexFile(t, fixture.check, cut, set, 0, 1, "set 1")
	fixture.requireCommitted(fixture.post(admin, fixture.bodyStaged(cut, [][]byte{cutStaged})), 1)
	if head := fixture.head(); head.Head.GetIndexEpoch() != 1 {
		t.Fatalf("the CUT's head carries index_epoch %d, want its version 1", head.Head.GetIndexEpoch())
	}

	// the push built before the CUT: refused, final, the head as it was
	before := fixture.head()
	requireRefusal(t, fixture.post(writer, staleBody), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH)
	if after := fixture.head(); after.Etag != before.Etag {
		t.Error("an index_epoch below the head's was recorded: it is final")
	}

	// its rebuilt twin, naming the head's epoch, commits and leaves the epoch alone
	rebuilt := fixture.plan()
	rebuilt.IndexEpoch = 1
	rebuiltStaged := cutTestIndexFile(t, fixture.check, rebuilt, shard, 0, 2, "rebuilt shard")
	fixture.requireCommitted(fixture.post(writer, fixture.bodyStaged(rebuilt, [][]byte{rebuiltStaged})), 2)
	if head := fixture.head(); head.Head.GetIndexEpoch() != 1 {
		t.Fatalf("an index push moved index_epoch to %d", head.Head.GetIndexEpoch())
	}

	// an index push naming an epoch above the head's: refused and recorded
	ahead := fixture.plan()
	ahead.IndexEpoch = 2
	aheadStaged := cutTestIndexFile(t, fixture.check, ahead, shard, 2, 3, "ahead shard")
	before = fixture.head()
	recorder := fixture.post(writer, fixture.bodyStaged(ahead, [][]byte{aheadStaged}))
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH)
	if after := fixture.head(); after.Etag == before.Etag || after.Version() != 2 {
		t.Error("an index_epoch above the head's was not recorded")
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)

	// a plain versioned write names no epoch and commits; the epoch stands
	plain := fixture.plan()
	fixture.create(plain, "plain")
	fixture.requireCommitted(fixture.push(plain), 3)

	// a second CUT at the head's epoch replaces the set and moves the epoch to its own version
	second := fixture.plan()
	second.Flags, second.IndexEpoch = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT), 1
	secondStaged := cutTestIndexFile(t, fixture.check, second, set, 1, 2, "set 2")
	fixture.requireCommitted(fixture.post(admin, fixture.bodyStaged(second, [][]byte{secondStaged})), 4)
	if head := fixture.head(); head.Head.GetIndexEpoch() != 4 {
		t.Fatalf("the second CUT's head carries index_epoch %d, want 4", head.Head.GetIndexEpoch())
	}

	// a CUT built at the first epoch, after the second: refused
	late := fixture.plan()
	late.Flags, late.IndexEpoch = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT), 1
	lateStaged := cutTestIndexFile(t, fixture.check, late, set, 2, 3, "set late")
	requireRefusal(t, fixture.post(admin, fixture.bodyStaged(late, [][]byte{lateStaged})), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH)
}

// I-EVS-16: a CUT below admin is refused before any commit, leaving no version and no index_epoch; its twin under
// admin commits.
func TestPushCutBelowAdminIsRefusedBeforeAnyCommit(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	cut := fixture.plan()
	cut.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	staged := cutTestIndexFile(t, fixture.check, cut, checkTestPath("set"), 0, 1, "set")
	body := fixture.bodyStaged(cut, [][]byte{staged})
	requireRefusal(t, fixture.post(fixture.token(fixture.check.signerId), body), http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	head := fixture.head()
	if !head.Absent() && (head.Version() != 0 || head.Head.GetIndexEpoch() != 0) {
		t.Fatalf("a refused CUT left version %d, index_epoch %d", head.Version(), head.Head.GetIndexEpoch())
	}
	fixture.clock.Advance(fixture.settings.RefusalFenceInterval)
	// the twin: another CUT under admin commits
	twin := fixture.plan()
	twin.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	twinStaged := cutTestIndexFile(t, fixture.check, twin, checkTestPath("set"), 0, 1, "set twin")
	fixture.requireCommitted(fixture.post(fixture.adminToken(), fixture.bodyStaged(twin, [][]byte{twinStaged})), 1)
}

// The epoch never falls across a page-out: a head whose window pages out keeps the index_epoch its CUT set.
func TestPushIndexEpochStandsAcrossAPageOut(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2Checked()
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	cut := fixture.plan()
	cut.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
	staged := cutTestIndexFile(t, fixture.check, cut, checkTestPath("set"), 0, 1, "set")
	fixture.requireCommitted(fixture.post(fixture.adminToken(), fixture.bodyStaged(cut, [][]byte{staged})), 1)
	version := uint64(1)
	pagedOut := func() bool {
		head := fixture.head()
		return uint64(len(head.Head.GetWindow())/sidecar.EvsWindowEntryByteCount) < head.Version()
	}
	for !pagedOut() {
		next := fixture.plan()
		fixture.create(next, fmt.Sprintf("file %d", version))
		version += 1
		fixture.requireCommitted(fixture.push(next), version)
		if 2*EvsWindowPageOutEntryCount < version {
			t.Fatal("no page-out within twice the window's bound")
		}
	}
	if head := fixture.head(); head.Head.GetIndexEpoch() != 1 {
		t.Fatalf("after a page-out at version %d the head carries index_epoch %d", version, head.Head.GetIndexEpoch())
	}
}
