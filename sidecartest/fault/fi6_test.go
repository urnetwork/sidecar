package fault

// FI-6's oracle (fi6.go) on T2, in fi1_test.go's two worlds: each mutant a step that changes the store the way the
// bug it stands for would, caught at that step, beside the timing or outcome twin that reads clean. The healthy run
// that reads clean at every step is fi1_test.go's TestFi1AndFi6ReadAHealthyMultiPushRunClean.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The idx/ entry of main whose newest folded version committed at version, with its ETag.
func (self *fiWorld) entryAt(ctx context.Context, version uint64) (string, string, *protocol.EvsIndexEntry, error) {
	infos, err := fiKeys(ctx, self.cluster(), evsOracleRefPrefix("idx/", self.repoId, self.refId))
	if err != nil {
		return "", "", nil, err
	}
	for _, info := range infos {
		object, err := self.cluster().Get(ctx, info.Key)
		if err != nil {
			return "", "", nil, err
		}
		body := new(bytes.Buffer)
		_, err = body.ReadFrom(object.Body)
		object.Body.Close()
		if err != nil {
			return "", "", nil, err
		}
		entry := &protocol.EvsIndexEntry{}
		if err := proto.Unmarshal(body.Bytes(), entry); err != nil {
			return "", "", nil, err
		}
		if versions := entry.GetVersions(); 0 < len(versions) && versions[0].GetCommitVersion() == version {
			return info.Key, object.Etag, entry, nil
		}
	}
	return "", "", nil, fmt.Errorf("no entry holds a version committed at %d", version)
}

// A fold of an uncommitted push's version over a path's folded newest: FI-6 finds the index holding a version the
// head history never committed, and the path's newest committed version evicted from where readers look.
func TestFi6CatchesAnUncommittedVersionEvictingTheNewest(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "evs", Action: world.fold},
		// its commit raises folded_through over a.txt's version
		{Actor: "writerA", Action: world.write("b.txt", 100)},
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			key, etag, entry, err := world.entryAt(ctx, 1)
			if err != nil {
				return err
			}
			uncommitted := proto.Clone(entry).(*protocol.EvsIndexEntry)
			uncommitted.Versions[0].PushId = sidecar.NewId().Bytes()
			uncommittedBytes, err := proto.Marshal(uncommitted)
			if err != nil {
				return err
			}
			_, err = world.cluster().PutIfMatch(ctx, key, etag, uncommittedBytes, nil)
			return err
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-uncommitted-eviction", Steps: steps, Check: fiChecks()}, world.net)
	fiRequireViolation(t, result, 4, "FI-6", "which the head history does not commit there: an uncommitted version in the index")
	fiRequireViolation(t, result, 4, "FI-6", "newest committed version is at 1", "it was evicted")
}

// A head whose horizon passed a directory's deltas, as a page-out's commit does, with the directory's name table
// never written: FI-6 finds a delta left the window before its table held it.
func TestFi6CatchesADeltaPastTheHorizonBeforeItsNameTable(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("docs/b.txt", 100)},
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			prior, err := world.head(ctx)
			if err != nil {
				return err
			}
			next := proto.Clone(prior.Head).(*protocol.EvsHead)
			next.FoldedThrough = prior.Version()
			next.Fence = prior.Head.GetFence() + 1
			_, err = world.engine.Heads().Commit(ctx, world.cluster(), world.repoId, world.refId, prior, next)
			return err
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-delta-before-table", Steps: steps, Check: fiChecks()}, world.net)
	fiRequireViolation(t, result, 2, "FI-6", "a delta left the window before its table held it")
}

// The twin: the same horizon raised by a fold and the commit after it, the table written first, reads clean.
func TestFi6TakesADeltaFoldedBeforeTheHorizon(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("docs/b.txt", 100)},
		{Actor: "evs", Action: world.fold},
		{Actor: "writerA", Action: world.write("docs/c.txt", 100)},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-delta-folded", Steps: steps, Check: fiChecks()}, world.net))
	head, err := world.head(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if head.Head.GetFoldedThrough() == 0 {
		t.Fatal("the commit after the fold raised no horizon, so the twin proves nothing")
	}
}

// A slot that no committed version names and no batch record lists, a dead push's left behind as a buggy evacuation
// would leave it: clean while it is young, and unreclaimable once past a dead push's deadline.
func TestFi6CatchesAnOrphanSlotLeftUnreclaimable(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			body, err := world.slotBody(1)
			if err != nil {
				return err
			}
			_, err = world.cluster.PutIfNoneMatch(ctx, evsOracleSlotKey(world.repoId, sidecar.NewEvsSlotId().Bytes()), body, nil)
			return err
		}},
		{Actor: "clock", Advance: 25 * time.Hour},
		{Actor: "clock", Advance: 2 * time.Hour},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-orphan-slot", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 3, "FI-6", "which no committed version names", "no batch record lists it: no reclaimer finds it")
}

// The twin: a slot a pending push's record lists stays reclaimable past the deadline, since evacuation finds it.
func TestFi6TakesAPendingPushsSlotPastTheDeadline(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, true)
			return err
		}},
		{Actor: "clock", Advance: 27 * time.Hour},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-listed-slot", Steps: steps, Check: []Invariant{FI(6)}}, world.net))
}

// Step 6 of a push on refId creating one file whose version names a new slot of two keys, as evs runs it in QD-806's
// order: the slot created If-None-Match carrying its statement's origin, encoded as evsservice encodes it (DESIGN-
// DETAILS 14.2.2), then, if recorded, the record, which keeps no slot body. One not recorded is an attempt that died
// between its slot round and its record. Returns the slot id and the push.
func (self *fiHandWorld) originSlotPush(ctx context.Context, refId sidecar.Id, recorded bool) (sidecar.Id, *fiHandPush, error) {
	slotId := sidecar.NewEvsSlotId()
	body, err := self.slotBody(2)
	if err != nil {
		return slotId, nil, err
	}
	pushId := sidecar.NewId()
	change, err := self.fileChange(pushId, slotId)
	if err != nil {
		return slotId, nil, err
	}
	push, err := self.build(refId, protocol.EvsRefKind_EVS_REF_SHARED, 0, self.admin, pushId, []*sidecar.EvsPlannedChange{change},
		[]*sidecar.EvsNewObject{{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()}}, [][]byte{body}, nil)
	if err != nil {
		return slotId, nil, err
	}
	origin, err := evsservice.EvsSlotOriginOf(push.statement)
	if err != nil {
		return slotId, nil, err
	}
	metadata, err := origin.Metadata(evsservice.DefaultEvsSettings().SlotOriginMaxByteCount)
	if err != nil {
		return slotId, nil, err
	}
	if _, err := self.cluster.PutIfNoneMatch(ctx, evsOracleSlotKey(self.repoId, slotId.Bytes()), body, &sidecar.BlobPutOptions{Metadata: metadata}); err != nil {
		return slotId, nil, err
	}
	if !recorded {
		return slotId, push, nil
	}
	return slotId, push, self.writeRecord(ctx, push)
}

// QD-870's leak, which FI-6 excuses: an attempt writes its slot under its statement's origin and dies before its
// record (QD-806's order), and its statement is never sent again, so no batch, container or head ever names it and
// nothing reclaims the slot. FI-6 reads the run clean past the 26 h deadline, beside a committed push's slot, and the
// slot still stands, so the pass is the excuse's and not the slot's absence.
func TestFi6TakesTheSlotOfAnAttemptThatDiedBeforeItsRecord(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var slotId sidecar.Id
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			slotId, _, err = world.originSlotPush(ctx, main, false)
			return err
		}},
		{Actor: "clock", Advance: 25 * time.Hour},
		{Actor: "clock", Advance: 2 * time.Hour},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-died-before-record", Steps: steps, Check: []Invariant{FI(6)}}, world.net))
	if _, err := world.cluster.Head(t.Context(), evsOracleSlotKey(world.repoId, slotId.Bytes())); err != nil {
		t.Fatalf("the dead attempt's slot is not there to excuse: %v", err)
	}
}

// The twin: the same slot under its statement's origin, but the attempt reached its record, so a batch held its
// statement and evacuation had the record to judge. Once the push is dead (the fence after its 35 min), a buggy
// evacuation drops the record's batch and leaves the slot; past the deadline FI-6 reports it, though the batch that
// held the statement is gone, since it remembers the statement from the check that saw the batch.
func TestFi6CatchesAnOrphanSlotWhoseStatementABatchHeld(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var pending *fiHandPush
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			_, pending, err = world.originSlotPush(ctx, main, true)
			return err
		}},
		{Actor: "clock", Advance: 36 * time.Minute},
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			if _, err := world.heads.RaiseFence(ctx, world.cluster, world.repoId, main); err != nil {
				return err
			}
			// the dead record goes with its batch, and its own slot is left behind
			return world.cluster.Delete(ctx, evsservice.BatchKey(pending.place.GetMinute(), pending.place.GetInstance(), pending.place.GetSeq()))
		}},
		{Actor: "clock", Advance: 25 * time.Hour},
		{Actor: "clock", Advance: 2 * time.Hour},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-held-orphan-slot", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 5, "FI-6", "which no committed version names", "no reclaimer finds it",
		"a batch held its origin's statement, push "+sidecar.Id(pending.statement.Push.GetPushId()).String())
}

// The excuse reads the origin as DESIGN-DETAILS 14.2.2 gives it, in FI-6's own code: what evsservice writes for a
// push's slot names that statement, and a re-seed's origin, no origin, a value past the bound and every malformed one
// name none, as evs reads them, so an orphan carrying any of them is still reported. Each case is held to evsservice's
// own reading too.
func TestFi6ReadsASlotOriginAsStepSixWritesIt(t *testing.T) {
	world := newFiHandWorld(t)
	_, push, err := world.originSlotPush(t.Context(), sidecar.NewId(), false)
	if err != nil {
		t.Fatal(err)
	}
	maxByteCount := DefaultFi6Settings().SlotOriginMaxByteCount
	origin, err := evsservice.EvsSlotOriginOf(push.statement)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := origin.Metadata(maxByteCount)
	if err != nil {
		t.Fatal(err)
	}
	statement, ok := fi6SlotOriginStatement(metadata, maxByteCount)
	if want := fi6StatementOf(sidecar.Id(push.statement.Push.GetPushId()), push.statement.Sha256); !ok || statement != want {
		t.Fatalf("read %v %t from %q, not the push's statement", statement, ok, metadata[fi6SlotOriginMetadataKey])
	}

	value := metadata[fi6SlotOriginMetadataKey]
	fields := strings.Split(value, ".")
	with := func(index int, field string) map[string]string {
		changed := append([]string{}, fields...)
		changed[index] = field
		return map[string]string{fi6SlotOriginMetadataKey: strings.Join(changed, ".")}
	}
	cases := []map[string]string{
		nil,
		{"origin-other": value},
		{fi6SlotOriginMetadataKey: evsservice.EvsSlotOriginReseeded().Encode()},
		{fi6SlotOriginMetadataKey: value + ".f"},
		{fi6SlotOriginMetadataKey: strings.Join(fields[:8], ".")},
		with(0, "2"),
		with(1, "r"),
		with(2, "A"+fields[2][1:]),
		with(3, fields[3][:30]),
		with(4, "zz"+fields[4][2:]),
		with(6, "0"+fields[6]),
		with(7, "-1"),
		with(8, "x"),
	}
	for i, metadata := range cases {
		if _, ok := fi6SlotOriginStatement(metadata, maxByteCount); ok {
			t.Errorf("case %d, %q, read as a statement's origin", i, metadata)
		}
		if evsservice.ParseEvsSlotOrigin(metadata, maxByteCount).Kind == evsservice.EvsSlotOriginPush {
			t.Errorf("case %d, %q, evs reads as a push's origin", i, metadata)
		}
	}
	if _, ok := fi6SlotOriginStatement(metadata, len(value)-1); ok {
		t.Error("an origin past the bound read as a statement's")
	}
}

// FI-6 judges an orphan by the deadline its settings name: narrowed to an hour, a slot no committed version names and
// no batch lists, with no origin, is reported two hours on, where the 26 h default would wait.
func TestFi6HoldsAnOrphanSlotToItsSettingsDeadline(t *testing.T) {
	world := newFiHandWorld(t)
	settings := DefaultFi6Settings()
	settings.DeadSlotDeadline = time.Hour
	SetFi6Settings(world.net, settings)
	steps := []*Step{
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			body, err := world.slotBody(1)
			if err != nil {
				return err
			}
			_, err = world.cluster.PutIfNoneMatch(ctx, evsOracleSlotKey(world.repoId, sidecar.NewEvsSlotId().Bytes()), body, nil)
			return err
		}},
		{Actor: "clock", Advance: 2 * time.Hour},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-settings-deadline", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 1, "FI-6", "is 2h0m0s old and no batch record lists it", "it carries no push's origin")
}

// A pending push's new slot deleted while its push may still commit: FI-6 finds an unknown outcome reclaimed.
func TestFi6CatchesAPendingPushsSlotReclaimed(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var pendingSlotId sidecar.Id
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			pendingSlotId, _, err = world.slotPush(ctx, main, true)
			return err
		}},
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			return world.cluster.Delete(ctx, evsOracleSlotKey(world.repoId, pendingSlotId.Bytes()))
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-pending-slot", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 2, "FI-6", "still pending", "an unknown outcome reclaimed")
}

// The twin: once evacuation's fence makes the push dead (its statement's 35 min passed and the head's fence_ms
// later), its slot goes cleanly, as §11.13's resolve row has it.
func TestFi6TakesADeadPushsSlotReclaimed(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var pendingSlotId sidecar.Id
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, _, err := world.slotPush(ctx, main, false)
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			pendingSlotId, _, err = world.slotPush(ctx, main, true)
			return err
		}},
		{Actor: "clock", Advance: 36 * time.Minute},
		{Actor: "evacuator", Action: func(ctx context.Context, net *Net) error {
			if _, err := world.heads.RaiseFence(ctx, world.cluster, world.repoId, main); err != nil {
				return err
			}
			return world.cluster.Delete(ctx, evsOracleSlotKey(world.repoId, pendingSlotId.Bytes()))
		}},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-dead-slot", Steps: steps, Check: []Invariant{FI(6)}}, world.net))
}

// An unadopted segment's bytes, uploaded under its id as the segment route stores them.
func (self *fiWorld) orphanSegment(ctx context.Context, net *Net) error {
	content := []byte(fmt.Sprintf("an orphan uploaded at %s", net.Clock().Now()))
	segmentId := sha256.Sum256(content)
	_, err := self.segmentCluster().PutIfNoneMatch(ctx, evsOracleSegmentKey(self.repoId, segmentId[:]), content, nil)
	return err
}

// A step deleting every segment no committed version names, as orphan GC would.
func (self *fiWorld) deleteOrphanSegments(ctx context.Context, net *Net) error {
	segments, err := fiKeys(ctx, self.segmentCluster(), evsOracleRepoPrefix("seg/", self.repoId))
	if err != nil {
		return err
	}
	for _, segment := range segments {
		if err := self.segmentCluster().Delete(ctx, segment.Key); err != nil {
			return err
		}
	}
	return nil
}

// An unadopted segment deleted 10 h after its upload, before GC's horizon could pass its bound: FI-6 finds a
// segment a push could still adopt reclaimed (DESIGN-DETAILS 2.2.4).
func TestFi6CatchesASegmentDeletedBeforeTheHorizon(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "uploaderB", Action: world.orphanSegment},
		{Actor: "clock", Advance: 10 * time.Hour},
		{Actor: "gc", Action: world.deleteOrphanSegments},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-early-gc", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 4, "FI-6", "GC's horizon is never past its bound")
}

// An unadopted segment deleted 50 h after its upload while a batch from before its bound is left: the horizon is
// that batch's, short of the bound, so FI-6 finds it reclaimed too early.
func TestFi6CatchesASegmentDeletedBehindAnOldBatch(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "uploaderB", Action: world.orphanSegment},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "clock", Advance: 50 * time.Hour},
		{Actor: "gc", Action: world.deleteOrphanSegments},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-gc-behind-batch", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 4, "FI-6", "before its bound, was left: a push in it could still adopt it")
}

// The twin: evacuation has taken every batch, and the segment is 50 h old, so GC's horizon passed its bound and its
// deletion reads clean.
func TestFi6TakesAnOrphanSegmentPastTheHorizon(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "uploaderB", Action: world.orphanSegment},
		{Actor: "writerA", Action: world.write("a.txt", 100)},
		{Actor: "clock", Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.evacuate},
		{Actor: "clock", Advance: 24 * time.Hour},
		{Actor: "gc", Action: world.deleteOrphanSegments},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-gc-past-horizon", Steps: steps, Check: []Invariant{FI(6)}}, world.net))
}

// Across a cut-over, a path folded in epoch 1 is found where a reader finds it while the source stands: in its source
// copy, which the committed map's move names, then in its current copy once the copy moved it and deleted the source,
// reading clean at each step (DESIGN-DETAILS 9.2.1's one home per path).
func TestFi6FindsANewestVersionInItsSourceAcrossACutOver(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var source, target sidecar.EvsTokenPath
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			source, err = world.foldedFile(ctx, main)
			return err
		}},
		{Actor: "mapperA", Action: func(ctx context.Context, net *Net) error {
			var move *protocol.EvsPathMove
			move, target = fiMove(source)
			_, err := world.cutOver(ctx, main, []*protocol.EvsPathMove{move})
			return err
		}},
		{Actor: "copier", Action: func(ctx context.Context, net *Net) error {
			sourceKey := evsOracleIndexKey(world.repoId, main, 1, source)
			object, err := world.cluster.Get(ctx, sourceKey)
			if err != nil {
				return err
			}
			body := new(bytes.Buffer)
			_, err = body.ReadFrom(object.Body)
			object.Body.Close()
			if err != nil {
				return err
			}
			if _, err := world.cluster.PutIfNoneMatch(ctx, evsOracleIndexKey(world.repoId, main, 2, target), body.Bytes(), nil); err != nil {
				return err
			}
			return world.cluster.Delete(ctx, sourceKey)
		}},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-cut-over", Steps: steps, Check: fiChecks()}, world.net))
}

// A source copy deleted while the source stands and before the copy wrote the current one: the path's newest
// version is in no entry a reader reads, and FI-6 says so.
func TestFi6CatchesASourceCopyDeletedBeforeTheCopy(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	var source sidecar.EvsTokenPath
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			source, err = world.foldedFile(ctx, main)
			return err
		}},
		{Actor: "mapperA", Action: func(ctx context.Context, net *Net) error {
			move, _ := fiMove(source)
			_, err := world.cutOver(ctx, main, []*protocol.EvsPathMove{move})
			return err
		}},
		{Actor: "copier", Action: func(ctx context.Context, net *Net) error {
			return world.cluster.Delete(ctx, evsOracleIndexKey(world.repoId, main, 1, source))
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-source-deleted", Steps: steps, Check: []Invariant{FI(6)}}, world.net)
	fiRequireViolation(t, result, 2, "FI-6", "newest version at 1 is folded", "in no entry: the reader cannot find it")
}

// A directory's table missing a row its folded deltas leave, names_through kept: FI-6 reads the rows themselves, not
// names_through alone.
func TestFi6CatchesANameTableMissingAFoldedRow(t *testing.T) {
	world := newFiWorld(t)
	steps := []*Step{
		{Actor: "writerA", Action: world.createGroup},
		{Actor: "writerA", Action: world.write("docs/b.txt", 100)},
		{Actor: "writerA", Action: world.write("docs/c.txt", 100)},
		{Actor: "evs", Action: world.fold},
		{Actor: "writerA", Action: world.write("d.txt", 100)},
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			infos, err := fiKeys(ctx, world.cluster(), evsOracleRefPrefix("idx/", world.repoId, world.refId))
			if err != nil {
				return err
			}
			for _, info := range infos {
				object, err := world.cluster().Get(ctx, info.Key)
				if err != nil {
					return err
				}
				body := new(bytes.Buffer)
				_, err = body.ReadFrom(object.Body)
				object.Body.Close()
				if err != nil {
					return err
				}
				entry := &protocol.EvsIndexEntry{}
				if err := proto.Unmarshal(body.Bytes(), entry); err != nil {
					return err
				}
				if len(entry.GetNames().GetNames()) < 2 {
					continue
				}
				entry.Names.Names = entry.Names.Names[1:]
				entryBytes, err := proto.Marshal(entry)
				if err != nil {
					return err
				}
				_, err = world.cluster().PutIfMatch(ctx, info.Key, object.Etag, entryBytes, nil)
				return err
			}
			return fmt.Errorf("no directory entry with two rows among %d entries", len(infos))
		}},
	}
	result := Run(t.Context(), &Schedule{Id: "fi6-table-row", Steps: steps, Check: fiChecks()}, world.net)
	fiRequireViolation(t, result, 5, "FI-6", "its table lacks the row")
}

// An orphan marker under idx/<repo>/<ref>/_o/ sits outside every epoch (QD-011): FI-6 leaves it to format 2's
// oracles rather than reading it as an entry of no epoch.
func TestFi6LeavesAnOrphanMarkerOutsideTheEpochs(t *testing.T) {
	world := newFiHandWorld(t)
	main := sidecar.NewId()
	steps := []*Step{
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			_, err := world.foldedFile(ctx, main)
			return err
		}},
		{Actor: "evs", Action: func(ctx context.Context, net *Net) error {
			markerBytes, err := proto.Marshal(&protocol.EvsIndexEntry{Marker: &protocol.EvsRemovalMarker{PushId: sidecar.NewId().Bytes(), RemovalVersion: 1}})
			if err != nil {
				return err
			}
			key := evsOracleRefPrefix("idx/", world.repoId, main) + "_o/" + evsOracleNumber(1) + "-0123456789abcdef.e"
			_, err = world.cluster.PutIfNoneMatch(ctx, key, markerBytes, nil)
			return err
		}},
	}
	fiRequirePass(t, Run(t.Context(), &Schedule{Id: "fi6-orphan-marker", Steps: steps, Check: []Invariant{FI(6)}}, world.net))
}
