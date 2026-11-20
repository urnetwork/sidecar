// EVS1-M2-30's root tests: a CLOSURE re-checkpoints standing files with its flag, its erased list and its erasure's
// id in its sealed metadata's erasure note (QD-682), and one refused 412 PATH_EPOCH is re-tokenized with its segment
// and receipt kept, so its closure upload is charged once (DESIGN-DETAILS 9.6's K); a CLOSURE that would create a
// path, or that names no erasure, is refused before anything is sent; and the two notes' layouts. The ERASE's
// end-to-end cases are sidecartest/evs_deposit_test.go's.
//
// SlotKeysOf's rule (QD-1109; EVS2-M10-12) on the evs stand-in, whose general repo names no slot, so a list is empty
// and only whether it is a list shows: a path first created at version N past its ref's first push walks whole, as
// does one created again whose first life began past 1; a walk cut at HistoryVersionCount, one ending where evs
// answers nothing below a removal, and one ending where evs answers nothing for the version a listed one replaced are
// refused. The lists' slots on the real engine are sidecartest/evs_erase_seam_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A CLOSURE across a cut-over: one upload for its checkpoint, the retoken keeping it, its statement carrying CLOSURE
// and the erased list it was given.
func TestEvsClosureAcrossACutOverUploadsOnce(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.uploadMs = writer.test.clock.Now().UnixMilli()
	if _, err := writer.write(t, "index.bin", evsTestContent("index", 64*1024)); err != nil {
		t.Fatal(err)
	}
	uploads := len(writer.server.uploads)
	writer.gkm.newest = 2
	writer.world.generation = 2
	writer.cutOverAtPushes(2)
	erased := []*EvsErasedKey{{SlotId: evsTestId("old chain's slot"), KeyIndex: 3}}
	closed := evsTestContent("index without the entry", 64*1024)
	erasureId := evsTestId("the erasure")
	result, err := writer.repo.Closure(context.Background(), &EvsClosureArgs{
		ErasureId: erasureId, Writes: []*EvsPathWrite{{Path: "index.bin", Content: bytes.NewReader(closed)}}, Erased: erased,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(writer.server.uploads) - uploads; got != 1 {
		t.Fatalf("%d closure uploads across the cut-over", got)
	}
	statement, checked := writer.committedPayload(t, result.Version)
	if statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) == 0 || statement.Push.GetPathEpoch() != 2 ||
		len(checked.Erased) != 1 || checked.Erased[0].SlotId != erased[0].SlotId || checked.Erased[0].KeyIndex != 3 {
		t.Fatalf("the CLOSURE's statement: flags %d, epoch %d, erased %v", statement.Push.GetFlags(), statement.Push.GetPathEpoch(), checked.Erased)
	}
	// its erasure's id, sealed with the push's metadata under the generation the retoken's statement names, and
	// nothing more (QD-682)
	metadata, err := EvsOpenMetadata(evsTestKeys(t, writer.world.repoId, statement.Push.GetGeneration()).manifest, checked.SealedMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(metadata.GetErasureNote(), erasureId.Bytes()) {
		t.Fatalf("the CLOSURE's erasure note: %x", metadata.GetErasureNote())
	}
	if noted, err := ParseEvsClosureNote(metadata.GetErasureNote()); err != nil || noted != erasureId {
		t.Fatalf("the CLOSURE's note parsed: %v %v", noted, err)
	}
	if read, _, err := writer.read(t, "index.bin"); err != nil || !bytes.Equal(read, closed) {
		t.Fatalf("read back: %v", err)
	}
	// a write that is no CLOSURE or ERASE carries no erasure note
	plain, err := writer.write(t, "index.bin", evsTestContent("index again", 64*1024))
	if err != nil {
		t.Fatal(err)
	}
	statement, checked = writer.committedPayload(t, plain.Version)
	metadata, err = EvsOpenMetadata(evsTestKeys(t, writer.world.repoId, statement.Push.GetGeneration()).manifest, checked.SealedMetadata)
	if err != nil || len(metadata.GetErasureNote()) != 0 {
		t.Fatalf("a plain write's erasure note: %x %v", metadata.GetErasureNote(), err)
	}
}

// A CLOSURE replaces committed file versions alone: one that would create a path is refused, nothing sent.
func TestEvsClosureRefusesACreation(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.know("new.bin")
	_, err := writer.repo.Closure(context.Background(), &EvsClosureArgs{
		ErasureId: evsTestId("the erasure"), Writes: []*EvsPathWrite{{Path: "new.bin", Content: bytes.NewReader([]byte("x"))}},
	})
	if !errors.Is(err, ErrEvsWriteInvalid) || len(writer.server.postedStatements) != 0 {
		t.Fatalf("a creating CLOSURE: %v, %d posts", err, len(writer.server.postedStatements))
	}
}

// A CLOSURE's sealed note names its erasure (§11.12's rekey row): one given no erasure id is refused, nothing read or
// sent.
func TestEvsClosureRefusesNoErasure(t *testing.T) {
	writer := newEvsTestWriter(t)
	if _, err := writer.write(t, "index.bin", []byte("index")); err != nil {
		t.Fatal(err)
	}
	posts := len(writer.server.postedStatements)
	_, err := writer.repo.Closure(context.Background(), &EvsClosureArgs{Writes: []*EvsPathWrite{{Path: "index.bin", Content: bytes.NewReader([]byte("x"))}}})
	if !errors.Is(err, ErrEvsWriteInvalid) || len(writer.server.postedStatements) != posts {
		t.Fatalf("a CLOSURE of no erasure: %v, %d posts", err, len(writer.server.postedStatements)-posts)
	}
}

// The erasure notes' bytes (QD-682; EVS-FORMAT.md's erasure notes): an ERASE's is its erasure's id, 16 B, the complete
// byte and the caller's bytes; a CLOSURE's is the id alone. Each parse refuses the other's shape where the lengths
// tell them apart, a short note, and a complete byte that is neither 0 nor 1.
func TestEvsErasureNoteLayout(t *testing.T) {
	erasureId := evsTestId("the erasure")
	caller := []byte("what the keys covered")
	for _, complete := range []bool{false, true} {
		note := EvsEraseNote(erasureId, complete, caller)
		want := append(append(erasureId.Bytes(), 0), caller...)
		if complete {
			want[16] = 1
		}
		if !bytes.Equal(note, want) {
			t.Fatalf("an ERASE's note: %x", note)
		}
		noted, notedComplete, notedCaller, err := ParseEvsEraseNote(note)
		if err != nil || noted != erasureId || notedComplete != complete || !bytes.Equal(notedCaller, caller) {
			t.Fatalf("an ERASE's note parsed: %v %v %q %v", noted, notedComplete, notedCaller, err)
		}
	}
	// an ERASE with no caller bytes is its 17 B header
	if note := EvsEraseNote(erasureId, true, nil); len(note) != 17 {
		t.Fatalf("an ERASE's note of no caller bytes: %d bytes", len(note))
	}
	closure := EvsClosureNote(erasureId)
	if !bytes.Equal(closure, erasureId.Bytes()) {
		t.Fatalf("a CLOSURE's note: %x", closure)
	}
	if noted, err := ParseEvsClosureNote(closure); err != nil || noted != erasureId {
		t.Fatalf("a CLOSURE's note parsed: %v %v", noted, err)
	}
	badComplete := EvsEraseNote(erasureId, false, caller)
	badComplete[16] = 2
	for label, note := range map[string][]byte{
		"none": nil, "a CLOSURE's note as an ERASE's": closure, "a complete byte of 2": badComplete,
	} {
		if _, _, _, err := ParseEvsEraseNote(note); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("an ERASE's note, %s: %v", label, err)
		}
	}
	for label, note := range map[string][]byte{
		"none": nil, "an ERASE's note as a CLOSURE's": EvsEraseNote(erasureId, true, nil), "15 bytes": closure[:15],
	} {
		if _, err := ParseEvsClosureNote(note); !errors.Is(err, ErrEvsEntryRefused) {
			t.Errorf("a CLOSURE's note, %s: %v", label, err)
		}
	}
}

// A path first created by its ref's Nth push starts at version N (§11.7's versions row: a creation takes max(b, m) + 1),
// and one created again after a removal walks across it into the life before; each walk ends at a creation evs answers
// nothing below, so SlotKeysOf takes it whole (QD-1109): a list, here of no slot.
func TestEvsSlotKeysOfAPathBornPastVersionOneIsWhole(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	world.push(&evsTestChange{path: "b.txt", content: []byte("b")})
	// c.txt first created by the third push, then written again
	world.push(&evsTestChange{path: "c.txt", content: []byte("c one")})
	world.push(&evsTestChange{path: "c.txt", content: []byte("c two")})
	// d.txt first created by the fifth push, removed at 6, created again at max(6, 6) + 1 = 7
	world.push(&evsTestChange{path: "d.txt", content: []byte("d one")})
	world.push(&evsTestChange{path: "d.txt"})
	world.push(&evsTestChange{path: "d.txt", content: []byte("d again")})
	reader := world.reader(t, evsTestId("reader"))
	repo := reader.client.Repo(world.repoId)
	for _, c := range []struct {
		path     string
		versions string
	}{
		{path: "c.txt", versions: "[4 3/created]"},
		{path: "d.txt", versions: "[7/created 6/removed 5/created]"},
	} {
		history, err := repo.History(context.Background(), &EvsReadArgs{Path: c.path})
		if err != nil || evsTestHistoryVersions(history) != c.versions || !history.Whole || history.BelowUnknown {
			t.Fatalf("%s: %s %v, whole %v", c.path, evsTestHistoryVersions(history), err, history != nil && history.Whole)
		}
		if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{c.path}); err != nil || keys == nil || len(keys) != 0 {
			t.Fatalf("%s's slot keys: %v %v", c.path, keys, err)
		}
	}
	if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A walk cut at HistoryVersionCount read nothing below its last version, even where that is the path's creation, so
// SlotKeysOf refuses it (QD-1109's "the walk not cut at HistoryVersionCount"); one version more and the walk reads
// below the creation and is whole.
func TestEvsSlotKeysOfRefusesAWalkCutAtItsBound(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
	for _, content := range []string{"c one", "c two", "c three"} {
		world.push(&evsTestChange{path: "c.txt", content: []byte(content)})
	}
	reader := world.reader(t, evsTestId("reader"))
	repo := reader.client.Repo(world.repoId)
	reader.client.settings.HistoryVersionCount = 3
	history, err := repo.History(context.Background(), &EvsReadArgs{Path: "c.txt"})
	if err != nil || evsTestHistoryVersions(history) != "[4 3 2/created]" || history.Whole {
		t.Fatalf("cut at 3: %s %v, whole %v", evsTestHistoryVersions(history), err, history != nil && history.Whole)
	}
	if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"c.txt"}); !errors.Is(err, ErrEvsSlotKeysIncomplete) || keys != nil {
		t.Fatalf("slot keys of a walk cut at its bound: %v %v", keys, err)
	}
	reader.client.settings.HistoryVersionCount = 4
	if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"c.txt"}); err != nil || len(keys) != 0 {
		t.Fatalf("slot keys of the walk one version longer: %v %v", keys, err)
	}
}

// Where evs answers nothing at a number the walk must find a version at, the walk reached no first version, and
// SlotKeysOf refuses it: below a removal, whose ended life's last version stands one below it, and below a version
// that names the one it replaced. Before, each such walk was taken whole, so an ERASE built from it would have left
// the hidden versions' slots standing.
func TestEvsSlotKeysOfRefusesAWalkEvsAnswersNothingInside(t *testing.T) {
	// the reply evs gives for a path's version hidden, as if nothing stood at or below its number
	hide := func(world *evsTestWorld, hidden uint64) {
		world.mutatePath = func(reply *protocol.EvsReadPathReply) {
			entry := &protocol.EvsEntryVersion{}
			if reply.GetVersion() == nil || proto.Unmarshal(reply.GetVersion().GetEntryVersion(), entry) != nil || entry.GetVersion() != hidden {
				return
			}
			reply.Version, reply.Statement, reply.Proof, reply.Absences = nil, nil, nil, nil
		}
	}
	for _, c := range []struct {
		label    string
		contents []string
		hidden   uint64
		versions string
	}{
		// e.txt created at 2, written at 3, removed at 4 and created again at 5; evs hides 3, the removed life's last
		{label: "below a removal", contents: []string{"e one", "e two", "", "e again"}, hidden: 3, versions: "[5/created 4/removed]"},
		// e.txt created at 2 and written at 3 and 4; evs hides 3, which 4 names as the version it replaced
		{label: "below a version naming its predecessor", contents: []string{"e one", "e two", "e three"}, hidden: 3, versions: "[4]"},
	} {
		world := newEvsTestWorld(t)
		world.push(&evsTestChange{path: "a.txt", content: []byte("a")})
		for _, content := range c.contents {
			if content == "" {
				world.push(&evsTestChange{path: "e.txt"})
				continue
			}
			world.push(&evsTestChange{path: "e.txt", content: []byte(content)})
		}
		hide(world, c.hidden)
		reader := world.reader(t, evsTestId("reader"))
		repo := reader.client.Repo(world.repoId)
		history, err := repo.History(context.Background(), &EvsReadArgs{Path: "e.txt"})
		if err != nil || evsTestHistoryVersions(history) != c.versions || history.Whole {
			t.Fatalf("%s: %s %v, whole %v", c.label, evsTestHistoryVersions(history), err, history != nil && history.Whole)
		}
		if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"e.txt"}); !errors.Is(err, ErrEvsSlotKeysIncomplete) || keys != nil {
			t.Fatalf("%s: slot keys %v %v", c.label, keys, err)
		}
		// served again, the same walk reaches the first creation
		world.mutatePath = nil
		if keys, err := repo.SlotKeysOf(context.Background(), nil, []string{"e.txt"}); err != nil || len(keys) != 0 {
			t.Fatalf("%s, served: slot keys %v %v", c.label, keys, err)
		}
	}
}
