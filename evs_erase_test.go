// EVS1-M2-30's root tests: a CLOSURE re-checkpoints standing files with its flag, its erased list and its erasure's
// id in its sealed metadata's erasure note (QD-682), and one refused 412 PATH_EPOCH is re-tokenized with its segment
// and receipt kept, so its closure upload is charged once (DESIGN-DETAILS 9.6's K); a CLOSURE that would create a
// path, or that names no erasure, is refused before anything is sent; and the two notes' layouts. The ERASE's
// end-to-end cases are sidecartest/evs_deposit_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"

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
