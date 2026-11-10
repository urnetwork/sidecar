// EVS1-M2-30's root tests: a CLOSURE re-checkpoints standing files with its flag and erased list, and one refused 412
// PATH_EPOCH is re-tokenized with its segment and receipt kept, so its closure upload is charged once (DESIGN-DETAILS
// 9.6's K); a CLOSURE that would create a path is refused before anything is sent. The ERASE's end-to-end cases are
// sidecartest/evs_deposit_test.go's.

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
	result, err := writer.repo.Closure(context.Background(), &EvsClosureArgs{
		Writes: []*EvsPathWrite{{Path: "index.bin", Content: bytes.NewReader(closed)}}, Erased: erased,
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
	if read, _, err := writer.read(t, "index.bin"); err != nil || !bytes.Equal(read, closed) {
		t.Fatalf("read back: %v", err)
	}
}

// A CLOSURE replaces committed file versions alone: one that would create a path is refused, nothing sent.
func TestEvsClosureRefusesACreation(t *testing.T) {
	writer := newEvsTestWriter(t)
	writer.server.know("new.bin")
	_, err := writer.repo.Closure(context.Background(), &EvsClosureArgs{Writes: []*EvsPathWrite{{Path: "new.bin", Content: bytes.NewReader([]byte("x"))}}})
	if !errors.Is(err, ErrEvsWriteInvalid) || len(writer.server.postedStatements) != 0 {
		t.Fatalf("a creating CLOSURE: %v, %d posts", err, len(writer.server.postedStatements))
	}
}
