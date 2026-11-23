//go:build !ios_extension

// Format 2's own rule beside §11.8's refs table, a CUT's signer a repo admin at the statement's pin (I-EVS-16's reader
// half), asks its signer a right there, so it is not judged where that pin lies before what the reader retains
// (QD-1178).

package sidecar

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A format-2 reader refuses a CUT by a writer that is no repo admin at a judged pin, and walks it where every pin lies
// before what it retains, reading the path before it with no alarm.
func TestEvsUnjudgedCutByAWriterThatIsNoAdminWalks(t *testing.T) {
	cut := func(world *evsTestWorld) {
		world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
		world.nextFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
		world.push(&evsTestChange{path: ".ur-index/i1/a/0", content: []byte("shard"),
			format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_INDEX, "shard")})
	}

	judged := newEvsTestWorld(t)
	cut(judged)
	reader := evsTestFormat2Reader(t, judged)
	if _, _, err := evsTestRead(t, reader, judged, "a.txt"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a CUT by a writer that is no admin at a judged pin: %v", err)
	}

	unjudged := newEvsTestWorld(t)
	cut(unjudged)
	func() {
		unjudged.config.stateLock.Lock()
		defer unjudged.config.stateLock.Unlock()
		unjudged.config.atErr = ErrGkmAuthNotRetained
	}()
	reader = evsTestFormat2Reader(t, unjudged)
	if content, _, err := evsTestRead(t, reader, unjudged, "a.txt"); err != nil || string(content) != "one" {
		t.Fatalf("a CUT by a writer that is no admin, unjudged: %q %v", content, err)
	}
	evsTestRequireNoAlarm(t, "an unjudged CUT", reader)
}
