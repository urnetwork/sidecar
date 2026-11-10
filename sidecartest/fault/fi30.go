// FI-30, store settle (D-OPS-20), and the store's share of FI-2, read from what clients saw.

package fault

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Three of FI-30's four clauses, on whichever store the Net's host holds: a PUT or DELETE takes effect
// before the next request or never, none past its deadline does, and no write or heal undoes what a
// later write acknowledged or a read returned. A DELETE that named its object and was refused 412 took
// no effect, like any failed condition. The fourth, that a key is held only while a PUT lacking a write
// quorum could still reach a read quorum, or a DELETE lacking one has a drive commit yet to answer or
// be reverted (§19.6), needs real drives: FS-114 checks it on T3, on D-OPS-20's build.
var _ = RegisterInvariant(30, func(ctx context.Context, oracle *Oracle) error {
	return sidecartest.CheckBlobHistory(oracle.BlobHistory(), nil)
})

// FI-2's clause a store can show by itself: unknown never triggers destructive cleanup. An actor whose
// write's outcome is unknown does not delete that key before it has read it again. The rest of FI-2
// is evs's, and FI(2) stays unbuilt until evs writes it, so this is a separate invariant.
var UnknownDeletesNothing Invariant = NewInvariant("FI-2/unknown", func(ctx context.Context, oracle *Oracle) error {
	unknownKeys := map[string]bool{}
	for _, entry := range oracle.BlobHistory() {
		actorKey := entry.Actor + "\x00" + entry.ClusterId + "\x00" + entry.Key
		switch entry.Op {
		case sidecartest.BlobHistoryGet, sidecartest.BlobHistoryGetRange, sidecartest.BlobHistoryHead:
			if entry.Outcome == sidecartest.BlobOutcomeOk || entry.Outcome == sidecartest.BlobOutcomeNotFound {
				delete(unknownKeys, actorKey)
			}
		case sidecartest.BlobHistoryDelete:
			if unknownKeys[actorKey] {
				return fmt.Errorf("%s deleted %s on an unknown outcome, with no read between", entry.Actor, entry.Key)
			}
		case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
			if entry.Outcome == sidecartest.BlobOutcomeUnknown {
				unknownKeys[actorKey] = true
			}
		}
	}
	return nil
})
