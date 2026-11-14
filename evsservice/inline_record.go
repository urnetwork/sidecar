// Inline records on evs (QD-735; question evs1-m2-01-inline-record-home): an inline record rides only inside its
// entry version's kind-2 locator, so entry_sha256 covers it and a push carries it once.
//
//	push      the codecs refuse payload section 3 and EvsPushPart.inline_records, held for kind 3's push-payload
//	          range (§11.6's kinds row), and a kind-2 locator holding no record or naming an id, an offset or a
//	          length, each 400 INVALID; 5h adopts nothing for a kind-2 locator (check_objects.go)
//	idx/      a file's newest folded version keeps its inline records and each older one has them elided, every
//	          locator's inline bytes cut and nothing else (fold.go's elideEvsIndexVersion); evs restores an elided
//	          version from its push record before it serves the signed bytes, by its leaf place, or in an inline
//	          list whose place is unrecorded by the one write of its push whose bytes elide to its own (read.go,
//	          read_proof.go)
//	dropped   from a drop's not_before_ms evs serves a listed version's entry version only when its chain names no
//	          inline record, and never an inline record of its chain (§11.9's serve row; DESIGN-DETAILS 10.2's
//	          withheld rows): droppedEntryVersionServed. Format 1 serves no drop state, so nothing reads a listed
//	          version through it until format 2's drop states are served (EVS2-M10-10)
//
// Package-level functions are safe for concurrent use.

package evsservice

import (
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Whether a version's chain names an inline record: a kind-2 locator, whole or elided.
func evsChainNamesInlineRecord(entry *protocol.EvsEntryVersion) bool {
	for _, locator := range entry.GetChain() {
		if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_INLINE {
			return true
		}
	}
	return false
}

// The entry version bytes evs may serve for a version an executed drop lists, from the drop's not_before_ms on
// (§11.9's serve row): the bytes as given when the chain names no inline record, else nil, the path's reply then
// carrying the statement and the state alone, since serving that entry version would serve its records. Bytes that
// do not parse as an entry version are withheld too.
func droppedEntryVersionServed(entryBytes []byte) []byte {
	entry := &protocol.EvsEntryVersion{}
	if len(entryBytes) == 0 || proto.Unmarshal(entryBytes, entry) != nil || evsChainNamesInlineRecord(entry) {
		return nil
	}
	return entryBytes
}
