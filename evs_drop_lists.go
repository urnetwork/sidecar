//go:build !ios_extension

// A version's membership in a DROP's lists, from its signed body alone (plan-EVS2-drop-list-proof, decided): a ref's
// version V, committed in path epoch e at token path t, is listed exactly when one of the body's paths holds (e, t) in
// its lineage, V is below that path's through_version, and V has an entry, a removal never being listed
// (plan-EVS2-small-readings#1). A head reader decides from the body its read returns (EvsReadPathReply.drop_body),
// checked against the DROP's drop_sha256; listed_sha256 and the listed set's equality with the lineage's versions are a
// replaying reader's and the drop job's resolve, since only they hold the whole list.
//
// On every leg. An EvsDropLists is immutable once built, and safe for concurrent use.

package sidecar

import (
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// One lineage entry's place: its epoch and token path.
type evsDropLineageKey struct {
	epoch     uint64
	tokenPath string
}

// A DROP's body, checked and indexed by lineage entry.
type EvsDropLists struct {
	history *protocol.EvsDropHistory
	// each lineage entry's paths, by index in the body
	entryPaths map[evsDropLineageKey][]int
}

// The lists of the DROP push states: body must hash to its drop_sha256 and hold its shape and not_before_ms, as
// EvsCheckDropPayload's body checks hold them; a cancel's lists hold nothing.
func NewEvsDropLists(push *protocol.EvsPush, body []byte) (*EvsDropLists, error) {
	history, err := evsCheckDropBody(DefaultEvsFormatSettings(), push, body)
	if err != nil {
		return nil, err
	}
	lists := &EvsDropLists{history: history, entryPaths: map[evsDropLineageKey][]int{}}
	for i, path := range history.GetPaths() {
		for _, entry := range path.GetLineage() {
			tokenPath, err := ParseEvsChangedTokenPath(entry.GetTokenPath())
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
			}
			key := evsDropLineageKey{epoch: entry.GetEpoch(), tokenPath: string(tokenPath.Bytes())}
			lists.entryPaths[key] = append(lists.entryPaths[key], i)
		}
	}
	return lists, nil
}

// The body as parsed.
func (self *EvsDropLists) History() *protocol.EvsDropHistory {
	return self.history
}

// Whether the DROP lists the version of a path that committed in pathEpoch at tokenPath, a removal or not, and the
// index of the path listing it, -1 when none does.
func (self *EvsDropLists) Lists(pathEpoch uint64, tokenPath EvsTokenPath, version uint64, removal bool) (int, bool) {
	if removal || version == 0 {
		return -1, false
	}
	for _, i := range self.entryPaths[evsDropLineageKey{epoch: pathEpoch, tokenPath: string(tokenPath.Bytes())}] {
		if version < self.history.GetPaths()[i].GetThroughVersion() {
			return i, true
		}
	}
	return -1, false
}
