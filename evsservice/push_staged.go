// A format-2 record's tail (§11.8's batches and record rows, EVS-FORMAT.md's batches; R-EVS-20, D-EVS-36; EVS2-M10-06):
// a push's or a part's staged segments ride its record after its payload, outside every hash, as the request carried
// them, so evacuation writes each to seg/ only while its version is retained (§11.13's staged row); and a push's,
// part's or seal's purge list rides after them (push_purge.go). A record with neither keeps format 1's form. Every
// bound counts the tail: the list is marked when it would take the record past 1 MiB (plan-EVS2-small-readings#13).
//
// Not safe for concurrent use: it lives on its attempt.

package evsservice

import (
	"fmt"

	"github.com/urnetwork/sidecar"
)

// The tail of the record this attempt appends at step 6, its purge list computed once and kept for every rerun: a
// one-part push's candidates, or a seal's from its parts' (a part's is push_part.go's). nil for a format-1 record.
func (self *pushAttempt) recordTail() (*sidecar.EvsBatchRecordTail, error) {
	if !self.engine.format2Instance() || self.reads == nil || self.reads.view == nil || self.payload == nil {
		return nil, nil
	}
	if self.purge == nil {
		base := sidecar.EvsBatchRecordHeaderByteCount + len(self.batchRecord().Body)
		if 0 < len(self.staged) {
			base += 4 + len(self.staged)
		}
		room := evsPurgeListRoom(base)
		if self.seal != nil {
			self.purge = evsSealPurge(self.reads.view, self.seal.partLists, room)
		} else {
			self.purge = evsPushPurge(self.reads.view, room)
		}
	}
	return evsRecordTail(self.staged, self.purge)
}

// A record's tail from its staged bytes and its purge list; nil when it carries neither.
func evsRecordTail(staged []byte, purge *pushPurge) (*sidecar.EvsBatchRecordTail, error) {
	tail := &sidecar.EvsBatchRecordTail{Staged: staged}
	if purge != nil && purge.list != nil {
		listBytes, err := sidecar.EncodeEvsPurgeList(purge.list)
		if err != nil {
			return nil, fmt.Errorf("evs: a purge list that does not encode: %w", err)
		}
		tail.PurgeList = listBytes
	}
	if tail.Empty() {
		return nil, nil
	}
	return tail, nil
}
