//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The journal (DESIGN-DETAILS 8.2.8; D-EVS-28): one sealed file per ref with open work, local/<repo>/journal/<ref_id>,
// rewritten whole under the ref's apply lock L_r. It records intent, never truth: what the daemon meant to do with a
// ref and every push id it sent for it. An outcome is read from the ref's history and nowhere else (resolve), so no
// crash, lost answer or late attempt can make it wrong in a way that moves a ref.
//
//	state      written                                          at a start
//	RECEIVED   before anything else an update does              shared: delete it (nothing was sent, no ref moved);
//	                                                            owned: the local ref is old -> move it, go LOCAL;
//	                                                            else delete it
//	LOCAL      an owned ref's local ref is new                  the queue goes on
//	SENT       before an attempt's first POST, with its record, resolve(r)
//	           on every update the attempt covers
//	(deleted)  the update is applied, refused or dead
//
//	resolve    replay(r) to the head, from the cluster; then under L_r: an attempt's push id in the history
//	           (its statement hash equal; another hash alarms) -> committed, settle applies it and deletes the update;
//	           the head above every attempt's base and none in the history -> dead, TIP lets none commit, a shared
//	           ref's update deleted and an owned ref's back to LOCAL; else pending ("remote outcome pending"), asked
//	           again at each hint and each JournalResolveInterval, and dead once the local clock is past each attempt's
//	           time bound (10 min, 30 for parts) plus JournalResolveMargin and a head read after that shows none
//
// A daemon never sends a statement again after a restart, and never needs to: an attempt in the history committed,
// one the head has passed never will, and one that is neither can land only until its statement's time bound. A
// wrong "dead" moves no ref: a late attempt that commits after all is a version like any other, which replay applies.
//
// The record is JSON, as the local tier's other records are: it is never sent, and DESIGN-DETAILS 8.2.8's message is
// its shape. Oids are hex.
//
// Desktop legs only. Package functions are safe for concurrent use as the store is; callers hold L_r.

package sidecar

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// An update's states (8.2.8's table).
type EvsJournalState int

const (
	EvsJournalReceived EvsJournalState = 1
	EvsJournalLocal    EvsJournalState = 2
	EvsJournalSent     EvsJournalState = 3
)

// Who journaled an update.
type EvsJournalKind int

const (
	EvsJournalKindReceive  EvsJournalKind = 1
	EvsJournalKindQueue    EvsJournalKind = 2
	EvsJournalKindImport   EvsJournalKind = 3
	EvsJournalKindConflict EvsJournalKind = 4
)

// One ref's journal (8.2.8's EvsJournalRef).
type EvsJournalRef struct {
	RefName []byte `json:"ref_name,omitempty"`
	// Oldest first; a shared ref holds at most one.
	Updates []*EvsJournalUpdate `json:"updates,omitempty"`
	// Every push id sent for them and not yet resolved, oldest first.
	Attempts []*EvsJournalAttempt `json:"attempts,omitempty"`
	NextSeq  uint64               `json:"next_seq,omitempty"`
	// An owned ref's final refusal, which holds its queue until its local ref moves or `ur evs retry`: the refusal's
	// code and when it came. Empty for none.
	HoldCode string `json:"hold_code,omitempty"`
	HoldMs   int64  `json:"hold_ms,omitempty"`
	// The local ref when the hold came, so a move of it releases the hold.
	HoldLocal string `json:"hold_local,omitempty"`
}

// One update of a ref.
type EvsJournalUpdate struct {
	Seq uint64 `json:"seq"`
	// Hex oids, empty for none.
	Old        string          `json:"old,omitempty"`
	New        string          `json:"new,omitempty"`
	State      EvsJournalState `json:"state"`
	Kind       EvsJournalKind  `json:"kind"`
	ReceivedMs int64           `json:"received_ms"`
}

// One attempt sent for a ref's updates.
type EvsJournalAttempt struct {
	PushId          Id     `json:"push_id"`
	StatementSha256 string `json:"statement_sha256"`
	BaseVersion     uint64 `json:"base_version"`
	Old             string `json:"old,omitempty"`
	New             string `json:"new,omitempty"`
	// The statement's time, and whether it seals (30 min) or posts (10 min).
	TimeMs int64 `json:"time_ms"`
	Parts  bool  `json:"parts,omitempty"`
}

// A journal record that does not decode.
var ErrEvsJournalInvalid = errors.New("evs: a journal record that does not decode")

// An oid's hex, empty for none.
func evsOidText(oid *EvsGitOid) string {
	if oid == nil {
		return ""
	}
	return hex.EncodeToString(oid[:])
}

// The oid hex gives, nil for empty.
func evsOidOfText(text string) (*EvsGitOid, error) {
	if text == "" {
		return nil, nil
	}
	oid, err := evsGitOidDecodeHex([]byte(text))
	if err != nil {
		return nil, err
	}
	return &oid, nil
}

// Whether two optional oids are one.
func evsOidEqual(a *EvsGitOid, b *EvsGitOid) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// The ref's journal, empty when it has none.
func (self *evsLocalState) journal(refId Id) (*EvsJournalRef, error) {
	journal := &EvsJournalRef{}
	if _, err := self.readJson(EvsLocalKey{Family: EvsLocalJournals, RefId: refId}, journal); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsJournalInvalid, err)
	}
	return journal, nil
}

// Writes the ref's journal whole, durable once it answers, or removes it when it holds no work.
func (self *evsLocalState) writeJournal(refId Id, journal *EvsJournalRef) error {
	key := EvsLocalKey{Family: EvsLocalJournals, RefId: refId}
	if len(journal.Updates) == 0 && len(journal.Attempts) == 0 && journal.HoldCode == "" {
		return self.remove(key)
	}
	return self.writeJson(key, journal)
}

// Every ref with a journal.
func (self *evsLocalState) journalRefIds() ([]Id, error) {
	keys, err := self.list(EvsLocalJournals)
	if err != nil {
		return nil, err
	}
	refIds := make([]Id, 0, len(keys))
	for _, key := range keys {
		refIds = append(refIds, key.RefId)
	}
	return refIds, nil
}

// Adds an update in state, answering it.
func (self *EvsJournalRef) add(old *EvsGitOid, new *EvsGitOid, state EvsJournalState, kind EvsJournalKind, at time.Time) *EvsJournalUpdate {
	self.NextSeq += 1
	update := &EvsJournalUpdate{
		Seq: self.NextSeq, Old: evsOidText(old), New: evsOidText(new), State: state, Kind: kind, ReceivedMs: at.UnixMilli(),
	}
	self.Updates = append(self.Updates, update)
	return update
}

// The update of seq, nil for none.
func (self *EvsJournalRef) update(seq uint64) *EvsJournalUpdate {
	for _, update := range self.Updates {
		if update.Seq == seq {
			return update
		}
	}
	return nil
}

// Deletes the update of seq.
func (self *EvsJournalRef) deleteUpdate(seq uint64) {
	kept := self.Updates[:0]
	for _, update := range self.Updates {
		if update.Seq != seq {
			kept = append(kept, update)
		}
	}
	self.Updates = kept
	if len(self.Updates) == 0 {
		// no update left for an attempt to cover
		self.Attempts = nil
	}
}

// Notes an attempt sent for the updates, before its first POST.
func (self *EvsJournalRef) addAttempt(attempt *EvsJournalAttempt) {
	self.Attempts = append(self.Attempts, attempt)
	// every update the attempt covers, a receive's RECEIVED or the queue's LOCAL, goes SENT
	for _, update := range self.Updates {
		update.State = EvsJournalSent
	}
}

// Whether it queues work for an owned ref whose local ref is local: settle's Q (DESIGN-DETAILS 8.2.7), its newest
// LOCAL or SENT update's new being the local ref.
func (self *EvsJournalRef) queued(local *EvsGitOid) bool {
	for i := len(self.Updates) - 1; 0 <= i; i -= 1 {
		update := self.Updates[i]
		if update.State == EvsJournalLocal || update.State == EvsJournalSent {
			return update.New == evsOidText(local)
		}
	}
	return false
}

// The statement hash of a built push, as an attempt records it.
func evsStatementHashText(digest [sha256.Size]byte) string {
	return hex.EncodeToString(digest[:])
}
