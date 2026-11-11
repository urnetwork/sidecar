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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
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
	// C at the base version, which resolve walks the statement at base + 1 from: local state beside 8.2.8's
	// fields, so the walk is the verifier's.
	BaseChain string `json:"base_chain"`
	Old       string `json:"old,omitempty"`
	New       string `json:"new,omitempty"`
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

// A statement's own time bounds, §11.8's: a push posts within 10 minutes of its time_ms, and one in parts seals within
// 30. Format values every evs process applies, not tunables.
const (
	evsStatementPostBound = 10 * time.Minute
	evsStatementSealBound = 30 * time.Minute
)

// What resolve found of one attempt.
type evsJournalOutcome int

const (
	evsJournalPending evsJournalOutcome = iota
	evsJournalCommitted
	evsJournalDead
)

// resolve(r) (see the file header): the ref replayed to its head from the cluster, then each attempt judged by the
// history alone. A git-mode push on base b can commit only at b + 1 (TIP), so the statement at b + 1, walked from the
// attempt's base chain, says whether it did: its push id the attempt's is committed (another statement hash under it
// alarms), any other is dead; a head still at b is pending until the attempt's time bound and JournalResolveMargin
// have passed and a head read after that still shows none.
func (self *EvsGitReceiver) resolve(ctx context.Context, refId Id) error {
	journal, err := self.engine.state.journal(refId)
	if err != nil || len(journal.Attempts) == 0 {
		return err
	}
	if err := self.engine.Replay(ctx, refId); err != nil {
		return err
	}
	head, err := self.repo.pinnedHead(ctx, refId)
	if err != nil {
		return err
	}
	outcomes := map[Id]evsJournalOutcome{}
	now := self.clock.Now()
	for _, attempt := range journal.Attempts {
		outcome, err := self.judgeAttempt(ctx, refId, head, attempt, now)
		if err != nil {
			return err
		}
		outcomes[attempt.PushId] = outcome
	}
	return self.withApply(ctx, refId, func() error {
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return err
		}
		committed, pending := false, false
		kept := []*EvsJournalAttempt{}
		for _, attempt := range journal.Attempts {
			outcome, judged := outcomes[attempt.PushId]
			switch {
			case !judged, outcome == evsJournalPending:
				pending = true
				kept = append(kept, attempt)
			case outcome == evsJournalCommitted:
				committed = true
			}
		}
		journal.Attempts = kept
		_, owned := EvsOwnedRefOwner(journal.RefName)
		switch {
		case committed:
			// the version applied through the replay above; what settle has not covered goes too
			ref, err := self.engine.state.gitRef(refId)
			if err != nil {
				return err
			}
			if err := self.engine.dropCoveredWithLock(ctx, ref, journal); err != nil {
				return err
			}
			for _, update := range slices.Clone(journal.Updates) {
				if update.State == EvsJournalSent && !owned {
					journal.deleteUpdate(update.Seq)
				}
			}
		case !pending:
			// dead: TIP lets none of them commit, ever
			for _, update := range slices.Clone(journal.Updates) {
				if update.State != EvsJournalSent {
					continue
				}
				if owned {
					update.State = EvsJournalLocal
				} else {
					journal.deleteUpdate(update.Seq)
				}
			}
		}
		return self.engine.state.writeJournal(refId, journal)
	})
}

// One attempt's outcome against the verified head.
func (self *EvsGitReceiver) judgeAttempt(ctx context.Context, refId Id, head *EvsVerifiedHead, attempt *EvsJournalAttempt, now time.Time) (evsJournalOutcome, error) {
	if head.Version <= attempt.BaseVersion {
		bound := evsStatementPostBound
		if attempt.Parts {
			bound = evsStatementSealBound
		}
		if now.After(time.UnixMilli(attempt.TimeMs).Add(bound + self.settings.JournalResolveMargin)) {
			// this head was read after the bound passed, and shows none
			return evsJournalDead, nil
		}
		return evsJournalPending, nil
	}
	chainBytes, err := hex.DecodeString(attempt.BaseChain)
	if err != nil || len(chainBytes) != 32 {
		return evsJournalPending, fmt.Errorf("%w: an attempt's base chain", ErrEvsJournalInvalid)
	}
	version := attempt.BaseVersion + 1
	statements, err := self.client.readLog(ctx, self.mount.RepoId, refId, version, version)
	if err != nil {
		return evsJournalPending, err
	}
	walked, err := self.client.verifier.walk(self.mount.RepoId, refId, attempt.BaseVersion, [32]byte(chainBytes), statements, version)
	if err != nil {
		return evsJournalPending, err
	}
	statement := walked[0].Statement
	if Id(statement.Push.GetPushId()) != attempt.PushId {
		return evsJournalDead, nil
	}
	if evsStatementHashText(statement.Sha256) != attempt.StatementSha256 {
		// a statement under this device's push id that is not the one it journaled: one push id signed twice
		self.client.alarm(self.mount.RepoId, refId, SidecarEvsAlarmTamper, "", nil)
	}
	return evsJournalCommitted, nil
}

// resolve for every ref with an attempt open: the queue's each JournalResolveInterval, and each hint's.
func (self *EvsGitReceiver) resolveAll(ctx context.Context) {
	refIds, err := self.engine.state.journalRefIds()
	if err != nil {
		return
	}
	for _, refId := range refIds {
		if err := self.resolve(ctx, refId); err != nil && self.client.log.V(1).Enabled() {
			self.client.log.Infof("[evs]resolve of repo %s ref %s: %v", self.mount.RepoId, refId, err)
		}
	}
}

// One ref's open work as `ur status` shows it: its pending outcomes, LOCAL updates and hold.
type EvsJournalStatus struct {
	RefId   Id
	RefName []byte
	// An attempt whose outcome is unknown: "remote outcome pending".
	Pending bool
	// Updates the queue has not published.
	Queued int
	// A final refusal holding an owned ref's queue: its code, empty for none.
	HoldCode string
}

// Every ref's open work in the mount's journals.
func (self *EvsGitReceiver) JournalStatus() ([]*EvsJournalStatus, error) {
	refIds, err := self.engine.state.journalRefIds()
	if err != nil {
		return nil, err
	}
	statuses := []*EvsJournalStatus{}
	for _, refId := range refIds {
		journal, err := self.engine.state.journal(refId)
		if err != nil {
			return nil, err
		}
		status := &EvsJournalStatus{RefId: refId, RefName: journal.RefName, Pending: 0 < len(journal.Attempts), HoldCode: journal.HoldCode}
		for _, update := range journal.Updates {
			if update.State == EvsJournalLocal {
				status.Queued += 1
			}
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}
