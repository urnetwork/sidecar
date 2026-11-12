// §11.8's outcomes rows for one attempt of a push (D-EVS-23):
//
//	5a       on every head the attempt reads: P committed answers 200 {its version}, P under another statement 409
//	         PUSH_ID_REUSED, P's refusal record its refusal with recorded: true (resolve.go's standing)
//	fence    an attempt that reads a head whose fence_ms is later than its arrival less 100 ms ends 503 {push_id,
//	         outcome: unknown}, issuing no further step 7: only evacuation and GC fences set fence_ms (push_step4.go)
//	412      reread the head from the cluster; committed, recorded or fenced settle it; otherwise, since an ETag never
//	         repeats, the old PUT can never apply, so 5 (b-h) runs again on the reread head against the gate view read
//	         again (QD-660), the entries keeping the folded_through they were read after, and step 7 goes again on its
//	         ETag, at most PushConflictRetryCount times before 429 BUSY (push_commit.go counts)
//	unknown  a timeout, EOF or 5xx on step 7 deletes nothing: the head is reread from the cluster up to
//	         PushUnknownRereadCount times, PushUnknownRereadInterval apart, a read the settle rule orders after the
//	         PUT; committed or recorded settle it; the ETag step 7 named means the PUT never landed, so it is issued
//	         again within the 5 s window, else steps 4 and 5 run again; another ETag is a 412; no reread answering
//	         is 503 unknown
//
// A commit 5a finds after this attempt's own lost PUT, at this attempt's place and version, is this attempt's, so
// step 8 runs for it.

package evsservice

import (
	"context"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// 5a on head: an outcome when the push id is settled there, nil to go on.
func (self *pushAttempt) settle(stored *EvsStoredHead) *pushOutcome {
	push := self.statement.Push
	gitMode := protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
	standing, err := EvsPushStandingIn(self.ctx, stored.Head, self.pushId, self.statement.Sha256, push.GetBaseVersion(), gitMode,
		func(ctx context.Context, page uint64) (*LogPage, error) {
			return self.engine.readLogPage(ctx, self.cluster, self.repoId, self.refId, page)
		})
	if err != nil {
		return self.unavailableOn(err)
	}
	switch {
	case standing.Committed:
		var ownCommit *EvsStoredHead
		if self.issued && self.place != nil && sameEvsPlace(standing.Place, self.place) && stored.Version() == standing.Version {
			// this attempt's own step 7, whose answer was lost: step 8 is still owed
			ownCommit = stored
		}
		self.issued = false
		outcome := committedOutcome(standing.Version, ownCommit)
		if ownCommit == nil {
			outcome.committedPlace = standing.Place
		}
		if self.ownDepositRef() {
			// a 5a retry carries the current head (plan-EVS1-deposit-head)
			outcome.depositHead = self.depositHeadOf(stored.Head)
		}
		return outcome
	case standing.Reused:
		return refusedOutcome(&protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED})
	case standing.Recorded != nil:
		self.issued = false
		return refusedOutcome(&protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: standing.Recorded.Code, Recorded: true})
	}
	return nil
}

// Whether two places name the same record.
func sameEvsPlace(a *protocol.EvsPlace, b *protocol.EvsPlace) bool {
	return a.GetMinute() == b.GetMinute() && a.GetInstance() == b.GetInstance() && a.GetSeq() == b.GetSeq() &&
		a.GetOffset() == b.GetOffset() && a.GetLength() == b.GetLength()
}

// §11.8's 412 row after step 7 failed its precondition: reread, settle, or rerun 5 (b-h) on the reread head. A nil
// outcome with again false issues step 7 again on self.head.
func (self *pushAttempt) afterConflict() (*pushOutcome, bool) {
	reread, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		return self.unavailableOn(err), false
	}
	return self.recheck(reread)
}

// 5a, the fence and 5 (b-h) on a head reread from the cluster, which the next step 7 writes on.
func (self *pushAttempt) recheck(reread *EvsStoredHead) (*pushOutcome, bool) {
	if outcome := self.settle(reread); outcome != nil {
		return outcome, false
	}
	if self.fenced(reread.Head) {
		return self.unknown(), false
	}
	self.head = reread
	if outcome := self.readGateView(); outcome != nil {
		return outcome, false
	}
	if outcome, again := self.buildView(); outcome != nil || again {
		return outcome, again
	}
	if refusal := self.check(); refusal != nil {
		return self.refuse(refusal), false
	}
	return nil, false
}

// §11.8's unknown row after step 7's outcome was lost, prior being the head it was issued on. A nil outcome with again
// false issues step 7 again on self.head.
func (self *pushAttempt) afterUnknown(prior *EvsStoredHead) (*pushOutcome, bool) {
	var reread *EvsStoredHead
	for attempt := 0; attempt < self.settings.PushUnknownRereadCount; attempt += 1 {
		if 0 < attempt && 0 < self.settings.PushUnknownRereadInterval {
			select {
			case <-self.engine.clock.After(self.settings.PushUnknownRereadInterval):
			case <-self.ctx.Done():
				return self.unknown(), false
			}
		}
		head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
		if err == nil {
			reread = head
			break
		}
	}
	if reread == nil {
		// the store unreachable: the client's retry resolves it
		return self.unknown(), false
	}
	if outcome := self.settle(reread); outcome != nil {
		return outcome, false
	}
	if self.fenced(reread.Head) {
		return self.unknown(), false
	}
	if reread.Etag == prior.Etag && reread.Absent() == prior.Absent() {
		// the PUT never landed and never will (§19.6's settle rule orders this read after it)
		self.issued = false
		if self.withinStepSeven() {
			return nil, false
		}
		return nil, true
	}
	// another write came first: as a 412
	self.issued = false
	return self.recheck(reread)
}

// The answer to a push whose refusal fence this attempt could not land: another attempt of it may still, so the
// client retries.
func (self *pushAttempt) recordingUnknown() *pushOutcome {
	return refusedOutcome(&protocol.EvsRefusalReply{
		PushId:  self.pushId.Bytes(),
		Code:    protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE,
		Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN,
	})
}

// Whether a head records refusal itself: its push, statement and code.
func headRecords(head *protocol.EvsHead, record *sidecar.EvsRefusal) bool {
	refusals, err := sidecar.DecodeEvsRefusals(head.GetRefused())
	if err != nil {
		return false
	}
	for _, refusal := range refusals {
		if refusal.PushIdPrefix == record.PushIdPrefix && refusal.StatementPrefix == record.StatementPrefix && refusal.Code == record.Code {
			return true
		}
	}
	return false
}
