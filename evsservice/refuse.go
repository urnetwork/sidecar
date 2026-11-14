// §11.8's refuse and first rows (D-EVS-23, I-EVS-3): every refusal rests on a head read from the cluster. One the
// head or a terminal repo/ state settles for good is final and answered as is, as is one that refuses nothing (400,
// 429, 503). Any other is recorded before it is answered: one head CAS, the push's refusal fence, raises the fence
// and adds {P's first 8 bytes, its statement's first 2, the code, until} to the head's refusal records, until being
// time_ms plus P's bound and 1 s, and sets refused_ms. Then no attempt of P commits, however late it reaches evs: one
// that read an older head fails step 7 on the new ETag, one that reads the record gets it from 5a, and one that
// reads the head after the record lapsed fails 5b's time check, the dropping writer's clock being within 50 ms.
//
//	limit    with 8 records live, or a refusal fence under RefusalFenceInterval old by refused_ms, the push gets 429
//	         WAIT with retry_after_ms instead, refusing nothing: a stream of failing pushes records one a second and
//	         ends no honest push's attempt, since a refusal fence sets no fence_ms
//	retry    on a 412 the head is reread from the cluster: P committed answers 200, P recorded its refusal, a fence
//	         past the arrival 503 unknown, else the CAS again, at most PushRefusalRetryCount times, then 503 {push_id,
//	         outcome: unknown}; an unknown outcome rereads and finds its own record or tries again
//	first    a push creating its ref, whose head is absent, records in a placeholder head created If-None-Match at
//	         version 0 with no window, kind or mode, which reads treat as absent and the ref's first commit replaces
//	         by If-Match, keeping its records; the placeholder stays, as a tombstone head does
//
// The recording CAS is paid with its request (§11.13's order row: "a refusal's record with its request"), at one head
// overwrite. A PATH_EPOCH_DUE refusal of a push crossing a REMOVE generation also writes that due, as the commit
// would have (DESIGN-DETAILS 9.2.6; question details-9-crossing-creation).

package evsservice

import (
	"errors"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The answer for refusal: as is when final or refusing nothing, else after the refuse row records it.
func (self *pushAttempt) refuse(refusal *EvsCheckRefusal) *pushOutcome {
	if refusal.Fate != EvsRefusalRecorded || self.part != nil || self.reseed != nil {
		// a part's refusal needs no record, since only its push's seal commits (§11.8's refuse row); a re-seed's
		// records none, so the device sends the push again once what it lacked is there (reseed.go)
		return refusedOutcome(refusal.Reply(self.pushId))
	}
	return self.record(refusal)
}

// The refuse row's recording CAS over self.head, a cluster head. See the file header.
func (self *pushAttempt) record(refusal *EvsCheckRefusal) *pushOutcome {
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPushRefuseBefore, barrierKey)
	defer testHookBarrier(BarrierPushRefuseAfter, barrierKey)
	push := self.statement.Push
	untilMs := time.UnixMilli(push.GetTimeMs()).Add(self.timeBound() + time.Second).UnixMilli()
	record, err := sidecar.NewEvsRefusal(self.pushId, self.statement.Sha256, refusal.Code, untilMs)
	if err != nil {
		// a code the table records but the record cannot hold: this code's fault, and nothing is written
		self.engine.log.Errorf("[evs] alarm refusal_record: %v", err)
		return self.unavailable()
	}
	if outcome := self.admitRecording(); outcome != nil {
		return outcome
	}
	head := self.head
	if head.Cached {
		reread, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
		if err != nil {
			return self.unavailableOn(err)
		}
		head = reread
	}
	for attempt := 0; attempt <= self.settings.PushRefusalRetryCount; attempt += 1 {
		if 0 < attempt {
			if outcome := self.settle(head); outcome != nil {
				return outcome
			}
			if self.fenced(head.Head) {
				return self.unknown()
			}
		}
		now := self.engine.clock.Now()
		live, err := liveRefusals(head.Head, now)
		if err != nil {
			return self.unavailableOn(err)
		}
		if wait := self.recordingWait(head.Head, live, now); 0 < wait {
			return refusedOutcome(&protocol.EvsRefusalReply{
				PushId:       self.pushId.Bytes(),
				Code:         protocol.EvsRefusalCode_EVS_REFUSAL_WAIT,
				RetryAfterMs: uint32(max(1, (wait+time.Millisecond-1)/time.Millisecond)),
			})
		}
		next := CloneEvsHead(head.Head)
		next.Fence = head.Head.GetFence() + 1
		next.RefusedMs = now.UnixMilli()
		refused, err := sidecar.EncodeEvsRefusals(append(live, record))
		if err != nil {
			return self.unavailableOn(err)
		}
		next.Refused = refused
		if due := self.refusalDue(refusal, head.Head); due != nil {
			next.PathEpoch = applyPathEpochDue(next.GetPathEpoch(), due, now)
		}
		written, err := self.engine.heads.Commit(self.writeCtx, self.cluster, self.repoId, self.refId, head, next)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			self.head = written
			return refusedOutcome(refusal.Reply(self.pushId))
		case errors.Is(err, sidecar.ErrBlobPrecondition):
		case errors.As(err, &unknown):
			reread, readErr := self.rereadAfterUnknown()
			if readErr != nil {
				return self.recordingUnknown()
			}
			if headRecords(reread.Head, record) {
				self.head = reread
				return refusedOutcome(refusal.Reply(self.pushId))
			}
			head = reread
			continue
		default:
			return self.unavailableOn(err)
		}
		reread, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
		if err != nil {
			return self.unavailableOn(err)
		}
		head = reread
	}
	return self.recordingUnknown()
}

// The due a refusal's fence write records over head (DESIGN-DETAILS 9.2.6): a PATH_EPOCH_DUE refusal of a push
// that crosses a REMOVE generation records that due as its commit would have, so the first push across a removal
// stops creation whether it commits or not. nil for any other refusal, and for a head whose current epoch already
// reaches the due's generation, which a PATH_EPOCH landing first cleared.
func (self *pushAttempt) refusalDue(refusal *EvsCheckRefusal, head *protocol.EvsHead) *pathEpochDue {
	if self.due == nil || refusal.Reason != EvsCheckReasonPathEpochDue || head.GetVersion() == 0 {
		return nil
	}
	if self.due.generation <= EvsHeadCurrentEpoch(head) {
		return nil
	}
	return self.due
}

// The head's refusal records not lapsed at now.
func liveRefusals(head *protocol.EvsHead, now time.Time) ([]*sidecar.EvsRefusal, error) {
	refusals, err := sidecar.DecodeEvsRefusals(head.GetRefused())
	if err != nil {
		return nil, err
	}
	live := make([]*sidecar.EvsRefusal, 0, len(refusals))
	for _, refusal := range refusals {
		if !refusal.LapsedAt(now.UnixMilli()) {
			live = append(live, refusal)
		}
	}
	return live, nil
}

// How long the push waits before a refusal fence may be raised for it: until the oldest of 8 live records lapses,
// or until the newest refusal fence is RefusalFenceInterval old; zero when it may be raised now.
func (self *pushAttempt) recordingWait(head *protocol.EvsHead, live []*sidecar.EvsRefusal, now time.Time) time.Duration {
	wait := time.Duration(0)
	if sidecar.EvsHeadMaxRefusalCount <= len(live) {
		earliest := live[0].UntilS
		for _, refusal := range live {
			earliest = min(earliest, refusal.UntilS)
		}
		wait = max(wait, time.Unix(int64(earliest), 0).Sub(now))
	}
	if refusedMs := head.GetRefusedMs(); refusedMs != 0 {
		wait = max(wait, time.UnixMilli(refusedMs).Add(self.settings.RefusalFenceInterval).Sub(now))
	}
	return wait
}

// The head from the cluster after a write whose outcome was lost: up to PushUnknownRereadCount reads,
// PushUnknownRereadInterval apart.
func (self *pushAttempt) rereadAfterUnknown() (*EvsStoredHead, error) {
	var lastErr error
	for attempt := 0; attempt < self.settings.PushUnknownRereadCount; attempt += 1 {
		if 0 < attempt && 0 < self.settings.PushUnknownRereadInterval {
			select {
			case <-self.engine.clock.After(self.settings.PushUnknownRereadInterval):
			case <-self.ctx.Done():
				return nil, self.ctx.Err()
			}
		}
		head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
		if err == nil {
			return head, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// The budget for the recording CAS: the push's own grant when step 6 took one, else one head overwrite at P1.
func (self *pushAttempt) admitRecording() *pushOutcome {
	if self.grant != nil {
		return nil
	}
	cost, err := PricePush(self.engine.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: WriteOperationOverwrite, ObjectByteCount: int64(len(self.head.Bytes) + sidecar.EvsRefusalByteCount), Count: 1}},
	})
	if err != nil {
		return self.unavailableOn(err)
	}
	grant, err := self.engine.budget.AdmitP1(self.ctx, self.cluster.ClusterId(), connect.Id(self.tokenNetworkId), cost)
	var budgetRefusal *sidecar.WriteRefusal
	switch {
	case errors.As(err, &budgetRefusal):
		return refusedOutcome(&protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED,
			RetryAfterMs: max(1, budgetRefusal.RetryAfterMs()),
		})
	case err != nil:
		return self.unavailable()
	}
	self.grant = grant
	self.writeCtx = grant.Context()
	return nil
}
