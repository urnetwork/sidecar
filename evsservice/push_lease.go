// POST /evs/v1/repos/<id>/push/<push_id>/lease (§11.8's lease row; EVS1-M2-13): the seal lease of a git-mode push in
// parts, {ref_id, base_version, ms <= 120,000} (rw), taken after the push's segments and before its parts. It reads
// the head as step 4 does, then one head CAS sets lease {P, until} and raises the fence, changing no version, only
// if v = base_version and no other push's lease is live:
//
//	own      P's own live lease answers 200 without a write; P committed in the window answers 200, and P in the
//	         head's refusal records their refusal, as 5a
//	412      the head is reread from the cluster: the version still base_version with no other live lease -> the CAS
//	         again on the reread ETag, at most PushConflictRetryCount times, then 429 BUSY
//	other    another push's live lease -> 429 WAIT with retry_after_ms; another version, read from the cluster -> 409
//	         NON_FAST_FORWARD; a file-mode head -> 409 REF_MODE, since only git-mode refs take leases
//	first    a ref with no head takes its lease in a placeholder head created If-None-Match at version 0, as a
//	         refusal record does (§11.8's first row), which reads treat as absent and the seal replaces by If-Match
//
// Then other pushes to the ref get 429 from 5f until the lease ends or the seal clears it; reads never wait, since
// a lease sets no fence_ms and changes no version; an expired lease is ignored, and the seal still commits only by
// TIP and the head If-Match, so a stalled holder cannot commit over a newer tip. A lease sets no fence_ms, so it
// ends no attempt (§11.8's fence row).

package evsservice

import (
	"bytes"
	"errors"
	"net/http"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route's template.
const evsLeaseRouteTemplate = "POST /evs/v1/repos/{repo_id}/push/{push_id}/lease"

// §11.8's lease row: ms at most 120,000.
const evsLeaseMaxDuration = 120 * time.Second

// The lease route.
func (self *EvsEngine) leaseRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:         http.MethodPost,
			Pattern:        evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/push/{" + evsPushIdPathValue + "}/lease",
			Name:           evsLeaseRouteTemplate,
			Rights:         sidecar.AclEvsWrite | sidecar.AclEvsAdmin,
			Write:          true,
			NeedsSureClock: true,
			Placed:         true,
			Serve:          self.serveLease,
		},
	}
}

// See the file header.
func (self *EvsEngine) serveLease(request *EvsRequest) {
	pushId, err := parseEvsHexId(request.Http.PathValue(evsPushIdPathValue))
	if err != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	body := &protocol.EvsLeaseRequest{}
	if !request.ReadMessage(body, self.settings.PushBodyMaxByteCount) {
		return
	}
	refId, err := sidecar.IdFromBytes(body.GetRefId())
	duration := time.Duration(body.GetMs()) * time.Millisecond
	if err != nil || duration <= 0 || min(evsLeaseMaxDuration, self.settings.LeaseMaxDuration) < duration {
		request.Refuse(&protocol.EvsRefusalReply{PushId: pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID})
		return
	}
	request.NoteRefIds(refId)
	lease := &leaseAttempt{
		engine:   self,
		request:  request,
		repoId:   request.RepoId,
		refId:    refId,
		pushId:   pushId,
		base:     body.GetBaseVersion(),
		duration: duration,
	}
	reply := lease.run()
	switch {
	case reply == nil:
		request.Reply(nil)
	case reply.GetCode() == protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE:
		request.Unavailable(reply)
	default:
		request.Refuse(reply)
	}
}

// One request for a lease.
type leaseAttempt struct {
	engine   *EvsEngine
	request  *EvsRequest
	repoId   sidecar.Id
	refId    sidecar.Id
	pushId   sidecar.Id
	base     uint64
	duration time.Duration
	grant    sidecar.WriteGrant
}

// The lease's answer: nil for a 200, else the refusal.
func (self *leaseAttempt) run() *protocol.EvsRefusalReply {
	defer func() {
		if self.grant != nil {
			self.grant.Close()
		}
	}()
	engine := self.engine
	ctx := self.request.Ctx
	cluster := self.request.Cluster
	head, err := engine.heads.ReadCached(ctx, cluster, self.repoId, self.refId, self.base, false)
	if err != nil {
		return self.unavailable()
	}
	for attempt := 0; attempt <= engine.settings.PushConflictRetryCount; attempt += 1 {
		reply, write := self.decide(head)
		if reply != nil || !write {
			if reply != nil && head.Cached && reply.GetCode() != protocol.EvsRefusalCode_EVS_REFUSAL_WAIT {
				// every refusal rests on a head read from the cluster
				head, err = engine.heads.ReadCluster(ctx, cluster, self.repoId, self.refId)
				if err != nil {
					return self.unavailable()
				}
				continue
			}
			return reply
		}
		if reply := self.admit(head); reply != nil {
			return reply
		}
		untilMs := engine.clock.Now().Add(self.duration).UnixMilli()
		next := CloneEvsHead(head.Head)
		if next == nil {
			next = &protocol.EvsHead{}
		}
		next.Fence = next.GetFence() + 1
		next.Lease = &protocol.EvsSealLease{PushId: self.pushId.Bytes(), UntilMs: untilMs}
		barrierKey := barrierRefKey(self.repoId, self.refId)
		testHookBarrier(BarrierLeaseCasBefore, barrierKey)
		written, err := engine.heads.Commit(self.grant.Context(), cluster, self.repoId, self.refId, head, next)
		testHookBarrier(BarrierLeaseCasAfter, barrierKey)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			_ = written
			return nil
		case errors.Is(err, sidecar.ErrBlobPrecondition):
		case errors.As(err, &unknown):
			reread, readErr := engine.heads.ReadCluster(ctx, cluster, self.repoId, self.refId)
			if readErr != nil {
				return self.unavailable()
			}
			if lease := reread.Head.GetLease(); lease != nil && bytes.Equal(lease.GetPushId(), self.pushId.Bytes()) && lease.GetUntilMs() == untilMs {
				return nil
			}
			head = reread
			continue
		default:
			return self.unavailable()
		}
		head, err = engine.heads.ReadCluster(ctx, cluster, self.repoId, self.refId)
		if err != nil {
			return self.unavailable()
		}
	}
	return &protocol.EvsRefusalReply{
		PushId:       self.pushId.Bytes(),
		Code:         protocol.EvsRefusalCode_EVS_REFUSAL_BUSY,
		RetryAfterMs: uint32(max(1, self.engine.settings.UnavailableRetryAfter.Milliseconds())),
	}
}

// What head says to the lease: a refusal, or write true for the CAS, or neither for a 200 with no write.
func (self *leaseAttempt) decide(head *EvsStoredHead) (*protocol.EvsRefusalReply, bool) {
	now := self.engine.clock.Now()
	refuse := func(code protocol.EvsRefusalCode) *protocol.EvsRefusalReply {
		return &protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: code}
	}
	if !head.Absent() {
		window, err := EvsHeadWindow(head.Head)
		if err != nil {
			return self.unavailable(), false
		}
		for _, entry := range window {
			if entry.PushId == self.pushId {
				// 5a: P committed, so its lease is moot
				return nil, false
			}
		}
		refusals, err := sidecar.DecodeEvsRefusals(head.Head.GetRefused())
		if err != nil {
			return self.unavailable(), false
		}
		for _, refusal := range refusals {
			if refusal.RecordsPush(self.pushId) && !refusal.LapsedAt(now.UnixMilli()) {
				reply := refuse(refusal.Code)
				reply.Recorded = true
				return reply, false
			}
		}
	}
	exists := !head.Absent() && (0 < head.Version() || head.Head.GetRefKind() != 0 || head.Head.GetRefMode() != 0)
	if exists && protocol.EvsRefMode(head.Head.GetRefMode()) != protocol.EvsRefMode_EVS_REF_GIT {
		return refuse(protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE), false
	}
	if head.Version() != self.base {
		return refuse(protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD), false
	}
	if lease := head.Head.GetLease(); lease != nil && len(lease.GetPushId()) != 0 && now.UnixMilli() < lease.GetUntilMs() {
		if bytes.Equal(lease.GetPushId(), self.pushId.Bytes()) {
			return nil, false
		}
		reply := refuse(protocol.EvsRefusalCode_EVS_REFUSAL_WAIT)
		reply.RetryAfterMs = uint32(max(1, lease.GetUntilMs()-now.UnixMilli()))
		return reply, false
	}
	return nil, true
}

// The budget for the lease's CAS: one head overwrite at P1 in the token network's queue, once.
func (self *leaseAttempt) admit(head *EvsStoredHead) *protocol.EvsRefusalReply {
	if self.grant != nil {
		return nil
	}
	cost, err := PricePush(self.engine.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: WriteOperationOverwrite, ObjectByteCount: int64(len(head.Bytes) + 32), Count: 1}},
	})
	if err != nil {
		return self.unavailable()
	}
	grant, err := self.engine.budget.AdmitP1(self.request.Ctx, self.request.Cluster.ClusterId(), connect.Id(networkIdOf(self.request.Principal)), cost)
	var refusal *sidecar.WriteRefusal
	switch {
	case errors.As(err, &refusal):
		return &protocol.EvsRefusalReply{
			PushId:       self.pushId.Bytes(),
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED,
			RetryAfterMs: max(1, refusal.RetryAfterMs()),
		}
	case err != nil:
		return self.unavailable()
	}
	self.grant = grant
	return nil
}

// 503: the store did not answer, and nothing this request wrote can take effect unseen, since a lease's write is
// found on the next read.
func (self *leaseAttempt) unavailable() *protocol.EvsRefusalReply {
	return &protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE}
}
