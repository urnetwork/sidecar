// POST /evs/v1/repos/<id>/push (§11.8's push and outcomes rows, §11.20; EVS1-M2-12): a one-part push, line by line.
//
//	4  the head first: the verified cache entry when its version is at least b, else a cluster GET; then one round
//	   on the repo's cluster after it: repo/ (cached at most 5 s), every changed entry by §11.6's read rule, each
//	   reuse source, and the statements of the window versions after folded_through that may touch a changed path,
//	   which the newest rule combines with that head's folded_through; the authorization state and the generation
//	   record from this process's caches (push_step4.go)
//	5a P committed in the window or the log pages of (b, b+64] answers 200 {its version}; another statement under
//	   its id 409 PUSH_ID_REUSED; a refusal record answers its status with recorded: true (outcome.go)
//	5  b to h as check.go's pure functions over what step 4 read; a refusal on a cached head runs step 4 again from
//	   the cluster, since every refusal rests on a cluster head; a final one is answered, one that refuses nothing is
//	   answered, and the rest are recorded first by the refuse row (refuse.go)
//	6  the record joins this process's open batch and waits for its write; a window about to pass 127 versions pages
//	   out; new slots are PUT If-None-Match (push_commit.go)
//	7  the head If-Match step 4's ETag, issued only within 5 s of step 4's reads; a 412 rereads, settles or reruns
//	   5 (b-h) at most 8 times, then 429 BUSY; an unknown outcome rereads 3 times 200 ms apart (outcome.go)
//	8  off the reply path: the push sequence and hints, usage, the head cache and the fold trigger (push_commit.go)
//
// The seal form of this route, {statement, part places}, is EVS1-M2-13's and answers 503 until it lands.
//
// An attempt runs to its end once its request has arrived, whether or not its client is still there: the lb
// re-sends a POST on an error, a 503 or 30 s of silence, so another attempt of the same push id may arrive at any
// time, even after this one's answer, and every rule above holds against that (I-EVS-3). No answer deletes anything:
// a refused or unknown push's record and new slots stay for evacuation (I-EVS-2). Nothing here holds a lock across
// I/O.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route's template, for the service log and metrics.
const evsPushRouteTemplate = "POST /evs/v1/repos/{repo_id}/push"

// The newest verified authorization state of each network, which 5b's identity keys and 5d's gate read (§11.8's
// authorization row, §7.9's {acl_}e cache through AclGateCache, C-09). Safe for concurrent use; answers from memory.
type EvsGateViews interface {
	// The newest verified state of networkId, or Unknown while it is not loaded, which answers 503.
	View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer)
}

// AclGateCache's newest verified state of each network as EvsGateViews reads it: one map read, no lock, no I/O.
type aclGateViews struct {
	cache *sidecar.AclGateCache
}

// The process's gate cache as the push route reads it (C-09: one cache, shared).
func NewAclGateViews(cache *sidecar.AclGateCache) EvsGateViews {
	return &aclGateViews{cache: cache}
}

// See EvsGateViews. A network the cache does not track yet is told to it, which starts its load, and is unknown
// meanwhile.
func (self *aclGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	snapshot, status := self.cache.State(networkId)
	switch {
	case status == sidecar.AclGateUnknown:
		self.cache.Changed(networkId)
		return nil, EvsAuthUnknown
	case status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Config == nil:
		return nil, EvsAuthUnknown
	}
	return snapshot.Config, EvsAuthAllowed
}

// The push route.
func (self *EvsEngine) pushRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:  http.MethodPost,
			Pattern: evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/push",
			Name:    evsPushRouteTemplate,
			// deposit only to the caller's own deposit ref, which 5c holds it to
			Rights:         sidecar.AclEvsWrite | sidecar.AclEvsDeposit | sidecar.AclEvsAdmin,
			Write:          true,
			NeedsSureClock: true,
			Placed:         true,
			Serve:          self.servePush,
		},
	}
}

// See the file header.
func (self *EvsEngine) servePush(request *EvsRequest) {
	body := &protocol.EvsPushRequest{}
	if !request.ReadMessage(body, self.settings.PushBodyMaxByteCount) {
		return
	}
	if 0 < len(body.GetPartPlaces()) {
		// a seal, which EVS1-M2-13 builds on this route: refused 503, so nothing commits unchecked
		request.Unavailable(nil)
		return
	}
	attempt, ok := self.newPushAttempt(request, body)
	if !ok {
		return
	}
	outcome := attempt.run()
	attempt.answer(outcome)
}

// What one attempt ends in: a commit, its own or one 5a found, or a refusal.
type pushOutcome struct {
	// 200 {version}.
	committed        bool
	committedVersion uint64
	// The head this attempt's own step 7 wrote, for step 8; nil when 5a found the push committed by another.
	ownCommit *EvsStoredHead
	// The caller's own deposit ref's head (plan-EVS1-deposit-head), carried by a 200.
	depositHead *protocol.EvsDepositHead
	// Otherwise the refusal, its code deciding its status.
	reply *protocol.EvsRefusalReply
}

// A 200 at version, with the head it read for a depositor.
func committedOutcome(version uint64, ownCommit *EvsStoredHead) *pushOutcome {
	return &pushOutcome{committed: true, committedVersion: version, ownCommit: ownCommit}
}

// A refusal reply as is.
func refusedOutcome(reply *protocol.EvsRefusalReply) *pushOutcome {
	return &pushOutcome{reply: reply}
}

// One attempt of a push: what its request carried, what step 4 read, and what it has written. Not safe for
// concurrent use: it lives on its request's goroutine.
type pushAttempt struct {
	engine   *EvsEngine
	request  *EvsRequest
	settings *EvsSettings
	// runs past the client's leaving, within the engine's life and PushAttemptTimeout
	ctx    context.Context
	cancel context.CancelFunc
	// when the handler began: the fence row's arrival
	arrival time.Time

	repoId  sidecar.Id
	refId   sidecar.Id
	pushId  sidecar.Id
	cluster sidecar.BlobCluster

	// the statement as received, parsed, and its payload checked against it; a format-2 construct leaves payload nil
	// and formatRefusal set, answered after 5a (plan-EVS1-format-unsupported)
	statement     *sidecar.EvsStatement
	payloadBytes  []byte
	payload       *sidecar.EvsCheckedPayload
	formatRefusal *EvsCheckRefusal
	receipts      []*protocol.EvsUploadReceipt
	// the repo's network, whose state judges the push and whose storage counts it, and the token's, whose fair
	// queue its writes wait in
	gateView       sidecar.GkmAuthView
	networkId      sidecar.Id
	tokenNetworkId sidecar.Id

	// step 4's reads, kept across reruns of 5 (b-h)
	reads  *pushReads
	pushes *RecordPushSource
	// the head the next step 7 writes on
	head *EvsStoredHead

	// what the attempt has written: the grant its writes spend, its record's place, whether its new slots are in,
	// and whether a step 7 has been issued, which leaves the outcome unknown until a reread settles it
	grant        sidecar.WriteGrant
	writeCtx     context.Context
	place        *protocol.EvsPlace
	slotsWritten bool
	issued       bool

	// EVS1-M2-16's reads over self.head: the due its commit records, and a PATH_EPOCH's map and tail
	due       *pathEpochDue
	pathEpoch *pathEpochReads
	// EVS1-M2-20's: the slots an ERASE names, as step 4 read them
	erasureSlots map[sidecar.Id]*erasureSlotRead
}

// The attempt for body, or false once the request has been answered: a statement or payload that does not parse
// or verify refuses nothing (400), and a state not loaded answers 503.
func (self *EvsEngine) newPushAttempt(request *EvsRequest, body *protocol.EvsPushRequest) (*pushAttempt, bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Ctx), self.settings.PushAttemptTimeout)
	stop := context.AfterFunc(self.ctx, cancel)
	attempt := &pushAttempt{
		engine:         self,
		request:        request,
		settings:       self.settings,
		ctx:            ctx,
		cancel:         func() { stop(); cancel() },
		arrival:        request.started,
		repoId:         request.RepoId,
		cluster:        request.Cluster,
		payloadBytes:   body.GetPayload(),
		receipts:       body.GetReceipts(),
		tokenNetworkId: networkIdOf(request.Principal),
	}
	ok := false
	defer func() {
		if !ok {
			attempt.cancel()
		}
	}()

	statement, err := sidecar.ParseEvsStatement(body.GetStatement())
	if err != nil {
		refusal := EvsCheckRefusalOfCodec(err)
		if refusal.Reason != EvsCheckReasonFormatUnsupported {
			request.Refuse(refusal.Reply(sidecar.Id{}))
			return nil, false
		}
		// a format-2 statement: read whole by format 2's parse, so its push id can be settled and recorded
		statement, err = sidecar.ParseEvsStatementFormat2(body.GetStatement())
		if err != nil {
			request.Refuse(EvsCheckRefusalOfCodec(err).Reply(sidecar.Id{}))
			return nil, false
		}
		attempt.formatRefusal = refusal
	}
	attempt.statement = statement
	push := statement.Push
	attempt.pushId = sidecar.Id(push.GetPushId())
	attempt.refId = sidecar.Id(push.GetRefId())
	request.NoteRefIds(attempt.refId)
	if 0 < push.GetPartCount() {
		// a push in parts is sealed by its parts' places, never posted whole
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a push in parts posted as one").Reply(attempt.pushId))
		return nil, false
	}
	if attempt.formatRefusal == nil {
		payload, err := sidecar.EvsCheckPayload(statement, body.GetPayload())
		if err != nil {
			refusal := EvsCheckRefusalOfCodec(err)
			if refusal.Reason != EvsCheckReasonFormatUnsupported {
				request.Refuse(refusal.Reply(attempt.pushId))
				return nil, false
			}
			attempt.formatRefusal = refusal
		} else {
			attempt.payload = payload
		}
	}
	if len(body.GetStaged()) != 0 && attempt.formatRefusal == nil {
		// staged segments are format 2's
		refusal := newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, "staged segments")
		refusal.NeedsFormat = 2
		attempt.formatRefusal = refusal
	}

	// the repo's network: repo/ names it once created, and a token reaches only its own network's repos
	attempt.networkId = attempt.tokenNetworkId
	if self.deps.GateViews == nil {
		request.Unavailable(nil)
		return nil, false
	}
	view, answer := self.deps.GateViews.View(attempt.networkId)
	if answer != EvsAuthAllowed || view == nil {
		request.Unavailable(nil)
		return nil, false
	}
	attempt.gateView = view
	// 5b's identity, before any store read: a statement the token's sidecar did not sign costs evs nothing, and
	// refuses nothing, since a refusal recorded for a replayed statement would block its push (refusal_codes.go)
	identity := &PushView{
		RepoId:         attempt.repoId,
		Statement:      statement,
		TokenSidecarId: request.SidecarId,
		TokenClientId:  sidecar.Id(request.Principal.ClientId),
		Auth:           view,
		Stage:          PushStageOnePart,
		Now:            request.Now(),
	}
	if refusal := CheckSignature(identity); refusal != nil && refusal.Reason != EvsCheckReasonTimeStale && refusal.Reason != EvsCheckReasonTimeAhead {
		request.Refuse(refusal.Reply(attempt.pushId))
		return nil, false
	}
	attempt.pushes = NewRecordPushSource(self.records, attempt.cluster, attempt.repoId, attempt.refId)
	ok = true
	return attempt, true
}

// The attempt from step 4 to its outcome. See the file header.
func (self *pushAttempt) run() *pushOutcome {
	defer self.cancel()
	defer func() {
		if self.grant != nil {
			self.grant.Close()
		}
	}()
	outcome := self.runSteps()
	if outcome.ownCommit != nil {
		// the commit stands even when its post-commit work did not finish, so its step 8 runs
		finished := self.afterCommitted(outcome)
		if !finished.committed {
			self.engine.afterCommit(self.newCommitted(outcome.ownCommit))
		}
		return finished
	}
	return self.afterCommitted(outcome)
}

// Steps 4 to 7 and their outcomes, without the post-commit work.
func (self *pushAttempt) runSteps() *pushOutcome {
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierPushArrive, barrierKey)
	cached := true
	for rerun := 0; rerun <= self.settings.PushRerunCount; rerun += 1 {
		outcome := self.step4(cached)
		if outcome != nil {
			return outcome
		}
		cached = false
		if outcome := self.settle(self.head); outcome != nil {
			return outcome
		}
		if self.fenced(self.head.Head) {
			return self.unknown()
		}
		refusal := self.check()
		if refusal != nil {
			if self.head.Cached {
				// every refusal rests on a head read from the cluster
				continue
			}
			return self.refuse(refusal)
		}
		if outcome := self.countedRules(); outcome != nil {
			return outcome
		}
		outcome, again := self.commit()
		if !again {
			return outcome
		}
	}
	return self.busy()
}

// After a commit, its own or one 5a found: an ERASE's slot rewrites and an own CONSUME's slot deletes, before the
// 200 (§11.12).
func (self *pushAttempt) afterCommitted(outcome *pushOutcome) *pushOutcome {
	if !outcome.committed || self.payload == nil {
		return outcome
	}
	flags := self.statement.Push.GetFlags()
	switch {
	case flags&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) != 0:
		if unfinished := self.finishErase(); unfinished != nil {
			return unfinished
		}
	case flags&uint32(protocol.EvsPushFlag_EVS_PUSH_CONSUME) != 0 && outcome.ownCommit != nil:
		if unfinished := self.finishConsume(); unfinished != nil {
			return unfinished
		}
	}
	return outcome
}

// 5 (b-h) over what step 4 read, with the rules other tasks own: a format-2 construct first, after 5a, as
// plan-EVS1-format-unsupported reads it.
func (self *pushAttempt) check() *EvsCheckRefusal {
	if self.formatRefusal != nil {
		return self.formatRefusal
	}
	return CheckPush(self.reads.view)
}

// 429 BUSY: another attempt of the push may still land, so the client retries the same statement.
func (self *pushAttempt) busy() *pushOutcome {
	return refusedOutcome(&protocol.EvsRefusalReply{
		PushId:       self.pushId.Bytes(),
		Code:         protocol.EvsRefusalCode_EVS_REFUSAL_BUSY,
		RetryAfterMs: uint32(max(1, self.settings.UnavailableRetryAfter.Milliseconds())),
	})
}

// 503 {push_id, outcome: unknown} once a step 7 may have been issued, else a plain 503: nothing this attempt wrote
// can commit it.
func (self *pushAttempt) unavailable() *pushOutcome {
	reply := &protocol.EvsRefusalReply{PushId: self.pushId.Bytes(), Code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE}
	if self.issued {
		reply.Outcome = protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN
	}
	return refusedOutcome(reply)
}

// 503 {push_id, outcome: unknown}, whatever was issued: a fence ended the attempt, or the store did not answer a
// write.
func (self *pushAttempt) unknown() *pushOutcome {
	return refusedOutcome(&protocol.EvsRefusalReply{
		PushId:  self.pushId.Bytes(),
		Code:    protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE,
		Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN,
	})
}

// The answer, then step 8 for this attempt's own commit, off the reply path.
func (self *pushAttempt) answer(outcome *pushOutcome) {
	request := self.request
	if !outcome.committed {
		reply := outcome.reply
		if reply.GetCode() == protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
			request.Unavailable(reply)
		} else {
			request.Refuse(reply)
		}
		return
	}
	request.Reply(&protocol.EvsPushReply{Version: outcome.committedVersion, DepositHead: outcome.depositHead})
	if outcome.ownCommit != nil {
		self.engine.afterCommit(self.newCommitted(outcome.ownCommit))
	}
}

// Whether the push writes the caller's own deposit ref, whose head a depositor learns (plan-EVS1-deposit-head).
func (self *pushAttempt) ownDepositRef() bool {
	push := self.statement.Push
	return protocol.EvsRefKind(push.GetRefKind()) == protocol.EvsRefKind_EVS_REF_DEPOSIT &&
		sidecar.Id(push.GetOwnerSidecarId()) == self.request.SidecarId
}

// The depositor's view of head: version, chain and consumed_through, C_0 for a ref with none.
func (self *pushAttempt) depositHeadOf(head *protocol.EvsHead) *protocol.EvsDepositHead {
	if head == nil || head.GetVersion() == 0 {
		chain := sidecar.EvsChainStart(self.repoId, self.refId)
		return &protocol.EvsDepositHead{Chain: chain[:], ConsumedThrough: head.GetConsumedThrough()}
	}
	return &protocol.EvsDepositHead{Version: head.GetVersion(), Chain: append([]byte{}, head.GetChain()...), ConsumedThrough: head.GetConsumedThrough()}
}

// gen/<g> records as evs reads them (§11.8 step 4: "the generation record from evs's caches"): the Signed GenRotate
// gkm created at gkm/<group_id>/gen/<g> on the repo's cluster, where generation g exists and nowhere else
// (D-KEYS-15), verified under its signer's identity key in the newest state, and kept for the process's life,
// since it never changes while its repo lives. Safe for concurrent use.
type GenerationRecords struct {
	settings *EvsSettings

	stateLock sync.Mutex
	records   map[generationRecordKey]*protocol.GenRotate
}

// One record's key: its cluster, group and generation.
type generationRecordKey struct {
	clusterId  string
	groupId    sidecar.Id
	generation uint64
}

// An empty cache.
func NewGenerationRecords(settings *EvsSettings) *GenerationRecords {
	return &GenerationRecords{settings: settings, records: map[generationRecordKey]*protocol.GenRotate{}}
}

// gen/<generation> of groupId on cluster, its signature checked against view's identity keys; nil with no error when
// gkm holds no such generation.
func (self *GenerationRecords) Read(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64, view sidecar.GkmAuthView) (*protocol.GenRotate, error) {
	key := generationRecordKey{clusterId: cluster.ClusterId(), groupId: groupId, generation: generation}
	if record, ok := func() (*protocol.GenRotate, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		record, ok := self.records[key]
		return record, ok
	}(); ok {
		return record, nil
	}
	object, err := cluster.Get(ctx, sidecar.GkmGenerationPath(groupId, generation))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	objectBytes, err := readAllLimited(object, evsGenerationRecordMaxByteCount)
	if err != nil {
		return nil, err
	}
	generationRecord, err := sidecar.ParseGenRotate(objectBytes, groupId, generation, func(signerId sidecar.Id) ([]byte, error) {
		identityKey := view.IdentityKey(signerId)
		if len(identityKey) == 0 {
			return nil, fmt.Errorf("%w: a rotator the state admits no identity key for", sidecar.ErrGkmAuthentication)
		}
		return identityKey, nil
	})
	if err != nil {
		return nil, err
	}
	if 0 < self.settings.GenerationCacheCount {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.GenerationCacheCount <= len(self.records) {
			for evicted := range self.records {
				delete(self.records, evicted)
				break
			}
		}
		self.records[key] = generationRecord.Rotate
	}
	return generationRecord.Rotate, nil
}

// gen/<g>'s bound: a Signed GenRotate with its GenLink and leaf wrap, well under a metadata object's 4 KiB.
const evsGenerationRecordMaxByteCount = 16 * 1024

// An object's body, at most maxByteCount, else ErrEvsPushInvalid.
func readAllLimited(object *sidecar.BlobObject, maxByteCount int64) ([]byte, error) {
	objectBytes, err := io.ReadAll(io.LimitReader(object.Body, maxByteCount+1))
	if err != nil {
		return nil, err
	}
	if maxByteCount < int64(len(objectBytes)) {
		return nil, fmt.Errorf("%w: an object past %d bytes", sidecar.ErrEvsPushInvalid, maxByteCount)
	}
	return objectBytes, nil
}

// A proto's deterministic bytes.
func marshalDeterministic(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}
