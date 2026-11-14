// POST /evs/v1/repos/<id>/push (§11.8's push and outcomes rows, §11.20; EVS1-M2-12): a one-part push, line by line.
//
//	4  the head first: the verified cache entry when its version is at least b, else a cluster GET; then one round
//	   on the repo's cluster after it: repo/ (cached at most 5 s), every changed entry by §11.6's read rule, each
//	   reuse source, and the statements of the window versions after folded_through that may touch a changed path,
//	   which the newest rule combines with that head's folded_through; the authorization state read again from this
//	   process's gate cache at each run, and the generation record from its caches (push_step4.go)
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
// The seal form of this route, {statement, part places}, runs the same steps over the parts' joined payload once
// push_seal.go has read them; a part of a push (push_part.go) runs steps 4 and 5 (a-e, g, h) over its own entries
// and appends its record, and the git-mode seal lease is push_lease.go's.
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
	// Where the committed push's record is, when 5a or a reread found it committed: a 5a retry's purge list
	// (push_purge.go).
	committedPlace *protocol.EvsPlace
	// A part's 200 {place}: where its record is (push_part.go).
	partPlace *protocol.EvsPlace
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

	// the statement as received, parsed, and its payload checked against it; at a format-1 instance a format-2
	// construct leaves payload nil and formatRefusal set, answered after 5a (plan-EVS1-format-unsupported); at a
	// format-2 instance the format-2 parsers read it whole and needsFormat2 says it carries format 2, which 5c holds
	// to §19.11's gate and whose commit raises a format-1 repo (repo_format.go); a part or seal carrying format 2
	// at a format-2 instance keeps formatRefusal too, since its format-2 checks are EVS2-M10-06's
	statement     *sidecar.EvsStatement
	payloadBytes  []byte
	payload       *sidecar.EvsCheckedPayload
	formatRefusal *EvsCheckRefusal
	needsFormat2  bool
	receipts      []*protocol.EvsUploadReceipt
	// format 2: the request's staged bytes as received, which ride the record's tail outside every hash, and the
	// record's purge list once computed at its first write, which a rerun keeps (push_staged.go, push_purge.go)
	staged []byte
	purge  *pushPurge
	// the repo's network, whose state judges the push and whose storage counts it, and the token's, whose fair
	// queue its writes wait in. gateView is networkId's newest state, read again at each run of step 4 and at each
	// rerun of 5 (b-h) on a reread head (readGateView, QD-660): what step 5 judges, the generation record's signer
	// and the PATH_EPOCH and CLOSURE rules read. bind's read at arrival is not kept: it judges only bind's own 5b
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

	// EVS1-M2-13's: a seal's parts, read before step 4 (push_seal.go), or the one part this attempt is of
	// (push_part.go). At most one is set; both nil for a one-part push.
	seal *sealReads
	part *partReads
}

// Which of §11.8's requests this attempt is: a one-part push, a part or a seal.
func (self *pushAttempt) stage() PushStage {
	switch {
	case self.seal != nil:
		return PushStageSeal
	case self.part != nil:
		return PushStagePart
	}
	return PushStageOnePart
}

// 5b's time bound for the stage: 10 min for a one-part push, 30 for a part or a seal.
func (self *pushAttempt) timeBound() time.Duration {
	if self.stage() == PushStageOnePart {
		return self.settings.PushTimeBound
	}
	return self.settings.SealTimeBound
}

// An attempt's context: it runs past the client's leaving, within the engine's life and PushAttemptTimeout.
func (self *EvsEngine) newAttemptContext(request *EvsRequest) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Ctx), self.settings.PushAttemptTimeout)
	stop := context.AfterFunc(self.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

// The attempt for body, or false once the request has been answered: a statement or payload that does not parse
// or verify refuses nothing (400), and a state not loaded answers 503.
func (self *EvsEngine) newPushAttempt(request *EvsRequest, body *protocol.EvsPushRequest) (*pushAttempt, bool) {
	ctx, cancel := self.newAttemptContext(request)
	attempt := &pushAttempt{
		engine:         self,
		request:        request,
		settings:       self.settings,
		ctx:            ctx,
		cancel:         cancel,
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

	format2 := self.format2Instance()
	statement, err := sidecar.ParseEvsStatement(body.GetStatement())
	if err != nil {
		refusal := EvsCheckRefusalOfCodec(err)
		if refusal.Reason != EvsCheckReasonFormatUnsupported {
			request.Refuse(refusal.Reply(sidecar.Id{}))
			return nil, false
		}
		// a format-2 statement: read whole by format 2's parse, so its push id can be settled and recorded; at a
		// format-2 instance it is the gate's question, not a format refusal
		statement, err = sidecar.ParseEvsStatementFormat2(body.GetStatement())
		if err != nil {
			request.Refuse(EvsCheckRefusalOfCodec(err).Reply(sidecar.Id{}))
			return nil, false
		}
		if format2 {
			attempt.needsFormat2 = true
		} else {
			attempt.formatRefusal = refusal
		}
	}
	attempt.statement = statement
	push := statement.Push
	attempt.pushId = sidecar.Id(push.GetPushId())
	attempt.refId = sidecar.Id(push.GetRefId())
	request.NoteRefIds(attempt.refId)
	switch {
	case 0 < len(body.GetPartPlaces()):
		// a seal: the parts' places, in part order, one per part the statement counts (push_seal.go)
		if push.GetPartCount() == 0 || uint32(len(body.GetPartPlaces())) != push.GetPartCount() || len(body.GetPayload()) != 0 {
			request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a seal whose places are not one per part").Reply(attempt.pushId))
			return nil, false
		}
		attempt.seal = &sealReads{places: body.GetPartPlaces()}
		request.Note("seal")
	case 0 < push.GetPartCount():
		// a push in parts is sealed by its parts' places, never posted whole
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a push in parts posted as one").Reply(attempt.pushId))
		return nil, false
	}
	switch {
	case attempt.seal != nil:
		// the parts' round reads and checks the payload (push_seal.go)
	case format2:
		// format 2's parsers take format 1's pushes too, since format-1 data is valid format 2; whether the push
		// carries format 2 is then 5c's question against the gate, and its own rules EVS2-M10-06's
		payload, err := sidecar.EvsCheckPayloadFormat2(statement, body.GetPayload(), body.GetStaged())
		if err != nil {
			request.Refuse(EvsCheckRefusalOfCodec(err).Reply(attempt.pushId))
			return nil, false
		}
		attempt.payload = payload
		attempt.staged = body.GetStaged()
		attempt.needsFormat2 = attempt.needsFormat2 || sidecar.EvsPushNeedsFormat2(statement, payload)
	case attempt.formatRefusal == nil:
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
	if len(body.GetStaged()) != 0 && !format2 && attempt.formatRefusal == nil {
		// staged segments are format 2's
		refusal := newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, "staged segments")
		refusal.NeedsFormat = 2
		attempt.formatRefusal = refusal
	}

	if !attempt.bind() {
		return nil, false
	}
	ok = true
	return attempt, true
}

// 5b's identity, before any store read, for every stage, against the gate view as it stands at arrival: a statement
// the token's sidecar did not sign costs evs nothing, and refuses nothing, since a refusal recorded for a replayed
// statement would block its push (refusal_codes.go). That read judges this alone: steps 4 and 5 judge the view each
// run of step 4 reads again, 5d's predicate above all (readGateView, QD-660). false once the request has been
// answered.
func (self *pushAttempt) bind() bool {
	engine := self.engine
	request := self.request
	// the repo's network: repo/ names it once created, and a token reaches only its own network's repos
	self.networkId = self.tokenNetworkId
	if engine.deps.GateViews == nil {
		request.Unavailable(nil)
		return false
	}
	view, answer := engine.deps.GateViews.View(self.networkId)
	if answer != EvsAuthAllowed || view == nil {
		request.Unavailable(nil)
		return false
	}
	identity := &PushView{
		RepoId:         self.repoId,
		Statement:      self.statement,
		TokenSidecarId: request.SidecarId,
		TokenClientId:  sidecar.Id(request.Principal.ClientId),
		Auth:           view,
		Stage:          self.stage(),
		Now:            request.Now(),
		TimeBound:      self.timeBound(),
	}
	if refusal := CheckSignature(identity); refusal != nil && refusal.Reason != EvsCheckReasonTimeStale && refusal.Reason != EvsCheckReasonTimeAhead {
		request.Refuse(refusal.Reply(self.pushId))
		return false
	}
	self.pushes = NewRecordPushSource(engine.records, engine.locator, self.cluster, self.repoId, self.refId)
	return true
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
	if outcome.committed && outcome.ownCommit == nil && outcome.committedPlace != nil && self.part == nil {
		// a 5a retry or a reread found the push committed by another attempt: its record's list is the purge's
		// (EVS2-M10-06), off the reply path
		version, place := outcome.committedVersion, outcome.committedPlace
		self.engine.stepEightCount.Update(func(count int) int { return count + 1 })
		go func() {
			defer self.engine.stepEightDoneCount.Update(func(count int) int { return count + 1 })
			self.handRetriedPurge(version, place)
		}()
	}
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
	// a seal reads the cluster's head, since its own lease left the cached ETag stale (§11.9's cache row)
	cached := self.seal == nil
	for rerun := 0; rerun <= self.settings.PushRerunCount; rerun += 1 {
		if self.seal != nil {
			if outcome := self.readSealParts(); outcome != nil {
				return outcome
			}
		}
		outcome := self.step4(cached)
		if outcome != nil {
			return outcome
		}
		cached = false
		if outcome := self.settle(self.head); outcome != nil {
			return outcome
		}
		// the fence row ends an attempt that may issue step 7: a push or a seal, never a part
		if self.part == nil && self.fenced(self.head.Head) {
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
		if self.part != nil {
			return self.appendPart()
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
	if !outcome.committed || self.payload == nil || self.part != nil {
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
// plan-EVS1-format-unsupported reads it. At a format-2 instance a part or seal carrying format 2, whose format-2
// checks are EVS2-M10-06's, takes 5c's gate answer: 409 VERSIONING outside the gate, recorded for a seal, and 503
// inside it, refusing nothing, so nothing commits unchecked.
func (self *pushAttempt) check() *EvsCheckRefusal {
	if self.formatRefusal != nil {
		if !self.engine.format2Instance() {
			return self.formatRefusal
		}
		if !self.engine.format2.Admits(self.networkId) {
			return newEvsCheckRefusal(EvsCheckReasonFormat2Gate, "a format-2 part or seal from a network outside the format2 gate")
		}
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "format 2's part and seal checks are not supplied")
	}
	refusal := CheckPush(self.reads.view)
	if refusal == nil && self.seal != nil {
		// §11.8's seal row: 5g again for the parts against the head the seal commits on, which the joined payload's
		// newest reads carry (push_seal.go)
		refusal = CheckPaths(self.reads.view)
	}
	return refusal
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
	if outcome.partPlace != nil {
		request.Reply(&protocol.EvsPushReply{Place: outcome.partPlace})
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
	objectBytes, err := readAllLimited(object, self.settings.GenerationRecordMaxByteCount)
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
