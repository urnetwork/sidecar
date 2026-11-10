// §10.6's wrap checks and late wraps (D-KEYS-8, D-KEYS-24, D-KEYS-26; FI-4, FI-28): POST
// /gkm/groups/<id>/wraps/<g>/<c8>, a batch of 1 to 256 Signed ReaderWraps and DelegationWraps (QD-066), and GET
// /gkm/groups/<id>/wraps/<g>, a caller's own deliveries of g, over gkm/<group_id>/wrap/<g>/<c8>/<recipient>/<k8> on the
// repo's cluster.
//
// Each delivery is checked on its own and answered in order, so a batch of one behaves as one delivery would:
//
//	object  its body's group, generation, commitment prefix, recipient and key digest agree with the path; STAGED only
//	        while gen/<g> is absent, or of generation 1 by gen/1's signer while the repo is keying for its creation
//	        (KF1); LATE only once gen/<g> exists, is gen/'s newest and carries the body's commitment
//	signer  verifies as its SignedType under its signer's admitted identity key; admitted, not read_only, and not
//	        revoked, parked or suspended in gkm's newest state
//	late    auth at or past gen/<g>'s and the previous base, matching proj/ there; time_ms within 10 minutes of gkm's
//	        clock; the recipient reads R in gkm's newest state (a Delegation's reach holds R and it is live); a
//	        ReaderWrap's key digest names the ReaderKey gkm serves at rk/<recipient>
//	bound   one object per (recipient, key), by If-None-Match; an uploader's STAGED objects in a group within
//	        StagedRate's count per hour per reader of R
//
// A wrong kind, generation, commitment or key answers 409, a key another delivery holds 412 with the winner, a check
// refused 403, the STAGED bound 429, and a delivery gkm did not reach a definite answer for, because its PUT was not
// started by WrapBatchStartDeadline into the request or its store did not answer, 0: the client sends it again, and
// If-None-Match makes that safe. PUTs run WrapPutConcurrency at once. A malformed delivery is refused as one whose
// signature does not verify, 403, since gkm cannot tell the two apart without trusting it.
//
// Reads return only the caller's own objects: its s: deliveries and its covering Delegation's d: ones. A read asking
// for a key (?want=<k8>&since=) that finds no delivery to it is a late delivery's ask: gkm hints wrap-pending naming
// the recipient to the repo's writers, and once since is LateAskWidenAge (15 minutes) old to up to
// LateAskOtherHolderMaxCount other holders, the recipient's member's devices first (§10.6's late wraps), at most once
// per LateAskHintInterval per recipient and generation in a process.

package gkmservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §10.14's bound on one batch (QD-066): a format value.
const gkmWrapBatchMaxCount = 256

// The most bytes of one stored delivery a read takes: ~1.42 KB late (§10.6's sizes).
const gkmDeliveryMaxByteCount = 8 * 1024

// The STAGED and LATE kinds of KeyDelivery.delivery_kind (§10.9).
const (
	gkmDeliveryKindStaged = uint32(sidecar.GkmDeliveryStaged)
	gkmDeliveryKindLate   = uint32(sidecar.GkmDeliveryLate)
)

// The status of a delivery gkm did not reach a definite answer for (QD-066's 0).
const gkmWrapStatusNotTried = 0

// One item of a batch on its way to the store: its key and bytes, whether it is a LATE delivery, and where its answer
// goes.
type gkmWrapWrite struct {
	key    string
	body   []byte
	late   bool
	result *protocol.GkmWrapResult
}

// What a batch judges each item against: gen/<g> as it stands, the repo's state and the STAGED bound.
type gkmWrapBatchContext struct {
	request    *GkmRequest
	groupId    sidecar.Id
	generation uint64
	c8         string
	// gen/<g>'s facts, nil while it is absent
	generationFacts *gkmGenerationFacts
	// whether gen/<g+1> exists, read once a LATE item needs it
	nextRead   bool
	nextExists bool
	keying     bool
	stagedRate GkmRate
}

// The path's generation and commitment prefix of a batch route. false once it has answered 400.
func readGkmWrapPath(request *GkmRequest) (uint64, string, bool) {
	generation, err := parseGkmNumber(request.Http.PathValue(gkmPathValueGeneration))
	c8 := request.Http.PathValue(gkmPathValueCommitmentPrefix)
	if err != nil || generation == 0 || !gkmHexPrefixForm(c8) {
		request.BadRequest()
		return 0, "", false
	}
	return generation, c8, true
}

// The context a batch at the path's generation is judged in. false once it has answered.
func (self *GkmEngine) newWrapBatchContext(request *GkmRequest, generation uint64, c8 string) (*gkmWrapBatchContext, bool) {
	groupId := *request.GroupId
	batch := &gkmWrapBatchContext{request: request, groupId: groupId, generation: generation, c8: c8}
	// a re-formed group takes no wrap until its ladder reaches its form's generation (QD-074 rule 5; reform.go)
	if pending, ok := self.reformLadderPending(request, groupId); !ok {
		return nil, false
	} else if pending {
		request.Forbidden()
		return nil, false
	}
	facts, err := self.generationFacts(request.Ctx, request.Cluster, groupId, generation)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
	case err != nil:
		self.answerStoreError(request, err)
		return nil, false
	default:
		batch.generationFacts = facts
	}
	repoObject, err := self.repos.read(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		self.answerStoreError(request, err)
		return nil, false
	}
	batch.keying = repoObject.GetState() == protocol.EvsRepoState_EVS_REPO_KEYING
	readerIds, answer := self.deps.AuthState.RepoReaders(request.Principal, request.RepoId, request.Now())
	if answer == GkmAuthUnknown {
		request.Unavailable()
		return nil, false
	}
	batch.stagedRate = GkmRate{
		Count:    self.settings.StagedRate.Count * max(1, len(readerIds)),
		Interval: self.settings.StagedRate.Interval,
	}
	return batch, true
}

// Whether a STAGED object of the batch's generation may be written now, by uploaderId: gen/<g> absent and the repo
// active, or KF1's generation 1 by gen/1's signer while the repo is keying. The status refusing it, or 0.
func (self *gkmWrapBatchContext) stagedStatus(uploaderId sidecar.Id) int {
	if self.generationFacts != nil {
		if self.generation == 1 && self.keying && bytes.Equal(self.generationFacts.signerId, uploaderId.Bytes()) {
			return 0
		}
		return 409
	}
	if self.keying {
		// a keying repo takes only its creation's deliveries
		return 403
	}
	return 0
}

// Whether gen/<g+1> exists, read once per batch.
func (self *GkmEngine) wrapBatchNextExists(batch *gkmWrapBatchContext) (bool, error) {
	if !batch.nextRead {
		exists, err := self.generationExists(batch.request.Ctx, batch.request.Cluster, batch.groupId, batch.generation+1)
		if err != nil {
			return false, err
		}
		batch.nextRead = true
		batch.nextExists = exists
	}
	return batch.nextExists, nil
}

// The ReaderKey gkm serves for sidecarId, its X-Wing key's SHA-256: what a LATE ReaderWrap's key digest must name.
// false for none.
func (self *GkmEngine) servedReaderKeySha256(ctx context.Context, sidecarId sidecar.Id) ([]byte, bool, error) {
	cluster, err := self.firstCluster()
	if err != nil {
		return nil, false, err
	}
	signed, err := self.readReaderKey(ctx, cluster, sidecarId)
	if err != nil {
		return nil, false, err
	}
	if len(signed.GetBody()) == 0 {
		return nil, false, nil
	}
	body := &protocol.ReaderKey{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, false, errors.Join(errGkmStoreFault, err)
	}
	keySha256 := sha256Of(body.GetXwingPublicKey())
	return keySha256, true, nil
}

// Judges one delivery of a batch: the key and bytes to write, or the status refusing it. An answer of the state that
// could not tell fails the whole batch, 503, so its client sends it again: ok false once it has answered.
func (self *GkmEngine) judgeDelivery(batch *gkmWrapBatchContext, deliveryBytes []byte) (write *gkmWrapWrite, status int, ok bool) {
	request := batch.request
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(deliveryBytes, signed); err != nil {
		return nil, 403, true
	}
	var wrapType sidecar.GkmWrapType
	switch signed.GetType() {
	case uint32(bridge.SignedType_SIGNED_READER_WRAP):
		wrapType = sidecar.GkmWrapTypeReader
	case uint32(bridge.SignedType_SIGNED_DELEGATION_WRAP):
		wrapType = sidecar.GkmWrapTypeDelegation
	default:
		return nil, 409, true
	}
	lookup := self.newSignerLookup(request.Principal)
	delivery, err := sidecar.ParseGkmDelivery(signed, wrapType, lookup.identityKey)
	if lookup.answer == GkmAuthUnknown {
		request.Unavailable()
		return nil, 0, false
	}
	if err != nil {
		return nil, 403, true
	}
	switch lookup.signerStanding() {
	case GkmAuthAllowed:
	case GkmAuthUnknown:
		request.Unavailable()
		return nil, 0, false
	default:
		return nil, 403, true
	}
	body := delivery.Body
	commitmentPrefix, digestOk := gkmDigestPrefix(body.GetCommitment())
	if !bytes.Equal(body.GetGroupId(), batch.groupId.Bytes()) || body.GetGeneration() != batch.generation ||
		!digestOk || commitmentPrefix != batch.c8 {
		return nil, 409, true
	}
	key, err := sidecar.GkmDeliveryPath(batch.groupId, delivery)
	if err != nil {
		return nil, 403, true
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, 403, true
	}
	switch body.GetDeliveryKind() {
	case gkmDeliveryKindStaged:
		if status := batch.stagedStatus(request.SidecarId); status != 0 {
			return nil, status, true
		}
		rateKey := "staged:" + sidecar.EvsKeyId(request.SidecarId) + ":" + sidecar.EvsKeyId(batch.groupId)
		if !self.rates.Allow(batch.stagedRate, rateKey, request.Now()) {
			return nil, 429, true
		}
	case gkmDeliveryKindLate:
		status, ok := self.judgeLateDelivery(batch, delivery)
		if !ok || status != 0 {
			return nil, status, ok
		}
	default:
		return nil, 403, true
	}
	return &gkmWrapWrite{key: key, body: raw, late: body.GetDeliveryKind() == gkmDeliveryKindLate}, 0, true
}

// §10.6's late row for one LATE delivery: 0 when it passes, else the status refusing it. ok false once it has
// answered the whole batch.
func (self *GkmEngine) judgeLateDelivery(batch *gkmWrapBatchContext, delivery *sidecar.GkmDelivery) (status int, ok bool) {
	request := batch.request
	body := delivery.Body
	if batch.generationFacts == nil || batch.keying {
		// LATE only once gen/<g> exists, and a keying repo takes only its creation's deliveries
		return 409, true
	}
	next, err := self.wrapBatchNextExists(batch)
	if err != nil {
		self.answerStoreError(request, err)
		return 0, false
	}
	if next || !bytes.Equal(body.GetCommitment(), batch.generationFacts.commitment) {
		// not gen/'s newest, or another commitment than gen/<g>'s
		return 409, true
	}
	if body.GetAuth().GetVersion() < batch.generationFacts.auth.GetVersion() {
		return 403, true
	}
	switch self.deps.AuthState.CheckPin(request.Principal, body.GetAuth()) {
	case GkmAuthAllowed:
	case GkmAuthDenied:
		return 403, true
	default:
		request.Unavailable()
		return 0, false
	}
	now := request.Now()
	at := time.UnixMilli(body.GetTimeMs())
	if at.Before(now.Add(-sidecar.GkmClockSkew)) || now.Add(sidecar.GkmClockSkew).Before(at) {
		return 403, true
	}
	var answer GkmAuthAnswer
	if delivery.Type == sidecar.GkmWrapTypeReader {
		recipientId, err := sidecar.IdFromBytes(body.GetRecipient())
		if err != nil {
			return 403, true
		}
		answer = self.deps.AuthState.Reads(request.Principal, request.RepoId, recipientId, now)
		if answer == GkmAuthAllowed {
			keySha256, found, err := self.servedReaderKeySha256(request.Ctx, recipientId)
			if err != nil {
				self.answerStoreError(request, err)
				return 0, false
			}
			if !found || !bytes.Equal(keySha256, body.GetRecipientKeySha256()) {
				// sealed to a key gkm does not serve: a replaced or forged one (FI-28)
				return 409, true
			}
		}
	} else {
		answer = self.deps.AuthState.DelegationReads(request.Principal, request.RepoId, body.GetRecipient(), now)
	}
	switch answer {
	case GkmAuthAllowed:
		return 0, true
	case GkmAuthDenied:
		return 403, true
	}
	request.Unavailable()
	return 0, false
}

// POST /gkm/groups/<id>/wraps/<g>/<c8>: a GkmWrapBatch, answered by a GkmWrapBatchReply in order.
func (self *GkmEngine) serveWrapBatch(request *GkmRequest) {
	generation, c8, ok := readGkmWrapPath(request)
	if !ok {
		return
	}
	batchRequest := &protocol.GkmWrapBatch{}
	if !request.ReadMessage(batchRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	deliveries := batchRequest.GetDeliveries()
	if len(deliveries) == 0 || gkmWrapBatchMaxCount < len(deliveries) {
		request.BadRequest()
		return
	}
	batch, ok := self.newWrapBatchContext(request, generation, c8)
	if !ok {
		return
	}
	reply := &protocol.GkmWrapBatchReply{Results: make([]*protocol.GkmWrapResult, len(deliveries))}
	writes := []*gkmWrapWrite{}
	for i, deliveryBytes := range deliveries {
		reply.Results[i] = &protocol.GkmWrapResult{}
		write, status, ok := self.judgeDelivery(batch, deliveryBytes)
		if !ok {
			return
		}
		if write == nil {
			reply.Results[i].Status = uint32(status)
			continue
		}
		write.result = reply.Results[i]
		writes = append(writes, write)
	}
	if !self.writeWrapBatch(request, batch.groupId, generation, writes) {
		return
	}
	request.Reply(reply)
}

// Writes a batch's judged items, WrapPutConcurrency at once, each If-None-Match, starting none past
// WrapBatchStartDeadline into the request: 201, 412 with the winner, or 0 where no definite answer came. repo/ is
// reread first, so a write in flight at a shred lands before its repeat. The items spend the write budget by class
// (budget.go): STAGED ones as their rotation's, P0 while gkm's newest state shows a drop since gen/<g-1>'s pin and
// time, at once, and LATE ones and the rest as P1, which the budget may shed, answering those items 429. false once
// it has answered.
func (self *GkmEngine) writeWrapBatch(request *GkmRequest, groupId sidecar.Id, generation uint64, writes []*gkmWrapWrite) bool {
	if len(writes) == 0 {
		return true
	}
	if !request.CheckRepoWritable() {
		return false
	}
	stagedKind := sidecar.WriteP0Kind("")
	for _, write := range writes {
		if !write.late {
			stagedKind = self.stagedWriteKind(request, groupId, generation)
			break
		}
	}
	type writeGroup struct {
		kind      sidecar.WriteP0Kind
		writes    []*gkmWrapWrite
		byteCount int64
	}
	// P0 first, so the budget's queue never holds a REMOVE rotation's deliveries behind a LATE one
	p0Group := &writeGroup{kind: stagedKind}
	p1Group := &writeGroup{}
	for _, write := range writes {
		group := p1Group
		if !write.late && stagedKind != "" {
			group = p0Group
		}
		group.writes = append(group.writes, write)
		group.byteCount += self.settings.Prices.create(len(write.body))
	}
	deadline := request.started.Add(self.settings.WrapBatchStartDeadline)
	barrierKey := gkmBarrierNumberKey(groupId, generation)
	for _, group := range []*writeGroup{p0Group, p1Group} {
		if len(group.writes) == 0 {
			continue
		}
		writeCtx, err := request.spendWrites(request.Cluster, group.kind, group.byteCount)
		if err != nil {
			status := uint32(gkmWrapStatusNotTried)
			var refusal *sidecar.WriteRefusal
			if errors.As(err, &refusal) {
				// shed by §11.13's budget, nothing written: the client sends these again
				status = http.StatusTooManyRequests
			}
			for _, write := range group.writes {
				write.result.Status = status
			}
			continue
		}
		self.putWraps(writeCtx, request, group.writes, barrierKey, deadline)
	}
	return true
}

// PUTs writes under ctx, WrapPutConcurrency at once, starting none past deadline, and sets each one's answer.
func (self *GkmEngine) putWraps(ctx context.Context, request *GkmRequest, writes []*gkmWrapWrite, barrierKey string, deadline time.Time) {
	slots := make(chan struct{}, self.settings.WrapPutConcurrency)
	var group sync.WaitGroup
	for _, write := range writes {
		slots <- struct{}{}
		if !self.clock.Now().Before(deadline) {
			<-slots
			write.result.Status = gkmWrapStatusNotTried
			continue
		}
		group.Add(1)
		go func() {
			defer group.Done()
			defer func() { <-slots }()
			testHookBarrier(BarrierWrapPutBefore, barrierKey)
			winner, err := createGkmObject(ctx, request.Cluster, write.key, write.body, gkmDeliveryMaxByteCount)
			testHookBarrier(BarrierWrapPutAfter, barrierKey)
			switch {
			case err != nil:
				write.result.Status = gkmWrapStatusNotTried
			case winner != nil:
				write.result.Status = 412
				write.result.Winner = winner
			default:
				write.result.Status = 201
			}
		}()
	}
	group.Wait()
}

// GET /gkm/groups/<id>/wraps/<g>?recipient=&want=<k8>&since=<ms>: a GkmWrapsReply of the caller's own deliveries of
// g: the object at want first, or the recipient's prefix on a miss or with no want. A miss is a late delivery's ask.
func (self *GkmEngine) serveWrapsRead(request *GkmRequest) {
	groupId := *request.GroupId
	generation, err := parseGkmNumber(request.Http.PathValue(gkmPathValueGeneration))
	if err != nil || generation == 0 {
		request.BadRequest()
		return
	}
	query := request.Http.URL.Query()
	ownRecipient := "s:" + sidecar.EvsKeyId(request.SidecarId)
	recipient := query.Get("recipient")
	if recipient == "" {
		recipient = ownRecipient
	}
	covering := request.Sidecar.CoveringDelegationId
	if recipient != ownRecipient && (len(covering) == 0 || recipient != "d:"+hex.EncodeToString(covering)) {
		// a caller reads its own s: deliveries and its covering Delegation's d: ones alone
		request.Forbidden()
		return
	}
	want := query.Get("want")
	since := request.Now()
	if want != "" {
		if !gkmHexPrefixForm(want) {
			request.BadRequest()
			return
		}
		if sinceText := query.Get("since"); sinceText != "" {
			sinceMs, err := strconv.ParseInt(sinceText, 10, 64)
			if err != nil || sinceMs <= 0 {
				request.BadRequest()
				return
			}
			since = time.UnixMilli(sinceMs)
		}
	}
	facts, err := self.generationFacts(request.Ctx, request.Cluster, groupId, generation)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		request.NotFound()
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	c8, _ := gkmDigestPrefix(facts.commitment)
	prefix := GkmWrapRecipientPrefix(groupId, generation, c8, recipient)
	reply := &protocol.GkmWrapsReply{}
	read := func(key string) bool {
		held, _, err := readGkmObject(request.Ctx, request.Cluster, key, gkmDeliveryMaxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return true
		}
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(held, signed); err != nil {
			self.answerStoreError(request, errors.Join(errGkmStoreFault, err))
			return false
		}
		reply.Wraps = append(reply.Wraps, signed)
		return true
	}
	if want != "" {
		if !read(prefix + want) {
			return
		}
		if 0 < len(reply.GetWraps()) {
			request.Reply(reply)
			return
		}
	}
	infos, _, err := request.Cluster.List(request.Ctx, prefix, "", min(self.settings.WrapsReplyMaxCount, self.settings.ListPageCount))
	if err != nil {
		request.Unavailable()
		return
	}
	for _, info := range infos {
		if !read(info.Key) {
			return
		}
	}
	if want != "" {
		self.hintLateAsk(request, groupId, generation, recipient, since)
	}
	request.Reply(reply)
}

// A late delivery's ask: wrap-pending naming recipient to the repo's writers and, once since is LateAskWidenAge old,
// to up to LateAskOtherHolderMaxCount other holders, at most once per LateAskHintInterval per recipient and
// generation. A state that cannot answer now loses the hint, which the next ask, a minute later, sends again.
func (self *GkmEngine) hintLateAsk(request *GkmRequest, groupId sidecar.Id, generation uint64, recipient string, since time.Time) {
	now := request.Now()
	rate := GkmRate{Count: 1, Interval: self.settings.LateAskHintInterval}
	rateKey := "late_ask:" + sidecar.EvsKeyId(groupId) + ":" + strconv.FormatUint(generation, 10) + ":" + recipient
	if !rate.valid() || !self.rates.Allow(rate, rateKey, now) {
		return
	}
	writerIds, answer := self.deps.AuthState.RepoWriters(request.Principal, request.RepoId, now)
	if answer != GkmAuthAllowed {
		return
	}
	self.hintWork(writerIds, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &groupId, 0, []byte(recipient))
	if now.Sub(since) < self.settings.LateAskWidenAge {
		return
	}
	holderIds, answer := self.deps.AuthState.LateHolders(request.Principal, request.RepoId, recipient, now)
	if answer != GkmAuthAllowed {
		return
	}
	hinted := map[sidecar.Id]bool{request.SidecarId: true}
	for _, writerId := range writerIds {
		hinted[writerId] = true
	}
	otherIds := []sidecar.Id{}
	for _, holderId := range holderIds {
		if self.settings.LateAskOtherHolderMaxCount <= len(otherIds) {
			break
		}
		if !hinted[holderId] {
			hinted[holderId] = true
			otherIds = append(otherIds, holderId)
		}
	}
	self.hintWork(otherIds, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &groupId, 0, []byte(recipient))
}
