// POST /evs/v1/repos/<id>/reseed (§11.13's re-seed row, §19.10's repos step, D-EVS-17; EVSB-M2-20; the owner's answers
// QD-725 and QD-836): after a site loss, while sidecar.yml's reseed is on, a repo admin's device sends back what its
// mirror holds, one EvsReseedRequest a call, never re-signed:
//
//	push       {statement, payload}: one re-seeded Signed EvsPush. evs runs the push route's steps 4 to 8 in a reseed
//	           mode (push.go's attempt with reseed set), and its record is an EVS_BATCH_RESEED record
//	part       {statement, part_number, parts holding the one part}: one part of a re-seeded push in parts as the
//	           mirror holds it, sent as the push route's sender posts one (QD-836). evs checks it against the
//	           statement (its push id and its number under part_count, which part_number repeats, its changes_root
//	           over its own changes, no slot body; sidecar.EvsCheckPart, as the part route does) and the statement's
//	           signature at its own auth pin, then runs 5a on the cluster's head: a push that stands committed is
//	           answered its version, and nothing is written. Otherwise its EVS_BATCH_RESEED record, a part record's
//	           body with no receipts and the version of the head it read (QD-818), joins the open batch, paid at P1 as
//	           a posted part's record is, and its place is answered. Nothing reaches the ref
//	seal       {statement, part_places}: the push's seal, naming each part's record as its part call answered it, in
//	           part order. The same mode runs the push route's seal over the records at those places (push_seal.go's
//	           round, which takes EVS_BATCH_RESEED records alone, so the seal's checks with no slot body
//	           (EvsCheckRecordSeal; QD-819) and 5g for every part are the push route's own): a place that holds no
//	           part of this statement answers 409 PARTS_MISSING, and parts that are not the statement's push 400, each
//	           committing nothing. Step 6 writes the EVS_BATCH_SEAL record naming their places, which the window entry
//	           names as a pushed seal's, and step 7 commits
//	slot       {statement, slot_id, slot}: one slot object, taken only once the statement's push stands committed in
//	           its ref's history as a re-seeded version that names the slot, stripped of every key an ERASE evs holds
//	           covers, and written If-None-Match with origin 1.r (DESIGN-DETAILS 14.2.6); a slot left with no key is
//	           not stored (QD-096)
//	statement  {statement} alone, a Signed EvsReseed: kept at reseed/<repo>/<ref> once it names the ref's current head
//	           and a repo admin of evs's newest state signed it, and served with the head to a read whose pin is above
//	           it (read.go), which is how a reader's AcceptReseed gets it
//
// What the reseed mode skips of a push's checks, each of which a site loss makes impossible: 5b's time window and
// TIME_STALE; 5b's binding of the statement to the token, since an admin's device re-seeds other signers' pushes; 5c's
// storage limit and the cluster's cohort limit, and the counted rules (QD-084 leaves re-seed uploads unbilled); 5d's
// predicate against the newest state, which a generation of the history need not cover; 5h's receipts and their 24 h
// rule; an ERASE's NOTHING_TO_ERASE and a CLOSURE's slot rules, since slots come last; and the refuse row's recording,
// so every refusal refuses nothing and the device sends the push again once what it lacked is there.
//
// What it keeps: 5a, so a retry answers the version the push committed at and no version commits twice; the fence
// row; the signature under the identity key the state at the statement's own auth pin admits for its signer; §11.8's
// refs table at that state, read for the signer as readers read it (evs_verify.go); the pins never falling below the
// head's; 5e; 5f and 5g as the push route runs them, its own CheckBase and CheckPaths (QD-815); and 5h's rules for
// segments and slots, a new segment counting only once PUT seg/ holds it at its padded size (EVSB-M2-09 takes
// re-seed uploads while reseed is on). Step 6 writes no slot: the bodies a payload carries are as old as the push,
// and slots come last, stripped.
//
// So a git-mode push, and a file-mode push on the head, chain onto the current head, base_version and base_chain
// equal to it (QD-725), a git-mode one also waiting out another push's live seal lease. A file-mode push that a
// concurrent writer built on an older base commits on that base as it first did: inside 5f's window below the head,
// with base_chain the C_b the history holds and no path a version after its base changed (5g), so a ref several
// devices wrote re-seeds as far as the mirror holds it. A re-seed only adds versions past the head, and 5g refuses a
// push whose path a version after its base changed, so no stale mirror returns what a later version replaced. Where
// the new site's head is not the version before the one a push first committed at, after a sender skipped a version
// or another push landed first, the push lands at another version than it first held: evs takes it there, and the
// device, which sends in version order and checks the version each statement lands at, stops its ref
// (ErrEvsReseedVersion). BASE_STALE answers where the push route would, and carries the ref's head only on the
// caller's own deposit ref (plan-EVS1-deposit-head), as a 200 does: the checks judge the statement's signer, and the
// caller is the repo admin re-seeding it.
//
// The repo (§11.13, §11.12's refused row): evs takes re-seeds only for repos the projection lists live or restorable.
// One whose newest RepoDelete carries now, or is past ReseedRestoreWindow, is refused 409 SHREDDING; one whose
// RepoDelete is unrestored and inside the window has repo/ moved to deleted{deletion_id, its entry's time} before
// anything is taken, and then takes its history and slots while deleted, and its admin's segments at PUT .../segments
// (reseedAdmitsDeleted).
//
// A push in parts goes one part a call and then its seal, never whole (QD-836; question
// evs-reseed-parts-request-bound): every call carries at most one part of at most 1 MiB, so each is held to
// ReseedBodyMaxByteCount, within the lb's 16 MiB (RequestBodyMaxByteCount), and a request holds one part, whatever the
// push's 1,024 parts hold; the seal reads its parts back from their records for its checks, as the push route's seal
// does. A call carrying a push in parts whole, or more than one part, is INVALID. The parts'
// records are written before the seal is checked, as posted parts are: a part call retried after an answer it lost
// writes a second record and the seal names one, and parts a seal never names, a seal that never came's or a retry's
// copy, are dead weight that evacuation drops once their push is dead (resolve.go), as it drops a posted part no seal
// names. A re-seeded part carries no slot body, as no part does (QD-819): one that holds one is INVALID, so no reseed
// record keeps a key an ERASE may have destroyed, and the push's slots return by their own calls, stripped.
//
// Not built here, each refused before anything is written: a push carrying format 2 (EVS2-M10-13), and a statement at
// an auth pin evs's state does not retain. A reading waits on its question: a slot call names its version by the
// statement it carries (evs-reseed-route-slot-naming).

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The route's template.
const evsReseedRouteTemplate = "POST /evs/v1/repos/{repo_id}/reseed"

// reseed/<repo>/<ref>: the ref's Signed EvsReseed (evs-29). On the repo's metadata cluster.
const reseedKeyPrefix = "reseed/"

// reseed/<repo>/<ref>.
func ReseedKey(repoId sidecar.Id, refId sidecar.Id) string {
	return reseedKeyPrefix + sidecar.EvsKeyId(repoId) + "/" + sidecar.EvsKeyId(refId)
}

// The reseed route.
func (self *EvsEngine) reseedRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:         http.MethodPost,
			Pattern:        evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/reseed",
			Name:           evsReseedRouteTemplate,
			Rights:         sidecar.AclEvsAdmin,
			Write:          true,
			NeedsSureClock: true,
			Placed:         true,
			Serve:          self.serveReseed,
		},
	}
}

// What makes a push attempt a re-seed's. See the file header.
type reseedAttempt struct {
	// The unrestored RepoDelete a restorable repo's repo/ names while it takes its history; nil for a live repo.
	deletion *EvsRepoDeletionFacts
	// Each new segment's object size on the segment cluster, by id, read once per attempt; one seg/ does not hold has
	// no entry.
	segments     map[[32]byte]int64
	segmentsRead bool
}

// Whether a call is a part call or a seal call of a push in parts, by the fields only those carry (QD-836).
func reseedCallForm(body *protocol.EvsReseedRequest) (partCall bool, sealCall bool) {
	return body.GetPartNumber() != 0 || len(body.GetParts()) != 0, len(body.GetPartPlaces()) != 0
}

// See the file header.
func (self *EvsEngine) serveReseed(request *EvsRequest) {
	gates := self.host.GatesOrClosed()
	if !gates.Reseed() {
		// outside a recovery the route takes nothing: asked again at the interval the host rereads its gates
		request.retryAfter = gates.RetryAfter()
		request.Unavailable(nil)
		return
	}
	body := &protocol.EvsReseedRequest{}
	// every call carries at most one part (QD-836), so every call is held to the route's one bound
	if !request.ReadMessage(body, self.settings.ReseedBodyMaxByteCount) {
		return
	}
	deletion, ok := self.reseedRepo(request)
	if !ok {
		return
	}
	partCall, sealCall := reseedCallForm(body)
	switch {
	case len(body.GetSlotId()) != 0 || len(body.GetSlot()) != 0:
		if len(body.GetPayload()) != 0 || partCall || sealCall {
			request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a slot and a push in one call").Reply(sidecar.Id{}))
			return
		}
		request.Note("slot")
		self.serveReseedSlot(request, body)
	case sidecar.EvsSignedIsReseed(body.GetStatement()):
		if len(body.GetPayload()) != 0 || partCall || sealCall {
			request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "an EvsReseed with a payload").Reply(sidecar.Id{}))
			return
		}
		request.Note("statement")
		self.serveReseedStatement(request, body)
	default:
		attempt, ok := self.newReseedAttempt(request, body, deletion)
		if !ok {
			return
		}
		if attempt.part != nil {
			attempt.answer(attempt.runReseedPart())
			return
		}
		outcome := attempt.run()
		attempt.answer(outcome)
	}
}

// §11.13's repos rule before anything is taken: the projection lists the repo live or restorable, and a restorable
// one's repo/ reads deleted under its RepoDelete, moved there first when it stands active. The answer is that
// RepoDelete for a restorable repo, nil for a live one; false once the request has been answered.
func (self *EvsEngine) reseedRepo(request *EvsRequest) (*EvsRepoDeletionFacts, bool) {
	facts, answer := self.deps.AuthState.Repo(request.Principal, request.RepoId)
	switch answer {
	case EvsAuthAllowed:
	case EvsAuthDenied:
		// a repo the projection does not list is not re-seeded
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return nil, false
	default:
		request.Unavailable(nil)
		return nil, false
	}
	if facts == nil || facts.NetworkId != networkIdOf(request.Principal) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return nil, false
	}
	deletion, restorable := self.reseedDeletion(facts, request.Now())
	if !restorable {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
		return nil, false
	}
	read, err := self.repos.Read(request.Ctx, request.Cluster, request.RepoId)
	if !self.answerTransition(request, err) {
		return nil, false
	}
	object := read.Object
	switch object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE:
		if deletion == nil {
			return nil, true
		}
		// repo/ deleted{deletion_id, its entry's time} first, so access stays refused while the history returns
		// and restore and the timer resume
		moved, err := transitionRepo(request.Ctx, request.Cluster, self.repos, request.RepoId, self.settings.RepoTransitionRetryCount,
			self.p0Class(request.Cluster, sidecar.WriteP0KindLifecycle), decideDelete(deletion, request.Now()))
		if !self.answerTransition(request, err) {
			return nil, false
		}
		self.queueShred(request.Ctx, request.RepoId, moved.Object)
		return deletion, true
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		if deletion == nil || !evsRepoNamesDeletion(object, deletion.DeletionId) {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
			return nil, false
		}
		return deletion, true
	}
	// keying, shredding or shredded: nothing is taken
	request.RefuseCode(repoStateRefusal(object).Code)
	return nil, false
}

// The unrestored RepoDelete the projection's facts end in, nil for a live or restored repo, and whether the repo may
// still take its history back (§11.13, §11.12's re-seed exception): false for a RepoDelete with now or past
// ReseedRestoreWindow, the window a RepoRestore can still land in, after which nothing comes back. A RepoDelete the
// projection does not date is not known to be inside the window.
func (self *EvsEngine) reseedDeletion(facts *EvsRepoFacts, now time.Time) (*EvsRepoDeletionFacts, bool) {
	if facts == nil || facts.Deletion == nil || facts.Deletion.DeletionId == (sidecar.Id{}) || facts.Deletion.Restored {
		return nil, true
	}
	deletion := facts.Deletion
	if deletion.Now || deletion.Time.IsZero() || self.settings.ReseedRestoreWindow <= now.Sub(deletion.Time) {
		return deletion, false
	}
	return deletion, true
}

// §11.12's re-seed exception for a route that refuses a deleted repo (PUT .../segments): while sidecar.yml's reseed
// is on, a repo admin's request is taken for a repo whose repo/ reads deleted under the unrestored RepoDelete the
// projection ends in, inside the restore window, since its history, its segments with it, returns while it stays
// deleted. Everything else of a deleted repo stays refused.
func (self *EvsEngine) reseedAdmitsDeleted(request *EvsRequest, facts *EvsRepoFacts, object *protocol.EvsRepoObject) bool {
	if object.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || !self.host.GatesOrClosed().Reseed() || !request.Rights.Has(sidecar.AclEvsAdmin) {
		return false
	}
	deletion, restorable := self.reseedDeletion(facts, request.Now())
	return deletion != nil && restorable && evsRepoNamesDeletion(object, deletion.DeletionId)
}

// The attempt for a re-seeded push, one part of a push in parts, or its seal, or false once the request has been
// answered. A statement, payload or part that does not parse or verify refuses nothing.
func (self *EvsEngine) newReseedAttempt(request *EvsRequest, body *protocol.EvsReseedRequest, deletion *EvsRepoDeletionFacts) (*pushAttempt, bool) {
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
		tokenNetworkId: networkIdOf(request.Principal),
		// step 6 writes no slot: slots come last, stripped (serveReseedSlot)
		slotsWritten: true,
		reseed:       &reseedAttempt{deletion: deletion},
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
		if refusal.Reason == EvsCheckReasonFormatUnsupported {
			refusal = newEvsCheckRefusal(EvsCheckReasonUnchecked, "format 2's re-seed rules are EVS2-M10-13's")
		}
		request.Refuse(refusal.Reply(sidecar.Id{}))
		return nil, false
	}
	attempt.statement = statement
	push := statement.Push
	attempt.pushId = sidecar.Id(push.GetPushId())
	attempt.refId = sidecar.Id(push.GetRefId())
	request.NoteRefIds(attempt.refId)
	partCount := push.GetPartCount()
	partCall, sealCall := reseedCallForm(body)
	invalid := func(detail string) {
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, detail).Reply(attempt.pushId))
	}
	switch {
	case partCall && sealCall:
		invalid("a part and a seal in one call")
		return nil, false
	case partCount == 0 && (partCall || sealCall):
		invalid("a part or a seal of a one-part push")
		return nil, false
	case partCall && (len(body.GetParts()) != 1 || body.GetPartNumber() == 0 || partCount < body.GetPartNumber() || len(body.GetPayload()) != 0):
		invalid("a part call carrying other than one numbered part of its push")
		return nil, false
	case sealCall && (uint32(len(body.GetPartPlaces())) != partCount || len(body.GetPayload()) != 0):
		invalid("a seal whose places are not one per part")
		return nil, false
	case 0 < partCount && !partCall && !sealCall:
		// a push in parts goes one part a call, then its seal (QD-836)
		invalid("a push in parts sent whole")
		return nil, false
	}
	switch {
	case partCall:
		// one part, checked against its statement as the part route checks one (QD-836); its record is written by
		// runReseedPart, and the seal reads it at the place that answers
		part := body.GetParts()[0]
		checked, err := sidecar.EvsCheckPart(statement, part)
		if err != nil {
			refusal := EvsCheckRefusalOfCodec(err)
			if refusal.Reason == EvsCheckReasonFormatUnsupported {
				refusal = newEvsCheckRefusal(EvsCheckReasonUnchecked, "format 2's re-seed rules are EVS2-M10-13's")
			}
			request.Refuse(refusal.Reply(attempt.pushId))
			return nil, false
		}
		if checked.Part != body.GetPartNumber() {
			invalid("a part numbered unlike its call")
			return nil, false
		}
		request.Note("part")
		attempt.part = &partReads{number: checked.Part, bytes: part, checked: checked}
	case sealCall:
		// the push route's seal over the records at the places its part calls answered (push_seal.go), taking
		// EVS_BATCH_RESEED records alone
		request.Note("seal")
		attempt.seal = &sealReads{places: body.GetPartPlaces()}
	default:
		// the payload as the mirror holds the push's record, which evs served with no slot body (QD-806); slots come
		// last, by their own calls
		payload, err := sidecar.EvsCheckRecordPayload(statement, body.GetPayload())
		if err != nil {
			refusal := EvsCheckRefusalOfCodec(err)
			if refusal.Reason == EvsCheckReasonFormatUnsupported {
				refusal = newEvsCheckRefusal(EvsCheckReasonUnchecked, "format 2's re-seed rules are EVS2-M10-13's")
			}
			request.Refuse(refusal.Reply(attempt.pushId))
			return nil, false
		}
		attempt.payload = payload
		// and the record keeps none, whatever a mirror sends: a body an ERASE since destroyed a key of is not stored
		// again
		recordPayload, err := sidecar.EvsRecordPayload(body.GetPayload())
		if err != nil {
			request.Refuse(EvsCheckRefusalOfCodec(err).Reply(attempt.pushId))
			return nil, false
		}
		attempt.recordPayloadBytes = recordPayload
	}

	// the signature before any store read, at the statement's own auth pin: a statement nobody the log admitted
	// signed costs evs nothing
	attempt.networkId = attempt.tokenNetworkId
	if self.deps.GateViews == nil {
		request.Unavailable(nil)
		return nil, false
	}
	gateView, answer := self.deps.GateViews.View(attempt.networkId)
	if answer != EvsAuthAllowed || gateView == nil {
		request.Unavailable(nil)
		return nil, false
	}
	state, refusal := reseedPinState(gateView, push)
	if refusal == nil {
		refusal = checkReseedSignature(&PushView{RepoId: attempt.repoId, Statement: statement, Auth: state})
	}
	if refusal != nil {
		reply := refusal.Reply(attempt.pushId)
		if reply.GetCode() == protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE {
			request.Unavailable(reply)
		} else {
			request.Refuse(reply)
		}
		return nil, false
	}
	attempt.pushes = NewRecordPushSource(self.records, self.locator, attempt.cluster, attempt.repoId, attempt.refId)
	ok = true
	return attempt, true
}

// The state at the statement's own auth pin on evs's chain: what its signature and the refs table are judged at. A
// pin above evs's state, or one evs no longer retains, answers 503, refusing nothing; one off the chain is a fork.
func reseedPinState(gateView sidecar.GkmAuthView, push *protocol.EvsPush) (sidecar.GkmAuthView, *EvsCheckRefusal) {
	if gateView == nil {
		return nil, newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no authorization state")
	}
	state, err := gateView.At(push.GetAuth())
	switch {
	case err == nil && state != nil:
		return state, nil
	case err == nil:
		return nil, newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no state at the statement's auth pin")
	case errors.Is(err, sidecar.ErrGkmAuthAhead):
		return nil, newEvsCheckRefusal(EvsCheckReasonGateUnknown, "an auth pin above evs's state")
	case errors.Is(err, sidecar.ErrGkmAuthNotRetained):
		return nil, newEvsCheckRefusal(EvsCheckReasonUnchecked, "an auth pin evs's state does not retain")
	}
	return nil, newEvsCheckRefusal(EvsCheckReasonPinForked, "an auth pin off evs's chain")
}

// The rights §11.8's refs table reads for a re-seeded statement's signer, from the state at the statement's pin as a
// replaying reader holds them: rw for a writer the state lists, admin for a repo admin that stands, and deposit for a
// deposit ref's push, which the table holds to its depositor's own ref.
func reseedSignerRights(state sidecar.GkmAuthView, repoId sidecar.Id, signerId sidecar.Id, push *protocol.EvsPush) sidecar.AclEvsRights {
	rights := sidecar.AclEvsRights(0)
	if slices.Contains(state.RepoWriters(repoId), signerId) {
		rights |= sidecar.AclEvsWrite | sidecar.AclEvsRead
	}
	if sidecar.EvsRepoAdminIn(state, repoId, signerId) {
		rights |= sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	}
	if protocol.EvsRefKind(push.GetRefKind()) == protocol.EvsRefKind_EVS_REF_DEPOSIT {
		rights |= sidecar.AclEvsDeposit
	}
	return rights
}

// 5 (b-h) in the reseed mode, over what step 4 read: see the file header for what is skipped and kept.
func (self *pushAttempt) checkReseed() *EvsCheckRefusal {
	if self.formatRefusal != nil || self.needsFormat2 {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "format 2's re-seed rules are EVS2-M10-13's")
	}
	if self.reads == nil || self.reads.view == nil || self.reads.view.Payload == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no statement or payload in the view")
	}
	push := self.statement.Push
	state, refusal := reseedPinState(self.gateView, push)
	if refusal != nil {
		return refusal
	}
	signerId := sidecar.Id(push.GetSignerSidecarId())
	// the view step 4 built, judged for the statement's signer at the statement's own state in place of the token's
	// at the newest
	view := *self.reads.view
	view.Auth = state
	view.TokenSidecarId = signerId
	view.TokenClientId = sidecar.Id(push.GetClientId())
	view.Rights = reseedSignerRights(state, self.repoId, signerId, push)
	view.Receipts = nil
	if refusal := self.readReseedSegments(); refusal != nil {
		return refusal
	}
	checks := []func(view *PushView) *EvsCheckRefusal{
		checkReseedSignature,
		self.checkReseedRepo,
		checkRefTable,
		checkReseedPins,
		CheckPathEpoch,
		// the push route's own 5f and 5g, its window included (QD-815)
		CheckBase,
		CheckPaths,
		self.checkReseedObjects,
	}
	for _, check := range checks {
		if refusal := check(&view); refusal != nil {
			if refusal.DepositHead != nil && !self.ownDepositRef() {
				// the view's token is the statement's signer: a deposit ref's head goes to its own depositor alone
				refusal.DepositHead = nil
			}
			return refusal
		}
	}
	return nil
}

// 5b without its time window and its token binding: the statement names the route's repo and verifies under the
// identity key the state at its own auth pin, view.Auth, admits for its signer.
func checkReseedSignature(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	if !bytes.Equal(push.GetRepoId(), view.RepoId.Bytes()) {
		return newEvsCheckRefusal(EvsCheckReasonRepoMismatch, "a statement of another repo")
	}
	signerId, err := sidecar.IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return newEvsCheckRefusal(EvsCheckReasonSignature, "a statement with no signer")
	}
	if view.Auth == nil {
		return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no authorization state")
	}
	identityKey := view.Auth.IdentityKey(signerId)
	if len(identityKey) == 0 {
		return newEvsCheckRefusal(EvsCheckReasonSignature, "a signer the state at its pin admits no identity key for")
	}
	if err := view.Statement.Verify(identityKey); err != nil {
		return newEvsCheckRefusal(EvsCheckReasonSignature, "a signature that does not verify")
	}
	return nil
}

// 5c's repo/ state for a re-seed: active, or deleted under the unrestored RepoDelete the route held it to (§11.12's
// re-seed exception), and of a format the instance writes.
func (self *pushAttempt) checkReseedRepo(view *PushView) *EvsCheckRefusal {
	repo := view.Repo
	if repo == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no repo/ read")
	}
	if repo.GetState() == protocol.EvsRepoState_EVS_REPO_DELETED {
		deletion := self.reseed.deletion
		if deletion == nil || !evsRepoNamesDeletion(repo, deletion.DeletionId) {
			return newEvsCheckRefusal(EvsCheckReasonRepoDeleted, "repo/ deleted under another RepoDelete, or restored")
		}
		if view.InstanceFormat < repo.GetFormat() {
			return newEvsCheckRefusal(EvsCheckReasonRepoFormat, fmt.Sprintf("a repo of format %d at an instance of format %d", repo.GetFormat(), view.InstanceFormat))
		}
		return nil
	}
	return checkRepoState(repo, view.InstanceFormat)
}

// 5d's fence alone: neither pin of the statement lies below the head's, equal versions needing equal chains and
// commitments. A history's pins never fall, so one replayed in order passes.
func checkReseedPins(view *PushView) *EvsCheckRefusal {
	if !view.headExists() {
		return nil
	}
	push := view.Statement.Push
	head := view.Head
	pinBelow := func(detail string) *EvsCheckRefusal {
		return newEvsCheckRefusal(EvsCheckReasonPinBelowHead, detail)
	}
	if headAuth := head.GetAuth(); headAuth != nil {
		switch {
		case push.GetAuth().GetVersion() < headAuth.GetVersion():
			return pinBelow(fmt.Sprintf("auth pin %d below the head's %d", push.GetAuth().GetVersion(), headAuth.GetVersion()))
		case push.GetAuth().GetVersion() == headAuth.GetVersion() && !bytes.Equal(push.GetAuth().GetChain(), headAuth.GetChain()):
			return pinBelow("the head's auth pin under another chain")
		}
	}
	if 0 < head.GetGeneration() {
		switch {
		case push.GetGeneration() < head.GetGeneration():
			return pinBelow(fmt.Sprintf("generation %d below the head's %d", push.GetGeneration(), head.GetGeneration()))
		case push.GetGeneration() == head.GetGeneration() && !bytes.Equal(push.GetGenerationCommitment(), head.GetGenerationCommitment()):
			return pinBelow("the head's generation under another commitment")
		}
	}
	return nil
}

// Step 4's read for the reseed mode's 5h, once per attempt: seg/ for each new segment the payload lists.
func (self *pushAttempt) readReseedSegments() *EvsCheckRefusal {
	reseed := self.reseed
	if reseed.segmentsRead {
		return nil
	}
	segments := map[[32]byte]int64{}
	var segmentCluster sidecar.BlobCluster
	for _, object := range self.payload.NewObjects {
		if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT || len(object.Id) != 32 {
			continue
		}
		if segmentCluster == nil {
			cluster, err := self.engine.blobs.SegmentCluster()
			if err != nil {
				return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no segment cluster")
			}
			segmentCluster = cluster
		}
		segmentId := [32]byte(object.Id)
		info, err := segmentCluster.Head(self.ctx, SegmentKey(self.repoId, segmentId))
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
		case err != nil:
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a segment's HEAD that did not answer")
		default:
			segments[segmentId] = info.ByteCount
		}
	}
	reseed.segments = segments
	reseed.segmentsRead = true
	return nil
}

// The EVS_BATCH_RESEED record of a part call's part (QD-818, QD-836): a part record's body, the statement, the part as
// the call carried it, no receipts, since a re-seed takes its segments from seg/, and checkedVersion, the version of
// the head the call read.
func (self *pushAttempt) reseedPartRecord(checkedVersion uint64) *sidecar.EvsBatchRecord {
	push := self.statement.Push
	return &sidecar.EvsBatchRecord{
		Type:            protocol.EvsBatchRecordType_EVS_BATCH_RESEED,
		RepoId:          self.repoId,
		RefId:           self.refId,
		PushId:          self.pushId,
		SignerSidecarId: sidecar.Id(push.GetSignerSidecarId()),
		TimeMs:          push.GetTimeMs(),
		Body:            sidecar.EvsPartRecordBody(self.statement.Bytes, self.part.bytes, nil, checkedVersion),
	}
}

// A part call once its statement and part have checked (QD-836): 5a on the cluster's head, then the part's
// EVS_BATCH_RESEED record, paid at P1 in the token network's queue as a posted part's record is (push_part.go's
// admitPart), and 200 {place}. A part of a push that stands committed answers 200 {version}, writing nothing, so a
// walk that sends a version evs holds again costs no record. Nothing reaches the head: a part issues no step 7, so the
// fence row ends none, and only its seal commits. A record whose append does not answer is a record no seal names
// yet, and the device's retry writes another; the seal names one.
func (self *pushAttempt) runReseedPart() *pushOutcome {
	defer self.cancel()
	defer func() {
		if self.grant != nil {
			self.grant.Close()
		}
	}()
	head, err := self.engine.heads.ReadCluster(self.ctx, self.cluster, self.repoId, self.refId)
	if err != nil {
		return self.unavailableOn(err)
	}
	if outcome := self.settle(head); outcome != nil {
		return outcome
	}
	if outcome := self.admitPart(); outcome != nil {
		return outcome
	}
	barrierKey := barrierRefKey(self.repoId, self.refId)
	testHookBarrier(BarrierReseedPartAppendBefore, barrierKey)
	place, err := self.engine.batches.AppendFormat2(self.writeCtx, self.cluster.ClusterId(), self.reseedPartRecord(head.Version()), nil)
	testHookBarrier(BarrierReseedPartAppendAfter, barrierKey)
	if err != nil {
		return self.unavailable()
	}
	return &pushOutcome{committed: true, partPlace: place}
}

// 5h in the reseed mode: check_objects.go's segment and slot rules with seg/ in the receipts' place. Each new segment
// of the new-objects list is one seg/ holds at its padded size, else 409 SEGMENT_GONE, on which the device uploads it
// and sends the push again; every segment a new version names is one of those or appears in a version step 4 read;
// every slot a new version names is one the push introduces or one a version step 4 read names, on a deposit ref only
// one it introduces. An ERASE's and a CLOSURE's own slot rules are not run: slots come last.
func (self *pushAttempt) checkReseedObjects(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	newSegments := map[[32]byte]bool{}
	newSlots := map[sidecar.Id]bool{}
	for _, object := range view.Payload.NewObjects {
		switch object.Kind {
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
			if len(object.Id) != 32 {
				return newEvsCheckRefusal(EvsCheckReasonInvalid, "a new segment's id")
			}
			segmentId := [32]byte(object.Id)
			size, held := self.reseed.segments[segmentId]
			if !held {
				// the re-upload is still to come: nothing is refused for good
				return newEvsCheckRefusal(EvsCheckReasonSegmentGone, "a new segment seg/ does not hold")
			}
			if uint64(size) != object.PaddedSize {
				return newEvsCheckRefusal(EvsCheckReasonReceiptInvalid, "a new segment unlike the object seg/ holds")
			}
			newSegments[segmentId] = true
		case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT:
			newSlots[sidecar.Id(object.Id)] = true
		default:
			return newEvsCheckRefusal(EvsCheckReasonUnchecked, fmt.Sprintf("a re-seeded new object of kind %d", object.Kind))
		}
	}
	citedSegments, citedSlots, refusal := evsCitable(view)
	if refusal != nil {
		return refusal
	}
	deposit := protocol.EvsRefKind(push.GetRefKind()) == protocol.EvsRefKind_EVS_REF_DEPOSIT
	for _, change := range view.Payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return newEvsCheckRefusal(EvsCheckReasonInvalid, "an entry version that does not parse")
		}
		for _, locator := range entry.GetChain() {
			switch protocol.EvsLocatorKind(locator.GetKind()) {
			case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
				if len(locator.GetId()) != 32 {
					return newEvsCheckRefusal(EvsCheckReasonInvalid, "a segment locator's id")
				}
				segmentId := [32]byte(locator.GetId())
				if !newSegments[segmentId] && !citedSegments[segmentId] {
					refusal := newEvsCheckRefusal(EvsCheckReasonSegmentUnknown, "a segment neither held nor named by a version read")
					refusal.Paths = []sidecar.EvsTokenPath{change.TokenPath}
					return refusal
				}
			case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
				if len(locator.GetInline()) == 0 {
					return newEvsCheckRefusal(EvsCheckReasonInvalid, "an inline locator holding no record")
				}
			}
		}
		for _, slotId := range entry.GetSlotIds() {
			switch {
			case newSlots[sidecar.Id(slotId)]:
			case deposit:
				refusal := newEvsCheckRefusal(EvsCheckReasonSlotUnknown, "a deposit naming a slot its push does not introduce")
				refusal.Paths = []sidecar.EvsTokenPath{change.TokenPath}
				return refusal
			case !citedSlots[sidecar.Id(slotId)]:
				refusal := newEvsCheckRefusal(EvsCheckReasonSlotUnknown, "a slot neither introduced nor named by a version read")
				refusal.Paths = []sidecar.EvsTokenPath{change.TokenPath}
				return refusal
			}
		}
	}
	return nil
}

// A slot call: see the file header. 200 with an empty EvsPushReply once the slot stands without any key an ERASE evs
// holds covers, or holds no key and is not stored; 409 SLOT_UNKNOWN while no re-seeded version names it, and 409
// SLOT_STALE when the cluster already holds another object at its id, which is left as it is.
func (self *EvsEngine) serveReseedSlot(request *EvsRequest, body *protocol.EvsReseedRequest) {
	invalid := func(detail string) {
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, detail).Reply(sidecar.Id{}))
	}
	slotId, err := sidecar.IdFromBytes(body.GetSlotId())
	if err != nil {
		invalid("a slot id")
		return
	}
	if len(body.GetSlot()) == 0 || self.settings.SlotMaxByteCount < int64(len(body.GetSlot())) {
		invalid("a slot's size")
		return
	}
	if _, err := sidecar.EvsDecodeSlotObject(body.GetSlot()); err != nil {
		invalid("a slot that does not parse")
		return
	}
	statement, err := sidecar.ParseEvsStatement(body.GetStatement())
	if err != nil {
		// no version named: nothing says a re-seeded version names the slot
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
		return
	}
	push := statement.Push
	if !bytes.Equal(push.GetRepoId(), request.RepoId.Bytes()) {
		invalid("a statement of another repo")
		return
	}
	refId := sidecar.Id(push.GetRefId())
	request.NoteRefIds(refId)
	named, err := self.reseededVersionNames(request.Ctx, request.Cluster, request.RepoId, refId, statement, slotId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	if !named {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN)
		return
	}
	// every ERASE evs holds, applied before the slot is served (QD-096)
	erasedIndexes, err := self.reseedErasedIndexes(request.Ctx, request.Cluster, request.RepoId, slotId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	stripped, _, err := sidecar.EvsSlotWithoutKeys(body.GetSlot(), erasedIndexes)
	if err != nil {
		invalid("a slot that does not parse")
		return
	}
	slot, err := sidecar.EvsDecodeSlotObject(stripped)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	if len(slot.GetKeys()) == 0 {
		// a slot left with no key is not stored
		request.Reply(&protocol.EvsPushReply{})
		return
	}
	metadata, err := EvsSlotOriginReseeded().Metadata(self.settings.SlotOriginMaxByteCount)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	grant, ok := self.admitOne(request, WriteOperationCreate, int64(len(stripped)))
	if !ok {
		return
	}
	defer grant.Close()
	key := SlotKey(request.RepoId, slotId)
	barrierKey := barrierSlotKey(request.RepoId, slotId)
	testHookBarrier(BarrierReseedSlotPutBefore, barrierKey)
	_, err = request.Cluster.PutIfNoneMatch(grant.Context(), key, stripped, &sidecar.BlobPutOptions{Metadata: metadata})
	testHookBarrier(BarrierReseedSlotPutAfter, barrierKey)
	// the bytes that stand at the id once this call may answer 200
	standing := stripped
	var unknown *sidecar.BlobUnknownError
	switch {
	case err == nil:
	case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		// the cluster holds the id, or the create's answer was lost: the object decides, compared after stripping
		// (DESIGN-DETAILS 14.2.6)
		object, err := request.Cluster.Get(request.Ctx, key)
		if err != nil {
			// a 404 after a lost answer: by the settle rule the create never landed, and the device sends it again
			request.Unavailable(nil)
			return
		}
		stored, err := readAllLimited(object, self.settings.SlotMaxByteCount)
		object.Body.Close()
		if err != nil {
			request.Unavailable(nil)
			return
		}
		storedStripped, _, err := sidecar.EvsSlotWithoutKeys(stored, erasedIndexes)
		if err != nil || !bytes.Equal(storedStripped, stripped) {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
			return
		}
		standing = stored
	default:
		request.Unavailable(nil)
		return
	}
	// An ERASE that committed after the list above was read found no slot to rewrite, so the slot may stand with a
	// key it covers. The list is read again now that the slot stands, and the keys it covers are dropped as that
	// ERASE's own rewrite drops them; an ERASE that commits after this read finds the slot and rewrites it itself.
	// A read or rewrite that does not finish answers 503, and the device's next call for the slot ends here again.
	erasedIndexes, err = self.reseedErasedIndexes(request.Ctx, request.Cluster, request.RepoId, slotId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	if _, removedCount, err := sidecar.EvsSlotWithoutKeys(standing, erasedIndexes); err != nil || 0 < removedCount {
		rewriter := &slotRewriter{budget: self.budget, priceTable: self.priceTable, settings: self.settings}
		if err := rewriter.rewriteSlot(request.Ctx, request.Cluster, request.RepoId, slotId, erasedIndexes); err != nil {
			self.log.Warningf("[evs] repo %s: a re-seeded slot's erased keys were not dropped: %v", sidecar.EvsKeyId(request.RepoId), err)
			request.Unavailable(nil)
			return
		}
	}
	request.Reply(&protocol.EvsPushReply{})
}

// Whether statement's push stands committed in refId's history as a re-seeded version whose payload names slotId: a
// slot its new-objects list introduces or one of its entry versions names. A re-seeded version is a one-part push's
// EVS_BATCH_RESEED record, or a seal whose parts are EVS_BATCH_RESEED records (QD-818): the record's type is the mark.
// A push the push route committed, one-part or sealed, names nothing for a re-seed.
func (self *EvsEngine) reseededVersionNames(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, statement *sidecar.EvsStatement, slotId sidecar.Id) (bool, error) {
	push := statement.Push
	head, err := self.heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil {
		return false, err
	}
	if head.Absent() || head.Version() == 0 {
		return false, nil
	}
	gitMode := protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
	standing, err := EvsPushStandingIn(ctx, head.Head, sidecar.Id(push.GetPushId()), statement.Sha256, push.GetBaseVersion(), gitMode,
		func(ctx context.Context, page uint64) (*LogPage, error) {
			return self.readLogPage(ctx, cluster, repoId, refId, page)
		})
	if err != nil {
		return false, err
	}
	if !standing.Committed || standing.Place == nil {
		return false, nil
	}
	record, err := self.readRecordAt(ctx, cluster, repoId, refId, standing.Place)
	if err != nil {
		return false, err
	}
	var payload *sidecar.EvsCheckedPayload
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return false, err
		}
		if !bytes.Equal(statementBytes, statement.Bytes) {
			return false, nil
		}
		if payload, err = sidecar.EvsCheckStoredPayload(statement, payloadBytes); err != nil {
			return false, err
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		reseeded := false
		if payload, reseeded, err = self.reseededSealPayload(ctx, cluster, repoId, refId, statement, record); err != nil || !reseeded {
			return false, err
		}
	default:
		return false, nil
	}
	for _, object := range payload.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT && bytes.Equal(object.Id, slotId.Bytes()) {
			return true, nil
		}
	}
	for _, change := range payload.Changes {
		if !change.WritesEntry() {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return false, err
		}
		for _, named := range entry.GetSlotIds() {
			if bytes.Equal(named, slotId.Bytes()) {
				return true, nil
			}
		}
	}
	return false, nil
}

// The joined payload of a committed seal that seals a re-seeded push in parts (QD-818): every part it names an
// EVS_BATCH_RESEED record of statement holding a part's body, checked whole as a stored seal is, each part matched to
// the root the seal names for it. false for a seal of another statement, or of parts the push route took, which
// re-seeded nothing.
func (self *EvsEngine) reseededSealPayload(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, statement *sidecar.EvsStatement, seal *sidecar.EvsBatchRecord) (*sidecar.EvsCheckedPayload, bool, error) {
	statementBytes, sealParts, err := sidecar.ParseEvsSealRecordBody(seal.Body)
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(statementBytes, statement.Bytes) {
		return nil, false, nil
	}
	partBytes := make([][]byte, len(sealParts))
	for i, sealPart := range sealParts {
		record, err := self.readRecordAt(ctx, cluster, repoId, refId, sealPart.Place)
		if err != nil {
			return nil, false, err
		}
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED || record.PushId != seal.PushId {
			return nil, false, nil
		}
		partStatement, part, _, _, err := sidecar.ParseEvsSealPartRecord(record)
		if err != nil {
			return nil, false, err
		}
		if !bytes.Equal(partStatement, statement.Bytes) {
			return nil, false, nil
		}
		partBytes[i] = part
	}
	payload, checkedParts, err := sidecar.EvsCheckStoredSeal(statement, partBytes)
	if err != nil {
		return nil, false, err
	}
	for i, checkedPart := range checkedParts {
		if checkedPart.Root != sealParts[i].ChangesRoot {
			return nil, false, fmt.Errorf("%w: a part whose changes_root the seal does not name", ErrEvsStatementMismatch)
		}
	}
	return payload, true, nil
}

// The key indexes of slotId that the ERASE pushes evs holds cover: every committed ERASE of the repo's erasure ref,
// from its first version to its head, in its window and its log pages.
func (self *EvsEngine) reseedErasedIndexes(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, slotId sidecar.Id) ([]uint32, error) {
	refId := sidecar.EvsErasureRefId(repoId)
	head, err := self.heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil {
		return nil, err
	}
	if head.Absent() || head.Version() == 0 {
		return nil, nil
	}
	pushes := newReadPushes(self, ctx, cluster, repoId, refId, head.Head)
	indexes := []uint32{}
	for version := uint64(1); version <= head.Version(); version += 1 {
		push, err := pushes.at(version)
		if err != nil {
			return nil, err
		}
		if push.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) == 0 {
			continue
		}
		if err := pushes.readRecord(push); err != nil {
			return nil, err
		}
		if push.payload == nil {
			return nil, fmt.Errorf("%w: an ERASE at version %d whose record holds no payload", ErrEvsStatementMismatch, version)
		}
		for _, erased := range push.payload.Erased {
			if erased.SlotId == slotId {
				indexes = append(indexes, uint32(erased.KeyIndex))
			}
		}
	}
	return indexes, nil
}

// A statement call: see the file header. 200 {version} once reseed/<repo>/<ref> holds the statement; 409 BASE_STALE
// for one that does not name the ref's current head, and 403 SCOPE for one no repo admin of the newest state signed.
func (self *EvsEngine) serveReseedStatement(request *EvsRequest, body *protocol.EvsReseedRequest) {
	statement, err := sidecar.ParseEvsReseedStatement(body.GetStatement(), self.settings.ReseedStatementMaxByteCount)
	if err != nil {
		request.Refuse(EvsCheckRefusalOfCodec(err).Reply(sidecar.Id{}))
		return
	}
	if statement.RepoId != request.RepoId {
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonRepoMismatch, "a reseed of another repo").Reply(sidecar.Id{}))
		return
	}
	request.NoteRefIds(statement.RefId)
	if self.deps.GateViews == nil {
		request.Unavailable(nil)
		return
	}
	gateView, answer := self.deps.GateViews.View(networkIdOf(request.Principal))
	if answer != EvsAuthAllowed || gateView == nil {
		request.Unavailable(nil)
		return
	}
	if !sidecar.EvsRepoAdminIn(gateView, request.RepoId, statement.SignerSidecarId) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return
	}
	if err := statement.Verify(gateView.IdentityKey(statement.SignerSidecarId)); err != nil {
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonSignature, "a reseed's signature").Reply(sidecar.Id{}))
		return
	}
	head, err := self.heads.ReadCluster(request.Ctx, request.Cluster, request.RepoId, statement.RefId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	if head.Absent() || head.Version() != statement.Version || !bytes.Equal(head.Head.GetChain(), statement.Chain[:]) {
		// it names another head than the one evs serves, which no reader could accept it for
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
		return
	}
	grant, ok := self.admitOne(request, WriteOperationOverwrite, int64(len(statement.Bytes)))
	if !ok {
		return
	}
	defer grant.Close()
	key := ReseedKey(request.RepoId, statement.RefId)
	barrierKey := barrierRefKey(request.RepoId, statement.RefId)
	for attempt := 0; attempt <= self.settings.ReseedStatementRetryCount; attempt += 1 {
		testHookBarrier(BarrierReseedStatementPutBefore, barrierKey)
		_, err := request.Cluster.PutIfNoneMatch(grant.Context(), key, statement.Bytes, nil)
		testHookBarrier(BarrierReseedStatementPutAfter, barrierKey)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			request.Reply(&protocol.EvsPushReply{Version: statement.Version})
			return
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		default:
			request.Unavailable(nil)
			return
		}
		object, err := request.Cluster.Get(request.Ctx, key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			request.Unavailable(nil)
			return
		}
		stored, err := readAllLimited(object, int64(self.settings.ReseedStatementMaxByteCount))
		object.Body.Close()
		if err != nil {
			request.Unavailable(nil)
			return
		}
		if bytes.Equal(stored, statement.Bytes) {
			request.Reply(&protocol.EvsPushReply{Version: statement.Version})
			return
		}
		// an earlier statement of the ref: the one naming the head evs serves now replaces it, since a reader accepts
		// only that one
		testHookBarrier(BarrierReseedStatementPutBefore, barrierKey)
		_, err = request.Cluster.PutIfMatch(grant.Context(), key, object.Etag, statement.Bytes, nil)
		testHookBarrier(BarrierReseedStatementPutAfter, barrierKey)
		switch {
		case err == nil:
			request.Reply(&protocol.EvsPushReply{Version: statement.Version})
			return
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown), errors.Is(err, sidecar.ErrBlobNotFound):
		default:
			request.Unavailable(nil)
			return
		}
	}
	request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
}

// The ref's Signed EvsReseed for a read whose pin is above the head it is served (§11.13; QD-725): the bytes
// reseed/<repo>/<ref> holds, nil when it holds none or the read fails, which costs the reader only the statement: it
// refuses the head below its pin as it does without one.
func (self *EvsEngine) readReseedStatement(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id) []byte {
	object, err := cluster.Get(ctx, ReseedKey(repoId, refId))
	if err != nil {
		return nil
	}
	defer object.Body.Close()
	stored, err := readAllLimited(object, int64(self.settings.ReseedStatementMaxByteCount))
	if err != nil {
		return nil
	}
	return stored
}

// The frame a read's reply carries the statement in, after its head.
func reseedStatementFrame(refId sidecar.Id, statement []byte) *protocol.EvsReadFrame {
	return &protocol.EvsReadFrame{Object: &protocol.EvsReadObject{
		Kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_RESEED,
		Id:   refId.Bytes(),
		Body: statement,
	}}
}
