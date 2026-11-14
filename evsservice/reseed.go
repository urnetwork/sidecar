// POST /evs/v1/repos/<id>/reseed (§11.13's re-seed row, §19.10's repos step, D-EVS-17; EVSB-M2-20; the owner's answer
// QD-725): after a site loss, while sidecar.yml's reseed is on, a repo admin's device sends back what its mirror
// holds, one EvsReseedRequest a call, never re-signed:
//
//	push       {statement, payload}: one re-seeded Signed EvsPush. evs runs the push route's steps 4 to 8 in a reseed
//	           mode (push.go's attempt with reseed set), and its record is an EVS_BATCH_RESEED record
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
// What it keeps: 5a, so a retry answers the version the push committed at; the fence row; the signature under the
// identity key the state at the statement's own auth pin admits for its signer; §11.8's refs table at that state,
// read for the signer as readers read it (evs_verify.go); the pins never falling below the head's; 5e; the chain
// onto the current head, base_version and base_chain equal to it, so only versions past the head go and no stale
// mirror returns what a later version replaced; 5f's lease; 5g; and 5h's rules for segments and slots, a new
// segment counting only once PUT seg/ holds it at its padded size (EVSB-M2-09 takes re-seed uploads while reseed is
// on). Step 6 writes no slot: the bodies a payload carries are as old as the push, and slots come last, stripped.
//
// The repo (§11.13, §11.12's refused row): evs takes re-seeds only for repos the projection lists live or restorable.
// One whose newest RepoDelete carries now, or is past ReseedRestoreWindow, is refused 409 SHREDDING; one whose
// RepoDelete is unrestored and inside the window has repo/ moved to deleted{deletion_id, its entry's time} before
// anything is taken, and then takes its history and slots while deleted.
//
// Not built here, each refused before anything is written: a push in parts (question
// evs-reseed-route-part-records), a push carrying format 2 (EVS2-M10-13), and a statement at an auth pin evs's state
// does not retain. Two readings wait on their questions: the base equal to the head holds for file mode too, so a
// push a concurrent writer built on an older base ends its ref's re-seed (evs-reseed-route-file-mode-base), and a
// slot call names its version by the statement it carries (evs-reseed-route-slot-naming).

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

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
	if !request.ReadMessage(body, self.settings.ReseedBodyMaxByteCount) {
		return
	}
	deletion, ok := self.reseedRepo(request)
	if !ok {
		return
	}
	switch {
	case len(body.GetSlotId()) != 0 || len(body.GetSlot()) != 0:
		if len(body.GetPayload()) != 0 || len(body.GetParts()) != 0 {
			request.Refuse(newEvsCheckRefusal(EvsCheckReasonInvalid, "a slot and a push in one call").Reply(sidecar.Id{}))
			return
		}
		request.Note("slot")
		self.serveReseedSlot(request, body)
	case sidecar.EvsSignedIsReseed(body.GetStatement()):
		if len(body.GetPayload()) != 0 || len(body.GetParts()) != 0 {
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
	var deletion *EvsRepoDeletionFacts
	if facts.Deletion != nil && facts.Deletion.DeletionId != (sidecar.Id{}) && !facts.Deletion.Restored {
		deletion = facts.Deletion
		// with now, or past the window a RepoRestore can still land in: never restorable, so nothing comes back. A
		// RepoDelete the projection does not date is not known to be inside the window
		if deletion.Now || deletion.Time.IsZero() || self.settings.ReseedRestoreWindow <= request.Now().Sub(deletion.Time) {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
			return nil, false
		}
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

// The attempt for a re-seeded push, or false once the request has been answered. A statement or payload that does
// not parse or verify refuses nothing.
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
	if 0 < len(body.GetParts()) || 0 < push.GetPartCount() {
		// a push in parts: what its part records are is unsettled (question evs-reseed-route-part-records), so
		// nothing of it is written
		refusal := newEvsCheckRefusal(EvsCheckReasonUnchecked, "a re-seeded push in parts")
		request.Unavailable(refusal.Reply(attempt.pushId))
		return nil, false
	}
	payload, err := sidecar.EvsCheckPayload(statement, body.GetPayload())
	if err != nil {
		refusal := EvsCheckRefusalOfCodec(err)
		if refusal.Reason == EvsCheckReasonFormatUnsupported {
			refusal = newEvsCheckRefusal(EvsCheckReasonUnchecked, "format 2's re-seed rules are EVS2-M10-13's")
		}
		request.Refuse(refusal.Reply(attempt.pushId))
		return nil, false
	}
	attempt.payload = payload

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
		checkReseedBase,
		CheckBase,
		CheckPaths,
		self.checkReseedObjects,
	}
	for _, check := range checks {
		if refusal := check(&view); refusal != nil {
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

// The chain onto the current head (QD-725): base_version is the head's version and base_chain its C_v, C_0 for a ref
// with none, so a re-seed takes only the version right past the head. Final for this head: the device sends the
// history in version order.
func checkReseedBase(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	version := view.headVersion()
	stale := func(detail string) *EvsCheckRefusal {
		if protocol.EvsRefMode(push.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT {
			return newEvsCheckRefusal(EvsCheckReasonNonFastForward, detail)
		}
		return newEvsCheckRefusal(EvsCheckReasonBaseStale, detail)
	}
	if push.GetBaseVersion() != version {
		return stale(fmt.Sprintf("a re-seeded push on base %d at version %d", push.GetBaseVersion(), version))
	}
	chain := sidecar.EvsChainStart(view.RepoId, sidecar.Id(push.GetRefId()))
	headChain := chain[:]
	if 0 < version {
		headChain = view.Head.GetChain()
	}
	if !bytes.Equal(push.GetBaseChain(), headChain) {
		return stale("a re-seeded push whose base chain is not the head's")
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

// A slot call: see the file header. 200 with an empty EvsPushReply once the slot stands, or holds no key and is not
// stored; 409 SLOT_UNKNOWN while no re-seeded version names it, and 409 SLOT_STALE when the cluster already holds
// another object at its id, which is left as it is.
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
	_, err = request.Cluster.PutIfNoneMatch(grant.Context(), key, stripped, &sidecar.BlobPutOptions{Metadata: metadata})
	var unknown *sidecar.BlobUnknownError
	switch {
	case err == nil:
		request.Reply(&protocol.EvsPushReply{})
		return
	case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
	default:
		request.Unavailable(nil)
		return
	}
	// the cluster holds the id, or the create's answer was lost: the object decides, compared after stripping, and
	// is left as it is either way (DESIGN-DETAILS 14.2.6)
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
	if err == nil && bytes.Equal(storedStripped, stripped) {
		request.Reply(&protocol.EvsPushReply{})
		return
	}
	request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE)
}

// Whether statement's push stands committed in refId's history as a re-seeded version whose payload names slotId: a
// slot its new-objects list introduces or one of its entry versions names. A push committed any other way, a push
// route's own or one in parts, names nothing for a re-seed.
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
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		return false, nil
	}
	statementBytes, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(statementBytes, statement.Bytes) {
		return false, nil
	}
	payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
	if err != nil {
		return false, err
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
	for attempt := 0; attempt <= self.settings.ReseedStatementRetryCount; attempt += 1 {
		_, err := request.Cluster.PutIfNoneMatch(grant.Context(), key, statement.Bytes, nil)
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
		_, err = request.Cluster.PutIfMatch(grant.Context(), key, object.Etag, statement.Bytes, nil)
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
