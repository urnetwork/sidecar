// A re-formed group's ladder and its first commit's floor (KEYS-M2-25; D-KEYS-12, D-KEYS-13; §10.8's site loss,
// plan-KEYS-reform-ladder's rules 3 to 5 as QD-074 decided them, DESIGN-DETAILS 6.2.2): POST /gkm/groups/<id>/ladder,
// over gkm/<group_id>/gen/<k> on the repo's cluster.
//
// A re-form files its GroupForm and its new group's epoch/0 through the forms route (groups.go), which carries no
// GenRotate. The group's generations at or below the form's follow here, the old group's Signed GenRotates byte for
// byte, each naming its old group_id, since GenLink's AAD and C_g hold no group_id and so the ladder carries over.
// The route's checks, in order:
//
//   - admin on the group's repo (the guard), with repo/ active or keying, or deleted while §19.10's re-seed mode is
//     on: a repo re-seeded as deleted takes its GroupForm and this ladder and nothing else (owner decision 82);
//   - the repo's newest GroupForm names the group and is a re-form, and the group's epoch/1 does not exist yet;
//   - at most 64 statements a call, consecutive and ascending, none past the form's generation, each a Signed
//     GenRotate of the repo held to its shape, whose parent_commitment is gen/<k-1>'s commitment, the call's own
//     previous statement or the one stored, so the ladder goes up in order from generation 1;
//   - each is written If-None-Match, equal bytes answering success, so a call a crash cut short is sent again;
//     other bytes at a generation answer 409 with them, and nothing past it is written.
//
// The claim checks' time and signer rows are skipped: a ladder's statements are years old and their signers may be
// long revoked, and gkm reads no signature here. Members hold each to its signer's key where their log reaches and
// to their cached C_k, a mismatch being an alarm and no adoption (rule 6).
//
// Until gen/<the form's generation> exists the group takes no commit, wrap or claim (rule 5): the claim route needs
// gen/<g-1> and refuses g at or below the form's (generations.go), the wrap routes ask reformLadderPending, and the
// epoch PUT check takes epoch 1's pin floor from that generation's auth (reformPinFloor), since a re-form's epoch 0
// carries none.

package gkmservice

import (
	"bytes"
	"errors"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The most Signed GenRotates one ladder call carries (QD-074 rule 4): a format value a client batches to.
const gkmLadderMaxCount = 64

// A GenLink's bytes, which every generation past the first carries.
const gkmGenLinkByteCount = gkmSealedKeyByteCount

// One statement of a ladder call, held to its shape.
type gkmLadderItem struct {
	raw    []byte
	rotate *protocol.GenRotate
}

// A ladder statement's shape: a Signed GenRotate of repoId whose ids, commitment, parent and pin are at their sizes.
// gkm verifies no signature here and holds the statement to no group: it names its old one.
func parseGkmLadderItem(signed *bridge.Signed, repoId sidecar.Id) (*gkmLadderItem, bool) {
	if signed == nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GEN_ROTATE) || len(signed.GetSignerId()) != 16 {
		return nil, false
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil || gkmStatementMaxByteCount < len(raw) {
		return nil, false
	}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
		return nil, false
	}
	if len(rotate.GetGroupId()) != 16 || !bytes.Equal(rotate.GetRepoId(), repoId.Bytes()) || rotate.GetGeneration() == 0 ||
		len(rotate.GetCommitment()) != 32 {
		return nil, false
	}
	if auth := rotate.GetAuth(); auth == nil || auth.GetVersion() == 0 || len(auth.GetChain()) != 32 {
		return nil, false
	}
	if rotate.GetGeneration() == 1 {
		if len(rotate.GetParentCommitment()) != 0 || len(rotate.GetGenlink()) != 0 {
			return nil, false
		}
	} else if len(rotate.GetParentCommitment()) != 32 || len(rotate.GetGenlink()) != gkmGenLinkByteCount {
		return nil, false
	}
	return &gkmLadderItem{raw: raw, rotate: rotate}, true
}

// The repo's newest GroupForm when it names groupId and re-forms another group, read fresh for a write and from the
// 5 s cache otherwise; nil for a group a creation formed, or one the newest form does not name. false once it has
// answered a store's failure.
func (self *GkmEngine) reformOf(request *GkmRequest, groupId sidecar.Id, fresh bool) (*protocol.GroupForm, bool) {
	if fresh {
		self.forms.forget(request.RepoId)
	}
	forms, err := self.forms.forms(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		self.answerStoreError(request, err)
		return nil, false
	}
	if len(forms) == 0 {
		return nil, true
	}
	newest := forms[len(forms)-1]
	if newest.GroupId != groupId || len(newest.Body.GetPreviousGroupId()) == 0 {
		return nil, true
	}
	return newest.Body, true
}

// Whether groupId is a re-formed group whose ladder has not reached its form's generation, in which it takes no
// wrap (rule 5). false in ok once it has answered a store's failure.
func (self *GkmEngine) reformLadderPending(request *GkmRequest, groupId sidecar.Id) (pending bool, ok bool) {
	form, ok := self.reformOf(request, groupId, false)
	if !ok || form == nil {
		return false, ok
	}
	exists, err := self.generationExists(request.Ctx, request.Cluster, groupId, form.GetGeneration())
	if err != nil {
		self.answerStoreError(request, err)
		return false, false
	}
	return !exists, true
}

// The pin floor of a commit onto an epoch that carries no pin (DESIGN-DETAILS 6.2.2): only epoch 1 of a re-formed
// group has one, gen/<the form's generation>'s auth, which the ladder writes before the group takes any commit.
// previous is epoch 0's header, which holds the form's generation. false once it has answered: 403 for any other
// pinless epoch and while the ladder has not reached that generation.
func (self *GkmEngine) reformPinFloor(request *GkmRequest, groupId sidecar.Id, epoch uint64, previous *protocol.GkmCommitHeader) (*bridge.AuthPin, bool) {
	if epoch != 1 || previous.GetGeneration() == 0 {
		request.Forbidden()
		return nil, false
	}
	form, ok := self.reformOf(request, groupId, false)
	if !ok {
		return nil, false
	}
	if form == nil || form.GetGeneration() != previous.GetGeneration() {
		// no re-form's epoch 0: a pinless epoch gives no floor, so nothing is built on it
		request.Forbidden()
		return nil, false
	}
	facts, err := self.generationFacts(request.Ctx, request.Cluster, groupId, form.GetGeneration())
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		request.Forbidden()
		return nil, false
	}
	if err != nil {
		self.answerStoreError(request, err)
		return nil, false
	}
	if facts.auth == nil || facts.auth.GetVersion() == 0 || len(facts.auth.GetChain()) != 32 {
		request.Forbidden()
		return nil, false
	}
	return facts.auth, true
}

// POST /gkm/groups/<id>/ladder: a GkmLadderRequest, a re-formed group's generations at or below its form's. See the
// file header.
func (self *GkmEngine) serveLadder(request *GkmRequest) {
	groupId := *request.GroupId
	ladderRequest := &protocol.GkmLadderRequest{}
	if !request.ReadMessage(ladderRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	signeds := ladderRequest.GetGenerations()
	if len(signeds) == 0 || gkmLadderMaxCount < len(signeds) {
		request.BadRequest()
		return
	}
	items := make([]*gkmLadderItem, 0, len(signeds))
	prices := self.settings.Prices
	price := int64(0)
	for index, signed := range signeds {
		item, ok := parseGkmLadderItem(signed, request.RepoId)
		if !ok {
			request.BadRequest()
			return
		}
		if 0 < index {
			previous := items[index-1].rotate
			if item.rotate.GetGeneration() != previous.GetGeneration()+1 {
				request.BadRequest()
				return
			}
			if !bytes.Equal(item.rotate.GetParentCommitment(), previous.GetCommitment()) {
				request.Forbidden()
				return
			}
		}
		items = append(items, item)
		price += prices.create(len(item.raw))
	}
	form, ok := self.reformOf(request, groupId, true)
	if !ok {
		return
	}
	if form == nil || form.GetGeneration() < items[len(items)-1].rotate.GetGeneration() {
		// not the repo's newest group, no re-form, or a statement past what the form carries over
		request.Forbidden()
		return
	}
	// open only before the group's first commit
	_, err := request.Cluster.Head(request.Ctx, GkmEpochKey(groupId, 1))
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
	case err != nil:
		request.Unavailable()
		return
	default:
		request.Forbidden()
		return
	}
	if first := items[0].rotate; 1 < first.GetGeneration() {
		parent, err := self.generationFacts(request.Ctx, request.Cluster, groupId, first.GetGeneration()-1)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// the ladder goes up in order
			request.Forbidden()
			return
		}
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if !bytes.Equal(first.GetParentCommitment(), parent.commitment) {
			request.Forbidden()
			return
		}
	}
	// a re-form's writes queue as P1, each on the repo's cluster
	writeCtx, ok := request.SpendWrites(request.Cluster, "", price)
	if !ok {
		return
	}
	request.Ctx = writeCtx
	for _, item := range items {
		if !request.CheckRepoWritable() {
			return
		}
		generation := item.rotate.GetGeneration()
		barrierKey := gkmBarrierNumberKey(groupId, generation)
		testHookBarrier(BarrierGenClaimBefore, barrierKey)
		winner, err := self.createGeneration(request.Ctx, request.Cluster, groupId, generation, item.raw)
		testHookBarrier(BarrierGenClaimAfter, barrierKey)
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if winner != nil {
			request.Conflict(winner)
			return
		}
	}
	request.Reply(nil)
}
