// §10.6's group objects and KF1 (D-KEYS-5, D-KEYS-18): POST /gkm/groups, which creates a repo's group, GET
// /gkm/groups/<id>, and GET and POST /gkm/repos/<id>/forms, over gkm/repo/<repo_id>/<seq> and a group's epoch/0 and
// gen/1 on the repo's cluster.
//
//   - A creation writes the GroupForm, then epoch/0, then gen/1, each If-None-Match, equal bytes answering success,
//     so KF1 resumes after a crash (QD-464). gkm writes epoch/0's uploader, time and network itself, from the token
//     and its clock, so a retry's epoch/0 is judged by the fields the request sets: equal ones are the same creation.
//     A creation is a repo's first form; a repo that has one re-forms through the forms route.
//   - A form is Signed by the sidecar that files it, whose admin scope on the repo the newest verified state honors:
//     §10.6's signer rule as gkm can judge it, since AclState.EvsAccess gives admin only to a repo admin's device and,
//     in owner-bound kinds, only to the owner's consented device. Its signature verifies under the identity key the
//     log admits for that sidecar.
//   - A group belongs to one repo from its first byte (DESIGN-DETAILS 6.2.2): the first write of a creation or a
//     re-form is the group's owner marker, gkm/<group_id>/owner, If-None-Match, a GkmGroupOwner {repo_id,
//     network_id} gkm writes from the token. A marker that stands with other bytes answers 409 and nothing else of
//     the request is written; equal bytes resume a crashed request. Every group route resolves through the marker
//     (resolveGroup): the repo it names must be among the token's scopes and that repo's forms must name the group,
//     so a form for one repo naming another's group reaches none of its routes, whichever form a process read first.
//   - A re-form (§10.8; D-KEYS-12, D-KEYS-13) writes the marker, then the repo's next form, which names the repo's
//     newest group as its previous one, then the new group's epoch/0, whose header holds the form's generation and
//     no auth pin, as GkmGroupReformRequest's landed body has it; the group's generations follow by the ladder route
//     (reform.go). After a site loss gkm holds no form, so the re-form is the repo's first. Epoch 1's pin floor in
//     a re-formed group is gen/<form.generation>'s auth (DESIGN-DETAILS 6.2.2; reform.go's reformPinFloor), so a
//     re-formed group takes no commit until its ladder has reached that generation.
//
// No KeyHolders or proposal is read here: members check the form's signer, their cached C_g and gen/1 (§10.9).

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The cipher suite a group takes: MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519 (owner decision 44). A re-form after
// an IANA renumbering takes the new value (D-KEYS-12), which no build knows yet, so none other is accepted.
const gkmCipherSuiteXWing uint32 = 0x0010

// A GenWrap, LeafWrap or GenLink: nonce, a 32-byte key and the tag (§10.6's sizes, 72 B).
const gkmSealedKeyByteCount = 24 + 32 + 16

// The purpose a GroupForm is signed under (QD-527).
const gkmGroupFormPurpose = "group-form"

// A GkmGroupOwner's bytes: two 16-byte ids, each under a tag and a length.
const gkmGroupOwnerByteCount = 2 * (2 + 16)

// The most bytes of a Signed GroupForm or GenRotate a route reads: a GenRotate with a drop key is about 1.7 KB.
const gkmStatementMaxByteCount = 16 * 1024

// A GroupForm a request carries, held to its shape.
type gkmFormUpload struct {
	signed  *bridge.Signed
	raw     []byte
	body    *protocol.GroupForm
	repoId  sidecar.Id
	groupId sidecar.Id
}

// The form's shape: a Signed of type SIGNED_GROUP_FORM whose GroupForm names 16-byte repo and group ids, and a
// previous group of 16 bytes or none. false once it has answered 400.
func (self *GkmEngine) readFormUpload(request *GkmRequest, signed *bridge.Signed) (*gkmFormUpload, bool) {
	if signed == nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GROUP_FORM) {
		request.BadRequest()
		return nil, false
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil || gkmStatementMaxByteCount < len(raw) {
		request.BadRequest()
		return nil, false
	}
	body := &protocol.GroupForm{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		request.BadRequest()
		return nil, false
	}
	repoId, err := sidecar.IdFromBytes(body.GetRepoId())
	if err != nil || repoId == (sidecar.Id{}) {
		request.BadRequest()
		return nil, false
	}
	groupId, err := sidecar.IdFromBytes(body.GetGroupId())
	if err != nil || groupId == (sidecar.Id{}) {
		request.BadRequest()
		return nil, false
	}
	if previous := body.GetPreviousGroupId(); len(previous) != 0 {
		previousGroupId, err := sidecar.IdFromBytes(previous)
		if err != nil || previousGroupId == (sidecar.Id{}) || previousGroupId == groupId {
			request.BadRequest()
			return nil, false
		}
	}
	return &gkmFormUpload{signed: signed, raw: raw, body: body, repoId: repoId, groupId: groupId}, true
}

// §10.6's form signer rule, as gkm judges it: the form is the token's own sidecar's, signed under the identity key
// the log admits for it, and the guard has honored its admin scope on the repo. false once it has answered 403.
func (self *GkmEngine) checkFormSigner(request *GkmRequest, form *gkmFormUpload) bool {
	if !bytes.Equal(form.signed.GetSignerId(), request.SidecarId.Bytes()) || !request.Rights.Has(sidecar.AclEvsAdmin) {
		request.Forbidden()
		return false
	}
	err := bridge.VerifySigned(form.signed, gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, bridge.SignedKeyAlgEd25519, request.Sidecar.IdentityPublicKey)
	if err != nil {
		request.Forbidden()
		return false
	}
	return true
}

// What epoch/0 holds besides what gkm writes, held to its shape: a 72-byte GenWrap_0, a sealed GroupInfo_0 within
// EpochGroupInfoMaxByteCount, and the one cipher suite. false once it has answered 400.
func (self *GkmEngine) checkEpochZeroUpload(request *GkmRequest, genWrap []byte, sealedGroupInfo []byte, cipherSuite uint32) bool {
	if len(genWrap) != gkmSealedKeyByteCount || len(sealedGroupInfo) == 0 ||
		self.settings.EpochGroupInfoMaxByteCount < int64(len(sealedGroupInfo)) || cipherSuite != gkmCipherSuiteXWing {
		request.BadRequest()
		return false
	}
	return true
}

// Resolves a statement signer's admitted identity key from gkm's newest state for sidecar.ParseGenRotate and
// sidecar.ParseGkmDelivery, keeping the facts it read and the state's answer, so the caller answers 503 for a state
// that could not tell and 403 for a signer it refuses.
type gkmSignerLookup struct {
	engine    *GkmEngine
	principal *sidecar.Principal
	answer    GkmAuthAnswer
	signerId  sidecar.Id
	facts     *GkmSidecarFacts
}

// A lookup on the token's network's state.
func (self *GkmEngine) newSignerLookup(principal *sidecar.Principal) *gkmSignerLookup {
	return &gkmSignerLookup{engine: self, principal: principal, answer: GkmAuthAllowed}
}

// sidecar.GkmIdentityKeyFunction's shape.
func (self *gkmSignerLookup) identityKey(signerId sidecar.Id) ([]byte, error) {
	facts, answer := self.engine.deps.AuthState.Sidecar(self.principal, signerId)
	self.answer = answer
	self.signerId = signerId
	if answer != GkmAuthAllowed || facts == nil || len(facts.IdentityPublicKey) == 0 {
		if answer == GkmAuthAllowed {
			self.answer = GkmAuthDenied
		}
		return nil, fmt.Errorf("%w: a signer gkm's state does not admit", sidecar.ErrGkmAuthentication)
	}
	self.facts = facts
	return facts.IdentityPublicKey, nil
}

// §10.6's signer row for a claim or delivery: admitted, not read_only, and not revoked, parked or suspended in gkm's
// newest state. Call after a parse used identityKey.
func (self *gkmSignerLookup) signerStanding() GkmAuthAnswer {
	if self.answer != GkmAuthAllowed {
		return self.answer
	}
	facts := self.facts
	if facts == nil || facts.Revoked || facts.Parked || facts.Suspended || facts.ReadOnly {
		return GkmAuthDenied
	}
	return GkmAuthAllowed
}

// Answers a lookup's refusal: 503 when the state could not tell, else 403.
func answerGkmAuth(request *GkmRequest, answer GkmAuthAnswer) {
	if answer == GkmAuthUnknown {
		request.Unavailable()
		return
	}
	request.Forbidden()
}

// gen/1 of a creation, held to the claim checks a first generation can meet: it verifies under its signer's admitted
// identity key, names the form's group and repo, generation 1 with no parent, a signer in standing, a time within
// gkm's clock skew and an auth pin gkm's state judges. false once it has answered.
func (self *GkmEngine) checkFirstGeneration(request *GkmRequest, form *gkmFormUpload, signed *bridge.Signed) ([]byte, *sidecar.GkmGeneration, bool) {
	if signed == nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GEN_ROTATE) {
		request.BadRequest()
		return nil, nil, false
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil || gkmStatementMaxByteCount < len(raw) {
		request.BadRequest()
		return nil, nil, false
	}
	lookup := self.newSignerLookup(request.Principal)
	generation, err := sidecar.ParseGenRotate(raw, form.groupId, 1, lookup.identityKey)
	switch {
	case err == nil:
	case lookup.answer != GkmAuthAllowed:
		answerGkmAuth(request, lookup.answer)
		return nil, nil, false
	case errors.Is(err, sidecar.ErrGkmAuthentication):
		request.Forbidden()
		return nil, nil, false
	default:
		request.BadRequest()
		return nil, nil, false
	}
	if answer := lookup.signerStanding(); answer != GkmAuthAllowed {
		answerGkmAuth(request, answer)
		return nil, nil, false
	}
	if !bytes.Equal(generation.Rotate.GetRepoId(), form.repoId.Bytes()) {
		request.BadRequest()
		return nil, nil, false
	}
	if !self.checkStatementTime(request, generation.Rotate.GetTimeMs()) {
		return nil, nil, false
	}
	if !self.checkPin(request, generation.Rotate.GetAuth()) {
		return nil, nil, false
	}
	return raw, generation, true
}

// §10.6's time rows: a statement's time_ms within 10 minutes of gkm's clock. false once it has answered 403.
func (self *GkmEngine) checkStatementTime(request *GkmRequest, timeMs int64) bool {
	now := request.Now()
	at := time.UnixMilli(timeMs)
	if at.Before(now.Add(-sidecar.GkmClockSkew)) || now.Add(sidecar.GkmClockSkew).Before(at) {
		request.Forbidden()
		return false
	}
	return true
}

// §10.6's auth rows: the pin is at or past the previous base and agrees with the log there, as gkm's newest state
// judges it. false once it has answered 403, or 503 for a pin past that state.
func (self *GkmEngine) checkPin(request *GkmRequest, pin *bridge.AuthPin) bool {
	if pin == nil || pin.GetVersion() == 0 || len(pin.GetChain()) != 32 {
		request.BadRequest()
		return false
	}
	switch self.deps.AuthState.CheckPin(request.Principal, pin) {
	case GkmAuthAllowed:
		return true
	case GkmAuthDenied:
		request.Forbidden()
	default:
		request.Unavailable()
	}
	return false
}

// The owner marker's bytes for a group of repoId in networkId.
func gkmGroupOwnerBytes(repoId sidecar.Id, networkId sidecar.Id) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmGroupOwner{
		RepoId:    repoId.Bytes(),
		NetworkId: networkId.Bytes(),
	})
}

// Writes the form's group's owner marker, If-None-Match, the first write of a creation or a re-form: the token's
// repo and network. Equal bytes already there are this request's earlier try; other bytes mean the group id is
// another repo's, and answer 409 before anything else of the request is written. false once it has answered.
func (self *GkmEngine) createGroupOwner(request *GkmRequest, form *gkmFormUpload) bool {
	ownerBytes, err := gkmGroupOwnerBytes(form.repoId, sidecar.Id(request.Principal.NetworkId))
	if err != nil {
		request.Unavailable()
		return false
	}
	if !request.CheckRepoWritable() {
		return false
	}
	barrierKey := gkmBarrierGroupKey(form.groupId)
	testHookBarrier(BarrierGroupOwnerBefore, barrierKey)
	winner, err := createGkmObject(request.Ctx, request.Cluster, GkmGroupOwnerKey(form.groupId), ownerBytes, self.settings.ObjectMaxByteCount)
	testHookBarrier(BarrierGroupOwnerAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return false
	}
	if winner != nil {
		// the id is taken: the creator draws another (KF1's step 3)
		request.Conflict(nil)
		return false
	}
	self.owners.remember(form.groupId, form.repoId)
	return true
}

// The seq a form takes among the repo's forms, read fresh: the seq of a stored form with its bytes, which is a
// retry, else the next. A retry must still be the repo's newest form. false once it has answered: 409 with the newest
// form when the form cannot be filed as the request's kind asks.
func (self *GkmEngine) formSeq(request *GkmRequest, form *gkmFormUpload, reform bool) (seq uint64, retry bool, ok bool) {
	self.forms.forget(form.repoId)
	forms, err := self.forms.forms(request.Ctx, request.Cluster, form.repoId)
	if err != nil {
		self.answerStoreError(request, err)
		return 0, false, false
	}
	if len(forms) == 0 {
		return 1, false, true
	}
	newest := forms[len(forms)-1]
	conflict := func() {
		request.Conflict(newest.Raw)
	}
	for _, existing := range forms {
		if bytes.Equal(existing.Raw, form.raw) {
			if existing != newest {
				conflict()
				return 0, false, false
			}
			return existing.Seq, true, true
		}
		if existing.GroupId == form.groupId {
			// a group a form of this repo already names is never formed again
			conflict()
			return 0, false, false
		}
	}
	previousGroupId, _ := sidecar.IdFromBytes(form.body.GetPreviousGroupId())
	if !reform || previousGroupId != newest.GroupId {
		// a creation is the repo's first form, and a re-form names the newest group as its previous one
		conflict()
		return 0, false, false
	}
	return newest.Seq + 1, false, true
}

// Files a form at seq, If-None-Match, after its group's owner marker: a form that loses its seq to other bytes
// answers 409 with them. false once it has answered.
func (self *GkmEngine) fileForm(request *GkmRequest, form *gkmFormUpload, seq uint64) bool {
	if !self.createGroupOwner(request, form) {
		return false
	}
	if !request.CheckRepoWritable() {
		return false
	}
	barrierKey := gkmBarrierGroupKey(form.groupId)
	testHookBarrier(BarrierGroupCreateBefore, barrierKey)
	winner, err := createGkmObject(request.Ctx, request.Cluster, GkmFormKey(form.repoId, seq), form.raw, self.settings.ObjectMaxByteCount)
	testHookBarrier(BarrierGroupCreateAfter, barrierKey)
	self.forms.forget(form.repoId)
	if err != nil {
		self.answerStoreError(request, err)
		return false
	}
	if winner != nil {
		request.Conflict(winner)
		return false
	}
	return true
}

// Creates a group's epoch/0, If-None-Match: an equal upload already there, this creation's earlier try, answers
// success, and any other answers 409 with it. false once it has answered.
func (self *GkmEngine) createEpochZero(request *GkmRequest, groupId sidecar.Id, object *protocol.GkmEpochObject) bool {
	objectBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(object)
	if err != nil {
		request.Unavailable()
		return false
	}
	if !request.CheckRepoWritable() {
		return false
	}
	barrierKey := gkmBarrierGroupKey(groupId)
	testHookBarrier(BarrierGroupCreateBefore, barrierKey)
	winner, err := createGkmObject(request.Ctx, request.Cluster, GkmEpochKey(groupId, 0), objectBytes, self.settings.ObjectMaxByteCount)
	testHookBarrier(BarrierGroupCreateAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return false
	}
	if winner != nil {
		held, err := parseGkmEpochObject(winner)
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		if !sameGkmEpochUpload(held, object) {
			request.Conflict(winner)
			return false
		}
	}
	self.rememberNewestEpoch(groupId, 0)
	return true
}

// POST /gkm/groups: a GkmGroupCreateRequest, KF1's GroupForm, epoch/0 and gen/1 of a repo's first group.
func (self *GkmEngine) serveGroupCreate(request *GkmRequest) {
	createRequest := &protocol.GkmGroupCreateRequest{}
	if !request.ReadMessage(createRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	form, ok := self.readFormUpload(request, createRequest.GetForm())
	if !ok {
		return
	}
	if len(form.body.GetPreviousGroupId()) != 0 || form.body.GetGeneration() != 1 {
		// a creation forms generation 1 and re-forms nothing
		request.BadRequest()
		return
	}
	if !request.AuthorizeRepo(form.repoId) || !self.checkFormSigner(request, form) {
		return
	}
	if !self.checkEpochZeroUpload(request, createRequest.GetGenWrap(), createRequest.GetSealedGroupInfo(), createRequest.GetCipherSuite()) {
		return
	}
	generationBytes, generation, ok := self.checkFirstGeneration(request, form, createRequest.GetGenRotate())
	if !ok {
		return
	}
	epochZero := &protocol.GkmEpochObject{
		Header:              &protocol.GkmCommitHeader{Generation: 1, Auth: generation.Rotate.GetAuth()},
		Uploader:            request.SidecarId.Bytes(),
		TimeMs:              request.Now().UnixMilli(),
		GenWrap:             createRequest.GetGenWrap(),
		SealedGroupInfo:     createRequest.GetSealedGroupInfo(),
		GroupInfoGeneration: 1,
		NetworkId:           request.Principal.NetworkId.Bytes(),
		CipherSuite:         createRequest.GetCipherSuite(),
	}
	// a repo's creation writes are §11.13's P1 (plan-EVSB-write-classes): the owner marker, the form, epoch/0 and
	// gen/1, every one on the repo's cluster, so the request's ctx carries their class from here
	prices := self.settings.Prices
	writeCtx, ok := request.SpendWrites(request.Cluster, "", prices.create(gkmGroupOwnerByteCount)+prices.create(len(form.raw))+prices.create(proto.Size(epochZero))+prices.create(len(generationBytes)))
	if !ok {
		return
	}
	request.Ctx = writeCtx
	seq, _, ok := self.formSeq(request, form, false)
	if !ok || !self.fileForm(request, form, seq) {
		return
	}
	if !self.createEpochZero(request, form.groupId, epochZero) {
		return
	}
	if !request.CheckRepoWritable() {
		return
	}
	barrierKey := gkmBarrierGroupKey(form.groupId)
	testHookBarrier(BarrierGroupCreateBefore, barrierKey)
	winner, err := self.createGeneration(request.Ctx, request.Cluster, form.groupId, 1, generationBytes)
	testHookBarrier(BarrierGroupCreateAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if winner != nil {
		request.Conflict(winner)
		return
	}
	request.Reply(nil)
}

// POST /gkm/repos/<id>/forms: a GkmGroupReformRequest, a re-form's GroupForm and its new group's epoch/0 (§10.8).
func (self *GkmEngine) serveReform(request *GkmRequest) {
	reformRequest := &protocol.GkmGroupReformRequest{}
	if !request.ReadMessage(reformRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	form, ok := self.readFormUpload(request, reformRequest.GetForm())
	if !ok {
		return
	}
	if len(form.body.GetPreviousGroupId()) == 0 || form.body.GetGeneration() == 0 || form.repoId != request.RepoId {
		// a re-form names its previous group and the newest generation its re-former holds, of the path's repo
		request.BadRequest()
		return
	}
	if !self.checkFormSigner(request, form) {
		return
	}
	if !self.checkEpochZeroUpload(request, reformRequest.GetGenWrap(), reformRequest.GetSealedGroupInfo(), reformRequest.GetCipherSuite()) {
		return
	}
	epochZero := &protocol.GkmEpochObject{
		// no auth pin: epoch 1's floor is gen/<form.generation>'s (DESIGN-DETAILS 6.2.2), which the ladder writes
		// before the group takes a commit (reform.go)
		Header:              &protocol.GkmCommitHeader{Generation: form.body.GetGeneration()},
		Uploader:            request.SidecarId.Bytes(),
		TimeMs:              request.Now().UnixMilli(),
		GenWrap:             reformRequest.GetGenWrap(),
		SealedGroupInfo:     reformRequest.GetSealedGroupInfo(),
		GroupInfoGeneration: form.body.GetGeneration(),
		NetworkId:           request.Principal.NetworkId.Bytes(),
		CipherSuite:         reformRequest.GetCipherSuite(),
	}
	// a re-form's writes queue as P1, each on the repo's cluster, so the request's ctx carries their class from here
	prices := self.settings.Prices
	writeCtx, ok := request.SpendWrites(request.Cluster, "", prices.create(gkmGroupOwnerByteCount)+prices.create(len(form.raw))+prices.create(proto.Size(epochZero)))
	if !ok {
		return
	}
	request.Ctx = writeCtx
	seq, _, ok := self.formSeq(request, form, true)
	if !ok || !self.fileForm(request, form, seq) {
		return
	}
	if !self.createEpochZero(request, form.groupId, epochZero) {
		return
	}
	request.Reply(nil)
}

// GET /gkm/groups/<id>: a GkmGroupReply, the newest of the repo's forms that names the group.
func (self *GkmEngine) serveGroupRead(request *GkmRequest) {
	forms, err := self.forms.forms(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	for i := len(forms) - 1; 0 <= i; i -= 1 {
		if forms[i].GroupId == *request.GroupId {
			request.Reply(&protocol.GkmGroupReply{Form: forms[i].Signed})
			return
		}
	}
	// the guard resolved the group by these forms, so a form gone since is a shred under way
	request.NotFound()
}

// GET /gkm/repos/<id>/forms: a GkmFormsReply, the repo's Signed GroupForms, oldest first (QD-156).
func (self *GkmEngine) serveFormsRead(request *GkmRequest) {
	forms, err := self.forms.forms(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	reply := &protocol.GkmFormsReply{}
	for _, form := range forms {
		reply.Forms = append(reply.Forms, form.Signed)
	}
	request.Reply(reply)
}

// A stored epoch object, held to its shape: errGkmStoreFault for bytes that do not parse or carry no header.
func parseGkmEpochObject(objectBytes []byte) (*protocol.GkmEpochObject, error) {
	object := &protocol.GkmEpochObject{}
	if err := proto.Unmarshal(objectBytes, object); err != nil {
		return nil, fmt.Errorf("%w: an epoch object that does not parse", errGkmStoreFault)
	}
	if object.GetHeader() == nil {
		return nil, fmt.Errorf("%w: an epoch object with no header", errGkmStoreFault)
	}
	return object, nil
}

// Epoch n of a group, parsed: sidecar.ErrBlobNotFound for none.
func (self *GkmEngine) readEpoch(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, epoch uint64) (*protocol.GkmEpochObject, []byte, error) {
	objectBytes, _, err := readGkmObject(ctx, cluster, GkmEpochKey(groupId, epoch), self.settings.ObjectMaxByteCount)
	if err != nil {
		return nil, nil, err
	}
	object, err := parseGkmEpochObject(objectBytes)
	if err != nil {
		return nil, nil, err
	}
	return object, objectBytes, nil
}

// Whether two epoch objects are one upload: every field a request sets, and gkm's uploader and network, alike. The
// time gkm stamped differs between an upload and its retry, so it is left out.
func sameGkmEpochUpload(a *protocol.GkmEpochObject, b *protocol.GkmEpochObject) bool {
	return bytes.Equal(a.GetCommit(), b.GetCommit()) &&
		proto.Equal(a.GetHeader(), b.GetHeader()) &&
		bytes.Equal(a.GetUploader(), b.GetUploader()) &&
		bytes.Equal(a.GetGenWrap(), b.GetGenWrap()) &&
		bytes.Equal(a.GetSealedGroupInfo(), b.GetSealedGroupInfo()) &&
		a.GetGroupInfoGeneration() == b.GetGroupInfoGeneration() &&
		bytes.Equal(a.GetNetworkId(), b.GetNetworkId()) &&
		a.GetCipherSuite() == b.GetCipherSuite()
}
