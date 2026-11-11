// Re-forming a repo's group (KEYS-M2-25; D-KEYS-12, D-KEYS-13, FI-5, FI-12; §10.8's site loss, plan-KEYS-reform-ladder's
// rules as QD-074 decided them, DESIGN-DETAILS 6.2.4's Re-form): what a device does after a site loss took gkm's
// objects, for a group a refused commit stalled, and for a group whose cipher suite IANA renumbered, and what every
// other member does when it meets the new group.
//
//	re-former  a device §10.6's GroupForm rule allows, a repo admin's and in an owner-bound repo only the owner's
//	           consented device, that holds the whole ladder in its keychain, RK_g with each Signed GenRotate:
//	           1  draws a new 16-byte group id, creates the MLS group, its only leaf its own, and signs a GroupForm
//	              naming the group it re-forms and the newest generation g it holds; seals GenWrap_0 and
//	              GroupInfo_0 under RK_g; keeps the whole request in the keychain before it posts it
//	           2  POST /gkm/repos/<id>/forms: gkm writes the owner marker, the form and epoch/0, whose header holds
//	              g and no pin; a marker another repo holds means the id is taken and another is drawn, and a form
//	              that lost its place to another re-form is dropped, since the group that stands is adopted instead
//	           3  POST ladder: gen/1 to gen/<g>, the old Signed GenRotates byte for byte, ascending, 64 a call
//	           4  moves its own pins to the new group, epoch 0, with epoch 1's floor at gen/<g>'s auth, its
//	              generation pin (g, C_g) unchanged
//	           5  unless the repo is re-seeded as deleted, which takes the form and the ladder and nothing else:
//	              rotates to g+1, the first generation that names the new group, which stages every delivery as any
//	              rotation does, ReaderWraps, DelegationWraps and each reading member's RecoveryWrap, so a member
//	              whose devices are lost keeps its recovery code's access; then the pending engine adds every
//	              member device that has a KeyPackage (KF2)
//	           A kill at any step resumes from the keychain's record with the same bytes: every write at gkm is an
//	           If-None-Match create that equal bytes resume.
//	member     at each sync, and at a Welcome to a group of the repo other than its own, a device whose pinned group
//	           is not the one the repo's newest GroupForm names follows the forms from its own group to the newest:
//	           each a Signed GroupForm of the repo, verified under its signer's admitted key, its signer held to
//	           §10.6's rule at the auth pin the form carries (QD-643): at that state where this device's retained log
//	           reaches it, waiting for one above its tip, judging nothing of one before its previous base, which
//	           counts against no one, and refusing one off its chain as a fork; the new group's ladder must have
//	           reached the form's generation,
//	           chain from gen/1 by parent_commitment, and hold, byte for byte, every statement this device has
//	           cached, its own generation pin (g, C_g) among them. A mismatch, or a form whose generation is below
//	           this device's own pin, is alarmed and nothing is adopted: the pin never falls (I-16). Then its pins
//	           move to the new group at epoch 0, its old group's MLS state is dropped, and it returns by a Welcome
//	           (KF2), by a late wrap, or by its member's recovery code
//	statements gen/<k> of a re-formed group at or below its form's generation names the group it was claimed in,
//	           so a statement naming another group is taken there only under a form this device verified, and is
//	           still held to its signer's key, its repo and the C_k chain (parseServedGeneration)
//	deliveries a delivery read from, or written in, the group this device pinned names that group, a generation the
//	           ladder carried included (rule 7; GkmDeliveryCheckArgs.GroupId), as gkm's wrap checks hold it to the
//	           path's group: a holder answers a late ask of the form's generation there before the re-former rotates
//	depositor  reads no GroupForm (QD-156 gives the forms route r, rw and admin), and gkm's drop-key route serves
//	           the newest group's generations: its pinned statement among the ladder's, byte for byte as the old
//	           group held it, and the re-former's rotation chained from it, so its generation pin, which compares
//	           (g, C_g) (rule 8), follows that chain to the new group (movePinsAlongChain)
//	heads      a GenHead of the group this device's adopted re-form replaced compares (g, C_g) along the form, whose
//	           ladder carries every C_k (DESIGN-DETAILS 6.2.6); a group this device never met is compared by nothing
//
// Readings, where the rule is not explicit. The re-former rotates before it adds: rule 9 says later rotations run
// as usual, and a rotation is the one path that stages RecoveryWraps, which only the member's own device may write
// otherwise, so "re-adds readers, ReaderWraps and RecoveryWraps" is that rotation and the engine's Adds. §10.6's "a network admin's"
// is a member whose role is Owner or Admin, the roles the rest of this package treats as the network's admins. A
// depositor's pin takes a new group id at a generation past its pin, along a chain it verified, where rule 8 speaks
// of an equal (g, C_g), which a depositor, holding no group, never meets.
//
// Not built here, each failing closed: evs's resolution of gen/<g> through the newest GroupForm (rule 8) is evs's; a
// member two re-forms behind, whose middle form a second site loss took, refuses the chain and alarms, and returns by
// a re-add or its recovery code; and a re-form keeps suite 0x0010, the one the subset speaks, until IANA's migration
// has another.
//
// Calls testHookSecret through the ladder's own functions at every key sealed.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A re-formed group failed a member's checks: its form's signer, its ladder against this device's cached C_k, or
// its generation against this device's pin. Nothing of it is adopted.
var ErrGkmReformRefused = errors.New("gkm: a re-formed group failed its member checks")

// The most Signed GenRotates one ladder call carries (QD-074 rule 4), as gkm holds it.
const gkmLadderBatchCount = 64

// The phases a re-form's record holds.
const (
	// the request is drafted; the form may or may not stand at gkm
	gkmReformPhasePosting = 1
	// the form and epoch/0 stand; the ladder is going up
	gkmReformPhaseLadder = 2
	// the ladder stands and this device's pins name the new group; the rotation and the Adds remain
	gkmReformPhaseFinishing = 3
)

// The barriers around a re-form's writes at gkm, keyed by the new group: the forms POST, whose owner marker, form and
// epoch/0 are each an If-None-Match create there, and each ladder call.
const (
	gkmBarrierReformFormBefore   = "gkm.reform.form.before"
	gkmBarrierReformFormAfter    = "gkm.reform.form.after"
	gkmBarrierReformLadderBefore = "gkm.reform.ladder.before"
	gkmBarrierReformLadderAfter  = "gkm.reform.ladder.after"
)

// What a re-form calls at gkm beside the group flows: GkmApi's methods, so a test fakes them.
type GkmReformApi interface {
	Reform(ctx context.Context, repoId Id, request *protocol.GkmGroupReformRequest) error
	UploadLadder(ctx context.Context, repoId Id, groupId Id, request *protocol.GkmLadderRequest) error
}

var _ GkmReformApi = (*GkmApi)(nil)

// More of §8.6's admin right than a repo's rows show, a rule's admin action among them, for a state that can
// compute it. A device it names may sign a GroupForm of a repo that is not owner-bound.
type GkmRepoAdminView interface {
	RepoAdmins(repoId Id) []Id
}

// §10.6's GroupForm signer rule at a state: a standing member device that is not read_only and, in an owner-bound
// repo, the owner's consented device; outside owner-bound kinds, one of the repo's admins, its access log's
// RepoAdmins (owner decision 8), a device of a network admin, a member whose role is Owner or Admin, or a device a
// state answering GkmRepoAdminView names. ErrGkmNotWriter for a signer the rule refuses. The rows hold no deletion's
// effect on these, so a repo re-seeded as deleted is re-formed by the devices that formed it.
func GkmFormSignerAllowed(view GkmAuthView, repoId Id, signerId Id) error {
	if view == nil {
		return fmt.Errorf("%w: no verified state", ErrGkmUnavailable)
	}
	repo := view.Repo(repoId)
	if repo == nil {
		return fmt.Errorf("%w: repo %s", ErrGkmNoRepo, repoId)
	}
	row := view.SidecarRow(signerId)
	if !gkmRowStanding(row) || gkmRowReadOnly(row) || !gkmRowMemberDevice(row) {
		return fmt.Errorf("%w: a GroupForm is a standing member device's that is not read_only", ErrGkmNotWriter)
	}
	if ownerMemberId := repo.GetOwnerMemberId(); 0 < len(ownerMemberId) {
		consented := slices.ContainsFunc(repo.GetConsentedSidecarIds(), func(consentedId []byte) bool {
			return bytes.Equal(consentedId, signerId.Bytes())
		})
		if !bytes.Equal(ownerMemberId, row.GetMemberId()) || !consented {
			return fmt.Errorf("%w: an owner-bound repo's GroupForm is its owner's consented device's", ErrGkmNotWriter)
		}
		return nil
	}
	for _, admin := range repo.GetAdmins() {
		if bytes.Equal(admin.GetSidecarId(), signerId.Bytes()) {
			return nil
		}
	}
	if memberId, err := IdFromBytes(row.GetMemberId()); err == nil {
		if member := view.Member(memberId); member != nil {
			switch member.GetRole() {
			case bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN:
				return nil
			}
		}
	}
	if adminView, ok := view.(GkmRepoAdminView); ok && slices.Contains(adminView.RepoAdmins(repoId), signerId) {
		return nil
	}
	return fmt.Errorf("%w: a GroupForm is a repo admin's or a network admin's device's", ErrGkmNotWriter)
}

// A GroupForm this device verified.
type gkmVerifiedForm struct {
	// the Signed GroupForm, encoded
	signedBytes     []byte
	signerId        Id
	groupId         Id
	previousGroupId Id
	generation      uint64
	// the signer's state when it signed (QD-643), at which its right to form the group is judged
	auth *bridge.AuthPin
}

// A Signed GroupForm of the repo, verified under its signer's admitted key and held to its shape. Who may sign one
// is GkmFormSignerAllowed's.
func gkmParseGroupForm(state GkmAuthView, repoId Id, signed *bridge.Signed) (*gkmVerifiedForm, error) {
	if signed == nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GROUP_FORM) {
		return nil, fmt.Errorf("%w: no Signed GroupForm", ErrGkmMalformed)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: a GroupForm names no signer", ErrGkmMalformed)
	}
	publicKey, err := GkmIdentityKeys(state)(signerId)
	if err != nil {
		return nil, err
	}
	if err := bridge.VerifySigned(signed, gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, bridge.SignedKeyAlgEd25519, publicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmAuthentication, err)
	}
	body := &protocol.GroupForm{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: a GroupForm: %w", ErrGkmMalformed, err)
	}
	groupId, err := IdFromBytes(body.GetGroupId())
	if err != nil || groupId == (Id{}) || !bytes.Equal(body.GetRepoId(), repoId.Bytes()) || body.GetGeneration() == 0 {
		return nil, fmt.Errorf("%w: a GroupForm of another repo, or of no group or generation", ErrGkmMalformed)
	}
	form := &gkmVerifiedForm{signerId: signerId, groupId: groupId, generation: body.GetGeneration(), auth: body.GetAuth()}
	if previous := body.GetPreviousGroupId(); 0 < len(previous) {
		form.previousGroupId, err = IdFromBytes(previous)
		if err != nil || form.previousGroupId == (Id{}) || form.previousGroupId == groupId {
			return nil, fmt.Errorf("%w: a GroupForm's previous group", ErrGkmMalformed)
		}
	}
	form.signedBytes, err = gkmSignedBytes(signed)
	if err != nil {
		return nil, err
	}
	return form, nil
}

// §10.6's GroupForm signer rule judged at the auth pin the form carries (QD-643; R1's judged row): at the state of
// that pin where this device's retained log reaches it; ErrGkmAuthAhead, to wait on, for a pin above its tip; a
// verdict that judges nothing for one before its previous base, which counts against no one; and a refusal with
// Fork for one off its chain, as for any judged pin. A form with no pin is refused, and so is a signer the rule does
// not allow at the pin, or whose pin's state does not hold the repo.
func gkmJudgeFormSigner(state GkmAuthView, repoId Id, form *gkmVerifiedForm) (GkmVerdict, error) {
	at, verdict, err := gkmJudgedView(state, form.auth)
	if err != nil || verdict.Refused || verdict.NotJudged {
		return verdict, err
	}
	err = GkmFormSignerAllowed(at, repoId, form.signerId)
	switch {
	case err == nil:
		return GkmVerdict{}, nil
	case errors.Is(err, ErrGkmNotWriter), errors.Is(err, ErrGkmNoRepo):
		return gkmRefuse(GkmRefusalSigner, "a GroupForm by a device that may not form the group at its pin %d", form.auth.GetVersion()), nil
	}
	return GkmVerdict{}, err
}

// The error a refused form's verdict answers, its alarm raised: head_alarm for a pin off this device's chain, refused
// for any other.
func (self *GkmGroupClient) refuseForm(repoId Id, form *gkmVerifiedForm, verdict GkmVerdict) error {
	kind := GkmAlarmRefused
	if verdict.Fork {
		kind = GkmAlarmHead
	}
	self.alarm(&GkmAlarm{
		Kind: kind, RepoId: repoId, GroupId: form.groupId, Generation: form.generation, SidecarId: form.signerId,
		Reason: verdict.Reason, Detail: verdict.Detail,
	})
	return fmt.Errorf("%w: %s", ErrGkmReformRefused, verdict.Detail)
}

// The keychain name of the GroupForm this device adopted for a repo's pinned group, kept only for a re-formed one.
func gkmFormRecordName(repoId Id) string {
	return gkmRepoRecordName(repoId, "form")
}

// The re-form's GroupForm this device verified and adopted for the repo's pinned group, nil for a group a creation
// formed. It was verified before it was stored, so it is held to its format alone here.
func (self *GkmGroupClient) adoptedForm(repoId Id) (*gkmVerifiedForm, error) {
	encoded, err := self.getRecord(gkmFormRecordName(repoId))
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	signed := &bridge.Signed{}
	body := &protocol.GroupForm{}
	if err := proto.Unmarshal(encoded, signed); err != nil {
		return nil, fmt.Errorf("%w: a stored GroupForm", ErrGkmMalformed)
	}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: a stored GroupForm", ErrGkmMalformed)
	}
	groupId, err := IdFromBytes(body.GetGroupId())
	if err != nil {
		return nil, fmt.Errorf("%w: a stored GroupForm", ErrGkmMalformed)
	}
	previousGroupId, err := IdFromBytes(body.GetPreviousGroupId())
	if err != nil {
		return nil, fmt.Errorf("%w: a stored GroupForm", ErrGkmMalformed)
	}
	return &gkmVerifiedForm{signedBytes: encoded, groupId: groupId, previousGroupId: previousGroupId, generation: body.GetGeneration()}, nil
}

// The re-form's GroupForm naming groupId, for a device that meets a re-formed group it never adopted, a joiner or a
// first wrap's reader: read from gkm, verified, its signer held to §10.6's rule, and kept. Nil for a group no
// re-form made.
func (self *GkmGroupClient) learnForm(ctx context.Context, state GkmAuthView, repoId Id, groupId Id) (*gkmVerifiedForm, error) {
	reply, err := self.args.Api.Forms(ctx, repoId)
	if err != nil {
		return nil, err
	}
	signedForms := reply.GetForms()
	for index := len(signedForms) - 1; 0 <= index; index -= 1 {
		body := &protocol.GroupForm{}
		if err := proto.Unmarshal(signedForms[index].GetBody(), body); err != nil || !bytes.Equal(body.GetGroupId(), groupId.Bytes()) {
			continue
		}
		form, err := gkmParseGroupForm(state, repoId, signedForms[index])
		if err != nil {
			return nil, err
		}
		if form.previousGroupId == (Id{}) {
			return nil, nil
		}
		verdict, err := gkmJudgeFormSigner(state, repoId, form)
		if err != nil {
			return nil, err
		}
		if verdict.Refused {
			return nil, self.refuseForm(repoId, form, verdict)
		}
		if err := self.args.Secrets.Put(gkmFormRecordName(repoId), form.signedBytes); err != nil {
			return nil, err
		}
		return form, nil
	}
	return nil, nil
}

// gen/<k> as groupId serves it, verified under its signer's admitted key: the group's own statement, or, in a
// re-formed group at or below its form's generation, the statement the ladder carried, which names the group it was
// claimed in (plan-KEYS-reform-ladder rule 3). The statement of another group is taken only under a form this device
// verified, and still names the repo. What ParseGenRotate refuses is refused.
func (self *GkmGroupClient) parseServedGeneration(ctx context.Context, state GkmAuthView, repoId Id, groupId Id, generation uint64, signedBytes []byte) (*GkmGeneration, error) {
	signed := &bridge.Signed{}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: gen object: %w", ErrGkmMalformed, err)
	}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
		return nil, fmt.Errorf("%w: GenRotate: %w", ErrGkmMalformed, err)
	}
	if bytes.Equal(rotate.GetGroupId(), groupId.Bytes()) {
		return ParseGenRotate(signedBytes, groupId, generation, GkmIdentityKeys(state))
	}
	namedGroupId, err := IdFromBytes(rotate.GetGroupId())
	if err != nil {
		return nil, fmt.Errorf("%w: gen/%d names no group", ErrGkmMalformed, generation)
	}
	form, err := self.adoptedForm(repoId)
	if err != nil {
		return nil, err
	}
	if form == nil || form.groupId != groupId {
		if form, err = self.learnForm(ctx, state, repoId, groupId); err != nil {
			return nil, err
		}
	}
	if form == nil || form.groupId != groupId || form.generation < generation || !bytes.Equal(rotate.GetRepoId(), repoId.Bytes()) {
		return nil, fmt.Errorf("%w: gen/%d of another group or generation", ErrGkmMalformed, generation)
	}
	return ParseGenRotate(signedBytes, namedGroupId, generation, GkmIdentityKeys(state))
}

// What a re-form reads.
type GkmReformArgs struct {
	RepoId Id
	// §19.10's re-seed of a repo that stands deleted (owner decision 82): the form, its epoch 0 and the ladder,
	// and nothing else, since gkm refuses every other route of a deleted repo. The rotation and the Adds follow
	// once the repo is restored, by a second call without it.
	Reseed bool
}

// A re-form under way, as the keychain holds it.
type gkmReformRecord struct {
	phase      int
	groupId    Id
	generation uint64
	// the GkmGroupReformRequest, byte for byte
	request []byte
}

// version | phase | group_id | u64 generation | u32 length | request.
func (self *gkmReformRecord) encode() []byte {
	encoded := []byte{gkmRecordVersion, byte(self.phase)}
	encoded = append(encoded, self.groupId.Bytes()...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.generation)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(self.request)))
	return append(encoded, self.request...)
}

// A re-form record's fields.
func decodeGkmReformRecord(encoded []byte) (*gkmReformRecord, error) {
	malformed := fmt.Errorf("%w: a re-form record", ErrGkmMalformed)
	headByteCount := 2 + gkmIdByteCount + 8 + 4
	if len(encoded) < headByteCount || encoded[0] != gkmRecordVersion {
		return nil, malformed
	}
	groupId, err := IdFromBytes(encoded[2 : 2+gkmIdByteCount])
	if err != nil {
		return nil, malformed
	}
	record := &gkmReformRecord{
		phase:      int(encoded[1]),
		groupId:    groupId,
		generation: binary.BigEndian.Uint64(encoded[2+gkmIdByteCount:]),
	}
	if int(binary.BigEndian.Uint32(encoded[headByteCount-4:])) != len(encoded)-headByteCount {
		return nil, malformed
	}
	record.request = bytes.Clone(encoded[headByteCount:])
	return record, nil
}

// The re-form's routes, or ErrGkmUnavailable for an api that serves none.
func (self *GkmGroupClient) reformApi() (GkmReformApi, error) {
	api, ok := self.args.Api.(GkmReformApi)
	if !ok {
		return nil, fmt.Errorf("%w: this api serves no re-form route", ErrGkmUnavailable)
	}
	return api, nil
}

// Re-forms the repo's group from this device's keychain. See the file header. It returns the new group's id once
// its steps are done, and resumes a re-form a kill or a wait cut short. ErrGkmNotWriter for a device §10.6's rule
// does not let form the group, ErrGkmKeyMissing for one that does not hold the whole ladder, ErrGkmWait when
// another re-form of the repo stands, which this device adopts at its next sync.
func (self *GkmGroupClient) ReformGroup(ctx context.Context, args *GkmReformArgs) (Id, error) {
	if args == nil || args.RepoId == (Id{}) {
		return Id{}, fmt.Errorf("%w: a re-form needs its repo", ErrGkmMalformed)
	}
	if self.args.Mls == nil {
		return Id{}, fmt.Errorf("%w: a sidecar that holds no leaf forms no group", ErrGkmUnavailable)
	}
	manager := self.manager(args.RepoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.reformInFlow(ctx, args)
}

// The keychain's re-form record, nil for none.
func (self *gkmGroupManager) reformRecord() (*gkmReformRecord, error) {
	encoded, err := self.client.getRecord(gkmRepoRecordName(self.repoId, "reform"))
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeGkmReformRecord(encoded)
}

// Keeps the re-form record, or with nil removes it.
func (self *gkmGroupManager) putReformRecord(record *gkmReformRecord) error {
	name := gkmRepoRecordName(self.repoId, "reform")
	if record == nil {
		return self.client.args.Secrets.Delete(name)
	}
	return self.client.args.Secrets.Put(name, record.encode())
}

// ReformGroup with the group's flow held.
func (self *gkmGroupManager) reformInFlow(ctx context.Context, args *GkmReformArgs) (Id, error) {
	client := self.client
	api, err := client.reformApi()
	if err != nil {
		return Id{}, err
	}
	state, err := client.currentState()
	if err != nil {
		return Id{}, err
	}
	if err := GkmFormSignerAllowed(state, self.repoId, client.args.SidecarId); err != nil {
		return Id{}, err
	}
	record, err := self.reformRecord()
	if err != nil {
		return Id{}, err
	}
	for drawCount := 0; record == nil || record.phase == gkmReformPhasePosting; drawCount += 1 {
		if max(1, client.settings.CreateGroupDrawCount) <= drawCount {
			return Id{}, fmt.Errorf("%w: every group id drawn was taken", ErrGkmWait)
		}
		if record == nil {
			record, err = self.draftReform(state)
			if err != nil {
				return Id{}, err
			}
			// persisted before the POST, so a kill resumes with the same bytes
			if err := self.putReformRecord(record); err != nil {
				return Id{}, err
			}
		}
		taken, err := self.postReform(ctx, api, record)
		if err != nil {
			return Id{}, err
		}
		if taken {
			// the id is another repo's: this draft goes, with its group's state, and another is drawn
			if forgetter, ok := client.args.Mls.(MlsGroupForgetter); ok {
				if err := forgetter.ForgetGroup(record.groupId); err != nil {
					return Id{}, err
				}
			}
			if err := self.putReformRecord(nil); err != nil {
				return Id{}, err
			}
			record = nil
			continue
		}
		record.phase = gkmReformPhaseLadder
		if err := self.putReformRecord(record); err != nil {
			return Id{}, err
		}
	}
	if record.phase == gkmReformPhaseLadder {
		if err := self.uploadLadder(ctx, api, record); err != nil {
			return Id{}, err
		}
		if err := self.adoptOwnReform(state, record); err != nil {
			return Id{}, err
		}
		record.phase = gkmReformPhaseFinishing
		if err := self.putReformRecord(record); err != nil {
			return Id{}, err
		}
	}
	if args.Reseed {
		// a deleted repo takes nothing more: the record stays, and a call once the repo is restored finishes
		return record.groupId, nil
	}
	// the first generation that names the new group, with every delivery; then the Adds, whose epochs carry it
	if _, err := self.rotateInFlow(ctx, GkmCauseRequest); err != nil {
		return Id{}, err
	}
	if err := self.runPendingInFlow(ctx); err != nil && !gkmLeafWaits(err) && !errors.Is(err, ErrGkmNotWriter) {
		return Id{}, err
	}
	if err := self.putReformRecord(nil); err != nil {
		return Id{}, err
	}
	return record.groupId, nil
}

// Step 1: the new group's id and MLS state, its GroupForm and the whole POST forms request.
func (self *gkmGroupManager) draftReform(state GkmAuthView) (*gkmReformRecord, error) {
	client := self.client
	repo := state.Repo(self.repoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, self.repoId)
	}
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return nil, err
	}
	top, err := client.newestHeldGeneration(self.repoId)
	if err != nil {
		return nil, err
	}
	generation := top.generation.Rotate.GetGeneration()
	if top.key == nil {
		return nil, fmt.Errorf("%w: generation %d is held without its key", ErrGkmKeyMissing, generation)
	}
	// the whole ladder, which no one can rebuild later: each Signed GenRotate below the newest
	for number := uint64(1); number < generation; number += 1 {
		if _, err := client.heldGeneration(self.repoId, number); err != nil {
			return nil, fmt.Errorf("%w: this device does not hold gen/%d to re-upload", ErrGkmKeyMissing, number)
		}
	}
	groupId := Id{}
	// never fails: a broken system generator crashes the program instead
	rand.Read(groupId[:])
	var ownerMemberId *Id
	if owner := repo.GetOwnerMemberId(); 0 < len(owner) {
		ownerId, err := IdFromBytes(owner)
		if err != nil {
			return nil, fmt.Errorf("%w: the repo's owner", ErrGkmMalformed)
		}
		ownerMemberId = &ownerId
	}
	group, err := client.args.Mls.CreateGroup(groupId, &MlsUrGroup{NetworkId: client.args.NetworkId, RepoId: self.repoId, Kind: repo.GetKind(), OwnerMemberId: ownerMemberId})
	if err != nil {
		return nil, err
	}
	formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{
		RepoId: self.repoId.Bytes(), GroupId: groupId.Bytes(), PreviousGroupId: pins.groupId.Bytes(), Generation: generation,
		// the state this device's right to re-form is judged at (QD-643)
		Auth: state.Pin(),
	})
	if err != nil {
		return nil, err
	}
	signedForm, err := gkmSign(gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, formBody, client.args.Sign)
	if err != nil {
		return nil, err
	}
	kek, err := MlsKek(group, self.repoId)
	if err != nil {
		return nil, err
	}
	genWrap, err := SealGkmGenWrap(top.key, groupId, group.Epoch(), kek)
	clear(kek)
	if err != nil {
		return nil, err
	}
	groupInfo, err := group.GroupInfo()
	if err != nil {
		return nil, err
	}
	sealedGroupInfo, err := SealGkmGroupInfo(top.key, groupId, group.Epoch(), groupInfo)
	if err != nil {
		return nil, err
	}
	request, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmGroupReformRequest{
		Form: signedForm, GenWrap: genWrap, SealedGroupInfo: sealedGroupInfo, CipherSuite: uint32(mlsCipherSuiteXWing),
	})
	if err != nil {
		return nil, err
	}
	return &gkmReformRecord{phase: gkmReformPhasePosting, groupId: groupId, generation: generation, request: request}, nil
}

// Step 2: POST forms with the record's bytes, sent again while its answer is lost. taken says the owner marker holds
// another repo. A form that lost its place to another re-form is dropped with its record, and answers ErrGkmWait.
func (self *gkmGroupManager) postReform(ctx context.Context, api GkmReformApi, record *gkmReformRecord) (taken bool, err error) {
	client := self.client
	request := &protocol.GkmGroupReformRequest{}
	if err := proto.Unmarshal(record.request, request); err != nil {
		return false, fmt.Errorf("%w: a re-form record's request", ErrGkmMalformed)
	}
	for sendCount := 0; sendCount < max(1, client.settings.CommitSendCount); sendCount += 1 {
		testHookBarrier(gkmBarrierReformFormBefore, gkmPathId(record.groupId))
		err := api.Reform(ctx, self.repoId, request)
		testHookBarrier(gkmBarrierReformFormAfter, gkmPathId(record.groupId))
		gkmError, refused := GkmErrorOf(err)
		switch {
		case err == nil:
			return false, nil
		case refused && gkmError.Status == http.StatusConflict && len(gkmError.Winner) == 0:
			return true, nil
		case refused && gkmError.Status == http.StatusConflict:
			// the repo's newest form is another's: that group stands, and this device adopts it at its next sync
			if forgetter, ok := client.args.Mls.(MlsGroupForgetter); ok {
				if err := forgetter.ForgetGroup(record.groupId); err != nil {
					return false, err
				}
			}
			if err := self.putReformRecord(nil); err != nil {
				return false, err
			}
			return false, fmt.Errorf("%w: another re-form of the repo stands", ErrGkmWait)
		case refused && gkmError.Status == http.StatusForbidden:
			return false, fmt.Errorf("%w: gkm refused the GroupForm", ErrGkmNotWriter)
		case refused:
			return false, err
		case ctx.Err() != nil:
			return false, err
		}
		// unknown: every write of the request is an If-None-Match create that equal bytes resume, so it goes again
	}
	return false, fmt.Errorf("%w: the re-form got no answer", ErrGkmUnavailable)
}

// Step 3: gen/1 to gen/<g> as this device holds them, ascending, gkmLadderBatchCount a call. A call sent again
// finds its own bytes and succeeds.
func (self *gkmGroupManager) uploadLadder(ctx context.Context, api GkmReformApi, record *gkmReformRecord) error {
	client := self.client
	yield := client.newYield()
	for first := uint64(1); first <= record.generation; first += gkmLadderBatchCount {
		request := &protocol.GkmLadderRequest{}
		for number := first; number < first+gkmLadderBatchCount && number <= record.generation; number += 1 {
			yield.step()
			held, err := client.heldGeneration(self.repoId, number)
			if err != nil {
				return err
			}
			request.Generations = append(request.Generations, held.generation.Signed)
		}
		landed := false
		for sendCount := 0; !landed; sendCount += 1 {
			if max(1, client.settings.CommitSendCount) <= sendCount {
				return fmt.Errorf("%w: the ladder from generation %d got no answer", ErrGkmUnavailable, first)
			}
			barrierKey := gkmPathId(record.groupId) + ":" + strconv.FormatUint(first, 10)
			testHookBarrier(gkmBarrierReformLadderBefore, barrierKey)
			err := api.UploadLadder(ctx, self.repoId, record.groupId, request)
			testHookBarrier(gkmBarrierReformLadderAfter, barrierKey)
			gkmError, refused := GkmErrorOf(err)
			switch {
			case err == nil:
				landed = true
			case refused && gkmError.Status == http.StatusConflict:
				// other bytes stand at a generation of this device's own new group
				client.alarm(&GkmAlarm{Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: record.groupId, Generation: first, Reason: GkmRefusalChain, Detail: "a re-formed group's ladder holds another statement"})
				return fmt.Errorf("%w: the ladder holds another statement at or past generation %d", ErrGkmReformRefused, first)
			case refused && gkmError.Status == http.StatusForbidden:
				return fmt.Errorf("%w: gkm refused the ladder from generation %d", ErrGkmWait, first)
			case refused:
				return err
			case ctx.Err() != nil:
				return err
			}
		}
	}
	return nil
}

// A header's encoding.
func gkmHeaderBytes(generation uint64, auth *bridge.AuthPin) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Generation: generation, Auth: auth})
}

// Moves a repo's pins to the group a verified re-form made (plan-KEYS-reform-ladder rule 8): a new group id and a
// new epoch pin from epoch 0, the generation pin (g, C_g) as it stands, which the caller has held to the new
// group's ladder. floorHeader is what epoch 1's commit is held to: the form's generation with gen/<it>'s auth.
// The one place a pinned group changes; advancePins refuses it.
func (self *GkmGroupClient) movePinsToReform(repoId Id, form *gkmVerifiedForm, epochAuthenticator []byte, floorHeader []byte) error {
	stored, err := self.repoPins(repoId)
	if err != nil {
		return err
	}
	next := *stored
	next.groupId = form.groupId
	next.epoch = 0
	next.epochAuthenticator = bytes.Clone(epochAuthenticator)
	next.epochHeader = bytes.Clone(floorHeader)
	if err := self.args.Secrets.Put(gkmFormRecordName(repoId), form.signedBytes); err != nil {
		return err
	}
	if err := self.args.Secrets.Put(gkmRepoRecordName(repoId, "pins"), next.encode()); err != nil {
		return err
	}
	self.pinsMoved(repoId, stored, &next)
	// a fork seen at the old group's epoch names nothing of the new one
	return self.editSyncRecord(repoId, func(record *gkmSyncRecord) {
		record.epochFork, record.forkedEpoch = false, 0
	})
}

// Moves a depositor's pins along the GenRotates it verified from its pin to newest, which names a re-formed group
// (the file header's depositor row): the caller held the statement at its pin to the pinned commitment and each one
// since to its parent's commitment and its signer's key, and judged newest by the rotation checks. A pin that holds
// a leaf's epoch, or one this would not raise, moves only as advancePins allows, so a leaf's group changes only by a
// form it verified.
func (self *GkmGroupClient) movePinsAlongChain(repoId Id, newest *GkmGeneration) error {
	stored, err := self.repoPins(repoId)
	if err != nil {
		return err
	}
	rotate := newest.Rotate
	edit := func(pins *gkmRepoPins) {
		pins.groupId = Id(rotate.GetGroupId())
		pins.generation = rotate.GetGeneration()
		pins.commitment = bytes.Clone(rotate.GetCommitment())
	}
	if 0 < len(stored.epochAuthenticator) || rotate.GetGeneration() <= stored.generation {
		return self.advancePins(repoId, edit)
	}
	next := *stored
	edit(&next)
	if err := self.args.Secrets.Put(gkmRepoRecordName(repoId, "pins"), next.encode()); err != nil {
		return err
	}
	self.pinsMoved(repoId, stored, &next)
	return nil
}

// Step 4: this device's own pins to the group it formed, and its old group's MLS state dropped.
func (self *gkmGroupManager) adoptOwnReform(state GkmAuthView, record *gkmReformRecord) error {
	client := self.client
	request := &protocol.GkmGroupReformRequest{}
	if err := proto.Unmarshal(record.request, request); err != nil {
		return fmt.Errorf("%w: a re-form record's request", ErrGkmMalformed)
	}
	form, err := gkmParseGroupForm(state, self.repoId, request.GetForm())
	if err != nil {
		return err
	}
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return err
	}
	if pins.groupId == form.groupId {
		// a resumed re-form whose pins already moved
		return nil
	}
	top, err := client.heldGeneration(self.repoId, record.generation)
	if err != nil {
		return err
	}
	group, err := client.loadGroup(form.groupId)
	if err != nil {
		return err
	}
	floorHeader, err := gkmHeaderBytes(record.generation, top.generation.Rotate.GetAuth())
	if err != nil {
		return err
	}
	oldGroupId := pins.groupId
	if err := client.movePinsToReform(self.repoId, form, group.EpochAuthenticator(), floorHeader); err != nil {
		return err
	}
	if forgetter, ok := client.args.Mls.(MlsGroupForgetter); ok {
		if err := forgetter.ForgetGroup(oldGroupId); err != nil {
			return err
		}
	}
	// the new group's only leaf is fresh
	return client.notePathCommitted(self.repoId)
}

// The member's row of the file header, for one repo: adopted says this device's pins moved to a re-formed group.
// ErrGkmReformRefused, alarmed, for a re-form that fails its checks; ErrGkmWait while the new group's ladder has not
// reached its form's generation.
func (self *GkmGroupClient) AdoptReform(ctx context.Context, repoId Id) (adopted bool, err error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return false, err
	}
	return manager.adoptReformInFlow(ctx, state)
}

// AdoptReform with the group's flow held.
func (self *gkmGroupManager) adoptReformInFlow(ctx context.Context, state GkmAuthView) (bool, error) {
	client := self.client
	pins, err := client.repoPins(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if record, err := self.reformRecord(); err != nil || record != nil {
		// this device's own re-form is under way: ReformGroup moves its pins
		return false, err
	}
	reply, err := client.args.Api.Forms(ctx, self.repoId)
	if err != nil {
		return false, err
	}
	signedForms := reply.GetForms()
	if len(signedForms) == 0 {
		return false, nil
	}
	newestBody := &protocol.GroupForm{}
	if err := proto.Unmarshal(signedForms[len(signedForms)-1].GetBody(), newestBody); err != nil {
		return false, fmt.Errorf("%w: a GroupForm", ErrGkmReplyInvalid)
	}
	newestGroupId, err := IdFromBytes(newestBody.GetGroupId())
	if err != nil {
		return false, fmt.Errorf("%w: a GroupForm's group", ErrGkmReplyInvalid)
	}
	if newestGroupId == pins.groupId {
		return false, nil
	}
	refuse := func(reason GkmRefusalReason, generation uint64, signerId Id, detail string) (bool, error) {
		client.alarm(&GkmAlarm{
			Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: newestGroupId, Generation: generation,
			SidecarId: signerId, Reason: reason, Detail: detail,
		})
		return false, fmt.Errorf("%w: %s", ErrGkmReformRefused, detail)
	}

	// the forms from this device's group to the newest, each verified and its signer held to §10.6's rule
	var newest *gkmVerifiedForm
	wantGroupId := newestGroupId
	for index := len(signedForms) - 1; 0 <= index && wantGroupId != pins.groupId; index -= 1 {
		body := &protocol.GroupForm{}
		if err := proto.Unmarshal(signedForms[index].GetBody(), body); err != nil || !bytes.Equal(body.GetGroupId(), wantGroupId.Bytes()) {
			continue
		}
		form, err := gkmParseGroupForm(state, self.repoId, signedForms[index])
		if err != nil {
			if errors.Is(err, ErrGkmAuthentication) || errors.Is(err, ErrGkmMalformed) {
				return refuse(GkmRefusalSigner, 0, Id{}, "a GroupForm that does not verify")
			}
			return false, err
		}
		verdict, err := gkmJudgeFormSigner(state, self.repoId, form)
		if err != nil {
			// a pin above this device's tip waits for the log
			return false, err
		}
		if verdict.Refused {
			return false, client.refuseForm(self.repoId, form, verdict)
		}
		if form.previousGroupId == (Id{}) {
			break
		}
		if newest == nil {
			newest = form
		}
		wantGroupId = form.previousGroupId
	}
	if newest == nil || wantGroupId != pins.groupId {
		return refuse(GkmRefusalChain, 0, Id{}, "the repo's newest GroupForm does not re-form the group this device holds")
	}
	// the pin never falls: a re-former that held fewer generations than this device cannot carry it over
	if newest.generation < pins.generation {
		return refuse(GkmRefusalChain, newest.generation, newest.signerId, "a re-form below this device's generation pin")
	}

	// the new group's ladder, against what this device has cached: each statement chained to the one below it, and
	// byte for byte the one this device holds wherever it holds one (rule 6), so a statement gkm altered at a
	// generation this device cached is refused even where its commitment was kept
	var floor *bridge.AuthPin
	var belowCommitment []byte
	since := uint64(0)
	yield := client.newYield()
	for since < newest.generation {
		page, err := self.generationsPage(ctx, newest.groupId, since)
		if err != nil {
			return false, err
		}
		if len(page) == 0 {
			return false, fmt.Errorf("%w: the re-formed group's ladder has reached generation %d of %d", ErrGkmWait, since, newest.generation)
		}
		for _, signed := range page {
			yield.step()
			since += 1
			if newest.generation < since {
				break
			}
			rotate := &protocol.GenRotate{}
			if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil || rotate.GetGeneration() != since || !bytes.Equal(rotate.GetRepoId(), self.repoId.Bytes()) {
				return refuse(GkmRefusalChain, since, newest.signerId, "a ladder statement out of place")
			}
			if 1 < since && !bytes.Equal(rotate.GetParentCommitment(), belowCommitment) {
				return refuse(GkmRefusalChain, since, newest.signerId, "a ladder statement that does not chain from the one below it")
			}
			belowCommitment = rotate.GetCommitment()
			held, err := client.heldGeneration(self.repoId, since)
			switch {
			case err == nil:
				if !proto.Equal(held.generation.Signed, signed) {
					return refuse(GkmRefusalChain, since, newest.signerId, "the ladder's statement is not the one this device holds")
				}
				if since == newest.generation {
					floor = held.generation.Rotate.GetAuth()
				}
			case errors.Is(err, ErrGkmKeyMissing) && since == newest.generation:
				// past this device's own pin, the refresh verifies and judges each statement on its parent; the
				// form's own generation, whose pin floors the new group's first commit, is verified here first
				namedGroupId, err := IdFromBytes(rotate.GetGroupId())
				if err != nil {
					return refuse(GkmRefusalChain, since, newest.signerId, "a ladder statement that names no group")
				}
				signedBytes, err := gkmSignedBytes(signed)
				if err != nil {
					return false, err
				}
				generation, err := ParseGenRotate(signedBytes, namedGroupId, since, GkmIdentityKeys(state))
				if err != nil {
					if errors.Is(err, ErrGkmAuthentication) || errors.Is(err, ErrGkmMalformed) {
						return refuse(GkmRefusalSigner, since, newest.signerId, "the form's generation does not verify")
					}
					return false, err
				}
				floor = generation.Rotate.GetAuth()
			case errors.Is(err, ErrGkmKeyMissing):
			default:
				return false, err
			}
		}
	}
	if floor == nil || floor.GetVersion() == 0 || len(floor.GetChain()) != gkmAuthChainByteCount {
		return refuse(GkmRefusalChain, newest.generation, newest.signerId, "the ladder's last statement carries no pin")
	}
	floorHeader, err := gkmHeaderBytes(newest.generation, floor)
	if err != nil {
		return false, err
	}
	oldGroupId := pins.groupId
	if err := client.movePinsToReform(self.repoId, newest, nil, floorHeader); err != nil {
		return false, err
	}
	if client.args.Mls != nil {
		if forgetter, ok := client.args.Mls.(MlsGroupForgetter); ok {
			if err := forgetter.ForgetGroup(oldGroupId); err != nil && !errors.Is(err, ErrMlsGroupUnknown) {
				return true, err
			}
		}
	}
	return true, nil
}
