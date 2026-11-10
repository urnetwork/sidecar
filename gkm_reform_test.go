//go:build !sidecar_http

// Re-forming on the fake gkm (KEYS-M2-25; FS-41's group legs and FS-6's re-seed leg as units, DESIGN-DETAILS 6.6):
// a vault re-formed by its owner's device after a site loss, its ladder carried over byte for byte, its readers
// returning by KF2 and a recovery-code-only member keeping access; a member refusing a mismatched C_g, a cached
// statement served under other bytes, a form by a device that may not form the group, and a re-form below its own
// pin; a re-form refused from a device that may not make one; a taken group id redrawn; a kill resumed; a repo
// re-seeded as deleted taking the form and the ladder alone; a stalled general repo's group re-formed by its admin
// while the old group stands, a member joining by its Welcome before any sync; a depositor's pin following the new
// group along its chain; and a GenHead of the replaced group compared along the form.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var _ sidecar.GkmReformApi = (*gkmFakeApi)(nil)

// POST forms as gkm serves it: the owner marker first, 409 with no winner for another repo's group; then the form,
// which must re-form the repo's newest group where one stands, 409 with the newest otherwise; then epoch/0, whose
// header holds the form's generation and no pin. Equal bytes resume.
func (self *gkmFakeApi) Reform(ctx context.Context, repoId sidecar.Id, request *protocol.GkmGroupReformRequest) error {
	return self.call("Reform", func() error {
		store := self.store
		form := &protocol.GroupForm{}
		if err := proto.Unmarshal(request.GetForm().GetBody(), form); err != nil {
			return gkmFakeRefusal(http.StatusBadRequest, nil)
		}
		groupId := sidecar.Id(form.GetGroupId())
		if ownerRepoId, taken := store.groupOwnerRepoIds[groupId]; taken && ownerRepoId != repoId {
			return gkmFakeRefusal(http.StatusConflict, nil)
		}
		forms := store.repoForms[repoId]
		resumed := 0 < len(forms) && proto.Equal(forms[len(forms)-1], request.GetForm())
		if 0 < len(forms) && !resumed {
			newest := &protocol.GroupForm{}
			if err := proto.Unmarshal(forms[len(forms)-1].GetBody(), newest); err != nil || !bytes.Equal(newest.GetGroupId(), form.GetPreviousGroupId()) {
				return gkmFakeRefusal(http.StatusConflict, forms[len(forms)-1])
			}
		}
		store.groupOwnerRepoIds[groupId] = repoId
		if !resumed {
			store.repoForms[repoId] = append(forms, request.GetForm())
		}
		if len(store.groupEpochs[groupId]) == 0 {
			store.groupEpochs[groupId] = []*protocol.GkmEpochObject{{
				Header:              &protocol.GkmCommitHeader{Generation: form.GetGeneration()},
				Uploader:            self.sidecarId.Bytes(),
				TimeMs:              store.clock.Now().UnixMilli(),
				GenWrap:             request.GetGenWrap(),
				SealedGroupInfo:     request.GetSealedGroupInfo(),
				GroupInfoGeneration: form.GetGeneration(),
				CipherSuite:         request.GetCipherSuite(),
			}}
		}
		return nil
	})
}

// POST ladder as gkm serves it: to the repo's newest group, a re-formed one, before its epoch 1; consecutive from
// what the group holds, none past the form's generation; equal bytes resume, others answer 409.
func (self *gkmFakeApi) UploadLadder(ctx context.Context, repoId sidecar.Id, groupId sidecar.Id, request *protocol.GkmLadderRequest) error {
	return self.call("UploadLadder", func() error {
		store := self.store
		forms := store.repoForms[repoId]
		form := &protocol.GroupForm{}
		if len(forms) == 0 || proto.Unmarshal(forms[len(forms)-1].GetBody(), form) != nil || !bytes.Equal(form.GetGroupId(), groupId.Bytes()) ||
			len(form.GetPreviousGroupId()) == 0 || 1 < len(store.groupEpochs[groupId]) || 64 < len(request.GetGenerations()) {
			return gkmFakeRefusal(http.StatusForbidden, nil)
		}
		for _, signed := range request.GetGenerations() {
			rotate := &protocol.GenRotate{}
			if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
				return gkmFakeRefusal(http.StatusBadRequest, nil)
			}
			held := store.groupGenerations[groupId]
			number := rotate.GetGeneration()
			switch {
			case form.GetGeneration() < number || uint64(len(held))+1 < number:
				return gkmFakeRefusal(http.StatusForbidden, nil)
			case number <= uint64(len(held)):
				if !proto.Equal(held[number-1], signed) {
					return gkmFakeRefusal(http.StatusConflict, held[number-1])
				}
			default:
				store.groupGenerations[groupId] = append(held, signed)
			}
		}
		return nil
	})
}

// A site loss: every object gkm held is gone (owner decisions 90, 94). Devices keep their keychains and MLS state.
func (self *gkmFakeStore) loseSite() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.groupOwnerRepoIds = map[sidecar.Id]sidecar.Id{}
	self.repoForms = map[sidecar.Id][]*bridge.Signed{}
	self.groupGenerations = map[sidecar.Id][]*bridge.Signed{}
	self.groupEpochs = map[sidecar.Id][]*protocol.GkmEpochObject{}
	self.pathWraps = map[string][]byte{}
	self.pathRecoveryWraps = map[string][]byte{}
	self.readerKeys = map[sidecar.Id]*bridge.Signed{}
	self.keyPackages = map[sidecar.Id][]*sidecar.MlsKeyPackage{}
	self.groupWelcomes = map[string][]byte{}
	self.groupInfos = map[sidecar.Id]*protocol.GkmGroupInfoObject{}
	self.welcomeEntries = map[sidecar.Id][]*protocol.GkmWelcomeEntry{}
}

// The engine world as an author's vault at generation 2: the world's member owns the repo and its devices have
// consented, a second member, n, reads it by its device x and holds a recovery binding, and every leaf holds both
// generations. oldGroupId is the group before any re-form.
type gkmReformWorld struct {
	*gkmFlowWorld
	oldGroupId sidecar.Id
	sharedId   sidecar.Id
	binding    *sidecar.GkmRecoveryBinding
}

func newGkmReformWorld(t *testing.T) *gkmReformWorld {
	world := &gkmReformWorld{gkmFlowWorld: newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_VAULT), sharedId: sidecar.NewId()}
	world.oldGroupId = world.groupId
	world.repo.OwnerMemberId = world.memberId.Bytes()
	for _, device := range []*gkmWorldDevice{world.a, world.b, world.c, world.p} {
		world.repo.ConsentedSidecarIds = append(world.repo.ConsentedSidecarIds, device.id.Bytes())
	}
	privateKey, keySha256 := gkmTestRecoveryKey(t, "n")
	world.binding = &sidecar.GkmRecoveryBinding{MemberId: world.sharedId, PrivateKey: privateKey, KeySha256: keySha256}
	world.members = append(world.members, &bridge.MemberRow{
		MemberId: world.sharedId.Bytes(), RecoveryKeySha256: keySha256,
		Bindings: []*bridge.RecoveryBindingRow{{KeySha256: keySha256, Signer: world.x.id.Bytes(), At: 1}},
	})
	world.recoveryKeys[world.sharedId] = &sidecar.GkmRecoveryKey{XwingPublicKey: privateKey.PublicKey().Bytes(), BindingKeySha256: keySha256}
	world.x.row.MemberId = world.sharedId.Bytes()
	world.stateFor()
	if key, err := world.flows[world.a].client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation to generation 2: %v", err)
	}
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		if err := world.flows[device].client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s takes generation 2: %v", device.label, err)
		}
	}
	return world
}

// The site is lost and every device comes back with a fresh ReaderKey and KeyPackages, as upkeep uploads them.
func (self *gkmReformWorld) loseSite() {
	self.t.Helper()
	self.store.loseSite()
	for _, device := range self.devices {
		self.flows[device].publishReaderKey()
		self.store.publishKeyPackages(device, 2, false)
	}
}

// The group the repo's newest form names at gkm.
func (self *gkmReformWorld) formedGroupId() sidecar.Id {
	self.t.Helper()
	forms := self.store.repoForms[self.repoId]
	if len(forms) == 0 {
		self.t.Fatalf("gkm holds no form of the repo")
	}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(forms[len(forms)-1].GetBody(), form); err != nil {
		self.t.Fatal(err)
	}
	return sidecar.Id(form.GetGroupId())
}

// FS-41's group legs as a unit (D-KEYS-13): after a site loss the vault's owner's device re-forms the group from its
// keychain; the new group's ladder is the old one byte for byte; the first generation past it names the new group
// and carries a RecoveryWrap, so a member with only its recovery code keeps access; every member checks the form and
// its cached C_g, moves its pins along the form, and returns by a Welcome; generation numbers continue and no pin
// falls.
func TestAVaultReformedByItsOwnersDeviceKeepsEveryReader(t *testing.T) {
	world := newGkmReformWorld(t)
	a := world.flows[world.a]
	oldStatements := slices.Clone(world.store.groupGenerations[world.oldGroupId])
	world.loseSite()

	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil {
		t.Fatalf("the re-form: %v", err)
	}
	if newGroupId == world.oldGroupId || world.formedGroupId() != newGroupId || world.store.groupOwnerRepoIds[newGroupId] != world.repoId {
		t.Fatalf("the re-formed group is not the repo's newest, under its owner marker")
	}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(world.store.repoForms[world.repoId][0].GetBody(), form); err != nil || !bytes.Equal(form.GetPreviousGroupId(), world.oldGroupId.Bytes()) || form.GetGeneration() != 2 {
		t.Errorf("the form names previous group and generation %d: %v", form.GetGeneration(), err)
	}
	// the ladder: the old statements byte for byte, then generation 3, the first that names the new group
	statements := world.store.groupGenerations[newGroupId]
	if len(statements) != 3 || !proto.Equal(statements[0], oldStatements[0]) || !proto.Equal(statements[1], oldStatements[1]) {
		t.Fatalf("the new group holds %d generations, or its ladder is not the old one's", len(statements))
	}
	gen3 := &protocol.GenRotate{}
	if err := proto.Unmarshal(statements[2].GetBody(), gen3); err != nil || !bytes.Equal(gen3.GetGroupId(), newGroupId.Bytes()) || sidecar.GkmCause(gen3.GetCause()) != sidecar.GkmCauseRequest {
		t.Errorf("generation 3 does not name the new group with cause REQUEST: %v", err)
	}
	// epoch 0 holds no pin, and epoch 1 is the Add of every reader that has a KeyPackage
	epochs := world.store.groupEpochs[newGroupId]
	if len(epochs) != 2 || epochs[0].GetHeader().GetAuth() != nil || epochs[0].GetHeader().GetGeneration() != 2 || epochs[1].GetHeader().GetGeneration() != 3 {
		t.Fatalf("the new group's epochs: %d", len(epochs))
	}
	if labels := world.rosterLabels(world.engineGroup2(world.a, newGroupId)); strings.Join(labels, "") != "abcpx" {
		t.Errorf("the new tree: %v", labels)
	}
	// a member with only its recovery code keeps access: generation 3's RecoveryWrap opens, and the ladder below it
	reply, err := a.api.RecoveryWraps(world.ctx, world.sharedId, false)
	if err != nil || len(reply.GetWraps()) != 1 || reply.GetWraps()[0].GetGeneration() != 3 {
		t.Fatalf("the recovery wraps of the member who reads by its code: %v %v", reply.GetWraps(), err)
	}
	tip := world.log.Tip()
	parsed3, err := sidecar.ParseGenRotate(mustGkmSignedBytes(t, statements[2]), newGroupId, 3, sidecar.GkmIdentityKeys(tip))
	if err != nil {
		t.Fatal(err)
	}
	key3, err := sidecar.OpenGkmRecoveryWrap(reply.GetWraps()[0].GetCiphertext(), parsed3, &sidecar.GkmRecoveryArgs{
		MemberId: world.sharedId, GroupId: newGroupId, BindingKeySha256: world.binding.KeySha256,
	}, world.binding.PrivateKey)
	if err != nil {
		t.Fatalf("the recovery wrap of generation 3: %v", err)
	}
	parsed2, err := sidecar.ParseGenRotate(mustGkmSignedBytes(t, statements[1]), world.oldGroupId, 2, sidecar.GkmIdentityKeys(tip))
	if err != nil {
		t.Fatal(err)
	}
	if key2, err := key3.OpenParent(parsed2); err != nil || !bytes.Equal(key2.Commitment(), world.storedCommitment(a, 2)) {
		t.Errorf("the ladder does not open from the new group's generation 3 to the old generation 2: %v", err)
	}

	// each member follows the form, keeps its generation pin, and returns by its Welcome
	for _, device := range []*gkmWorldDevice{world.b, world.c} {
		flow := world.flows[device]
		if err := flow.client.SyncRepo(world.ctx, world.repoId); err != nil {
			t.Fatalf("%s syncs after the re-form: %v", device.label, err)
		}
		groupId, epoch, generation, err := flow.client.TestPins(world.repoId)
		if err != nil || groupId != newGroupId || epoch != 0 || generation < 2 {
			t.Fatalf("%s after adopting the re-form: epoch %d, generation %d, %v", device.label, epoch, generation, err)
		}
		joined, err := flow.client.JoinWelcomes(world.ctx)
		if err != nil || !slices.Contains(joined, world.repoId) {
			t.Fatalf("%s joins the re-formed group: %v", device.label, err)
		}
		groupId, epoch, generation, err = flow.client.TestPins(world.repoId)
		if err != nil || groupId != newGroupId || epoch != 1 || generation != 3 {
			t.Errorf("%s in the re-formed group: epoch %d, generation %d, %v", device.label, epoch, generation, err)
		}
		// what it sealed under the old generations still opens
		for number := uint64(1); number <= 3; number += 1 {
			if key, err := flow.client.RepoKey(world.ctx, world.repoId, number); err != nil || key.Generation() != number {
				t.Errorf("%s reads generation %d after the re-form: %v", device.label, number, err)
			}
		}
		if len(flow.alarms) != 0 {
			t.Errorf("%s alarmed: %+v", device.label, flow.alarms[0])
		}
	}
}

// A Signed statement's stored bytes.
func mustGkmSignedBytes(t *testing.T, signed *bridge.Signed) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// C_g as a device holds it.
func (self *gkmReformWorld) storedCommitment(flow *gkmFlowDevice, generation uint64) []byte {
	self.t.Helper()
	key, _, found, err := flow.client.TestHeldGeneration(self.repoId, generation)
	if err != nil || !found || key == nil {
		self.t.Fatalf("%s holds no generation %d: %v", flow.label, generation, err)
	}
	return key.Commitment()
}

// A device's group of groupId as its engine holds it now, nil for none.
func (self *gkmFlowWorld) engineGroup2(device *gkmWorldDevice, groupId sidecar.Id) sidecar.MlsGroup {
	group, err := device.mls.LoadGroup(groupId)
	if err != nil {
		return nil
	}
	return group
}

// A member refuses a re-form that fails its checks, alarms, and keeps its pins: a ladder whose commitment at a
// generation is not the one it has cached, one whose statement there keeps the commitment under other bytes, a form
// by a device that may not form the group, and a re-form below its own generation pin. While the ladder has not
// reached the form's generation it waits.
func TestAMemberRefusesAReformThatFailsItsChecks(t *testing.T) {
	// a mismatched C_g
	world := newGkmReformWorld(t)
	a := world.flows[world.a]
	b := world.flows[world.b]
	world.loseSite()
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil {
		t.Fatal(err)
	}
	genuine := world.store.groupGenerations[newGroupId]
	strayKey1, strayRotate1, err := sidecar.NewGkmFirstGeneration(world.repoId, world.oldGroupId, &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: world.first.Pin(), Time: world.now, HoldersSha256: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, strayRotate2, err := strayKey1.NextGeneration(&sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: world.first.Pin(), Time: world.now, HoldersSha256: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = strayRotate1
	straySigned2, err := sidecar.SignGenRotate(strayRotate2, world.a.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	world.store.groupGenerations[newGroupId] = []*bridge.Signed{genuine[0], straySigned2, genuine[2]}
	if adopted, err := b.client.AdoptReform(world.ctx, world.repoId); adopted || !errors.Is(err, sidecar.ErrGkmReformRefused) {
		t.Fatalf("a re-form whose ladder holds another C_2: %v", err)
	}
	if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmRefused || b.alarms[0].Generation != 2 || b.alarms[0].SidecarId != world.a.id {
		t.Errorf("the refused re-form's alarm: %+v", b.alarms)
	}
	if groupId, epoch, generation, err := b.client.TestPins(world.repoId); err != nil || groupId != world.oldGroupId || epoch != 1 || generation != 2 {
		t.Errorf("a refused re-form moved the member's pins: %v", err)
	}
	// the genuine commitment and chain under other bytes, re-signed by the re-former's own key: refused, since the
	// ladder must hold byte for byte what this member cached
	altered := &protocol.GenRotate{}
	if err := proto.Unmarshal(genuine[1].GetBody(), altered); err != nil {
		t.Fatal(err)
	}
	altered.HoldersSha256 = bytes.Repeat([]byte{9}, 32)
	alteredSigned, err := sidecar.SignGenRotate(altered, world.a.signer.Sign)
	if err != nil {
		t.Fatal(err)
	}
	world.store.groupGenerations[newGroupId] = []*bridge.Signed{genuine[0], alteredSigned, genuine[2]}
	if adopted, err := b.client.AdoptReform(world.ctx, world.repoId); adopted || !errors.Is(err, sidecar.ErrGkmReformRefused) {
		t.Fatalf("a re-form whose ladder holds other bytes under C_2: %v", err)
	}
	if len(b.alarms) != 2 || b.alarms[1].Kind != sidecar.GkmAlarmRefused || b.alarms[1].Generation != 2 {
		t.Errorf("the altered statement's alarm: %+v", b.alarms)
	}
	// a ladder that stops short of the form's generation is waited on
	world.store.groupGenerations[newGroupId] = genuine[:1]
	if adopted, err := b.client.AdoptReform(world.ctx, world.repoId); adopted || !errors.Is(err, sidecar.ErrGkmWait) {
		t.Errorf("a re-form whose ladder is still going up: %v", err)
	}
	world.store.groupGenerations[newGroupId] = genuine
	if adopted, err := b.client.AdoptReform(world.ctx, world.repoId); !adopted || err != nil {
		t.Errorf("the genuine re-form: %v", err)
	}

	// a form by a device that is not the owner's consented one, and one below the member's pin
	for _, lowGeneration := range []bool{false, true} {
		world := newGkmReformWorld(t)
		b := world.flows[world.b]
		world.loseSite()
		signer := world.x
		generation := uint64(2)
		if lowGeneration {
			signer, generation = world.a, 1
		}
		forgedGroupId := sidecar.NewId()
		formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{
			RepoId: world.repoId.Bytes(), GroupId: forgedGroupId.Bytes(), PreviousGroupId: world.oldGroupId.Bytes(), Generation: generation,
		})
		if err != nil {
			t.Fatal(err)
		}
		form, err := signer.signer.Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
		if err != nil {
			t.Fatal(err)
		}
		world.store.repoForms[world.repoId] = []*bridge.Signed{form}
		world.store.groupGenerations[forgedGroupId] = []*bridge.Signed{world.gen1.signed}
		if adopted, err := b.client.AdoptReform(world.ctx, world.repoId); adopted || !errors.Is(err, sidecar.ErrGkmReformRefused) {
			t.Errorf("a forged re-form (below the pin: %v): %v", lowGeneration, err)
		}
		if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmRefused {
			t.Errorf("a forged re-form's alarm: %+v", b.alarms)
		}
		if groupId, _, _, err := b.client.TestPins(world.repoId); err != nil || groupId != world.oldGroupId {
			t.Errorf("a forged re-form moved the member's pins: %v", err)
		}
		// its sync goes on in the group it holds, refusing the re-form each time
		if err := b.client.SyncRepo(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmReformRefused) {
			t.Errorf("a sync past a forged re-form: %v", err)
		}
	}
}

// §10.6's GroupForm signer rule: a re-form is refused, with nothing written, from a device that is not the owner's
// consented one in an owner-bound repo and from a read_only one; outside owner-bound kinds, from a writer that is
// neither one of the repo's admins nor a network admin's device, while those, and a device a state that says more
// of §8.6's admin right names, may sign one.
func TestAReformIsRefusedFromADeviceThatMayNotFormTheGroup(t *testing.T) {
	world := newGkmReformWorld(t)
	world.loseSite()
	for _, device := range []*gkmWorldDevice{world.x, world.p} {
		if _, err := world.flows[device].client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); !errors.Is(err, sidecar.ErrGkmNotWriter) {
			t.Errorf("a re-form by %s: %v", device.label, err)
		}
	}
	// the owner's device that has not consented
	world.repo.ConsentedSidecarIds = [][]byte{world.a.id.Bytes()}
	world.stateFor()
	if _, err := world.flows[world.b].client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a re-form by the owner's unconsented device: %v", err)
	}
	if world.store.callCount("Reform") != 0 || len(world.store.repoForms[world.repoId]) != 0 {
		t.Errorf("a refused re-form wrote")
	}

	// a general repo whose member is no network admin, and whose access log names a as its admin
	general := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	general.members[0].Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
	general.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: general.a.id.Bytes(), Signer: general.a.id.Bytes(), At: 1}}
	tip := general.stateFor()
	if _, err := general.flows[general.b].client.ReformGroup(general.ctx, &sidecar.GkmReformArgs{RepoId: general.repoId}); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a re-form by a writer that administers nothing: %v", err)
	}
	if general.store.callCount("Reform") != 0 {
		t.Errorf("a refused re-form wrote")
	}
	if err := sidecar.GkmFormSignerAllowed(tip, general.repoId, general.a.id); err != nil {
		t.Errorf("a repo admin's device: %v", err)
	}
	if err := sidecar.GkmFormSignerAllowed(tip, general.repoId, general.p.id); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a read_only device: %v", err)
	}
	admins := &gkmAdminView{GkmAuthView: tip, repoAdminIds: map[sidecar.Id][]sidecar.Id{general.repoId: {general.c.id}}}
	if err := sidecar.GkmFormSignerAllowed(admins, general.repoId, general.c.id); err != nil {
		t.Errorf("a device a state names under §8.6's admin right: %v", err)
	}
	if err := sidecar.GkmFormSignerAllowed(admins, general.repoId, general.b.id); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a writer that does not administer the repo: %v", err)
	}
	// a network admin's devices
	for _, role := range []bridge.MemberRole{bridge.MemberRole_MEMBER_ROLE_OWNER, bridge.MemberRole_MEMBER_ROLE_ADMIN} {
		general.members[0].Role = role
		if err := sidecar.GkmFormSignerAllowed(general.stateFor(), general.repoId, general.b.id); err != nil {
			t.Errorf("a device of a member whose role is %v: %v", role, err)
		}
	}
	general.members[0].Role = bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN
	if err := sidecar.GkmFormSignerAllowed(general.stateFor(), general.repoId, general.b.id); !errors.Is(err, sidecar.ErrGkmNotWriter) {
		t.Errorf("a device of a member whose role is network admin: %v", err)
	}
}

// A state that says who administers each repo.
type gkmAdminView struct {
	sidecar.GkmAuthView
	repoAdminIds map[sidecar.Id][]sidecar.Id
}

func (self *gkmAdminView) RepoAdmins(repoId sidecar.Id) []sidecar.Id {
	return self.repoAdminIds[repoId]
}

// A re-form naming a taken group id is refused at the owner marker and another id is drawn; a kill while the ladder
// goes up resumes from the keychain with the same form, so the repo gains one form and one group.
func TestAReformRedrawsATakenIdAndResumesAfterAKill(t *testing.T) {
	world := newGkmReformWorld(t)
	a := world.flows[world.a]
	world.loseSite()
	world.store.refuseOnce("Reform", http.StatusConflict)
	world.store.plantCount("UploadLadder", true, 3)
	if _, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); err == nil {
		t.Fatalf("the killed re-form answered")
	}
	if world.store.callCount("Reform") != 2 || len(world.store.repoForms[world.repoId]) != 1 {
		t.Fatalf("a taken id: %d posts, %d forms", world.store.callCount("Reform"), len(world.store.repoForms[world.repoId]))
	}
	formedGroupId := world.formedGroupId()
	if groupId, _, _, err := a.client.TestPins(world.repoId); err != nil || groupId != world.oldGroupId {
		t.Fatalf("the re-former's pins moved before its ladder stood: %v", err)
	}
	a.restart()
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil || newGroupId != formedGroupId {
		t.Fatalf("the resumed re-form: %v", err)
	}
	if len(world.store.repoForms[world.repoId]) != 1 || len(world.store.groupGenerations[newGroupId]) != 3 {
		t.Errorf("the resumed re-form left %d forms and %d generations", len(world.store.repoForms[world.repoId]), len(world.store.groupGenerations[newGroupId]))
	}
	if groupId, epoch, generation, err := a.client.TestPins(world.repoId); err != nil || groupId != newGroupId || epoch != 1 || generation != 3 {
		t.Errorf("the re-former's pins: epoch %d, generation %d, %v", epoch, generation, err)
	}
}

// FS-6's re-seed leg as a unit (owner decision 82): a repo re-seeded as deleted takes its GroupForm, with its epoch
// 0, and its ladder, and the re-former sends nothing else; once the repo is restored the same re-form finishes with
// its rotation and its Adds.
func TestARepoReseededAsDeletedTakesItsFormAndLadderAlone(t *testing.T) {
	world := newGkmReformWorld(t)
	a := world.flows[world.a]
	world.loseSite()
	routes := []string{"ClaimGeneration", "CommitEpoch", "UploadWraps", "UploadRecoveryWraps", "UploadWelcome"}
	before := map[string]int{}
	for _, route := range routes {
		before[route] = world.store.callCount(route)
	}
	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId, Reseed: true})
	if err != nil {
		t.Fatalf("the re-seed's re-form: %v", err)
	}
	for _, route := range routes {
		if world.store.callCount(route) != before[route] {
			t.Errorf("a re-seed called %s", route)
		}
	}
	if len(world.store.groupGenerations[newGroupId]) != 2 || len(world.store.groupEpochs[newGroupId]) != 1 {
		t.Fatalf("a re-seeded group holds %d generations and %d epochs", len(world.store.groupGenerations[newGroupId]), len(world.store.groupEpochs[newGroupId]))
	}
	// the files of the repo open from the cached keys meanwhile
	if key, err := a.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Errorf("the re-former reads on its cached key: %v", err)
	}
	// restored: the same re-form finishes
	again, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil || again != newGroupId {
		t.Fatalf("the re-form after the repo is restored: %v", err)
	}
	if len(world.store.groupGenerations[newGroupId]) != 3 || len(world.store.groupEpochs[newGroupId]) != 2 {
		t.Errorf("the restored group holds %d generations and %d epochs", len(world.store.groupGenerations[newGroupId]), len(world.store.groupEpochs[newGroupId]))
	}
}

// A group a refused commit stalled is re-formed while its old group still stands at gkm (DESIGN-DETAILS 6.5): in a
// general repo one of the repo's admins files the next form, naming the group it re-forms, its ladder the old one
// byte for byte; a member that takes its Welcome before any sync follows the form chain first and joins, another
// syncs and then joins, and generation numbers continue.
func TestAStalledGroupIsReformedByARepoAdmin(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.members[0].Role = bridge.MemberRole_MEMBER_ROLE_MEMBER
	world.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.a.id.Bytes(), Signer: world.a.id.Bytes(), At: 1}}
	world.stateFor()
	for _, device := range []*gkmWorldDevice{world.b, world.c, world.p, world.x} {
		world.store.publishKeyPackages(device, 1, false)
	}
	a, b, c := world.flows[world.a], world.flows[world.b], world.flows[world.c]
	oldGroupId := world.groupId
	oldStatements := slices.Clone(world.store.groupGenerations[oldGroupId])

	newGroupId, err := a.client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
	if err != nil {
		t.Fatalf("the re-form of a standing group: %v", err)
	}
	forms := world.store.repoForms[world.repoId]
	if len(forms) != 2 {
		t.Fatalf("the repo holds %d forms", len(forms))
	}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(forms[1].GetBody(), form); err != nil || sidecar.Id(form.GetGroupId()) != newGroupId ||
		!bytes.Equal(form.GetPreviousGroupId(), oldGroupId.Bytes()) || form.GetGeneration() != 1 {
		t.Fatalf("the second form does not re-form the first's group at generation 1: %v", err)
	}
	statements := world.store.groupGenerations[newGroupId]
	if len(statements) != 2 || !proto.Equal(statements[0], oldStatements[0]) {
		t.Fatalf("the new group holds %d generations, or its ladder is not the old one's", len(statements))
	}

	// b takes its Welcome before it syncs: the join follows the form chain first
	joined, err := b.client.JoinWelcomes(world.ctx)
	if err != nil || !slices.Contains(joined, world.repoId) {
		t.Fatalf("b joins the re-formed group before a sync: %v %v", joined, err)
	}
	// c syncs, then joins
	if err := c.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("c syncs after the re-form: %v", err)
	}
	if joined, err := c.client.JoinWelcomes(world.ctx); err != nil || !slices.Contains(joined, world.repoId) {
		t.Fatalf("c joins the re-formed group: %v %v", joined, err)
	}
	for _, flow := range []*gkmFlowDevice{b, c} {
		groupId, epoch, generation, err := flow.client.TestPins(world.repoId)
		if err != nil || groupId != newGroupId || epoch != 1 || generation != 2 {
			t.Errorf("%s in the re-formed group: epoch %d, generation %d, %v", flow.label, epoch, generation, err)
		}
		for number := uint64(1); number <= 2; number += 1 {
			if key, err := flow.client.RepoKey(world.ctx, world.repoId, number); err != nil || key.Generation() != number {
				t.Errorf("%s reads generation %d after the re-form: %v", flow.label, number, err)
			}
		}
		if len(flow.alarms) != 0 {
			t.Errorf("%s alarmed: %+v", flow.label, flow.alarms[0])
		}
	}
}

// A depositor reads no GroupForm, so its pin follows a re-formed group along the GenRotates it verifies: the new
// group's ladder holds its pinned statement as the old group did, and the first generation that names the new group
// chains from it, so the depositor seals to that generation's drop key with no fork alarm. A re-form below its pin,
// whose new group holds another statement at the pinned generation, is a fork.
func TestADepositorFollowsAReformedGroupAlongItsChain(t *testing.T) {
	for _, belowPin := range []bool{false, true} {
		world := newGkmReformWorld(t)
		depositor := world.flow(world.admit("depositor", sidecar.NewId()))
		tip := world.stateFor()
		if dropKey, err := depositor.client.DropKey(world.ctx, world.repoId); err != nil || dropKey.Generation != 2 || dropKey.GroupId != world.oldGroupId {
			t.Fatalf("the drop key before the re-form: %v", err)
		}
		world.loseSite()
		if belowPin {
			// a re-former that held generation 1 alone: its group's gen/2 names the new group, under another C_2
			forgedGroupId := sidecar.NewId()
			formBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GroupForm{
				RepoId: world.repoId.Bytes(), GroupId: forgedGroupId.Bytes(), PreviousGroupId: world.oldGroupId.Bytes(), Generation: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			form, err := world.a.signer.Sign("group-form", bridge.SignedType_SIGNED_GROUP_FORM, formBody, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, rotate2, err := world.gen1.key.NextGenerationIn(forgedGroupId, &sidecar.GkmGenerationArgs{
				Cause: sidecar.GkmCauseRequest, Auth: tip.Pin(), Time: world.now, HoldersSha256: world.holdersSha256(tip, world.now),
			})
			if err != nil {
				t.Fatal(err)
			}
			signed2, err := sidecar.SignGenRotate(rotate2, world.a.signer.Sign)
			if err != nil {
				t.Fatal(err)
			}
			world.store.repoForms[world.repoId] = []*bridge.Signed{form}
			world.store.groupGenerations[forgedGroupId] = []*bridge.Signed{world.gen1.signed, signed2}
			if _, err := depositor.client.DropKey(world.ctx, world.repoId); !errors.Is(err, sidecar.ErrGkmAuthOffChain) {
				t.Errorf("a re-form below the depositor's pin: %v", err)
			}
			if len(depositor.alarms) != 1 || depositor.alarms[0].Kind != sidecar.GkmAlarmHead || len(depositor.forks) != 1 {
				t.Errorf("the fork's alarm and report: %+v %+v", depositor.alarms, depositor.forks)
			}
			if groupId, _, generation, err := depositor.client.TestPins(world.repoId); err != nil || groupId != world.oldGroupId || generation != 2 {
				t.Errorf("a re-form below the pin moved it: generation %d, %v", generation, err)
			}
			continue
		}
		newGroupId, err := world.flows[world.a].client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId})
		if err != nil {
			t.Fatal(err)
		}
		dropKey, err := depositor.client.DropKey(world.ctx, world.repoId)
		if err != nil || dropKey.Generation != 3 || dropKey.GroupId != newGroupId {
			t.Fatalf("the drop key after the re-form: %+v %v", dropKey, err)
		}
		if groupId, _, generation, err := depositor.client.TestPins(world.repoId); err != nil || groupId != newGroupId || generation != 3 {
			t.Errorf("the depositor's pin after the re-form: generation %d, %v", generation, err)
		}
		if len(depositor.alarms) != 0 || len(depositor.forks) != 0 {
			t.Errorf("the depositor alarmed: %+v", depositor.alarms)
		}
	}
}

// After a re-form a GenHead of the group it replaced compares (g, C_g) along the adopted form, whose ladder carries
// every C_k (DESIGN-DETAILS 6.2.6): an equal commitment agrees, a group this device never met is compared by nothing,
// and another commitment at a generation it holds is a fork.
func TestAGenHeadComparesAcrossAReform(t *testing.T) {
	world := newGkmReformWorld(t)
	b := world.flows[world.b]
	world.loseSite()
	if _, err := world.flows[world.a].client.ReformGroup(world.ctx, &sidecar.GkmReformArgs{RepoId: world.repoId}); err != nil {
		t.Fatal(err)
	}
	if err := b.client.SyncRepo(world.ctx, world.repoId); err != nil {
		t.Fatalf("b adopts the re-form: %v", err)
	}
	commitment := world.storedCommitment(b, 2)
	head := func(groupId sidecar.Id, commitment []byte) *protocol.GenHead {
		return &protocol.GenHead{GroupId: groupId.Bytes(), Generation: 2, Commitment: commitment}
	}
	if standing, err := b.client.ObserveGenHead(world.repoId, head(world.oldGroupId, commitment), nil); err != nil || standing != sidecar.GkmPinAgrees {
		t.Errorf("a head of the replaced group: %v %v", standing, err)
	}
	if standing, err := b.client.ObserveGenHead(world.repoId, head(sidecar.NewId(), bytes.Repeat([]byte{7}, 32)), nil); err != nil || standing != sidecar.GkmPinUnheld {
		t.Errorf("a head of a group b never met: %v %v", standing, err)
	}
	if len(b.alarms) != 0 {
		t.Fatalf("b alarmed: %+v", b.alarms[0])
	}
	if standing, _ := b.client.ObserveGenHead(world.repoId, head(world.oldGroupId, bytes.Repeat([]byte{7}, 32)), nil); standing != sidecar.GkmPinForked {
		t.Errorf("another commitment under the replaced group: %v", standing)
	}
	if len(b.alarms) != 1 || b.alarms[0].Kind != sidecar.GkmAlarmHead || len(b.forks) != 1 {
		t.Errorf("the fork's alarm and report: %+v %+v", b.alarms, b.forks)
	}
}
