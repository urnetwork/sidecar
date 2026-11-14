//go:build !sidecar_http

// The audit reader's deliveries on the fake gkm (KEYS-M6-02; §10.8's Escrow paragraph): no wrap before its block
// reaches every member's config, a member refusing a wrap its reader list does not show, and an opt-out's REMOVE
// rotation.

package sidecar_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Admits the audit reader's sidecar, a tagged agent with its flows and a ReaderKey at gkm, which reads nothing yet:
// its AuditOptIn has reached no base.
func (self *gkmFlowWorld) admitAuditor() *gkmFlowDevice {
	self.t.Helper()
	return self.flow(self.admit("q", sidecar.NewId()))
}

// The base that compiles the audit block: the reader list shows the auditor from the next state.
func (self *gkmFlowWorld) listAuditor(auditor *gkmFlowDevice) {
	self.grant(false, auditor.gkmWorldDevice)
	self.auditReaders = []sidecar.Id{auditor.id}
}

// An AuditOptOut: the auditor leaves the reader list at the next state, a shrink there.
func (self *gkmFlowWorld) optOutAuditor(auditor *gkmFlowDevice) {
	self.drop(auditor.gkmWorldDevice)
	self.auditReaders = nil
	self.repo.HoldersShrunkAt = self.nextPosition()
}

// The delivery gkm holds of generation to recipient, parsed under view's identity keys with its path; nil for none.
func (self *gkmFlowWorld) storedDelivery(view sidecar.GkmAuthView, generation uint64, recipient *gkmWorldDevice) (*sidecar.GkmDelivery, string) {
	self.t.Helper()
	for _, path := range self.store.wrapPaths(self.groupId, generation) {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(self.store.pathWraps[path], signed); err != nil {
			self.t.Fatal(err)
		}
		delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(view))
		if err != nil || string(delivery.Body.GetRecipient()) != string(recipient.id.Bytes()) {
			continue
		}
		return delivery, path
	}
	return nil, ""
}

// TestTheAuditReaderGetsNoWrapBeforeItsBlockReachesEveryMembersConfig: an admitted audit sidecar whose opt-in has
// reached no base is in no reader list, and a rotation there wraps nothing to it. From the base that compiles the
// block it is an ordinary agent among the key holders, the next rotation stages its ReaderWrap, it reads by it, and
// a member whose config does not hold that base yet waits before it judges the wrap.
func TestTheAuditReaderGetsNoWrapBeforeItsBlockReachesEveryMembersConfig(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	auditor := world.admitAuditor()
	second := world.stateFor()
	if holders, err := sidecar.KeyHolders(second, world.repoId, world.now); err != nil || holders.Contains(sidecar.GkmHolderAgent, auditor.id.Bytes()) {
		t.Fatalf("the audit reader holds a key before any reader list shows it: %v", err)
	}
	if key, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation before the block counts: %v", err)
	}
	if _, wrapped := world.deliveryRecipients(2)["s:q"]; wrapped {
		t.Fatalf("a rotation wrapped to the audit reader before its block reached a base")
	}
	if _, err := auditor.client.CurrentRepoKey(world.ctx, world.repoId); err == nil {
		t.Errorf("the audit reader reads before its block counts")
	}

	// the base compiles the block; c's config does not hold it yet
	world.listAuditor(auditor)
	third := world.stateFor(world.c)
	holders, err := sidecar.KeyHolders(third, world.repoId, world.now)
	if err != nil || !holders.Contains(sidecar.GkmHolderAgent, auditor.id.Bytes()) {
		t.Fatalf("the listed audit reader is no agent among the key holders: %v", err)
	}
	if audit := sidecar.GkmAuditHolders(third, world.repoId, holders, world.now); len(audit) != 1 || string(audit[0].Id) != string(auditor.id.Bytes()) {
		t.Errorf("the holders that read as the audit reader: %+v", audit)
	}
	if !sidecar.GkmAuditListed(third, world.repoId, auditor.id, world.now) || sidecar.GkmAuditListed(second, world.repoId, auditor.id, world.now) {
		t.Errorf("the reader list shows the audit reader at the wrong states")
	}
	if key, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 3 {
		t.Fatalf("the rotation once the block counts: %v", err)
	}
	if kind, wrapped := world.deliveryRecipients(3)["s:q"]; !wrapped || kind != sidecar.GkmDeliveryStaged {
		t.Fatalf("generation 3 holds no staged ReaderWrap to the audit reader")
	}
	if key, err := auditor.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 3 {
		t.Errorf("the audit reader's read by its ReaderWrap: %v", err)
	}
	delivery, path := world.storedDelivery(third, 3, auditor.gkmWorldDevice)
	if delivery == nil {
		t.Fatal("gkm holds no delivery to the audit reader")
	}
	args := &sidecar.GkmDeliveryCheckArgs{RepoId: world.repoId, Delivery: delivery, Generation: world.storedGeneration(third, 3), Path: path, Now: world.now}
	if verdict, err := sidecar.CheckDelivery(third, args); err != nil || !verdict.Passed() {
		t.Errorf("a member whose config holds the block: %+v, %v", verdict, err)
	}
	if _, err := sidecar.CheckDelivery(second, args); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a member whose config does not hold the block yet: %v", err)
	}
	if len(a.alarms) != 0 {
		t.Errorf("a listed audit reader's wrap alarmed: %+v", a.alarms)
	}
}

// TestAMemberRefusesAWrapToAnAuditReaderItsListDoesNotShow: a wrap to the audit reader signed at a state whose
// reader list does not show it is refused by every member, named as the audit refusal by one whose own state knows
// the reader, STAGED and LATE alike; a signer's own check refuses to seal one; and a late deliverer that finds one
// at the reader's path holds the generation as poisoned and alarms naming the signer with that reason.
func TestAMemberRefusesAWrapToAnAuditReaderItsListDoesNotShow(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	auditor := world.admitAuditor()
	second := world.stateFor()
	world.listAuditor(auditor)
	third := world.stateFor()

	// b, a holder, hands generation 1 to the audit reader at the state before any list showed it
	checked, err := sidecar.GkmAdmittedReaderKey(third, world.store.readerKeys[auditor.id], auditor.id, world.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	publicKey := checked.Body.GetXwingPublicKey()
	silent := world.deliveryTo(third, world.b, world.gen1, sidecar.GkmWrapTypeReader, auditor.id.Bytes(), publicKey, sidecar.GkmDeliveryLate, second.Pin(), world.now)
	world.expectDelivery("a late wrap to the audit reader below its list, at a member that knows the reader", third, silent, world.gen1, sidecar.GkmRefusalAudit)
	world.expectDelivery("the same wrap at a member whose own state names no audit reader", second, silent, world.gen1, sidecar.GkmRefusalDelivery)
	shown := world.deliveryTo(third, world.b, world.gen1, sidecar.GkmWrapTypeReader, auditor.id.Bytes(), publicKey, sidecar.GkmDeliveryLate, third.Pin(), world.now)
	world.expectDelivery("a late wrap to the audit reader at a state whose list shows it", third, shown, world.gen1, sidecar.GkmRefusalNone)
	// a generation claimed below the list, with a staged wrap to the audit reader
	below := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	staged := world.deliveryTo(third, world.a, below, sidecar.GkmWrapTypeReader, auditor.id.Bytes(), publicKey, sidecar.GkmDeliveryStaged, nil, time.Time{})
	world.expectDelivery("a staged wrap to the audit reader in a generation claimed below its list", third, staged, below, sidecar.GkmRefusalAudit)

	// the signer's own check
	if err := sidecar.GkmAuditWrapAllowed(third, second, world.repoId, auditor.id, world.now, world.now); !errors.Is(err, sidecar.ErrGkmAuditUnlisted) {
		t.Errorf("a signer's check of a wrap to the audit reader below its list: %v", err)
	}
	if err := sidecar.GkmAuditWrapAllowed(third, third, world.repoId, auditor.id, world.now, world.now); err != nil {
		t.Errorf("a signer's check of a wrap to the listed audit reader: %v", err)
	}
	if err := sidecar.GkmAuditWrapAllowed(third, second, world.repoId, world.c.id, world.now, world.now); err != nil {
		t.Errorf("a signer's check of a wrap to another reader: %v", err)
	}

	// never silent: a's late delivery finds the unlisted wrap at the reader's path
	path, err := sidecar.GkmDeliveryPath(world.groupId, silent)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(silent.Signed)
	world.store.pathWraps[path] = encoded
	if err := a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(auditor.gkmWorldDevice)); err != nil {
		t.Fatal(err)
	}
	named := slices.ContainsFunc(a.alarms, func(alarm *sidecar.GkmAlarm) bool {
		return alarm.Kind == sidecar.GkmAlarmRefused && alarm.SidecarId == world.b.id && alarm.Reason == sidecar.GkmRefusalAudit
	})
	if !named {
		t.Errorf("no alarm names the signer of an unlisted wrap to the audit reader: %+v", a.alarms)
	}
	// the generation is poisoned: a seals nothing to it and rotates past it with cause REMOVE
	key, err := a.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil {
		t.Fatalf("the rotation past the poisoned generation: %v", err)
	}
	if key.Generation() != 2 || key.Cause() != sidecar.GkmCauseRemove {
		t.Errorf("past the poisoned generation: generation %d, cause %d", key.Generation(), key.Cause())
	}
}

// TestAnAuditOptOutRotatesWithCauseRemove: an AuditOptOut drops the reader from the key holders, a shrink, so the
// next write rotates with cause REMOVE and wraps nothing to it; what it held opens nothing of the new generation,
// and a wrap to it at the state past the opt-out is refused.
func TestAnAuditOptOutRotatesWithCauseRemove(t *testing.T) {
	world := newGkmEngineWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	a := world.flows[world.a]
	auditor := world.admitAuditor()
	world.listAuditor(auditor)
	world.stateFor()
	if key, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the rotation that wraps to the audit reader: %v", err)
	}
	if _, wrapped := world.deliveryRecipients(2)["s:q"]; !wrapped {
		t.Fatalf("generation 2 holds no ReaderWrap to the audit reader")
	}
	if key, err := auditor.client.CurrentRepoKey(world.ctx, world.repoId); err != nil || key.Generation() != 2 {
		t.Fatalf("the audit reader's read: %v", err)
	}

	world.optOutAuditor(auditor)
	third := world.stateFor()
	if holders, err := sidecar.KeyHolders(third, world.repoId, world.now); err != nil || holders.Contains(sidecar.GkmHolderAgent, auditor.id.Bytes()) {
		t.Fatalf("the audit reader holds a key past its opt-out: %v", err)
	}
	key, err := a.client.EnsureWritable(world.ctx, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if key.Generation() != 3 || key.Cause() != sidecar.GkmCauseRemove {
		t.Fatalf("the generation past the opt-out: generation %d, cause %d", key.Generation(), key.Cause())
	}
	if _, wrapped := world.deliveryRecipients(3)["s:q"]; wrapped {
		t.Errorf("the generation past the opt-out wraps to the audit reader")
	}
	if key, err := auditor.client.RepoKey(world.ctx, world.repoId, 3); err == nil {
		t.Errorf("the audit reader reaches generation %d past its opt-out", key.Generation())
	}
	// a wrap to it at the state past the opt-out is refused, as to any sidecar that is no reader
	generation3 := &gkmWorldGeneration{key: key, generation: world.storedGeneration(third, 3)}
	publicKey := world.store.readerKeys[auditor.id]
	checked, err := sidecar.GkmAdmittedReaderKey(third, publicKey, auditor.id, world.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	late := world.deliveryTo(third, world.b, generation3, sidecar.GkmWrapTypeReader, auditor.id.Bytes(), checked.Body.GetXwingPublicKey(), sidecar.GkmDeliveryLate, third.Pin(), world.now)
	verdict, err := world.checkDelivery(third, late, generation3)
	if err != nil || !verdict.Refused {
		t.Errorf("a wrap to the audit reader past its opt-out: %+v, %v", verdict, err)
	}
}
