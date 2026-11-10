//go:build !sidecar_http

// §10.6's late deliveries on the fake gkm (KEYS-M2-20, DESIGN-DETAILS 6.6): a holder answers wrap-pending with one
// LATE delivery signed at its own state, at or past the claim's pin, after its random wait; a holder behind the
// claim, a read_only one and one with no key deliver nothing; a recipient that is no holder, or has no ReaderKey
// that passes, gets none; a 412's winner is judged; and a Delegation's signer writes its dwraps.

package sidecar_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A hint's recipient for a sidecar, as a wrap path writes it.
func gkmHintRecipient(device *gkmWorldDevice) string {
	return "s:" + hex.EncodeToString(device.id.Bytes())
}

// The deliveries gkm holds of one generation to one sidecar, each parsed under view's identity keys.
func (self *gkmFlowWorld) deliveriesTo(view sidecar.GkmAuthView, generation uint64, recipient *gkmWorldDevice) []*sidecar.GkmDelivery {
	self.t.Helper()
	deliveries := []*sidecar.GkmDelivery{}
	for _, path := range self.store.wrapPaths(self.groupId, generation) {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(self.store.pathWraps[path], signed); err != nil {
			self.t.Fatal(err)
		}
		if signed.GetType() != uint32(bridge.SignedType_SIGNED_READER_WRAP) {
			continue
		}
		delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeReader, sidecar.GkmIdentityKeys(view))
		if err != nil {
			self.t.Fatal(err)
		}
		if bytes.Equal(delivery.Body.GetRecipient(), recipient.id.Bytes()) {
			deliveries = append(deliveries, delivery)
		}
	}
	return deliveries
}

// R2 and R6 (TestALateDeliveryIsSignedAtOrPastTheClaimsPin's client half): a holder behind the claim does not
// deliver; one at the pin does, signed at its own state and at a time at or past the claim's, to the ReaderKey gkm
// serves; the recipient opens it and judges it valid; a read_only holder and a holder of nothing deliver nothing.
func TestALateDeliveryIsSignedAtOrPastTheClaimsPin(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a, b, c, p := world.flows[world.a], world.flows[world.b], world.flows[world.c], world.flows[world.p]
	// a late joiner: an agent that reads, with a ReaderKey and no wrap yet
	agent := world.admit("agent", sidecar.NewId())
	world.grant(false, agent)
	second := world.stateFor(world.b)
	late := world.flow(agent)
	if _, err := a.client.RotateRepo(world.ctx, world.repoId); err != nil {
		t.Fatal(err)
	}
	gen2 := world.storedGeneration(second, 2)
	// the rotation's own staged wrap goes away, as if its ReaderKey had lapsed when it was made
	for _, path := range world.store.wrapPaths(world.groupId, 2) {
		delete(world.store.pathWraps, path)
	}
	holdGen2 := func(flow *gkmFlowDevice) {
		kek, err := sidecar.MlsKek(flow.group, world.repoId)
		if err != nil {
			t.Fatal(err)
		}
		key, err := sidecar.OpenGkmLeafWrap(gen2, kek)
		if err != nil {
			t.Fatal(err)
		}
		if err := flow.client.TestHoldGeneration(world.repoId, world.groupId, gen2, key); err != nil {
			t.Fatal(err)
		}
	}
	holdGen2(b)
	holdGen2(c)
	holdGen2(p)
	recipient := gkmHintRecipient(agent)

	// b's log is below gen/2's pin
	if err := b.client.DeliverLate(world.ctx, world.repoId, recipient); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a holder behind the claim: %v", err)
	}
	// a read_only holder delivers nothing
	if err := p.client.DeliverLate(world.ctx, world.repoId, recipient); err != nil {
		t.Errorf("a read_only holder: %v", err)
	}
	if len(world.deliveriesTo(second, 2, agent)) != 0 {
		t.Fatalf("a delivery by a holder that may not deliver")
	}
	// a reader at the pin delivers
	if err := c.client.DeliverLate(world.ctx, world.repoId, recipient); err != nil {
		t.Fatal(err)
	}
	deliveries := world.deliveriesTo(second, 2, agent)
	if len(deliveries) != 1 {
		t.Fatalf("%d late deliveries", len(deliveries))
	}
	body := deliveries[0].Body
	if sidecar.GkmDeliveryKind(body.GetDeliveryKind()) != sidecar.GkmDeliveryLate || deliveries[0].SignerId != world.c.id ||
		body.GetAuth().GetVersion() != second.Pin().GetVersion() || body.GetTimeMs() < gen2.Rotate.GetTimeMs() ||
		!bytes.Equal(body.GetRecipientKeySha256(), late.readerKeySha256) {
		t.Errorf("the late delivery: kind %d, pin %d, time %d", body.GetDeliveryKind(), body.GetAuth().GetVersion(), body.GetTimeMs())
	}
	// the recipient opens it to a key it holds and judges it as any member does
	args := &sidecar.GkmDeliveryCheckArgs{RepoId: world.repoId, Delivery: deliveries[0], Generation: gen2, Now: world.clock.Now()}
	key, verdict, err := sidecar.GkmUseDelivery(second, args, agent.id.Bytes(), late.readerPrivateKeys[string(late.readerKeySha256)])
	if err != nil || !verdict.Passed() || key == nil || key.Generation() != 2 {
		t.Errorf("the recipient's use of the late delivery: %v %+v %v", key, verdict, err)
	}
	// a second holder finds it standing: judged, and nothing more written
	b.client.AuthAdvanced(second)
	if err := b.client.DeliverLate(world.ctx, world.repoId, recipient); err != nil || len(world.deliveriesTo(second, 2, agent)) != 1 || len(b.alarms) != 0 {
		t.Errorf("a second holder's delivery to the same key: %v, alarms %v", err, b.alarms)
	}
}

// R6's recipient half: nothing is delivered to a sidecar that is no holder at the deliverer's state, to one whose
// ReaderKey has lapsed or was not signed by its admitted key, or of a generation the deliverer holds as poisoned.
func TestALateDeliveryReachesOnlyAHolderAtAKeyItPublished(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a := world.flows[world.a]
	outsider := world.admit("outsider", sidecar.NewId())
	lapsed := world.admit("lapsed", sidecar.NewId())
	forged := world.admit("forged", sidecar.NewId())
	world.grant(false, lapsed, forged)
	second := world.stateFor()
	for _, device := range []*gkmWorldDevice{outsider, lapsed, forged} {
		world.flow(device)
	}
	// forged's ReaderKey at gkm was signed by another sidecar's key
	otherSigned, _ := world.readerKey(world.b)
	world.store.readerKeys[forged.id] = otherSigned
	// the revoked leaf asks too
	world.revoke(world.x)
	third := world.stateFor()
	uploads := world.store.callCount("UploadWraps")
	for _, device := range []*gkmWorldDevice{outsider, forged, world.x} {
		if err := a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(device)); err != nil {
			t.Errorf("a late delivery asked for %s: %v", device.label, err)
		}
	}
	// lapsed's key passes its not_after
	world.advance(sidecar.GkmReaderKeyLifetime)
	if err := a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(lapsed)); err != nil {
		t.Errorf("a late delivery asked for a lapsed key: %v", err)
	}
	if world.store.callCount("UploadWraps") != uploads || len(world.store.wrapPaths(world.groupId, 1)) != 0 {
		t.Errorf("a late delivery reached a non-holder or a key that does not pass")
	}
	// once it publishes a fresh key, it is served
	world.flows[lapsed].publishReaderKey()
	if err := a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(lapsed)); err != nil || len(world.deliveriesTo(third, 1, lapsed)) != 1 {
		t.Errorf("a late delivery to a fresh ReaderKey: %v", err)
	}
	if err := a.client.DeliverLate(world.ctx, world.repoId, "x:00"); !errors.Is(err, sidecar.ErrGkmMalformed) {
		t.Errorf("a hint naming no recipient: %v", err)
	}
	_ = second
}

// A 412 at a late delivery's path: the winner another signer wrote is judged as any delivery, and one a read_only
// device signed is alarmed refused, naming it.
func TestALateDeliverysWinnerIsJudged(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a := world.flows[world.a]
	agent := world.admit("agent", sidecar.NewId())
	world.grant(false, agent)
	second := world.stateFor()
	late := world.flow(agent)
	checked, err := sidecar.GkmAdmittedReaderKey(second, world.store.readerKeys[agent.id], agent.id, world.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	// p, read_only, wrote a late delivery to the same key first
	bad := world.deliveryTo(second, world.p, world.gen1, sidecar.GkmWrapTypeReader, agent.id.Bytes(), checked.Body.GetXwingPublicKey(), sidecar.GkmDeliveryLate, second.Pin(), world.now)
	path, err := sidecar.GkmDeliveryPath(world.groupId, bad)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(bad.Signed)
	world.store.pathWraps[path] = encoded
	if err := a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(agent)); err != nil {
		t.Fatal(err)
	}
	if len(a.alarms) != 1 || a.alarms[0].Kind != sidecar.GkmAlarmRefused || a.alarms[0].SidecarId != world.p.id || a.alarms[0].Reason != sidecar.GkmRefusalDelivery {
		t.Errorf("the alarm for a read_only signer's delivery: %+v", a.alarms)
	}
	_ = late
}

// The deliver row's wait: a holder answers wrap-pending only after its random wait of up to LateDeliverJitter, on
// the clock, so one holder normally delivers.
func TestALateDeliveryWaitsItsJitter(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a := world.flows[world.a]
	agent := world.admit("agent", sidecar.NewId())
	world.grant(false, agent)
	second := world.stateFor()
	world.flow(agent)
	world.jitter = 7 * time.Second
	_, timerAdded := world.clock.WatchTimers()
	done := make(chan error, 1)
	go func() {
		done <- a.client.DeliverLate(world.ctx, world.repoId, gkmHintRecipient(agent))
	}()
	<-timerAdded
	if len(world.deliveriesTo(second, 1, agent)) != 0 {
		t.Fatalf("a late delivery before its wait")
	}
	world.advance(7*time.Second - time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("a late delivery a millisecond early: %v", err)
	default:
	}
	world.advance(time.Millisecond)
	if err := <-done; err != nil || len(world.deliveriesTo(second, 1, agent)) != 1 {
		t.Errorf("the late delivery after its wait: %v", err)
	}
}

// A Delegation's dwraps (§10.5): the device that signed a Delegation writes a LATE DelegationWrap of the newest
// generation to its reader key in each repo it holds that the Delegation reaches, and none where it does not reach.
func TestADelegationsSignerWritesItsDwraps(t *testing.T) {
	world := newGkmFlowWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	world.holdAll()
	a := world.flows[world.a]
	tag := sidecar.NewId()
	delegationId := sha256.Sum256([]byte("a delegation"))
	delegationKey, err := sidecar.LoadGkmDelegationKey(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	world.delegations = []*bridge.DelegationRow{{
		DelegationId: delegationId[:], Signer: world.a.id.Bytes(), At: 2, TagAtoms: [][]byte{tag.Bytes()},
		NotAfter:             world.now.Add(30 * 24 * time.Hour).UnixMilli(),
		ReaderXwingPublicKey: delegationKey.PublicKey().Bytes(),
	}}
	// the Delegation's tags reach nothing yet
	second := world.stateFor()
	if err := a.client.DeliverDelegationWraps(world.ctx, delegationId[:]); err != nil || len(world.store.wrapPaths(world.groupId, 1)) != 0 {
		t.Errorf("dwraps for a Delegation that does not reach the repo: %v", err)
	}
	world.atomRepos[tag] = []sidecar.Id{world.repoId}
	third := world.stateFor()
	if err := a.client.DeliverDelegationWraps(world.ctx, delegationId[:]); err != nil {
		t.Fatal(err)
	}
	recipients := world.deliveryRecipients(1)
	if len(recipients) != 1 || recipients["d:delegation"] != sidecar.GkmDeliveryLate {
		t.Fatalf("the dwraps: %v", recipients)
	}
	// a member judges it valid, and the Delegation's key opens it
	path := world.store.wrapPaths(world.groupId, 1)[0]
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(world.store.pathWraps[path], signed); err != nil {
		t.Fatal(err)
	}
	delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeDelegation, sidecar.GkmIdentityKeys(third))
	if err != nil {
		t.Fatal(err)
	}
	args := &sidecar.GkmDeliveryCheckArgs{RepoId: world.repoId, Delivery: delivery, Generation: world.gen1.generation, Path: path, Now: world.clock.Now()}
	key, verdict, err := sidecar.GkmUseDelivery(third, args, delegationId[:], delegationKey)
	if err != nil || !verdict.Passed() || key == nil || key.Generation() != 1 {
		t.Errorf("the Delegation's use of its dwrap: %v %+v %v", key, verdict, err)
	}
	if err := a.client.DeliverDelegationWraps(world.ctx, []byte("short")); !errors.Is(err, sidecar.ErrGkmMalformed) {
		t.Errorf("a delegation id of the wrong size: %v", err)
	}
	_ = second
}
