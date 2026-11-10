//go:build !sidecar_http

// §10.9's delivery checks on fixtures (KEYS-M2-19, DESIGN-DETAILS 6.6): one success and one refusal per row, a
// delivery valid at its own state staying valid after a later revocation (FI-28), a LATE delivery signed below its
// claim's pin refused, and S3's forged ReaderKey.

package sidecar_test

import (
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A device's ReaderKey, signed now, with its private key.
func (self *gkmWorld) readerKey(device *gkmWorldDevice) (*bridge.Signed, hpke.PrivateKey) {
	self.t.Helper()
	signed, privateKey, err := sidecar.NewGkmReaderKey(device.id, self.now, self.now.Add(sidecar.GkmReaderKeyLifetime), device.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	return signed, privateKey
}

// A ReaderWrap of generation to recipient's fresh ReaderKey, signed by signer and parsed under view's identity keys:
// STAGED, or LATE at pin and at.
func (self *gkmWorld) delivery(view sidecar.GkmAuthView, signer *gkmWorldDevice, generation *gkmWorldGeneration, recipient *gkmWorldDevice, kind sidecar.GkmDeliveryKind, pin *bridge.AuthPin, at time.Time) *sidecar.GkmDelivery {
	self.t.Helper()
	_, privateKey := self.readerKey(recipient)
	return self.deliveryTo(view, signer, generation, sidecar.GkmWrapTypeReader, recipient.id.Bytes(), privateKey.PublicKey().Bytes(), kind, pin, at)
}

// A delivery of generation to one recipient key.
func (self *gkmWorld) deliveryTo(view sidecar.GkmAuthView, signer *gkmWorldDevice, generation *gkmWorldGeneration, wrapType sidecar.GkmWrapType, recipient []byte, publicKey []byte, kind sidecar.GkmDeliveryKind, pin *bridge.AuthPin, at time.Time) *sidecar.GkmDelivery {
	self.t.Helper()
	body, err := sidecar.SealGkmDelivery(generation.key, &sidecar.GkmDeliveryArgs{
		GroupId: self.groupId, Type: wrapType, Recipient: recipient, RecipientPublicKey: publicKey, Kind: kind, Auth: pin, Time: at,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := sidecar.SignGkmDelivery(body, wrapType, signer.signer.Sign)
	if err != nil {
		self.t.Fatal(err)
	}
	delivery, err := sidecar.ParseGkmDelivery(signed, wrapType, sidecar.GkmIdentityKeys(view))
	if err != nil {
		self.t.Fatal(err)
	}
	return delivery
}

// CheckDelivery of one delivery of generation at view.
func (self *gkmWorld) checkDelivery(view sidecar.GkmAuthView, delivery *sidecar.GkmDelivery, generation *gkmWorldGeneration) (sidecar.GkmVerdict, error) {
	return sidecar.CheckDelivery(view, &sidecar.GkmDeliveryCheckArgs{
		RepoId: self.repoId, Delivery: delivery, Generation: generation.generation, Now: self.now,
	})
}

// Fails unless the delivery passes, or is refused for reason when one is given.
func (self *gkmWorld) expectDelivery(label string, view sidecar.GkmAuthView, delivery *sidecar.GkmDelivery, generation *gkmWorldGeneration, reason sidecar.GkmRefusalReason) {
	self.t.Helper()
	verdict, err := self.checkDelivery(view, delivery, generation)
	switch {
	case err != nil:
		self.t.Errorf("%s: %v", label, err)
	case reason == sidecar.GkmRefusalNone && !verdict.Passed():
		self.t.Errorf("%s: %+v", label, verdict)
	case reason != sidecar.GkmRefusalNone && (!verdict.Refused || verdict.Reason != reason):
		self.t.Errorf("%s: %+v, want refused for %s", label, verdict, reason)
	}
}

// The body and staged rows: a STAGED delivery by gen/<g>'s signer to a holder of the claim's set passes, to a leaf,
// an uncovered agent and a live Delegation alike; one by another signer, to a non-holder, to an agent its Delegation
// covers, of another generation or off its path is refused.
func TestCheckDeliveryBodyAndStagedRows(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	tag := sidecar.NewId()
	delegationId := sha256.Sum256([]byte("a delegation"))
	delegationKey, err := sidecar.LoadGkmDelegationKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	world.delegations = []*bridge.DelegationRow{{
		DelegationId: delegationId[:], Signer: world.a.id.Bytes(), At: 1, TagAtoms: [][]byte{tag.Bytes()},
		NotAfter:             world.now.Add(30 * 24 * time.Hour).UnixMilli(),
		ReaderXwingPublicKey: delegationKey.PublicKey().Bytes(),
	}}
	world.atomRepos[tag] = []sidecar.Id{world.repoId}
	covered := world.admit("covered agent", tag)
	covered.row.DelegationId = delegationId[:]
	agent := world.admit("agent", sidecar.NewId())
	nonReader := world.admit("non-reader")
	world.grant(false, covered, agent)
	second := world.state()
	gen2 := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	staged := func(signer *gkmWorldDevice, recipient *gkmWorldDevice) *sidecar.GkmDelivery {
		return world.delivery(second, signer, gen2, recipient, sidecar.GkmDeliveryStaged, nil, time.Time{})
	}

	toLeaf := staged(world.a, world.c)
	world.expectDelivery("to a leaf", second, toLeaf, gen2, sidecar.GkmRefusalNone)
	world.expectDelivery("to an uncovered agent", second, staged(world.a, agent), gen2, sidecar.GkmRefusalNone)
	toDelegation := world.deliveryTo(second, world.a, gen2, sidecar.GkmWrapTypeDelegation, delegationId[:], delegationKey.PublicKey().Bytes(), sidecar.GkmDeliveryStaged, nil, time.Time{})
	world.expectDelivery("to a live Delegation", second, toDelegation, gen2, sidecar.GkmRefusalNone)

	world.expectDelivery("by another than gen/<g>'s signer", second, staged(world.b, world.c), gen2, sidecar.GkmRefusalDelivery)
	world.expectDelivery("to a non-holder", second, staged(world.a, nonReader), gen2, sidecar.GkmRefusalDelivery)
	world.expectDelivery("to an agent its Delegation covers", second, staged(world.a, covered), gen2, sidecar.GkmRefusalDelivery)
	world.expectDelivery("of another generation", second, toLeaf, world.gen1, sidecar.GkmRefusalDelivery)

	path, err := sidecar.GkmDeliveryPath(world.groupId, toLeaf)
	if err != nil {
		t.Fatal(err)
	}
	otherPath, err := sidecar.GkmDeliveryPath(world.groupId, staged(world.a, world.p))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		path    string
		refused bool
	}{{path: path}, {path: otherPath, refused: true}} {
		verdict, err := sidecar.CheckDelivery(second, &sidecar.GkmDeliveryCheckArgs{
			RepoId: world.repoId, Delivery: toLeaf, Generation: gen2.generation, Path: c.path, Now: world.now,
		})
		if err != nil || verdict.Refused != c.refused {
			t.Errorf("a delivery at path %s: %+v %v", c.path, verdict, err)
		}
	}

	// the Delegation ends: its wrap is refused at that state, and its agent now holds a wrap of its own
	world.delegations[0].EndedAt = world.nextPosition()
	third := world.state()
	gen3 := world.generation(third, world.a, gen2, sidecar.GkmCauseRemove, nil)
	ended := world.deliveryTo(third, world.a, gen3, sidecar.GkmWrapTypeDelegation, delegationId[:], delegationKey.PublicKey().Bytes(), sidecar.GkmDeliveryStaged, nil, time.Time{})
	world.expectDelivery("to an ended Delegation", third, ended, gen3, sidecar.GkmRefusalDelivery)
	world.expectDelivery("to its agent, uncovered now", third, world.delivery(third, world.a, gen3, covered, sidecar.GkmDeliveryStaged, nil, time.Time{}), gen3, sidecar.GkmRefusalNone)
}

// The late, judged and history rows (TestALateDeliveryIsSignedAtOrPastTheClaimsPin's member half; FI-28): a LATE
// delivery at or past its claim's pin by a holder to a holder passes and stays valid after its recipient's and its
// signer's later revocation; one below the claim's pin, before its time, to a non-holder at its own state, or by a
// read_only or revoked signer is refused; a pin above the tip and a time past this clock wait.
func TestCheckDeliveryLateJudgedAndHistoryRows(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	second := world.state()
	gen2 := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	late := func(view sidecar.GkmAuthView, signer *gkmWorldDevice, recipient *gkmWorldDevice, pin *bridge.AuthPin, at time.Time) *sidecar.GkmDelivery {
		return world.delivery(view, signer, gen2, recipient, sidecar.GkmDeliveryLate, pin, at)
	}
	atPin := late(second, world.b, world.x, second.Pin(), world.now)
	world.expectDelivery("a holder's LATE delivery at the claim's pin", second, atPin, gen2, sidecar.GkmRefusalNone)
	world.expectDelivery("a reader's LATE delivery", second, late(second, world.c, world.x, second.Pin(), world.now), gen2, sidecar.GkmRefusalNone)
	world.expectDelivery("a LATE delivery below the claim's pin", second, late(second, world.b, world.x, world.first.Pin(), world.now), gen2, sidecar.GkmRefusalPinFloor)
	world.expectDelivery("a LATE delivery before the claim's time", second, late(second, world.b, world.x, second.Pin(), world.now.Add(-time.Millisecond)), gen2, sidecar.GkmRefusalTime)
	world.expectDelivery("a read_only signer's LATE delivery", second, late(second, world.p, world.x, second.Pin(), world.now), gen2, sidecar.GkmRefusalDelivery)

	// x and b are revoked later: what was valid at its own state stays valid, and nothing new reaches x
	world.revoke(world.x)
	world.revoke(world.b)
	third := world.state()
	world.expectDelivery("the earlier delivery after its recipient's and signer's revocation", third, atPin, gen2, sidecar.GkmRefusalNone)
	world.expectDelivery("a LATE delivery to a dropped holder at its own state", third, late(third, world.a, world.x, third.Pin(), world.now), gen2, sidecar.GkmRefusalDelivery)
	world.expectDelivery("a revoked signer's LATE delivery", third, late(third, world.b, world.c, third.Pin(), world.now), gen2, sidecar.GkmRefusalDelivery)
	// an expiry with no entry: c stops reading in an hour
	world.readerExpiries[world.c.id] = world.now.Add(time.Hour)
	fourth := world.state()
	world.expectDelivery("a LATE delivery before its recipient's expiry", fourth, late(fourth, world.a, world.c, fourth.Pin(), world.now), gen2, sidecar.GkmRefusalNone)
	world.now = world.now.Add(time.Hour)
	world.expectDelivery("a LATE delivery at its recipient's expiry", fourth, late(fourth, world.a, world.c, fourth.Pin(), world.now), gen2, sidecar.GkmRefusalDelivery)

	if _, err := world.checkDelivery(second, late(fourth, world.a, world.p, fourth.Pin(), world.now), gen2); !errors.Is(err, sidecar.ErrGkmAuthAhead) {
		t.Errorf("a LATE delivery above the tip: %v", err)
	}
	ahead := late(fourth, world.a, world.p, fourth.Pin(), world.now.Add(sidecar.GkmMemberClockSkew+time.Millisecond))
	if verdict, err := world.checkDelivery(fourth, ahead, gen2); !errors.Is(err, sidecar.ErrGkmTimeAhead) || verdict.Refused {
		t.Errorf("a LATE delivery past this clock: %+v %v", verdict, err)
	}
	forked := late(fourth, world.a, world.p, sidecartest.FakeGkmForkPin(3), world.now)
	if verdict, err := world.checkDelivery(fourth, forked, gen2); err != nil || !verdict.Fork || !verdict.Refused {
		t.Errorf("a LATE delivery off the chain: %+v %v", verdict, err)
	}
	world.log.Retain(3)
	if verdict, err := world.checkDelivery(fourth, atPin, gen2); err != nil || !verdict.NotJudged || verdict.Refused || !verdict.Passed() {
		t.Errorf("a delivery before what is retained: %+v %v", verdict, err)
	}
}

// The use row and S3's forged ReaderKey: the recipient opens its own delivery to a key it holds and gets RK_g only
// when the delivery passes; a ReaderKey signed by another key for an admitted sidecar, or lapsed, seals nothing.
func TestGkmUseDeliveryAndForgedReaderKey(t *testing.T) {
	world := newGkmCommitWorld(t, protocol.RepoKind_REPO_KIND_GENERAL)
	second := world.state()
	gen2 := world.generation(second, world.a, world.gen1, sidecar.GkmCauseRequest, nil)
	readerKey, privateKey := world.readerKey(world.c)
	checked, err := sidecar.GkmAdmittedReaderKey(second, readerKey, world.c.id, world.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	delivery := world.deliveryTo(second, world.a, gen2, sidecar.GkmWrapTypeReader, world.c.id.Bytes(), checked.Body.GetXwingPublicKey(), sidecar.GkmDeliveryStaged, nil, time.Time{})
	args := &sidecar.GkmDeliveryCheckArgs{RepoId: world.repoId, Delivery: delivery, Generation: gen2.generation, Now: world.now}
	key, verdict, err := sidecar.GkmUseDelivery(second, args, world.c.id.Bytes(), privateKey)
	if err != nil || !verdict.Passed() || key == nil || key.Generation() != 2 {
		t.Fatalf("the recipient's own delivery: %v %+v %v", key, verdict, err)
	}
	_, otherPrivateKey := world.readerKey(world.c)
	if key, _, err := sidecar.GkmUseDelivery(second, args, world.c.id.Bytes(), otherPrivateKey); !errors.Is(err, sidecar.ErrGkmKeyMissing) || key != nil {
		t.Errorf("a delivery to a key it does not hold: %v %v", key, err)
	}
	if key, _, err := sidecar.GkmUseDelivery(second, args, world.x.id.Bytes(), privateKey); !errors.Is(err, sidecar.ErrGkmKeyMissing) || key != nil {
		t.Errorf("another's delivery: %v %v", key, err)
	}
	// a refused delivery gives no key
	byOther := world.deliveryTo(second, world.b, gen2, sidecar.GkmWrapTypeReader, world.c.id.Bytes(), checked.Body.GetXwingPublicKey(), sidecar.GkmDeliveryStaged, nil, time.Time{})
	refusedArgs := &sidecar.GkmDeliveryCheckArgs{RepoId: world.repoId, Delivery: byOther, Generation: gen2.generation, Now: world.now}
	if key, verdict, err := sidecar.GkmUseDelivery(second, refusedArgs, world.c.id.Bytes(), privateKey); err != nil || !verdict.Refused || key != nil {
		t.Errorf("a refused delivery: %v %+v %v", key, verdict, err)
	}

	// S3: a ReaderKey for c that c's identity key did not sign
	thief := sidecartest.NewFakeGkmSigner()
	forged, _, err := sidecar.NewGkmReaderKey(world.c.id, world.now, world.now.Add(sidecar.GkmReaderKeyLifetime), func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		signed, err := thief.Sign(purpose, signedType, body, agentId)
		if signed != nil {
			signed.SignerId = world.c.id.Bytes()
		}
		return signed, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.GkmAdmittedReaderKey(second, forged, world.c.id, world.now.UnixMilli()); !errors.Is(err, sidecar.ErrGkmAuthentication) {
		t.Errorf("a forged ReaderKey: %v", err)
	}
	if _, err := sidecar.GkmAdmittedReaderKey(second, readerKey, world.c.id, world.now.Add(sidecar.GkmReaderKeyLifetime).UnixMilli()); !errors.Is(err, sidecar.ErrGkmKeyMissing) {
		t.Errorf("a lapsed ReaderKey: %v", err)
	}
	if _, err := sidecar.GkmAdmittedReaderKey(second, readerKey, sidecar.NewId(), world.now.UnixMilli()); !errors.Is(err, sidecar.ErrGkmAuthentication) {
		t.Errorf("a ReaderKey for a sidecar the log never admitted: %v", err)
	}
}
