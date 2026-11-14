//go:build sidecar_testhooks

// EVSB-M2-20's schedules at the reseed route's barriers (reseed.go; QD-096, QD-725): an ERASE that commits while a
// re-seeded slot's create is held, before it and after it, never leaves the key it covers in the slot; and a head
// that moves while a Signed EvsReseed's write is held leaves a statement no reader takes for the new head.

package evsservice

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A recovery with a slot of two keys named by a re-seeded version, and an ERASE of its key 0 as the admin's mirror
// kept it, not sent yet.
func newReseedSlotRace(t *testing.T) (*reseedFixture, *protocol.EvsReseedRequest, sidecar.Id, []byte, *protocol.EvsReseedRequest) {
	t.Helper()
	fixture := newReseedFixture(t)
	check := fixture.check
	second := fixture.appendState(check.signingKey, []sidecar.Id{check.signerId, check.otherId}, check.otherId)
	slotId, slotObject, slot := eraseTestSlot(t, "raced", 2)
	named := fixture.keptWithSlot(slotId, slotObject, slot, "a")
	fixture.requireCommitted(fixture.reseed(named), 1)
	erase := fixture.erasePlan(&sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	erase.TimeMs = fixture.clock.Now().Add(-30 * 24 * time.Hour).UnixMilli()
	erase.Auth = second.Pin()
	erase.SignerSidecarId = check.otherId
	return fixture, named, slotId, slot, fixture.signedBody(erase, check.otherKey, check.otherId)
}

// The ERASE commits after the slot call read the ERASEs evs holds and before its create: the ERASE's own rewrite
// finds no slot, the create stores the slot as the mirror held it, and the call's second read of the ERASEs drops
// the erased key before its 200.
func TestReseedSlotDropsAKeyAnEraseTookBeforeItsCreate(t *testing.T) {
	fixture, named, slotId, slot, erase := newReseedSlotRace(t)
	var erased *int
	reached := atBarrierOnce(t, BarrierReseedSlotPutBefore, barrierSlotKey(fixture.check.repoId, slotId), func() {
		recorder := fixture.reseed(erase)
		erased = &recorder.Code
	})
	recorder := fixture.reseedSlot(named, slotId, slot)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || erased == nil || *erased != http.StatusOK {
		t.Fatalf("the slot call reached its create %d times; the ERASE: %v", *reached, erased)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d (%s) for the slot", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v, want key 1 alone", indexes)
	}
	// the origin rode on through the rewrite
	info, err := fixture.cluster.Head(fixture.ctx, SlotKey(fixture.check.repoId, slotId))
	if err != nil {
		t.Fatal(err)
	}
	if origin := ParseEvsSlotOrigin(info.Metadata, fixture.settings.SlotOriginMaxByteCount); origin.Kind != EvsSlotOriginReseed {
		t.Fatalf("the slot's origin is %q", origin.Encode())
	}
	// a stale mirror's copy sent again finds the slot, equal after stripping, and leaves it
	if again := fixture.reseedSlot(named, slotId, slot); again.Code != http.StatusOK {
		t.Fatalf("status %d for the slot sent again", again.Code)
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v after it was sent again", indexes)
	}
}

// The twin: the ERASE commits right after the create, and its own rewrite drops the key.
func TestReseedSlotIsRewrittenByAnEraseAfterItsCreate(t *testing.T) {
	fixture, named, slotId, slot, erase := newReseedSlotRace(t)
	var erased *int
	reached := atBarrierOnce(t, BarrierReseedSlotPutAfter, barrierSlotKey(fixture.check.repoId, slotId), func() {
		if indexes := fixture.slotIndexes(slotId); len(indexes) != 2 {
			t.Errorf("slot keys %v right after its create", indexes)
		}
		recorder := fixture.reseed(erase)
		erased = &recorder.Code
	})
	recorder := fixture.reseedSlot(named, slotId, slot)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || erased == nil || *erased != http.StatusOK {
		t.Fatalf("the slot call passed its create %d times; the ERASE: %v", *reached, erased)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d (%s) for the slot", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v, want key 1 alone", indexes)
	}
}

// A slot whose create's answer is lost while an ERASE lands: the call reads the object back, finds its own bytes,
// and still drops the key the ERASE covers.
func TestReseedSlotFoundStandingStillDropsAnErasedKey(t *testing.T) {
	fixture, named, slotId, slot, erase := newReseedSlotRace(t)
	// the slot stands as a stale mirror's copy, stored before the ERASE below, with no rewrite of it: what a create
	// whose ERASE raced it and whose call then died leaves
	metadata, err := EvsSlotOriginReseeded().Metadata(fixture.settings.SlotOriginMaxByteCount)
	if err != nil {
		t.Fatal(err)
	}
	reached := atBarrierOnce(t, BarrierReseedSlotPutBefore, barrierSlotKey(fixture.check.repoId, slotId), func() {
		fixture.requireCommitted(fixture.reseed(erase), 1)
		if _, err := fixture.cluster.PutIfNoneMatch(fixture.ctx, SlotKey(fixture.check.repoId, slotId), slot, &sidecar.BlobPutOptions{Metadata: metadata}); err != nil {
			t.Error(err)
		}
	})
	recorder := fixture.reseedSlot(named, slotId, slot)
	sidecar.SetTestHooks(nil)
	if *reached != 1 || recorder.Code != http.StatusOK {
		t.Fatalf("status %d after %d creates", recorder.Code, *reached)
	}
	if indexes := fixture.slotIndexes(slotId); len(indexes) != 1 || indexes[0] != 1 {
		t.Fatalf("slot keys %v, want key 1 alone", indexes)
	}
}

// A Signed EvsReseed whose head moves while its write is held is stored as sent, naming the older head: a read
// serves it only below a pin, where a reader refuses it for the head it does not name, and the admin's next
// statement, of the new head, replaces it.
func TestReseedStatementHeldWhileTheHeadMovesIsReplacedByTheNext(t *testing.T) {
	fixture := newReseedFixture(t)
	check := fixture.check
	fixture.appendState(check.signingKey, []sidecar.Id{check.signerId, check.otherId}, check.otherId)
	first := fixture.kept()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.reseed(fixture.reseedBody(first)), 1)
	statementOf := func() []byte {
		head := fixture.head()
		chain := [32]byte(head.Head.GetChain())
		signed, err := sidecar.SignEvsReseed(checkTestSign(check.otherKey, check.otherId), check.repoId, check.refId, head.Version(), chain, []byte("incident"))
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	older := statementOf()
	next := fixture.kept()
	fixture.create(next, "b")
	nextBody := fixture.reseedBody(next)
	reached := atBarrierOnce(t, BarrierReseedStatementPutBefore, barrierRefKey(check.repoId, check.refId), func() {
		fixture.requireCommitted(fixture.reseed(nextBody), 2)
	})
	recorder := fixture.reseed(&protocol.EvsReseedRequest{Statement: older})
	sidecar.SetTestHooks(nil)
	if *reached != 1 || recorder.Code != http.StatusOK {
		t.Fatalf("status %d after %d writes", recorder.Code, *reached)
	}
	stored := fixture.engine.readReseedStatement(fixture.ctx, fixture.cluster, check.repoId, check.refId)
	if !bytes.Equal(stored, older) {
		t.Fatal("reseed/ does not hold the statement as sent")
	}
	// the statement of the head evs serves now takes its place
	newer := statementOf()
	if recorder := fixture.reseed(&protocol.EvsReseedRequest{Statement: newer}); recorder.Code != http.StatusOK {
		t.Fatalf("status %d (%s) for the new head's statement", recorder.Code, refusalOf(t, recorder).GetCode())
	}
	if stored := fixture.engine.readReseedStatement(fixture.ctx, fixture.cluster, check.repoId, check.refId); !bytes.Equal(stored, newer) {
		t.Fatal("reseed/ still holds the older head's statement")
	}
	// and the older one, sent again, names no head evs serves
	requireRefusal(t, fixture.reseed(&protocol.EvsReseedRequest{Statement: older}), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE)
}
