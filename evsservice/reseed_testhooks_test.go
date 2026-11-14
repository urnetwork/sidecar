//go:build sidecar_testhooks

// EVSB-M2-20's schedules at the reseed route's barriers (reseed.go; QD-096, QD-725, QD-815): an ERASE that commits
// while a re-seeded slot's create is held, before it and after it, never leaves the key it covers in the slot; a head
// that moves while a Signed EvsReseed's write is held leaves a statement no reader takes for the new head; and a
// writer's push that commits while a re-seeded file-mode push waits at its head CAS sends it through 5f and 5g again
// on the new head, where it lands one version past the mirror's, which the device's walk stops at, or is refused for
// a path the writer changed, recording nothing.

package evsservice

import (
	"bytes"
	"errors"
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

// The new site's ref holding the two-device history through version 4, from a walk of a mirror that held no more,
// and the device's mirror then holding all six versions: the next walk's first commit is the other device's push, at
// version 5, on a base 3 below the head.
func newReseedLivePushRace(t *testing.T) (*reseedFixture, *reseedDevice, *reseedTwoDeviceHistory) {
	t.Helper()
	history := newReseedTwoDeviceHistory(t)
	fixture := newReseedFixture(t)
	device := fixture.device()
	device.holds(history, 4)
	if ref := device.reseed(); ref.Stopped != nil || ref.Version != 4 {
		t.Fatalf("the first walk ended at %d, stopped by %v", ref.Version, ref.Stopped)
	}
	device.holds(history, 6)
	device.reseedCallCount = 0
	return fixture, device, history
}

// The device's walk, with a writer's push on the head the first walk left committing at the walk's first head CAS:
// the writer's plan, under a push id of its own, as change makes it. What the walk did to the ref, the writer's
// status, and how many head CASes the walk reached.
func (self *reseedFixture) walkPastALivePush(device *reseedDevice, change func(plan *sidecar.EvsPushPlan)) (*sidecar.EvsReseedRef, int, int) {
	t := self.t
	t.Helper()
	status := 0
	reached := atBarrierOnce(t, BarrierHeadCasBefore, barrierRefKey(self.check.repoId, self.check.refId), func() {
		live := self.plan()
		live.PushId = testId("reseed live push")
		change(live)
		status = self.push(live).Code
	})
	ref := device.reseed()
	sidecar.SetTestHooks(nil)
	return ref, status, *reached
}

// A writer's push on another path commits while the walk's re-seeded file-mode push waits at its head CAS: the
// re-seeded push's If-Match fails, and its rerun runs 5a, 5f and 5g again on the head the writer left, where its base
// 1 stays inside the window with nothing it changes written since, so it commits at 6, one past where the mirror held
// it. The walk stops the ref at 4 with ErrEvsReseedVersion and sends nothing past it.
func TestReseedRerunPastALivePushLandsAtAnotherVersion(t *testing.T) {
	fixture, device, history := newReseedLivePushRace(t)
	ref, status, reached := fixture.walkPastALivePush(device, func(plan *sidecar.EvsPushPlan) {
		fixture.create(plan, "z")
	})
	if status != http.StatusOK || reached != 2 {
		t.Fatalf("the writer's push answered %d, and the walk reached %d head CASes", status, reached)
	}
	if !errors.Is(ref.Stopped, sidecar.ErrEvsReseedVersion) || ref.Version != 4 || device.reseedCallCount != 5 {
		t.Fatalf("the walk ended at %d after %d reseed calls, stopped by %v", ref.Version, device.reseedCallCount, ref.Stopped)
	}
	head := fixture.head()
	if head.Version() != 6 || !bytes.Equal(head.Head.GetPushId(), history.statement(t, 5).Push.GetPushId()) || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with push %x", head.Version(), head.Head.GetPushId())
	}
}

// The twin: the writer's push writes a, which the re-seeded push writes on a's version 1, so the rerun's 5g refuses
// it 409 PATH_CONFLICT, recording nothing, and the walk stops the ref at 4 with that refusal; sent again, it answers
// the same.
func TestReseedRerunPastAConflictingLivePushIsRefused(t *testing.T) {
	fixture, device, history := newReseedLivePushRace(t)
	check := fixture.check
	ref, status, reached := fixture.walkPastALivePush(device, func(plan *sidecar.EvsPushPlan) {
		plan.Changes = append(plan.Changes, check.change(plan, checkTestPath("a"), 1, 2))
	})
	if status != http.StatusOK || reached != 1 {
		t.Fatalf("the writer's push answered %d, and the walk reached %d head CASes", status, reached)
	}
	evsError, ok := sidecar.EvsErrorOf(ref.Stopped)
	if !ok || evsError.Status != http.StatusConflict || evsError.Code != protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT || evsError.Recorded ||
		ref.Version != 4 || device.reseedCallCount != 5 {
		t.Fatalf("the walk ended at %d after %d reseed calls, stopped by %v", ref.Version, device.reseedCallCount, ref.Stopped)
	}
	head := fixture.head()
	if head.Version() != 5 || !bytes.Equal(head.Head.GetPushId(), testId("reseed live push").Bytes()) || len(head.Head.GetRefused()) != 0 {
		t.Fatalf("head at %d with push %x and %d bytes of refusals", head.Version(), head.Head.GetPushId(), len(head.Head.GetRefused()))
	}
	requireRefusal(t, fixture.reseed(history.bodies[4]), http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
}
