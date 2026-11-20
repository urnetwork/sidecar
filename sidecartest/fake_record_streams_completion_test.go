package sidecartest

// QD-1132's completion ERASE on the record streams' fake: what it takes, and the refusals the erasers rely on.

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// An ERASE naming only keys gone is taken as a completion once it says complete and an earlier ERASE of its erasure
// named each key, the newest ERASE naming each being no completion and the erasure's newest ERASE not saying complete.
// A second completion of the erasure, one naming a key the erasure never destroyed, and one saying nothing complete
// are refused NOTHING_TO_ERASE, and one from a sidecar below admin SCOPE, none of them committing. A late copy's ERASE
// reopens the erasure: a completion naming the key the first completion took stays refused, and one naming a key no
// completion took ends the erasure again.
func TestFakeRecordStreamsTakesOneCompletionEraseWhileAnErasureIsOpen(t *testing.T) {
	ctx := t.Context()
	world := NewFakeRecordStreams(nil, nil, nil)
	repoId, err := world.NewRepo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	writerId, adminId, memberId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	err = grantRecordStreams(world, repoId, map[sidecar.Id]RecordStreamsScope{
		writerId: {Read: true, Write: true},
		adminId:  {Read: true, Admin: true},
		memberId: {Read: true, Write: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1", "e/0/0/2", "e/0/0/3")
	if _, err := world.For(writerId).Append(ctx, repoId, push); err != nil {
		t.Fatal(err)
	}
	admin := world.For(adminId)
	erasureId, otherId := sidecar.NewId(), sidecar.NewId()
	key := func(index uint32) []*sidecar.RecordSlotKey {
		return []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: index}}
	}
	erase := func(streams sidecar.RecordStreams, erasureId sidecar.Id, keys []*sidecar.RecordSlotKey, complete bool) error {
		_, err := streams.Erase(ctx, repoId, &sidecar.RecordStreamErase{PushId: sidecar.NewEvsPushId(), ErasureId: erasureId, Complete: complete, Keys: keys})
		return err
	}
	// the erasure's first ERASE, saying nothing complete, and another erasure's of another key
	if err := erase(admin, erasureId, key(0), false); err != nil {
		t.Fatal(err)
	}
	if err := erase(admin, otherId, key(1), false); err != nil {
		t.Fatal(err)
	}
	refusals := []struct {
		what     string
		streams  sidecar.RecordStreams
		keys     []*sidecar.RecordSlotKey
		complete bool
		code     protocol.EvsRefusalCode
	}{
		{what: "a completion from a sidecar below admin", streams: world.For(memberId), keys: key(0), complete: true, code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE},
		{what: "a completion of a key another erasure destroyed", streams: admin, keys: key(1), complete: true, code: protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE},
		{what: "an ERASE of the erasure's gone key saying nothing complete", streams: admin, keys: key(0), complete: false, code: protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE},
	}
	for _, refusal := range refusals {
		if err := wantRecordStreamRefusal(refusal.what, erase(refusal.streams, erasureId, refusal.keys, refusal.complete), refusal.code); err != nil {
			t.Error(err)
		}
	}
	if err := erase(admin, erasureId, key(0), true); err != nil {
		t.Fatalf("the completion: %v", err)
	}
	if err := wantRecordStreamRefusal("a second completion", erase(admin, erasureId, key(0), true), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		t.Error(err)
	}
	// a late copy's ERASE reopens the erasure
	if err := erase(admin, erasureId, key(2), false); err != nil {
		t.Fatal(err)
	}
	if err := wantRecordStreamRefusal("a completion of the key a completion took", erase(admin, erasureId, key(0), true), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		t.Error(err)
	}
	if err := erase(admin, erasureId, key(2), true); err != nil {
		t.Fatalf("the reopened erasure's completion: %v", err)
	}
	erasures, err := admin.ReadErasures(ctx, repoId, 0)
	if err != nil {
		t.Fatal(err)
	}
	complete := []bool{}
	for _, erasure := range erasures {
		complete = append(complete, erasure.Complete)
	}
	if len(erasures) != 5 || !erasures[4].Complete || erasures[4].ErasureId != erasureId || erasures[2].ErasureId != erasureId || !erasures[2].Complete {
		t.Fatalf("%d ERASEs committed, complete %v", len(erasures), complete)
	}
}
