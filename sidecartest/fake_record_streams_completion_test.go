package sidecartest

// QD-1132's completion ERASE on the record streams' fake, as QD-1137 has evs and its readers take it.

import (
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A completion ERASE, flagged, naming only keys no slot holds, is taken where an earlier ERASE named each key and the
// newest such is no completion. One naming a held key, and one saying nothing complete, are INVALID; one naming a key
// no ERASE named, a second completion and an unflagged duplicate get NOTHING_TO_ERASE; one below admin SCOPE; none of
// them commits. One naming a key another erasure's ERASE destroyed commits, as evs cannot see whose it was, and reads
// back as completing nothing. A late copy's ERASE reopens the erasure: a completion naming the key the first completion
// took stays refused, and one naming the late copy's key ends the erasure again.
func TestFakeRecordStreamsTakesACompletionEraseAsEvsDoes(t *testing.T) {
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
	push := recordStreamsSuitePush(world, writerId, "e/0/0/1", "e/0/0/2", "e/0/0/3", "e/0/0/4")
	if _, err := world.For(writerId).Append(ctx, repoId, push); err != nil {
		t.Fatal(err)
	}
	admin := world.For(adminId)
	erasureId, otherId := sidecar.NewId(), sidecar.NewId()
	key := func(index uint32) []*sidecar.RecordSlotKey {
		return []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: index}}
	}
	erase := func(streams sidecar.RecordStreams, erasureId sidecar.Id, keys []*sidecar.RecordSlotKey, complete bool, completion bool) error {
		_, err := streams.Erase(ctx, repoId, &sidecar.RecordStreamErase{
			PushId: sidecar.NewEvsPushId(), ErasureId: erasureId, Complete: complete, Completion: completion, Keys: keys,
		})
		return err
	}
	// the erasure's first ERASE, saying nothing complete, and another erasure's of another key
	if err := erase(admin, erasureId, key(0), false, false); err != nil {
		t.Fatal(err)
	}
	if err := erase(admin, otherId, key(1), false, false); err != nil {
		t.Fatal(err)
	}
	refusals := []struct {
		what     string
		streams  sidecar.RecordStreams
		keys     []*sidecar.RecordSlotKey
		complete bool
		code     protocol.EvsRefusalCode
	}{
		{what: "a completion naming a held key", streams: admin, keys: key(3), complete: true, code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID},
		{what: "a completion saying nothing complete", streams: admin, keys: key(0), code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID},
		{what: "a completion naming a key no ERASE named", streams: admin, keys: []*sidecar.RecordSlotKey{{SlotId: push.SlotId, KeyIndex: 9}}, complete: true, code: protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE},
		{what: "a completion from a sidecar below admin", streams: world.For(memberId), keys: key(0), complete: true, code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE},
	}
	for _, refusal := range refusals {
		if err := wantRecordStreamRefusal(refusal.what, erase(refusal.streams, erasureId, refusal.keys, refusal.complete, true), refusal.code); err != nil {
			t.Error(err)
		}
	}
	if err := wantRecordStreamRefusal("an unflagged duplicate", erase(admin, erasureId, key(0), true, false), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		t.Error(err)
	}
	// evs cannot see whose ERASE destroyed a key: a completion of the other erasure's key commits, completing nothing
	if err := erase(admin, erasureId, key(1), true, true); err != nil {
		t.Fatalf("a completion of another erasure's key: %v", err)
	}
	if err := erase(admin, erasureId, key(0), true, true); err != nil {
		t.Fatalf("the completion: %v", err)
	}
	if err := wantRecordStreamRefusal("a second completion", erase(admin, erasureId, key(0), true, true), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		t.Error(err)
	}
	// a late copy's ERASE reopens the erasure
	if err := erase(admin, erasureId, key(2), false, false); err != nil {
		t.Fatal(err)
	}
	if err := wantRecordStreamRefusal("a completion of the key a completion took", erase(admin, erasureId, key(0), true, true), protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE); err != nil {
		t.Error(err)
	}
	if err := erase(admin, erasureId, key(2), true, true); err != nil {
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
	if len(erasures) != 6 || erasures[2].Complete || !erasures[3].Complete || erasures[4].Complete || !erasures[5].Complete {
		t.Fatalf("%d ERASEs read back, complete %v", len(erasures), complete)
	}
}
