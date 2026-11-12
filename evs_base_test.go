//go:build !sidecar_http

// EVS1-M6-03 on T2: EvsRepo.Base against evsservice on record_evs_test.go's world (plan-EVS1-v1-unspecified#6), on a
// fake clock. A retention expiry: the expired entry's slot erased first, then a repo admin's BASE on the writer's
// stream removes its file, naming its newest version; every statement, the BASE's among them, still verifies from the
// stream's start, and the stream's live set is what stands after it; a writer's own BASE without admin, a BASE of a
// file that does not stand, and a BASE of nothing are refused. Export's stub of an expired entry and §11.13's GC
// after the fence are not built (EVSB-M6-01 waits on plan-EVSB-fs94-compaction-clause#2), so nothing here deletes.

package sidecar_test

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A writer's three entries; the first expires: its slot erased, then a BASE removes it, and the live set holds the
// other two while every statement still verifies.
func TestEvsBaseReListsTheLiveSetAfterAnErasure(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	world.append(t, writer, 1, 3)
	ctx := t.Context()
	admin := world.world.newClient(world.world.ownerId, sidecartest.NewFakeStore().Root())
	repo := admin.Repo(world.repoId)
	expired, err := sidecar.RecordStreamPath(1)
	if err != nil {
		t.Fatal(err)
	}
	// the retention's day passes on the fake clock: the entry is past its keep_days
	world.world.Advance(31 * 24 * time.Hour)
	history, err := repo.History(ctx, &sidecar.EvsReadArgs{RefName: sidecar.RecordStreamRefName(writer), Path: expired})
	if err != nil || len(history.Versions) != 1 {
		t.Fatalf("the expired entry's history %+v %v", history, err)
	}
	keys := []*sidecar.EvsErasedKey{}
	for _, slotId := range history.Versions[0].SlotIds {
		keys = append(keys, &sidecar.EvsErasedKey{SlotId: slotId, KeyIndex: 0})
	}
	if _, err := repo.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	based, err := repo.Base(ctx, &sidecar.EvsBaseArgs{RefName: sidecar.RecordStreamRefName(writer), Paths: []string{expired}})
	if err != nil {
		t.Fatalf("the BASE: %v", err)
	}
	if based.Version != 2 {
		t.Fatalf("the BASE committed at %d", based.Version)
	}
	// every statement verifies from the stream's start, the BASE's at the next version with its removal alone
	answers, err := world.reader.Repo(world.repoId).ReadStreams(ctx, world.reads())
	if err != nil {
		t.Fatal(err)
	}
	versions := answers[0].Versions
	if len(versions) != 2 || len(versions[0].Files) != 3 {
		t.Fatalf("%d versions after the BASE", len(versions))
	}
	// the expired entry reads as erased, the others with their bytes
	erased := 0
	for _, file := range versions[0].Files {
		if file.Erased {
			erased += 1
		} else if len(file.Content) == 0 {
			t.Fatal("a live entry read with no content")
		}
	}
	if erased != 1 {
		t.Fatalf("%d entries read as erased", erased)
	}
	base := versions[1]
	if base.Statement.Statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) == 0 || len(base.Files) != 0 ||
		len(base.Payload.Changes) != 1 || base.Payload.Changes[0].WritesEntry() || len(base.Payload.NewObjects) != 0 {
		t.Fatalf("the BASE's push: flags %d, %d files, %d changes", base.Statement.Statement.Push.GetFlags(), len(base.Files), len(base.Payload.Changes))
	}
	// the live set
	stream, err := world.world.For(world.readerId).ReadStream(ctx, world.repoId, writer, 0)
	if err != nil {
		t.Fatal(err)
	}
	live := []string{}
	for _, version := range stream {
		for _, entry := range version.Entries {
			live = append(live, entry.Path)
		}
	}
	second, _ := sidecar.RecordStreamPath(2)
	third, _ := sidecar.RecordStreamPath(3)
	if len(live) != 2 || live[0] != second || live[1] != third {
		t.Fatalf("the live set %v", live)
	}
}

// A BASE takes admin scope, a file that stands, and something to remove; each refusal sends nothing that commits.
func TestEvsBaseRefusals(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	world.append(t, writer, 1, 1)
	ctx := t.Context()
	first, _ := sidecar.RecordStreamPath(1)
	// the writer has rw and no admin: evs answers SCOPE
	own := world.world.newClient(writer, sidecartest.NewFakeStore().Root())
	_, err := own.Repo(world.repoId).Base(ctx, &sidecar.EvsBaseArgs{RefName: sidecar.RecordStreamRefName(writer), Paths: []string{first}})
	if !sidecar.IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE) {
		t.Fatalf("a BASE below admin: %v", err)
	}
	admin := world.world.newClient(world.world.ownerId, sidecartest.NewFakeStore().Root())
	repo := admin.Repo(world.repoId)
	missing, _ := sidecar.RecordStreamPath(9)
	if _, err := repo.Base(ctx, &sidecar.EvsBaseArgs{RefName: sidecar.RecordStreamRefName(writer), Paths: []string{missing}}); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("a BASE of a file that does not stand: %v", err)
	}
	if _, err := repo.Base(ctx, &sidecar.EvsBaseArgs{RefName: sidecar.RecordStreamRefName(writer)}); !errors.Is(err, sidecar.ErrEvsWriteInvalid) {
		t.Fatalf("a BASE of nothing: %v", err)
	}
	if _, err := repo.Base(ctx, &sidecar.EvsBaseArgs{RefName: sidecar.RecordStreamRefName(writer), Paths: []string{first, first}}); !errors.Is(err, sidecar.ErrEvsWriteInvalid) {
		t.Fatalf("a path named twice: %v", err)
	}
	answers, err := world.reader.Repo(world.repoId).ReadStreams(ctx, world.reads())
	if err != nil || len(answers[0].Versions) != 1 {
		t.Fatalf("after the refusals the stream holds %d versions: %v", len(answers[0].Versions), err)
	}
}
