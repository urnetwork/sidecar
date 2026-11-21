//go:build !sidecar_http

// The keyless-slot rule on the verifying reader (§11.12's push and closure rows; evs_read_erased.go), on T2: a vault's
// stream entries read through ReadHead and ReadVersion against evsservice on record_evs_test.go's world, each entry
// keeping its chain's key in a slot of its own. A version whose key a committed ERASE destroyed reads as erased,
// ErrEvsErased with nothing of it shown and no alarm, where the reader used to raise tamper (FS-92 (c)); a key gone
// from its slot with no ERASE naming it is one evs withheld, which alarms tamper and refuses the read, with the ERASEs
// read once, after the slot.

package sidecar_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A reader of the streams world's vault, a writer of its own stream as the directory's daemons are, so the
// owner-bound read needs no receipt, whose evs alarms go to alarms and whose transport is hook's.
func evsReadErasedReader(t *testing.T, world *evsStreamsWorld, hook *directoryEvsHookTransport, alarms *[]sidecar.SidecarEvent) *sidecar.EvsRepo {
	t.Helper()
	readerId := sidecar.NewId()
	if err := world.world.Grant(world.repoId, readerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	hook.world = world.world
	reader := world.world.newClient(readerId, sidecartest.NewFakeStore().Root(), func(args *sidecar.EvsClientArgs) {
		args.Transport = hook
		args.Emit = func(event sidecar.SidecarEvent) {
			if event.Kind == sidecar.SidecarEventEvsAlarm {
				*alarms = append(*alarms, event)
			}
		}
	})
	return reader.Repo(world.repoId)
}

// The slot keys the n-th entry of writer's stream keeps its chain in (EvsRepo.SlotKeysOf), read by the vault's owner.
func evsReadErasedEntryKeys(t *testing.T, world *evsStreamsWorld, writer sidecar.Id, n uint64) []*sidecar.EvsErasedKey {
	t.Helper()
	path, err := sidecar.RecordStreamPath(n)
	if err != nil {
		t.Fatal(err)
	}
	admin := world.world.newClient(world.world.ownerId, sidecartest.NewFakeStore().Root())
	keys, err := admin.Repo(world.repoId).SlotKeysOf(t.Context(), sidecar.RecordStreamRefName(writer), []string{path})
	if err != nil || len(keys) == 0 {
		t.Fatalf("entry %d's slot keys %v: %v", n, keys, err)
	}
	return keys
}

// A version an ERASE emptied reads as erased by ReadHead and by ReadVersion, nothing shown and no alarm, and the
// ERASEs are read once, after the slot; the stream's other entry reads its bytes.
func TestEvsReadHeadReadsAVersionAnEraseEmptiedAsErased(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	world.append(t, writer, 1, 2)
	ctx := t.Context()
	keys := evsReadErasedEntryKeys(t, world, writer, 1)
	admin := world.world.newClient(world.world.ownerId, sidecartest.NewFakeStore().Root())
	if _, err := admin.Repo(world.repoId).Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Keys: keys, Complete: true}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	hook := &directoryEvsHookTransport{}
	alarms := []sidecar.SidecarEvent{}
	repo := evsReadErasedReader(t, world, hook, &alarms)
	erased, err := sidecar.RecordStreamPath(1)
	if err != nil {
		t.Fatal(err)
	}
	refName := sidecar.RecordStreamRefName(writer)
	out := &bytes.Buffer{}
	if _, err := repo.ReadHead(ctx, &sidecar.EvsReadArgs{RefName: refName, Path: erased, Fresh: true}, out); !errors.Is(err, sidecar.ErrEvsErased) || out.Len() != 0 {
		t.Fatalf("the erased entry's head read: %v, %d bytes", err, out.Len())
	}
	if _, err := repo.ReadVersion(ctx, &sidecar.EvsReadArgs{RefName: refName, Path: erased, Version: 1, Fresh: true}, out); !errors.Is(err, sidecar.ErrEvsErased) || out.Len() != 0 {
		t.Fatalf("the erased entry's version 1: %v, %d bytes", err, out.Len())
	}
	if len(alarms) != 0 {
		t.Fatalf("alarms %+v", alarms)
	}
	// each read judged its own slot on ERASEs read after it, once
	if reads := hook.erasureHeadReads(world.repoId); reads != 2 {
		t.Fatalf("the ERASEs read %d times by two reads", reads)
	}
	kept, err := sidecar.RecordStreamPath(2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReadHead(ctx, &sidecar.EvsReadArgs{RefName: refName, Path: kept, Fresh: true}, out); err != nil || out.String() != "entry "+kept {
		t.Fatalf("the other entry: %v, %q", err, out.String())
	}
}

// A key gone from its slot with no ERASE naming it is one evs withheld: ReadHead alarms tamper and refuses, after
// one read of the ERASEs, which name another entry's key alone.
func TestEvsReadHeadAlarmsAKeyWithheld(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	world.append(t, writer, 1, 2)
	ctx := t.Context()
	// the second entry's key erased, so the ERASEs the reader reads name a key, just not the first entry's
	admin := world.world.newClient(world.world.ownerId, sidecartest.NewFakeStore().Root())
	if _, err := admin.Repo(world.repoId).Erase(ctx, &sidecar.EvsEraseArgs{
		ErasureId: sidecar.NewId(), Keys: evsReadErasedEntryKeys(t, world, writer, 2), Complete: true,
	}); err != nil {
		t.Fatalf("the ERASE: %v", err)
	}
	// evs drops the first entry's key with no ERASE: its slot stored with no key, as an ERASE would leave it
	withheld := evsReadErasedEntryKeys(t, world, writer, 1)
	key := evsservice.SlotKey(world.repoId, withheld[0].SlotId)
	stored, err := world.world.cluster.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	stored.Body.Close()
	if _, err := world.world.cluster.PutIfMatch(ctx, key, stored.Etag, []byte{}, nil); err != nil {
		t.Fatal(err)
	}
	hook := &directoryEvsHookTransport{}
	alarms := []sidecar.SidecarEvent{}
	repo := evsReadErasedReader(t, world, hook, &alarms)
	path, err := sidecar.RecordStreamPath(1)
	if err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	_, err = repo.ReadHead(ctx, &sidecar.EvsReadArgs{RefName: sidecar.RecordStreamRefName(writer), Path: path, Fresh: true}, out)
	if !errors.Is(err, sidecar.ErrEvsSealInvalid) || errors.Is(err, sidecar.ErrEvsErased) || out.Len() != 0 {
		t.Fatalf("a key evs withheld: %v, %d bytes", err, out.Len())
	}
	if len(alarms) != 1 || alarms[0].EvsAlarm != sidecar.SidecarEvsAlarmTamper {
		t.Fatalf("alarms %+v", alarms)
	}
	if reads := hook.erasureHeadReads(world.repoId); reads != 1 {
		t.Fatalf("the ERASEs read %d times", reads)
	}
}

// ReadStream verifies both pushes of the writer and serves the surviving entries when an ERASE precedes any BASE.
func TestRecordEvsStreamsReadPastErasedFiles(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	ctx := t.Context()
	writer := world.writers[0]
	world.append(t, writer, 1, 1)
	world.append(t, writer, 2, 2)
	admin := world.world.evsRepo(world.world.ownerId, world.repoId)
	keys := append(evsReadErasedEntryKeys(t, world, writer, 1), evsReadErasedEntryKeys(t, world, writer, 2)...)
	if result, err := admin.Erase(ctx, &sidecar.EvsEraseArgs{ErasureId: sidecar.NewId(), Complete: true, Keys: keys}); err != nil || result.Version != 1 {
		t.Fatalf("erasure was not committed: %+v, %v", result, err)
	}
	path, err := sidecar.RecordStreamPath(3)
	if err != nil {
		t.Fatal(err)
	}
	reader := world.world.For(world.readerId)
	for _, after := range []uint64{0, 1} {
		versions, err := reader.ReadStream(ctx, world.repoId, writer, after)
		if err != nil || len(versions) != 1 || versions[0].Version != 2 || len(versions[0].Entries) != 1 {
			t.Fatalf("stream after %d: %+v, %v", after, versions, err)
		}
		entry := versions[0].Entries[0]
		if entry.Path != path || string(entry.Entry) != "entry "+path {
			t.Fatalf("surviving entry: %+v", entry)
		}
	}
}
