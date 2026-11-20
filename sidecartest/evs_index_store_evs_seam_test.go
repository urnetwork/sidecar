//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// The index eraser's history walk over EvsRepo on the real engine (QD-1110; question
// mail-m10-04-index-eraser-history-reads; SEARCH-M10-17's indexEvsStore.Retained and Read), on a mailbox at format 2
// as mailworld's M10World builds it: mail through the router into evsservice's engine, ingested with its index delta
// by two consented devices, erased by the owner's MailEraser.
//
//	read      a writer's head file first created by the mailbox's second push and written again by its next one: the
//	          version it replaced is one Retained names, from History, with no content hash, and the store's Read
//	          gives its bytes as they stood, held to nothing more than evs's reader held them to, its entry's own
//	          sealed fields, rather than refusing them as a plaintext hash mismatch
//	erased    once an erasure's CLOSURE rewrote that head file and its ERASE destroyed the slot key its earlier
//	          versions share, evs still lists those versions kept and a read of one reads erased, its key gone by a
//	          committed ERASE (sidecar.ErrEvsErased, no alarm); Retained
//	          leaves each out, since a committed ERASE named every slot it opens under, and every version it does name
//	          reads. A second erasure then destroys the key of the first's CLOSURE, and a resume of the first goes on,
//	          its walk meeting none of them

package sidecartest_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest/mailworld"
)

// The one index file that holds message at the head, and its version and bytes there, as the owner's laptop reads
// them.
func seamHeadFile(t *testing.T, world *mailworld.M10World, message *mailworld.M10Message) (string, uint64, []byte) {
	t.Helper()
	ctx := world.Context()
	held, err := sidecar.SearchTestEvsFilesHolding(ctx, world.Owner.Repo, nil, message.Path)
	if err != nil || len(held) != 1 || !held[0].Live {
		t.Fatalf("the files holding %s: %+v %v", message.Path, held, err)
	}
	index, err := world.Index(world.Owner)
	if err != nil {
		t.Fatal(err)
	}
	files, err := sidecar.ReadSearchTestEvsIndexFiles(ctx, world.Owner.Repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	return held[0].Path, index.Files[held[0].Path], files[held[0].Path]
}

// The versions Retained names, every readable one read without error; it never answers complete on EvsRepo, since it
// names no removed index path (SEARCH-M10-17's note).
func seamRetained(t *testing.T, world *mailworld.M10World, label string) []*sidecar.SearchTestEvsRetained {
	t.Helper()
	retained, complete, err := sidecar.SearchTestEvsRetainedVersions(world.Context(), world.Owner.Repo, nil)
	if err != nil {
		t.Fatalf("%s: the retained versions: %v", label, err)
	}
	if complete {
		t.Fatalf("%s: the retained versions answered complete", label)
	}
	for _, version := range retained {
		if version.Readable && version.ReadErr != nil {
			t.Fatalf("%s: %s at %d does not read: %v", label, version.Path, version.Version, version.ReadErr)
		}
	}
	return retained
}

// The listed version of path at version, nil where Retained does not name it.
func seamListed(retained []*sidecar.SearchTestEvsRetained, path string, version uint64) *sidecar.SearchTestEvsRetained {
	for _, listed := range retained {
		if listed.Path == path && listed.Version == version {
			return listed
		}
	}
	return nil
}

func TestEvsIndexRetainedVersionReadsEndToEnd(t *testing.T) {
	world := newMailM10World(t)
	sender := "signup@" + mailworld.M8SenderDomain
	world.DeliverAndIngest(world.Owner, sender, mailworld.M8Message(world.Address, "cormorant ledger", "The cormorant ledger closes at noon."))
	second := world.DeliverAndIngest(world.Reader, sender, mailworld.M8Message(world.Address, "lighthouse rota", "The lighthouse rota for the spring tides."))
	headPath, headVersion, headBytes := seamHeadFile(t, world, second)
	if headVersion <= 1 {
		t.Fatalf("the second device's head file stands at %d, not past the first push", headVersion)
	}
	world.DeliverAndIngest(world.Reader, sender, mailworld.M8Message(world.Address, "harbor notice", "The harbor notice lists the dredging days."))
	retained := seamRetained(t, world, "after the second device's second ingest")
	listed := seamListed(retained, headPath, headVersion)
	if listed == nil || !listed.Readable || !bytes.Equal(listed.Plaintext, headBytes) {
		t.Fatalf("the head file's replaced version %d: %+v of %+v", headVersion, listed, retained)
	}
}

func TestEvsIndexRetainedLeavesOutAVersionAnEraseDestroyedEndToEnd(t *testing.T) {
	world := newMailM10World(t)
	ctx := world.Context()
	sender := "signup@" + mailworld.M8SenderDomain
	world.DeliverAndIngest(world.Owner, sender, mailworld.M8Message(world.Address, "cormorant ledger", "The cormorant ledger closes at noon."))
	erased := world.DeliverAndIngest(world.Reader, sender, mailworld.M8Message(world.Address, "lighthouse rota", "The lighthouse rota for the spring tides."))
	headPath, firstVersion, _ := seamHeadFile(t, world, erased)
	world.DeliverAndIngest(world.Reader, sender, mailworld.M8Message(world.Address, "harbor notice", "The harbor notice lists the dredging days."))
	index, err := world.Index(world.Owner)
	if err != nil {
		t.Fatal(err)
	}
	secondVersion := index.Files[headPath]
	if seamListed(seamRetained(t, world, "before the erasure"), headPath, firstVersion) == nil {
		t.Fatalf("the head file's replaced version %d is not retained before the erasure", firstVersion)
	}

	first, err := world.Eraser(world.Owner).Erase(ctx, erased.Month, []sidecar.Id{erased.Id})
	if err != nil {
		t.Fatalf("the first erasure: %v", err)
	}
	if first.State != sidecar.MailErasureRewriting || !first.Unproven {
		t.Fatalf("the first erasure: %+v", first)
	}
	// its CLOSURE rewrote the head file, and its ERASE took the key both earlier versions open under: evs lists them
	// kept, and a read of either reads erased
	history, err := world.Owner.Repo.History(ctx, &sidecar.EvsReadArgs{Path: headPath, Fresh: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range history.Versions {
		if version.Version != firstVersion && version.Version != secondVersion {
			continue
		}
		if version.State != "kept" {
			t.Fatalf("version %d of the head file reads state %q", version.Version, version.State)
		}
		_, err := world.Owner.Repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: headPath, Version: version.Version, Fresh: true}, io.Discard)
		if !errors.Is(err, sidecar.ErrEvsErased) {
			t.Fatalf("version %d of the head file read after the ERASE: %v", version.Version, err)
		}
	}
	retained := seamRetained(t, world, "after the first erasure")
	for _, version := range []uint64{firstVersion, secondVersion} {
		if listed := seamListed(retained, headPath, version); listed != nil {
			t.Fatalf("the head file's version %d, its key destroyed, is retained: %+v", version, listed)
		}
	}

	// a second erasure destroys the first's CLOSURE's key, and a resume of the first goes on
	later := world.DeliverAndIngest(world.Reader, sender, mailworld.M8Message(world.Address, "tide tables", "The tide tables for the estuary."))
	if _, err := world.Eraser(world.Owner).Erase(ctx, later.Month, []sidecar.Id{later.Id}); err != nil {
		t.Fatalf("the second erasure: %v", err)
	}
	seamRetained(t, world, "after the second erasure")
	resumed, err := world.Eraser(world.Owner).Resume(ctx)
	if err != nil {
		t.Fatalf("the resume after the second erasure: %v", err)
	}
	if len(resumed) == 0 || resumed[0].ErasureId != first.ErasureId || resumed[0].State != sidecar.MailErasureRewriting {
		t.Fatalf("the resume took up %+v, not the first erasure", resumed)
	}
}
