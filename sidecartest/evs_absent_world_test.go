// QD-979's absent read end to end on T2, with QD-1043 and QD-1041: sidecar.EvsClient devices against an
// evsservice.EvsEngine over FakeHost's stores, in the epoch world (evs_epoch_world_test.go). x.txt is written, read by
// two devices, and removed by a push whose change list is under changes_root; 130 more pushes page the removal out of
// the window, the page-out's fold writing x.txt's marker, and deleting x.txt's entry stands in for the marker's
// collection, so evs serves x.txt plain absent.
//
//	walked   a writer device pinned below the removal pages the log and walks it, the removal shown by the present
//	         of x.txt's own change evs sends beside the reply (QD-1043): it reads x.txt absent, and creates it again
//	         at b + 1
//	gap      a device whose catch-up budget the walk passes re-pins at the head with the gap marked, its walk the
//	         window's statements alone: it reads x.txt absent, its record dropped (QD-1041)

package sidecartest

import (
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

func TestEvsRootedRemovalPagedOutReadsAbsentAndIsCreatedAgainEndToEnd(t *testing.T) {
	world := newEpochWorld(t)
	w := world.device("w", nil)
	v := world.device("v", nil)
	r := world.device("r", func(settings *sidecar.EvsSettings) {
		// the window's statements alone pass it, so a read from below the window gaps
		settings.CatchUpByteCount = 16 * 1024
	})
	if _, err := w.write("x.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*epochDevice{v, r} {
		if content, _, err := device.read("x.txt"); err != nil || string(content) != "first" {
			t.Fatalf("%s's read of x.txt: %q %v", device.label, content, err)
		}
	}
	refId := world.mainRefId(w)
	files := map[string][]byte{"x.txt": nil}
	for i := range 30 {
		files[fmt.Sprintf("e/n%02d", i)] = []byte("n")
	}
	removed, err := w.writePaths(files)
	if err != nil {
		t.Fatal(err)
	}
	window, err := evsservice.EvsHeadWindow(world.head(refId))
	if err != nil || len(window) < int(removed.Version) || !window[removed.Version-1].ChangesInPayload() {
		t.Fatalf("the removal at %d: its list not under changes_root (%v)", removed.Version, err)
	}
	for i := range 130 {
		if _, err := w.write(fmt.Sprintf("p%03d", i), []byte("p")); err != nil {
			t.Fatal(err)
		}
	}
	head := world.head(refId)
	if first := evsservice.EvsHeadWindowFirstVersion(head); first <= removed.Version || head.GetFoldedThrough() < removed.Version {
		t.Fatalf("the window from %d, folded through %d: the removal at %d not paged out", first, head.GetFoldedThrough(), removed.Version)
	}
	// the marker's collection
	grant, err := world.host.Budget.AdmitP1(world.ctx, "meta-1", connect.Id(world.networkId), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	err = world.cluster.Delete(grant.Context(), evsservice.IndexEntryKey(world.repoId, refId, 1, w.tokenPath("x.txt", 1)))
	grant.Close()
	if err != nil {
		t.Fatal(err)
	}

	// gap: r's walk from its record's pin passes its budget
	if _, _, err := r.read("x.txt"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("r past its catch-up budget: %v", err)
	}
	if r.repo.VerifiedSince(refId).IsZero() {
		t.Fatal("r read with no gap")
	}
	// walked: v pages the log from its record's pin and walks the rooted removal
	if _, _, err := v.read("x.txt"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("v pinned below the removal: %v", err)
	}
	if !v.repo.VerifiedSince(refId).IsZero() {
		t.Fatal("v read with a gap")
	}
	created, err := v.write("x.txt", []byte("again"))
	if err != nil {
		t.Fatalf("v's creation of x.txt: %v", err)
	}
	if created.Version != head.GetVersion()+1 || created.PathVersions[0] != head.GetVersion()+1 {
		t.Fatalf("created at %d with version %d, want b + 1 = %d", created.Version, created.PathVersions[0], head.GetVersion()+1)
	}
	for _, device := range []*epochDevice{w, v, r} {
		if content, info, err := device.read("x.txt"); err != nil || string(content) != "again" || info.Version != created.PathVersions[0] {
			t.Fatalf("%s's read of x.txt created again: %q %+v %v", device.label, content, info, err)
		}
	}
}
