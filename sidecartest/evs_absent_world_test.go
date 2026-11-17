// QD-979's absent read end to end on T2, with QD-1043, QD-1041 and QD-1055: sidecar.EvsClient devices against an
// evsservice.EvsEngine over FakeHost's stores, in the epoch world (evs_epoch_world_test.go). x.txt is written, read by
// two devices, and removed by a push whose change list is under changes_root; 130 more pushes page the removal out of
// the window, the page-out's fold writing x.txt's marker (absentWorldRemoved).
//
//	walked   with x.txt's entry deleted, as the marker's collection would, evs serves x.txt plain absent; a writer
//	         device pinned below the removal pages the log and walks it, the removal shown by the present of x.txt's
//	         own change evs sends beside the reply (QD-1043): it reads x.txt absent, and creates it again at b + 1
//	gap      a device whose catch-up budget the walk passes re-pins at the head with the gap marked, its walk the
//	         window's statements alone: it reads x.txt absent, its record dropped (QD-1041)
//	removal  with the marker standing, evs serves x.txt's removal: that device's first read gaps and drops its record,
//	         and its next read pages no log (QD-1055)

package sidecartest

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// One world of absentWorldRemoved: its devices, the main ref, the removal's push and the head after the pushes past it.
type absentWorld struct {
	world   *epochWorld
	w       *epochDevice
	v       *epochDevice
	r       *epochDevice
	refId   sidecar.Id
	removed *sidecar.EvsWritePathsResult
	head    *protocol.EvsHead
}

// x.txt written by w and read by v, a writer, and r, a reader whose catch-up budget the window's statements alone
// pass; x.txt removed by w beside 30 creations, which put the push's list under changes_root; and 130 pushes after
// it, which page the removal out of the window, the page-out's fold writing x.txt's marker.
func absentWorldRemoved(t *testing.T) *absentWorld {
	t.Helper()
	world := newEpochWorld(t)
	absent := &absentWorld{
		world: world,
		w:     world.device("w", nil),
		v:     world.device("v", nil),
		r: world.device("r", func(settings *sidecar.EvsSettings) {
			settings.CatchUpByteCount = 16 * 1024
		}),
	}
	if _, err := absent.w.write("x.txt", []byte("first")); err != nil {
		t.Fatal(err)
	}
	for _, device := range []*epochDevice{absent.v, absent.r} {
		if content, _, err := device.read("x.txt"); err != nil || string(content) != "first" {
			t.Fatalf("%s's read of x.txt: %q %v", device.label, content, err)
		}
	}
	absent.refId = world.mainRefId(absent.w)
	files := map[string][]byte{"x.txt": nil}
	for i := range 30 {
		files[fmt.Sprintf("e/n%02d", i)] = []byte("n")
	}
	removed, err := absent.w.writePaths(files)
	if err != nil {
		t.Fatal(err)
	}
	absent.removed = removed
	window, err := evsservice.EvsHeadWindow(world.head(absent.refId))
	if err != nil || len(window) < int(removed.Version) || !window[removed.Version-1].ChangesInPayload() {
		t.Fatalf("the removal at %d: its list not under changes_root (%v)", removed.Version, err)
	}
	for i := range 130 {
		if _, err := absent.w.write(fmt.Sprintf("p%03d", i), []byte("p")); err != nil {
			t.Fatal(err)
		}
	}
	absent.head = world.head(absent.refId)
	if first := evsservice.EvsHeadWindowFirstVersion(absent.head); first <= removed.Version || absent.head.GetFoldedThrough() < removed.Version {
		t.Fatalf("the window from %d, folded through %d: the removal at %d not paged out", first, absent.head.GetFoldedThrough(), removed.Version)
	}
	return absent
}

func TestEvsRootedRemovalPagedOutReadsAbsentAndIsCreatedAgainEndToEnd(t *testing.T) {
	absent := absentWorldRemoved(t)
	world, refId, head := absent.world, absent.refId, absent.head
	// the marker's collection
	grant, err := world.host.Budget.AdmitP1(world.ctx, "meta-1", connect.Id(world.networkId), sidecar.WriteCost{ImmediateByteCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	err = world.cluster.Delete(grant.Context(), evsservice.IndexEntryKey(world.repoId, refId, 1, absent.w.tokenPath("x.txt", 1)))
	grant.Close()
	if err != nil {
		t.Fatal(err)
	}

	// gap: r's walk from its record's pin passes its budget
	if _, _, err := absent.r.read("x.txt"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("r past its catch-up budget: %v", err)
	}
	if absent.r.repo.VerifiedSince(refId).IsZero() {
		t.Fatal("r read with no gap")
	}
	// walked: v pages the log from its record's pin and walks the rooted removal
	if _, _, err := absent.v.read("x.txt"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("v pinned below the removal: %v", err)
	}
	if !absent.v.repo.VerifiedSince(refId).IsZero() {
		t.Fatal("v read with a gap")
	}
	created, err := absent.v.write("x.txt", []byte("again"))
	if err != nil {
		t.Fatalf("v's creation of x.txt: %v", err)
	}
	if created.Version != head.GetVersion()+1 || created.PathVersions[0] != head.GetVersion()+1 {
		t.Fatalf("created at %d with version %d, want b + 1 = %d", created.Version, created.PathVersions[0], head.GetVersion()+1)
	}
	for _, device := range []*epochDevice{absent.w, absent.v, absent.r} {
		if content, info, err := device.read("x.txt"); err != nil || string(content) != "again" || info.Version != created.PathVersions[0] {
			t.Fatalf("%s's read of x.txt created again: %q %+v %v", device.label, content, info, err)
		}
	}
}

// QD-1055 on the engine: with x.txt's marker standing, evs serves its removal. r's first read of x.txt, from its
// record's pin, passes its budget and gaps, and drops the record; its next read starts from the head and asks for no
// log, where a record kept at its old pin sent every read through the same gap.
func TestEvsRemovalServedOnAGapHeadDropsItsRecordEndToEnd(t *testing.T) {
	absent := absentWorldRemoved(t)
	world, r := absent.world, absent.r
	var logCount atomic.Int64
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if device == r && request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/log") {
			logCount.Add(1)
		}
		return nil
	})
	if _, _, err := r.read("x.txt"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("r's read of x.txt's removal past its budget: %v", err)
	}
	if logCount.Load() == 0 || r.repo.VerifiedSince(absent.refId).IsZero() {
		t.Fatalf("r's first read: %d log requests, verified since %v: no gap", logCount.Load(), r.repo.VerifiedSince(absent.refId))
	}
	logCount.Store(0)
	if _, _, err := r.read("x.txt"); !errors.Is(err, sidecar.ErrEvsPathAbsent) {
		t.Fatalf("r's read of x.txt again: %v", err)
	}
	if logCount.Load() != 0 {
		t.Fatalf("r's read of x.txt again: %d log requests, its record kept below the gap", logCount.Load())
	}
}
