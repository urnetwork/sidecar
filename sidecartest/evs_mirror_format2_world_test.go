// Format 2's mirror end to end on T2 (EVS2-M10-13; §11.13's contents row, FS-70's first clause): a desktop mirror
// syncing as a purge lands. Its sync lists the head at a versionless path's first version; while it reads that
// version's kind-5 segment, the path is written again and the purge deletes the replaced segment, so the read finds
// nothing. The walk's end finds no replacement in what it walked, reads the ref's head again, walks on to the
// replacement and holds the replaced version complete with no content: nothing is named missing, the ref reaches the
// head, the mirror holds only the newest content, and coverage reads full once a hash check ran. A segment evs no
// longer serves whose version nothing replaces stays named missing, the ref below it.

package sidecartest

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Whether request is a read asking for segment ranges, its body left as it was.
func epochReadsSegments(request *http.Request) bool {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/read") || request.Body == nil {
		return false
	}
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	request.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	read := &protocol.EvsReadRequest{}
	return proto.Unmarshal(body, read) == nil && 0 < len(read.GetRanges())
}

func TestEvsMirrorSyncingAsAPurgeLandsHoldsTheReplacementEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	purger := world.startPurger()
	w := world.format2Device("w")
	path := "big.bin"
	if _, err := w.writeSetting(path, versionlessContent("the first version", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the first write: %v", err)
	}
	replaced := world.segmentKeys()
	if len(replaced) != 1 {
		t.Fatalf("%d segments after the first write", len(replaced))
	}
	m := world.format2Device("m")
	mirror := newWorldMirror(t, world, m)
	second := versionlessContent("the second version", 40*1024)
	landed := false
	world.setIntercept(func(device *epochDevice, request *http.Request) error {
		if device != m || landed || !epochReadsSegments(request) {
			return nil
		}
		// the replacement commits and the purge deletes the replaced segment while the mirror reads it
		landed = true
		if _, err := w.writeSetting(path, second, sidecar.EvsVersioningOff); err != nil {
			return err
		}
		if stats := world.purgeDue(purger); stats.DeletedCount != 1 {
			t.Errorf("the purge deleted %d", stats.DeletedCount)
		}
		return nil
	})
	result, err := mirror.Sync(world.ctx)
	world.setIntercept(nil)
	if err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(m)
	ref, ok, err := mirror.Store().Ref(refId)
	if !landed || err != nil || !ok || ref.Version != world.head(refId).GetVersion() {
		t.Fatalf("the mirrored ref %+v %v, the head at %d, landed %v", ref, err, world.head(refId).GetVersion(), landed)
	}
	if result.MissingCount != 0 || result.ReplacedMissingCount != 1 {
		t.Fatalf("the sync: %+v", result)
	}
	segments := mirrorKeys(t, mirror, sidecar.EvsMirrorSegments)
	newest := world.segmentKeys()
	if len(segments) != 1 || len(newest) != 1 || !strings.HasSuffix(newest[0], hex.EncodeToString(segments[0].ObjectId)) {
		t.Fatalf("the mirror holds %d segments, the cluster %v", len(segments), newest)
	}
	if _, err := mirror.Check(world.ctx); err != nil {
		t.Fatal(err)
	}
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || !coverage.Full || coverage.MissingCount != 0 {
		t.Fatalf("coverage %+v %v", coverage, err)
	}
	// a second sync takes nothing more and names nothing missing
	if again, err := mirror.Sync(world.ctx); err != nil || again.VersionCount != 0 || again.MissingCount != 0 {
		t.Fatalf("a second sync: %+v %v", again, err)
	}
}

// A newest version's segment that evs no longer serves, as when one is deleted by hand, is named missing, and the ref
// stays below its version: only a replacement or an executed drop makes a version complete without its content.
func TestEvsMirrorNamesANewestVersionsLostSegmentMissingEndToEnd(t *testing.T) {
	world := newVersionlessWorld(t)
	w := world.format2Device("w")
	if _, err := w.writeSetting("big.bin", versionlessContent("the only version", 40*1024), sidecar.EvsVersioningOff); err != nil {
		t.Fatalf("the write: %v", err)
	}
	keys := world.segmentKeys()
	if len(keys) != 1 {
		t.Fatalf("%d segments", len(keys))
	}
	segments, err := world.host.Blobs.SegmentCluster()
	if err != nil {
		t.Fatal(err)
	}
	if err := segments.Delete(world.ctx, keys[0]); err != nil {
		t.Fatal(err)
	}
	m := world.format2Device("m")
	mirror := newWorldMirror(t, world, m)
	result, err := mirror.Sync(world.ctx)
	if err != nil {
		t.Fatal(err)
	}
	refId := world.mainRefId(m)
	ref, ok, err := mirror.Store().Ref(refId)
	if err != nil || (ok && ref.Version == world.head(refId).GetVersion()) {
		t.Fatalf("the ref raised to %+v over a lost segment", ref)
	}
	if result.MissingCount != 1 || result.ReplacedMissingCount != 0 {
		t.Fatalf("the sync: %+v", result)
	}
	coverage, err := mirror.Coverage(world.ctx)
	if err != nil || coverage.Full || coverage.MissingCount != 1 {
		t.Fatalf("coverage %+v %v", coverage, err)
	}
}
