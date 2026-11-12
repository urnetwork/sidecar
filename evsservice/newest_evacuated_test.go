// QD-664 (question evs1-m2-41-newest-evacuated-window): a window version's record that hourly evacuation moved is
// read through pidx/ by every RecordPushSource, as read_proof.go's readRecordAt reads a statement, and cached so a
// process lists pidx/ for it once: the newest rule's read of a ref idle past 25 h, and a fold's read of every part of
// a push in parts, on a process that never cached them. Every caller of NewRecordPushSource passes its process's
// locator, which TestEveryRecordPushSourceReadsThroughALocator holds to the source.

package evsservice

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Moves every record the ref's window names, each seal's parts with it, into one parcel and its pidx/ entries, then
// deletes their batches, as hourly evacuation does 25 h on (§11.13, I-EVS-7: the container, then its entries, then
// the deletes), so a process that never cached them finds them only through pidx/. The parcel's key, for a test that
// then takes it away.
func evacuateWindowForTest(t *testing.T, ctx context.Context, blobs sidecar.BlobStore, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead) string {
	t.Helper()
	ctx = sidecar.WithWriteClass(ctx, sidecar.WriteClassP2)
	window, err := EvsHeadWindow(head)
	if err != nil {
		t.Fatal(err)
	}
	first := EvsHeadWindowFirstVersion(head)
	records := []*ContainerRecord{}
	batchKeys := map[string]bool{}
	move := func(version uint64, place *protocol.EvsPlace) *sidecar.EvsBatchRecord {
		recordBytes, err := readBlobRange(ctx, cluster, PlaceBatchKey(place), int64(place.GetOffset()), int64(place.GetLength()))
		if err != nil {
			t.Fatal(err)
		}
		record, err := sidecar.ParseEvsBatchRecord(recordBytes)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, &ContainerRecord{RefId: refId, Version: version, Place: place, Bytes: recordBytes})
		batchKeys[PlaceBatchKey(place)] = true
		return record
	}
	for i, entry := range window {
		version := first + uint64(i)
		record := move(version, entry.Place)
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
			continue
		}
		_, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range parts {
			move(version, part.Place)
		}
	}
	container, err := BuildContainer(protocol.EvsContainerKind_EVS_CONTAINER_PARCEL, records, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteContainer(ctx, blobs, cluster, repoId, container); err != nil {
		t.Fatal(err)
	}
	for key := range batchKeys {
		if err := cluster.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
	}
	return container.Key(repoId)
}

// The newest rule over a window whose records evacuation moved: with no locator the moved record answers
// ErrEvsRecordEvacuated, as every read did before QD-664; through the process's locator it answers the path's newest,
// and a second source on the same cache reads it with no pidx/ LIST. A record no container holds either is
// ErrEvsRecordEvacuated and the locator's ErrBlobNotFound alike.
func TestRecordPushSourceReadsAMovedWindowRecordThroughPidx(t *testing.T) {
	world := newEvsWorld(t)
	a := worldPath("a")
	world.push(&worldChange{path: a, version: 1})
	world.push(&worldChange{path: a, base: 1, version: 2})
	world.push(&worldChange{path: worldPath("b"), version: 1})
	head := world.head.Head
	parcelKey := evacuateWindowForTest(t, world.ctx, world.host.Blobs, world.cluster, world.repoId, world.refId, head)
	read, err := ReadEntry(world.ctx, world.cluster, world.repoId, world.refId, 1, a, head.GetFoldedThrough())
	if err != nil {
		t.Fatal(err)
	}
	source := func(cache *RecordCache, locator *RecordLocator) *RecordPushSource {
		return NewRecordPushSource(cache, locator, world.cluster, world.repoId, world.refId)
	}
	if _, err := Newest(world.ctx, read, head, source(NewRecordCache(world.settings), nil)); !errors.Is(err, ErrEvsRecordEvacuated) {
		t.Fatalf("batches alone: %v", err)
	}
	cache := NewRecordCache(world.settings)
	locator := NewRecordLocator(world.host.Blobs, nil)
	newest, err := Newest(world.ctx, read, head, source(cache, locator))
	if err != nil || !newest.Exists || newest.Version != 2 || newest.CommitVersion != 2 || !newest.FromWindow {
		t.Fatalf("through pidx/: %+v %v", newest, err)
	}
	lists := world.host.Blobs.RequestCount("meta-1", string(sidecartest.FaultOpList))
	if newest, err = Newest(world.ctx, read, head, source(cache, NewRecordLocator(world.host.Blobs, nil))); err != nil || newest.Version != 2 {
		t.Fatalf("from the cache: %+v %v", newest, err)
	}
	if after := world.host.Blobs.RequestCount("meta-1", string(sidecartest.FaultOpList)); after != lists {
		t.Errorf("%d LISTs for records the cache holds", after-lists)
	}

	// a record neither a batch nor a container holds
	paidCtx := sidecar.WithWriteClass(world.ctx, sidecar.WriteClassP2)
	pidx, _, err := world.cluster.List(world.ctx, PidxRefPrefix(world.repoId, world.refId), "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range pidx {
		if err := world.cluster.Delete(paidCtx, object.Key); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.cluster.Delete(paidCtx, parcelKey); err != nil {
		t.Fatal(err)
	}
	_, err = Newest(world.ctx, read, head, source(NewRecordCache(world.settings), NewRecordLocator(world.host.Blobs, nil)))
	if !errors.Is(err, ErrEvsRecordEvacuated) || !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatalf("a record nothing holds: %v", err)
	}
}

// A fold on a process that never cached a push in parts reads its seal and every part through pidx/ once evacuation
// moved them, allChangesAt's parts among them, and folds each path, where before it stopped at the first moved part.
func TestFoldReadsAPushInPartsEvacuationMovedThroughPidx(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	if len(built.Parts) < 2 {
		t.Fatalf("%d parts", len(built.Parts))
	}
	fixture.requireCommitted(fixture.seal(token, built, fixture.postParts(token, built)), 1)
	fixture.awaitStepEights()
	evacuateWindowForTest(t, fixture.ctx, fixture.host.Blobs, fixture.cluster, fixture.check.repoId, fixture.check.refId, fixture.head().Head)
	blobs := fixture.engine.Blobs()
	priceTable, err := DefaultPriceTable(fixture.settings.PriceBlockByteCount)
	if err != nil {
		t.Fatal(err)
	}
	log := sidecar.NewNoopLogger()
	folder := NewFolder(fixture.ctx, fixture.clock, fixture.host.ClockCheck, blobs, fixture.host.Budget,
		NewHeadStore(fixture.clock, fixture.host.ClockCheck, fixture.host.Redis, fixture.settings, log), NewRecordCache(fixture.settings), nil,
		NewRepoCache(fixture.clock, fixture.settings), priceTable, fixture.settings, log)
	cluster, err := blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	result, err := folder.Fold(fixture.ctx, &EvsFoldRequest{Cluster: cluster, RepoId: fixture.check.repoId, RefId: fixture.check.refId, Rank: sidecar.WriteP2RankFold})
	if err != nil || result.Superseded || result.Through != 1 || result.EntryWriteCount < 1100 {
		t.Fatalf("the fold: %+v %v", result, err)
	}
	for _, label := range []string{"file-00000", "file-00600", "file-01099"} {
		read := fixture.entryAt(1, label)
		if read.Entry == nil || len(read.Entry.GetVersions()) != 1 || read.Entry.GetVersions()[0].GetCommitVersion() != 1 {
			t.Fatalf("%s: %v", label, read.Entry)
		}
	}
}

// Every NewRecordPushSource in evsservice's code names a locator, so no caller reads a moved record as gone (QD-664):
// the newest rule's, a fold's, a page-out's, a copy's, a marker collection's, a purge's and step 4's.
func TestEveryRecordPushSourceReadsThroughALocator(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	callCount := 0
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "NewRecordPushSource" {
				return true
			}
			callCount += 1
			if len(call.Args) != 5 {
				t.Errorf("%s: NewRecordPushSource of %d arguments", path, len(call.Args))
				return true
			}
			if locator, ok := call.Args[1].(*ast.Ident); ok && locator.Name == "nil" {
				t.Errorf("%s: a record source with no locator", path)
			}
			return true
		})
	}
	if callCount < 9 {
		t.Errorf("%d calls of NewRecordPushSource found", callCount)
	}
}
