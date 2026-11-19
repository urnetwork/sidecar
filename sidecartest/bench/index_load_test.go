//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !windows

package bench

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The driver at reduced scale: two writers at 20 pushes a second for a second.
func benchSmallIndexLoad(t *testing.T) *IndexLoad {
	settings := DefaultIndexLoadSettings()
	settings.WriterCount = 2
	settings.PushRate = 20
	settings.WordsPerFile = 20
	load, err := NewIndexLoad(settings)
	if err != nil {
		t.Fatal(err)
	}
	return load
}

// A leg with the index off and one with in-ref indexing each commit their content pushes over the store and drain; the
// indexed leg's pushes carry their writers' index writes, which the off leg's never count.
func TestIndexLoadRunsTheOffAndIndexedLegs(t *testing.T) {
	load := benchSmallIndexLoad(t)
	defer load.Close()
	store := sidecartest.NewFakeBlobs(sidecar.RealClock{}, nil, nil, nil)
	ctx := context.Background()
	off, offEvents, offDrained, err := load.RunLeg(ctx, store, "off", []string{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if off[IndexLoadContentInRef] == 0 || len(offEvents) != 0 || !offDrained {
		t.Fatalf("the off leg: %v %v drained %v", off, offEvents, offDrained)
	}
	indexed, events, drained, err := load.RunLeg(ctx, store, "indexed", []string{IndexLoadClassIndexed}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if indexed[IndexLoadContentInRef] == 0 || !drained {
		t.Fatalf("the indexed leg: %v drained %v", indexed, drained)
	}
	if events[IndexLoadEventIndexed] == 0 || indexed[IndexLoadContentInRef] < events[IndexLoadEventIndexed] {
		t.Fatalf("the indexed leg's %d content pushes carried %d indexed ones", indexed[IndexLoadContentInRef], events[IndexLoadEventIndexed])
	}
}

// A class the driver does not run fails its leg before anything reaches the store, naming why: no leg reads a class
// as costing nothing.
func TestIndexLoadRefusesAClassItDoesNotRun(t *testing.T) {
	load := benchSmallIndexLoad(t)
	store := sidecartest.NewFakeBlobs(sidecar.RealClock{}, nil, nil, nil)
	for _, class := range []string{IndexLoadClassCompanion, IndexLoadClassRollup, IndexLoadClassCut, IndexLoadClassRewrite, IndexLoadClassMigration} {
		content, events, drained, err := load.RunLeg(context.Background(), store, class, []string{IndexLoadClassIndexed, class}, time.Second)
		if !errors.Is(err, ErrIndexLoadUnbuilt) || len(content) != 0 || len(events) != 0 || drained {
			t.Errorf("%s: %v %v %v %v", class, content, events, drained, err)
		}
	}
	first, err := store.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	if objects, _, err := first.List(context.Background(), "", "", 10); err != nil || len(objects) != 0 {
		t.Errorf("a refused leg wrote %d objects: %v", len(objects), err)
	}
}
