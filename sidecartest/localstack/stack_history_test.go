//go:build sidecar_localstack

package localstack

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// BlobRecorder wraps any store, so FI-30's check reads a real one's history as it reads a fake's:
// racing conditional writes on real drives have an order, and a read nobody could have seen has none.
func TestARealStoresHistoryPassesFi30AndAForgedOneFails(t *testing.T) {
	store := newStackBlobs(t)
	recorder := sidecartest.NewBlobRecorder(store, realClock{}, nil)
	cluster, err := recorder.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	key := "history/" + connect.NewId().String() + "/head/_"
	if _, err := cluster.PutIfNoneMatch(ctx, key, []byte("v0"), nil); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for racer := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for round := range 5 {
				info, err := cluster.Head(ctx, key)
				if err != nil {
					t.Error(err)
					return
				}
				body := fmt.Appendf(nil, "racer-%d-round-%d", racer, round)
				if _, err := cluster.PutIfMatch(ctx, key, info.Etag, body, nil); err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
					t.Error(err)
				}
			}
		}()
	}
	wait.Wait()
	if _, err := cluster.Head(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := cluster.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	history := recorder.History()
	if err := sidecartest.CheckBlobHistory(history, nil); err != nil {
		t.Fatalf("a real history has no order: %v", err)
	}
	winners := 0
	for _, entry := range history {
		if entry.Op == sidecartest.BlobHistoryPutIfMatch && entry.Outcome == sidecartest.BlobOutcomeOk {
			winners += 1
		}
	}
	if winners == 0 {
		t.Fatal("nobody won a race, so this proved nothing")
	}
	t.Logf("%d requests, %d conditional writes won", len(history), winners)

	last := slices.IndexFunc(history, func(entry *sidecartest.BlobHistoryEntry) bool {
		return entry.Op == sidecartest.BlobHistoryHead && entry.InvokeSeq == history[len(history)-2].InvokeSeq
	})
	if last < 0 {
		t.Fatal("no last read")
	}
	history[last].ReadEtag = "bytes-nobody-wrote"
	if err := sidecartest.CheckBlobHistory(history, nil); err == nil {
		t.Error("a forged read passed")
	}
}
