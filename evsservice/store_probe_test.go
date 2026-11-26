// The readiness probe is a store check (§11.15's fan-out; owner decision 790): its LIST of place/ goes on a ctx
// sidecar.WithBlobProbe marks, which the file clusters send outside their cap on a host's connections, so it
// measures the store and not the block's queue for it, and a probe the store fails still reads not ready.

package evsservice

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A store whose first cluster records every List it is sent, as the next probeRecordingCluster says.
type probeRecordingBlobs struct {
	sidecar.BlobStore
	first *probeRecordingCluster
}

func (self *probeRecordingBlobs) FirstCluster() (sidecar.BlobCluster, error) {
	return self.first, nil
}

func (self *probeRecordingBlobs) Cluster(clusterId string) (sidecar.BlobCluster, error) {
	if clusterId == self.first.ClusterId() {
		return self.first, nil
	}
	return self.BlobStore.Cluster(clusterId)
}

// One List a cluster was sent, and whether its ctx was a store check's.
type probeRecordedList struct {
	keyPrefix string
	limit     int
	probe     bool
}

// A cluster that records each List and, while failing, fails every one, as a store that does not answer. Safe for
// concurrent use.
type probeRecordingCluster struct {
	sidecar.BlobCluster

	stateLock sync.Mutex
	lists     []probeRecordedList
	failing   bool
}

func (self *probeRecordingCluster) List(ctx context.Context, keyPrefix string, startAfter string, limit int) ([]*sidecar.BlobInfo, bool, error) {
	failing := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.lists = append(self.lists, probeRecordedList{keyPrefix: keyPrefix, limit: limit, probe: sidecar.BlobProbe(ctx)})
		return self.failing
	}()
	if failing {
		return nil, false, errors.New("the store does not answer")
	}
	return self.BlobCluster.List(ctx, keyPrefix, startAfter, limit)
}

func (self *probeRecordingCluster) setFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = failing
}

// The probes' Lists, each one key of place/, and every other List sent.
func (self *probeRecordingCluster) recordedLists() (probeLists []probeRecordedList, otherLists []probeRecordedList) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, list := range self.lists {
		if list.keyPrefix == sidecar.EvsPlaceKeyPrefix && list.limit == 1 {
			probeLists = append(probeLists, list)
		} else {
			otherLists = append(otherLists, list)
		}
	}
	return probeLists, otherLists
}

// Returns once the engine has finished probeCount probes.
func awaitEvsProbes(t *testing.T, engine *EvsEngine, probeCount int) {
	t.Helper()
	for {
		count, changed := engine.Probes()
		if probeCount <= count {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
}

// Each probe's LIST of place/ goes on a ctx sidecar.WithBlobProbe marks, and no other request of the engine's does;
// the engine is ready while the store answers, and once a probe finds it failing, it reads not ready.
func TestEvsEngineProbeIsAStoreCheck(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	serviceHost := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil).ServiceHost()
	first, err := serviceHost.Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	recorder := &probeRecordingCluster{BlobCluster: first}
	serviceHost.Blobs = &probeRecordingBlobs{BlobStore: serviceHost.Blobs, first: recorder}
	settings := DefaultEvsSettings()
	engine, err := NewEvsEngine(ctx, serviceHost, settings, &EvsEngineDeps{AuthState: newFakeAuthState()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)

	awaitEvsProbes(t, engine, 1)
	if !engine.Ready() {
		t.Fatal("not ready with its first cluster answering its probe")
	}
	recorder.setFailing(true)
	clock.Advance(settings.StoreProbeInterval)
	awaitEvsProbes(t, engine, 2)
	if engine.Ready() {
		t.Fatal("ready once its probe found the store failing")
	}

	probeLists, otherLists := recorder.recordedLists()
	if len(probeLists) < 2 {
		t.Fatalf("%d probe LISTs after two probes", len(probeLists))
	}
	for i, list := range probeLists {
		if !list.probe {
			t.Errorf("probe LIST %d went on a ctx that is no store check's", i)
		}
	}
	for _, list := range otherLists {
		if list.probe {
			t.Errorf("a LIST of %s, limit %d, went as a store check", list.keyPrefix, list.limit)
		}
	}
}
