package blobsuite

import (
	"crypto/md5"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/localstack"
)

// An S3 store in this process, as localstack's client reaches it, on clock. With honorsDeadline it
// refuses a request whose x-ur-deadline-ms has passed, as D-OPS-20's build does (§19.6's settle (1));
// without, it applies whatever reaches it, as a stock MinIO does.
type inProcessStore struct {
	clock          sidecartest.Clock
	honorsDeadline bool

	stateLock    sync.Mutex
	objects      map[string][]byte
	lateArrivals int
}

func (self *inProcessStore) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.Count(request.URL.Path, "/") == 1 {
		// the bucket
		return
	}
	body, _ := io.ReadAll(request.Body)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if deadline, err := strconv.ParseInt(request.Header.Get("X-Ur-Deadline-Ms"), 10, 64); err == nil && deadline <= self.clock.Now().UnixMilli() {
		self.lateArrivals += 1
		if self.honorsDeadline {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
	}
	etagOf := func(body []byte) string {
		sum := md5.Sum(body)
		return `"` + hex.EncodeToString(sum[:]) + `"`
	}
	key := request.URL.Path
	current, exists := self.objects[key]
	switch request.Method {
	case http.MethodPut:
		if request.Header.Get("If-None-Match") == "*" && exists {
			writer.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		if match := request.Header.Get("If-Match"); match != "" && (!exists || match != etagOf(current)) {
			writer.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		self.objects[key] = body
		writer.Header().Set("Etag", etagOf(body))
	case http.MethodGet:
		if !exists {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Etag", etagOf(current))
		writer.Header().Set("Last-Modified", self.clock.Now().UTC().Format(http.TimeFormat))
		writer.Write(current)
	case http.MethodDelete:
		delete(self.objects, key)
		writer.WriteHeader(http.StatusNoContent)
	}
}

// localstack's store on an inProcessStore, with the target its settle cases would run on.
func newInProcessTarget(t *testing.T, honorsDeadline bool) (*inProcessStore, *Target) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := &inProcessStore{clock: clock, honorsDeadline: honorsDeadline, objects: map[string][]byte{}}
	// CheckStackAddress takes loopback above 50000 only
	var listener net.Listener
	for listener == nil {
		candidate, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		if 50000 < candidate.Addr().(*net.TCPAddr).Port {
			listener = candidate
		} else {
			candidate.Close()
		}
	}
	server := &http.Server{Handler: store}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	settings := localstack.DefaultBlobSettings()
	settings.Endpoint = "http://" + listener.Addr().String()
	settings.Clock = clock
	blobs, err := localstack.NewBlobStore(t.Context(), settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(blobs.Close)
	clusterId := settings.MetadataClusters[0].ClusterId
	cluster, err := blobs.Cluster(clusterId)
	if err != nil {
		t.Fatal(err)
	}
	delayed, err := blobs.DelayedCluster(clusterId)
	if err != nil {
		t.Fatal(err)
	}
	return store, &Target{Cluster: cluster, Now: clock.Now, Settle: &Settle{Now: clock.Now, Delayed: delayed}}
}

// FS-114's "a request delayed in the network past its x-ur-deadline-ms is refused", through
// localstack's own client: on a store that takes late requests, each settle case fails, because its
// late requests reach the store. A client that cancels at the deadline first would let them pass.
func TestTheSettleCasesFailAStoreThatTakesLateRequests(t *testing.T) {
	for _, c := range settleCases() {
		store, target := newInProcessTarget(t, false)
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
			t.Errorf("%s passed on a store that takes late requests", c.name)
		}
		if store.lateArrivals == 0 {
			t.Errorf("%s: no late request reached the store", c.name)
		}
	}
}

// The twin: a store that refuses late requests passes both cases, and they did reach it.
func TestTheSettleCasesPassAStoreThatRefusesLateRequests(t *testing.T) {
	for _, c := range settleCases() {
		store, target := newInProcessTarget(t, true)
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if store.lateArrivals == 0 {
			t.Errorf("%s: no late request reached the store", c.name)
		}
	}
}

// A settle target with no delayed path claims nothing: its settle cases fail.
func TestASettleTargetWithNoDelayedPathFails(t *testing.T) {
	_, target := newInProcessTarget(t, true)
	target.Settle.Delayed = nil
	for _, c := range settleCases() {
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
			t.Errorf("%s passed with no delayed path", c.name)
		}
	}
}

// The delayed path must reach the cluster under test.
func TestASettleTargetsDelayedPathIsTheSameCluster(t *testing.T) {
	_, target := newInProcessTarget(t, true)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeBlobsSettings()
	settings.MetadataClusterIds = []string{"meta-9"}
	other, err := sidecartest.NewFakeBlobs(clock, nil, nil, settings).FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	target.Settle.Delayed = other
	if _, err := delayedCluster(target); err == nil {
		t.Error("a delayed path to another cluster was taken")
	}
}
