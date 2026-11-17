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
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/localstack"
)

// An S3 store in this process, as localstack's client reaches it. With honorsDeadline it refuses a
// request whose x-ur-deadline-ms has passed by its own clock, as D-OPS-20's build does (§19.6's settle
// (1)); without, it applies whatever reaches it, as a stock MinIO does. Its own clock runs clockBehind
// behind clock, the suite's, as a store host's runs on another machine's clock than the suite's.
type inProcessStore struct {
	clock          sidecartest.Clock
	clockBehind    time.Duration
	honorsDeadline bool

	stateLock sync.Mutex
	objects   map[string][]byte
	// requests that reached the store past their deadline by the suite's clock, whatever the store's
	// own clock said of them
	lateArrivals int
}

func (self *inProcessStore) now() time.Time {
	return self.clock.Now().Add(-self.clockBehind)
}

func (self *inProcessStore) lateArrivalCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lateArrivals
}

func (self *inProcessStore) objectCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.objects)
}

func (self *inProcessStore) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.Count(request.URL.Path, "/") == 1 {
		// the bucket
		return
	}
	body, _ := io.ReadAll(request.Body)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if deadline, err := strconv.ParseInt(request.Header.Get("X-Ur-Deadline-Ms"), 10, 64); err == nil {
		if deadline <= self.clock.Now().UnixMilli() {
			self.lateArrivals += 1
		}
		if self.honorsDeadline && deadline <= self.now().UnixMilli() {
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
		writer.Header().Set("Last-Modified", self.now().UTC().Format(http.TimeFormat))
		writer.Write(current)
	case http.MethodDelete:
		delete(self.objects, key)
		writer.WriteHeader(http.StatusNoContent)
	}
}

// localstack's store on an inProcessStore, with the target its settle cases would run on: DefaultSettle's,
// reading the suite's clock.
func newInProcessTarget(t *testing.T, honorsDeadline bool, clockBehind time.Duration) (*inProcessStore, *Target) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	store := &inProcessStore{clock: clock, clockBehind: clockBehind, honorsDeadline: honorsDeadline, objects: map[string][]byte{}}
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
	return store, &Target{Cluster: cluster, Now: store.now, Settle: newTestSettle(clock.Now, delayed)}
}

// FS-114's "a request delayed in the network past its x-ur-deadline-ms is refused", through
// localstack's own client: on a store that takes late requests, each settle case fails, because its
// late requests reach the store. A client that cancels at the deadline first would let them pass.
func TestTheSettleCasesFailAStoreThatTakesLateRequests(t *testing.T) {
	for _, c := range settleCases() {
		store, target := newInProcessTarget(t, false, 0)
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
			t.Errorf("%s passed on a store that takes late requests", c.name)
		}
		if store.lateArrivalCount() == 0 {
			t.Errorf("%s: no late request reached the store", c.name)
		}
	}
}

// The twin: a store that refuses late requests passes both cases, and they did reach it.
func TestTheSettleCasesPassAStoreThatRefusesLateRequests(t *testing.T) {
	for _, c := range settleCases() {
		store, target := newInProcessTarget(t, true, 0)
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if store.lateArrivalCount() == 0 {
			t.Errorf("%s: no late request reached the store", c.name)
		}
	}
}

// QD-892: a store that refuses late requests by its own clock passes both cases while that clock trails
// the suite's by no more than LateBy: by 2 ms, as T3's hosts on docker's VM clock trailed this machine's;
// by 100 ms, the most two clocks §19.6's clock rule holds within 50 ms of true time can differ; and by
// LateBy itself, where the deadline is the store's now, which has passed.
func TestTheSettleCasesPassAStoreWhoseClockTrailsWithinLateBy(t *testing.T) {
	lateBy := DefaultSettle().LateBy
	for _, clockBehind := range []time.Duration{2 * time.Millisecond, 100 * time.Millisecond, lateBy} {
		for _, c := range settleCases() {
			store, target := newInProcessTarget(t, true, clockBehind)
			if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err != nil {
				t.Errorf("a clock %v behind: %s: %v", clockBehind, c.name, err)
			}
			if store.lateArrivalCount() == 0 {
				t.Errorf("a clock %v behind: %s: no late request reached the store", clockBehind, c.name)
			}
		}
	}
}

// The twin: a store whose clock trails the suite's by more than LateBy takes a request sent LateBy late,
// and fails both cases, as does any store that takes a request that late.
func TestTheSettleCasesFailAStoreThatTakesARequestLateByLate(t *testing.T) {
	clockBehind := DefaultSettle().LateBy + 1*time.Millisecond
	for _, c := range settleCases() {
		store, target := newInProcessTarget(t, true, clockBehind)
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
			t.Errorf("%s passed on a store that takes a request LateBy late", c.name)
		}
		if store.lateArrivalCount() == 0 {
			t.Errorf("%s: no late request reached the store", c.name)
		}
	}
}

// QD-892's failure, reproduced: a request sent 1 ms late by the suite's clock, as the cases sent one
// before LateBy, is on time by a store clock 2 ms behind, so a store that keeps the rule takes it and
// fails the cases.
func TestARequestOneMillisecondLateFailsAStoreWhoseClockTrails(t *testing.T) {
	for _, c := range settleCases() {
		store, target := newInProcessTarget(t, true, 2*time.Millisecond)
		target.Settle.LateBy = 1 * time.Millisecond
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
			t.Errorf("%s passed with a request 1 ms late on a store clock 2 ms behind, which takes it as on time", c.name)
		}
		if store.lateArrivalCount() == 0 {
			t.Errorf("%s: no late request reached the store", c.name)
		}
	}
}

// A settle target that sends no request late claims nothing: with LateBy zero or negative both cases
// fail before they write.
func TestASettleTargetWithNoLateByFails(t *testing.T) {
	for _, lateBy := range []time.Duration{0, -1 * time.Millisecond} {
		for _, c := range settleCases() {
			store, target := newInProcessTarget(t, true, 0)
			target.Settle.LateBy = lateBy
			if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
				t.Errorf("a LateBy of %v: %s passed", lateBy, c.name)
			}
			if count := store.objectCount(); count != 0 {
				t.Errorf("a LateBy of %v: %s wrote %d objects", lateBy, c.name, count)
			}
		}
	}
}

// A settle target with no delayed path claims nothing: its settle cases fail.
func TestASettleTargetWithNoDelayedPathFails(t *testing.T) {
	_, target := newInProcessTarget(t, true, 0)
	target.Settle.Delayed = nil
	for _, c := range settleCases() {
		if err := c.run(t.Context(), target, &keySpace{prefix: "settle/" + c.name + "/"}); err == nil {
			t.Errorf("%s passed with no delayed path", c.name)
		}
	}
}

// The delayed path must reach the cluster under test.
func TestASettleTargetsDelayedPathIsTheSameCluster(t *testing.T) {
	_, target := newInProcessTarget(t, true, 0)
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
