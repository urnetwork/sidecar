// T2's MxEdgeStore: Postgres in memory, until MAIL-M7-21's model.NewMxEdgeStore. Calls go through
// hostCall, so a plan under FaultOpHost with the key "mxedge.Ping" or "mxedge.InsertConnectionRecords"
// reaches them, and each is counted, so a test can show the connection path never called one, what
// DenyPostgresForTest shows on real stores (§22.5). Safe for concurrent use.

package sidecartest

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
)

var _ mxedgeservice.MxEdgeStore = (*FakeMxEdgeStore)(nil)

// Rows and call counts, in memory.
type FakeMxEdgeStore struct {
	faults *FaultQueue

	stateLock sync.Mutex
	records   []*mxedgeservice.MxConnectionRecord
	opCounts  map[string]int
}

// A nil faults takes a fresh queue.
func NewFakeMxEdgeStore(faults *FaultQueue) *FakeMxEdgeStore {
	if faults == nil {
		faults = NewFaultQueue()
	}
	return &FakeMxEdgeStore{faults: faults, opCounts: map[string]int{}}
}

// One call through the fake's fault and count.
func (self *FakeMxEdgeStore) call(ctx context.Context, method string, serve func()) error {
	return hostCall(ctx, self.faults, method, func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.opCounts[method] += 1
		serve()
		return nil
	})
}

// Answers unless a plan says otherwise.
func (self *FakeMxEdgeStore) Ping(ctx context.Context) error {
	return self.call(ctx, "mxedge.Ping", func() {})
}

// Keeps a copy of each row, so a caller reusing its batch changes nothing here.
func (self *FakeMxEdgeStore) InsertConnectionRecords(ctx context.Context, records []*mxedgeservice.MxConnectionRecord) error {
	return self.call(ctx, "mxedge.InsertConnectionRecords", func() {
		for _, record := range records {
			kept := *record
			self.records = append(self.records, &kept)
		}
	})
}

// Every row written, oldest first, as copies.
func (self *FakeMxEdgeStore) Records() []*mxedgeservice.MxConnectionRecord {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	records := make([]*mxedgeservice.MxConnectionRecord, 0, len(self.records))
	for _, record := range self.records {
		kept := *record
		records = append(records, &kept)
	}
	return records
}

// How often each method ran, by its fault key.
func (self *FakeMxEdgeStore) OpCounts() map[string]int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return maps.Clone(self.opCounts)
}

// Starts counting from zero, so a test can measure one path.
func (self *FakeMxEdgeStore) ResetOpCounts() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.opCounts)
}

// networkId's rows starting at since or later, as copies: RunMxEdgeStoreSuite's reader.
func (self *FakeMxEdgeStore) ReadRecords(ctx context.Context, networkId sidecar.Id, since time.Time) ([]*mxedgeservice.MxConnectionRecord, error) {
	records := []*mxedgeservice.MxConnectionRecord{}
	for _, record := range self.Records() {
		if record.NetworkId == networkId && !record.StartTime.Before(since) {
			records = append(records, record)
		}
	}
	return records, nil
}
