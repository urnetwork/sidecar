// ExportPushHistory (ABUSE-M5-17, §21.9) on T2's fakes: statements in order through the window and the log pages
// below it, each version's signer, client, time and token paths, and nothing decrypted: no slot, segment, gen or gkm
// object read, and no sealed metadata, sealed field or inline record in any row.

package evsservice

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A cluster that records the key of every read.
type exportHistoryRecordingCluster struct {
	sidecar.BlobCluster
	stateLock sync.Mutex
	readKeys  []string
}

func (self *exportHistoryRecordingCluster) note(key string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readKeys = append(self.readKeys, key)
}

func (self *exportHistoryRecordingCluster) Get(ctx context.Context, key string) (*sidecar.BlobObject, error) {
	self.note(key)
	return self.BlobCluster.Get(ctx, key)
}

func (self *exportHistoryRecordingCluster) GetRange(ctx context.Context, key string, offset int64, byteCount int64) (*sidecar.BlobObject, error) {
	self.note(key)
	return self.BlobCluster.GetRange(ctx, key, offset, byteCount)
}

func (self *exportHistoryRecordingCluster) Head(ctx context.Context, key string) (*sidecar.BlobInfo, error) {
	self.note(key)
	return self.BlobCluster.Head(ctx, key)
}

// Every key read, in order.
func (self *exportHistoryRecordingCluster) keys() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.readKeys...)
}

// The fixture's pushes exported: one row a version, oldest first, each naming its push, signer, client, time and the
// path it wrote; a version below the window read from its log page as a window version is from its record; one-part
// pushes' sizes read from their records; and no read of an object that holds a key or content.
func TestExportPushHistoryReadsStatementsInOrder(t *testing.T) {
	fixture := newPushFixture(t, nil)
	plan := fixture.plan()
	fixture.create(plan, "a")
	fixture.requireCommitted(fixture.push(plan), 1)
	plans := []*sidecar.EvsPushPlan{plan}
	// enough versions that the window pages out below its newest, so both readers are taken
	for version := uint64(2); EvsHeadWindowFirstVersion(fixture.head().Head) <= EvsLogPageVersionCount; version += 1 {
		next := fixture.plan()
		fixture.write(next, version-1, "a")
		fixture.requireCommitted(fixture.push(next), version)
		plans = append(plans, next)
	}
	fixture.awaitStepEights()
	head := fixture.head()
	if EvsHeadWindowFirstVersion(head.Head) <= 1 {
		t.Fatal("no version left the window")
	}

	cluster := &exportHistoryRecordingCluster{BlobCluster: fixture.cluster}
	rows := []*EvsPushHistoryRow{}
	export, err := ExportPushHistory(fixture.ctx, &EvsPushHistoryStores{Blobs: fixture.host.Blobs, Cluster: cluster}, fixture.check.repoId, nil, func(row *EvsPushHistoryRow) error {
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if export.RefCount != 1 || export.VersionCount != len(plans) || export.Truncated || len(rows) != len(plans) {
		t.Fatalf("export %+v with %d rows for %d pushes", export, len(rows), len(plans))
	}
	path := evsPushHistoryTokenPath(checkTestPath("a"))
	for index, row := range rows {
		plan := plans[index]
		if row.Version != uint64(index+1) || row.PushId != plan.PushId || row.SignerSidecarId != fixture.check.signerId ||
			row.ClientId != sidecar.Id(fixture.check.clientId) || row.TimeMs != plan.TimeMs ||
			row.RepoId != fixture.check.repoId || row.RefId != fixture.check.refId {
			t.Fatalf("row %d: %+v", index, row)
		}
		if row.ChangeCount != 1 || len(row.TokenPaths) != 1 || row.TokenPaths[0] != path || row.TokenPrefixes {
			t.Fatalf("row %d's paths: %+v", index, row)
		}
		if !row.SizesRead || row.Segments == nil || len(row.Segments) != 0 {
			t.Fatalf("row %d's sizes: %+v", index, row)
		}
	}

	// nothing a key or content lives in was read, and the pages were
	readPage := false
	for _, key := range cluster.keys() {
		for _, prefix := range []string{"slot/", "seg/", "gen/", "gkm/", "parcel/"} {
			if strings.HasPrefix(key, prefix) {
				t.Errorf("read %s", key)
			}
		}
		readPage = readPage || strings.HasPrefix(key, "log/")
	}
	if !readPage {
		t.Fatal("no log page read for the versions below the window")
	}
	// and no sealed byte reached a row
	rowBytes, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for _, sealed := range []string{"sealed metadata", "sealed fields", "inline record"} {
		if bytes.Contains(rowBytes, []byte(sealed)) {
			t.Errorf("a row holds %q", sealed)
		}
	}
}

// A ref past the version bound is cut and says so; an error from the writer stops the export.
func TestExportPushHistoryBoundsAndStops(t *testing.T) {
	fixture := newPushFixture(t, nil)
	for version := uint64(1); version <= 3; version += 1 {
		plan := fixture.plan()
		if version == 1 {
			fixture.create(plan, "a")
		} else {
			fixture.write(plan, version-1, "a")
		}
		fixture.requireCommitted(fixture.push(plan), version)
	}
	stores := &EvsPushHistoryStores{Blobs: fixture.host.Blobs, Cluster: fixture.cluster}
	settings := DefaultEvsPushHistorySettings()
	settings.RefVersionMaxCount = 2
	count := 0
	export, err := ExportPushHistory(fixture.ctx, stores, fixture.check.repoId, settings, func(row *EvsPushHistoryRow) error {
		count += 1
		return nil
	})
	if err != nil || !export.Truncated || export.VersionCount != 2 || count != 2 {
		t.Fatalf("a bounded export: %+v, %d rows, %v", export, count, err)
	}
	stop := sidecar.ErrBlobPrecondition
	_, err = ExportPushHistory(fixture.ctx, stores, fixture.check.repoId, nil, func(row *EvsPushHistoryRow) error {
		return stop
	})
	if err != stop {
		t.Fatalf("a writer's error: %v", err)
	}
	// a repo with no refs exports nothing
	export, err = ExportPushHistory(fixture.ctx, stores, testId("no such repo"), nil, func(row *EvsPushHistoryRow) error {
		t.Fatal("a row of no repo")
		return nil
	})
	if err != nil || export.RefCount != 0 || export.VersionCount != 0 {
		t.Fatalf("no repo: %+v %v", export, err)
	}
}
