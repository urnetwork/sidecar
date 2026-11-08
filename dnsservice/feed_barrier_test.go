//go:build sidecar_testhooks

package dnsservice_test

import (
	"testing"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The local snapshot at its hardest moment: the writer held between the new file's fsync and its
// rename, where a crash would stop it. The edge already serves the newer view; a restart there reads the
// older snapshot whole at its serial, and removes the write the crash left. Once the writer goes on,
// its next write lands the newer view.
func TestFeedLoopCrashBetweenFsyncAndRenameRecoversAConsistentSerial(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	written := func(serial uint64) func() bool {
		return func() bool {
			current, _ := loop.WrittenSerialForTest(edgeTestRoot)
			return current == serial
		}
	}
	advanceUntil(t, feed.edge.clock, loop, "the first write", written(1))

	site := "dnsservice.snapshot_write"
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	newer := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "newer")}, nil)
	awaitServed(t, feed.edge, newer)
	// the writer is held, never parked, so only the loop gates the clock here
	advanceWhileParked(t, feed.edge.clock, loop, false, "the writer held", func() bool {
		return len(driver.HeldSites()) != 0
	})

	restarted, err := dnsservice.NewSnapshotFile(feed.dir+"/zone.example", edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := restarted.Load(feed.edge.settings)
	if err != nil {
		t.Fatal(err)
	}
	if saved.View.Serial() != 1 {
		t.Errorf("a restart mid-write reads serial %d", saved.View.Serial())
	}

	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	advanceUntil(t, feed.edge.clock, loop, "the newer write", written(newer))
	saved, err = restarted.Load(feed.edge.settings)
	if err != nil || saved.View.Serial() != newer {
		t.Errorf("after the writer went on %+v %v", saved, err)
	}
	if failed := feed.edge.host.Metrics.Value("urnetwork_dnsedge_snapshot_writes_total", "failed"); failed != 1 {
		t.Errorf("failed writes %v", failed)
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}
