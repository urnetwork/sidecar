//go:build sidecar_testhooks

package dnsservice_test

import (
	"slices"
	"testing"
	"time"

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
	// a writer held at a barrier never parks again, so the clock moves only to its interval, which it
	// set when the swap handed it the newer view; the loop's hold, set then too, ends later
	writeDue := feed.edge.clock.Now().Add(time.Duration(feed.edge.settings.Feed.SnapshotWriteSeconds) * time.Second)
	feed.edge.awaitTimerAt(t, writeDue)
	feed.edge.clock.AdvanceTo(writeDue)
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}

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

// The loop's wait reads parked only from when its timer is set until the clock reaches its end. Held
// where it parks in its backoff after a failed poll, it reads parked with the backoff's end a timer
// set; once the clock reaches that end it reads woken, though it has not run. It used to read parked
// before the timer was set and on until it ran.
func TestFeedLoopWaitReadsParkedOnlyWhileItsTimerIsSet(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	feed := newTestFeed(t)
	scripted := newScriptedFeed()
	loop := feed.start(t, feed.deps(scripted, feed.edge), feed.edge)
	clock := feed.edge.clock
	loopIdle := func() bool {
		idle, _, _, _ := loop.IdleForTest(edgeTestRoot)
		return idle
	}
	site := "dnsservice.feed_wait"
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	scripted.queue(nil, errScriptedFeedDown)
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	backoffEnd := clock.Now().Add(time.Duration(feed.edge.settings.Feed.RetryMinSeconds) * time.Second)
	if !loopIdle() {
		t.Error("held where it parks, the loop reads busy")
	}
	if pending := clock.PendingTimers(); !slices.ContainsFunc(pending, backoffEnd.Equal) {
		t.Errorf("timers %v while parked in its backoff, want one at %v", pending, backoffEnd)
	}
	clock.AdvanceTo(backoffEnd)
	if loopIdle() {
		t.Error("past its backoff's end, a loop not yet run reads parked")
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}

// The writer reads woken, and so not parked, from its wait's end until it runs again: once a newer
// view is handed over while it waits for a change, and once the clock reaches the end of its interval.
// Held at each wait, it reads parked until then. It used to read parked until it ran, so a test moving
// the clock kept firing the loop's holds while a woken writer never ran.
func TestFeedLoopWriterReadsWokenBeforeItRuns(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	feed := newTestFeed(t)
	scripted := newScriptedFeed()
	clock := feed.edge.clock
	changeSite := "dnsservice.feed_writer_change"
	intervalSite := "dnsservice.feed_writer_interval"
	// armed before the loop starts, since its writer waits for a change at once
	if err := driver.Arm(changeSite, "", 0); err != nil {
		t.Fatal(err)
	}
	loop := feed.start(t, feed.deps(scripted, feed.edge), feed.edge)
	writerIdle := func() bool {
		_, _, idle, _ := loop.IdleForTest(edgeTestRoot)
		return idle
	}
	if err := driver.AwaitHeld(t.Context(), changeSite, ""); err != nil {
		t.Fatal(err)
	}
	if !writerIdle() {
		t.Error("waiting for a change, the writer reads busy")
	}

	scripted.queue(&dnsservice.DnsFeedAnswer{
		Format:    dnsservice.DnsFormat,
		Root:      edgeTestRoot,
		Serial:    1,
		Rows:      []dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 1, Upserts: edgeTestRows()}},
		KeyWindow: feed.edge.keys.window,
	}, nil)
	awaitServed(t, feed.edge, 1)
	// the view goes to the writer just after it serves, and then the loop parks in its next poll
	for {
		loopIdle, loopChanged, _, _ := loop.IdleForTest(edgeTestRoot)
		if loopIdle {
			break
		}
		select {
		case <-loopChanged:
		case <-t.Context().Done():
			t.Fatal("the loop never parked")
		}
	}
	if writerIdle() {
		t.Error("handed a newer view, a writer not yet run reads parked")
	}

	if err := driver.Arm(intervalSite, "", 0); err != nil {
		t.Fatal(err)
	}
	if err := driver.Release(changeSite); err != nil {
		t.Fatal(err)
	}
	if err := driver.AwaitHeld(t.Context(), intervalSite, ""); err != nil {
		t.Fatal(err)
	}
	writeDue := clock.Now().Add(time.Duration(feed.edge.settings.Feed.SnapshotWriteSeconds) * time.Second)
	if !writerIdle() {
		t.Error("waiting for its interval, the writer reads busy")
	}
	if pending := clock.PendingTimers(); !slices.ContainsFunc(pending, writeDue.Equal) {
		t.Errorf("timers %v while the writer waits, want one at %v", pending, writeDue)
	}
	clock.AdvanceTo(writeDue)
	if writerIdle() {
		t.Error("past its interval, a writer not yet run reads parked")
	}
	if err := driver.Release(intervalSite); err != nil {
		t.Fatal(err)
	}
	awaitWritten(t, loop, 1)
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}
