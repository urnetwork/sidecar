package dnsservice_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The interfaces the feed tests' block names.
func feedTestInterfaces() []dnsservice.DnsLbInterface {
	return probeTestInterfaces()[:2]
}

// A TXT row at label under the network, for writes that show up in answers.
func feedTestTxt(label string, text string) dnsservice.DnsRecordSet {
	return dnsservice.DnsRecordSet{
		Owner: label + ".net1." + edgeTestRoot,
		Type:  dns.TypeTXT,
		Ttl:   300,
		Kind:  dnsservice.DnsRecordKindUser,
		Rdata: []string{`"` + text + `"`},
	}
}

// An edge, the fake store and feed it follows, and a loop between them, on one clock.
type testFeed struct {
	edge   *testEdge
	store  *sidecartest.FakeDnsStore
	feed   *sidecartest.FakeDnsFeed
	faults *sidecartest.FaultQueue
	dir    string

	stateLock  sync.Mutex
	interfaces [][]dnsservice.DnsLbInterface
}

// A store holding edgeTestRows at serial 1, and a feed naming the edge's window and two interfaces.
func newTestFeed(t testing.TB) *testFeed {
	t.Helper()
	settings := edgeTestSettings(t)
	settings.Rrl.ResponsesPerSecond = 1000
	edge := newTestEdge(t, settings)
	faults := sidecartest.NewFaultQueue()
	store := sidecartest.NewFakeDnsStore(edge.clock, faults)
	if err := store.EnsureRoot(t.Context(), edgeTestRoot); err != nil {
		t.Fatal(err)
	}
	feed := sidecartest.NewFakeDnsFeed(store, edge.clock, faults, nil)
	feed.SetKeyWindow(edge.keys.window)
	feed.SetInterfaces(feedTestInterfaces())
	self := &testFeed{edge: edge, store: store, feed: feed, faults: faults, dir: t.TempDir()}
	self.write(t, edgeTestRows(), nil)
	return self
}

// One write through the store, returning its serial.
func (self *testFeed) write(t testing.TB, upserts []dnsservice.DnsRecordSet, deletes []dnsservice.DnsRecordKey) uint64 {
	t.Helper()
	serial, err := self.store.Write(t.Context(), &dnsservice.DnsZoneWrite{Root: edgeTestRoot, Upserts: upserts, Deletes: deletes})
	if err != nil {
		t.Fatal(err)
	}
	return serial
}

// The deps a loop of this test takes, over feed.
func (self *testFeed) deps(feed dnsservice.DnsFeed, edge *testEdge) *dnsservice.FeedLoopDeps {
	return &dnsservice.FeedLoopDeps{
		Feed:              feed,
		Edge:              edge.edge,
		Zsk:               edge.keys.zsk,
		Anchors:           map[string][]*dns.DNSKEY{edgeTestRoot: edge.keys.anchors},
		SnapshotDirectory: self.dir,
		OnInterfaces: func(interfaces []dnsservice.DnsLbInterface) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.interfaces = append(self.interfaces, interfaces)
		},
	}
}

// Starts a loop of deps, closed when the test ends.
func (self *testFeed) start(t testing.TB, deps *dnsservice.FeedLoopDeps, edge *testEdge) *dnsservice.FeedLoop {
	t.Helper()
	loop, err := dnsservice.NewFeedLoop(t.Context(), edge.host.ServiceHost(), edge.settings, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(loop.Close)
	return loop
}

// Waits until edge serves at least serial.
func awaitServed(t testing.TB, edge *testEdge, serial uint64) {
	t.Helper()
	for {
		current, changed := edge.edge.ServedSerial(edgeTestRoot)
		if serial <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("served %d, want %d", current, serial)
		}
	}
}

// Waits until loop's local snapshot holds serial.
func awaitWritten(t testing.TB, loop *dnsservice.FeedLoop, serial uint64) {
	t.Helper()
	for {
		current, changed := loop.WrittenSerialForTest(edgeTestRoot)
		if current == serial {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("written %d, want %d", current, serial)
		}
	}
}

// Moves clock until done holds, and only while loop and its writer are parked and not yet woken, so
// time never runs ahead of work in hand, a slow fsync included. A writer a test holds at a barrier
// never parks again, so a test moves the clock past that itself.
//
// Each move goes to the nearest timer set, so it fires at least one, and with none set this waits
// for one, or for the loop or the writer to move, leaving the clock alone. The loop's poll still reads
// parked once the block's hold has woken it, so a move can come before the loop runs, but never more
// than the timers already set: the loop sets its next only once it runs. The helper used to move a
// second at a time whenever bare flags read parked, and they read so from a wake until the goroutine
// ran; on a loaded machine it spent every move before a woken goroutine got to run. Fails once done
// has not held within 200,000 s of fake time.
func advanceUntil(t testing.TB, clock *sidecartest.FakeClock, loop *dnsservice.FeedLoop, what string, done func() bool) {
	t.Helper()
	deadline := clock.Now().Add(200 * 1000 * time.Second)
	for !done() {
		loopIdle, loopChanged, writerIdle, writerChanged := loop.IdleForTest(edgeTestRoot)
		if !loopIdle || !writerIdle {
			select {
			case <-loopChanged:
			case <-writerChanged:
			case <-t.Context().Done():
				t.Fatalf("%s: the loop never parked", what)
			}
			continue
		}
		pending, added := clock.WatchTimers()
		if len(pending) == 0 {
			select {
			case <-added:
			case <-loopChanged:
			case <-writerChanged:
			case <-t.Context().Done():
				t.Fatalf("%s: no timer to move the clock to", what)
			}
			continue
		}
		if deadline.Before(pending[0]) {
			t.Fatalf("%s never held", what)
		}
		clock.AdvanceTo(pending[0])
	}
}

// What edge answers for a TXT at label, over UDP from a fresh socket.
func edgeTxt(t testing.TB, edge *testEdge, label string) []string {
	t.Helper()
	conn := edge.serveUdp(t)
	conn.send(t, edgeTestQuery(label+".net1."+edgeTestRoot, dns.TypeTXT, true), "198.51.100.1")
	reply, _ := conn.receive(t)
	texts := []string{}
	for _, record := range reply.Answer {
		if txt, ok := record.(*dns.TXT); ok {
			texts = append(texts, txt.Txt...)
		}
	}
	return texts
}

// Rows arrive in serial order and each swaps in whole, signed and checked; the interfaces the block
// names reach the prober's seam once each.
func TestFeedLoopServesRowsInSerialOrder(t *testing.T) {
	feed := newTestFeed(t)
	feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "one")}, nil)
	feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "two")}, nil)
	last := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("b", "three")}, nil)
	awaitServed(t, feed.edge, last)
	if texts := edgeTxt(t, feed.edge, "a"); !slices.Equal(texts, []string{"two"}) {
		t.Errorf("a %v", texts)
	}
	if texts := edgeTxt(t, feed.edge, "b"); !slices.Equal(texts, []string{"three"}) {
		t.Errorf("b %v", texts)
	}
	feed.stateLock.Lock()
	defer feed.stateLock.Unlock()
	if len(feed.interfaces) != 1 || len(feed.interfaces[0]) != 2 {
		t.Errorf("interfaces %v", feed.interfaces)
	}
}

// A local snapshot serves through a core outage: an edge restarted with the block unreachable serves
// the view the last one wrote, with its window and interfaces.
func TestFeedLoopServesItsLocalSnapshotWithTheCoreDown(t *testing.T) {
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	last := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "kept")}, nil)
	awaitServed(t, feed.edge, last)
	// Close writes what serves
	loop.Close()
	if written, _ := loop.WrittenSerialForTest(edgeTestRoot); written != last {
		t.Fatalf("written %d", written)
	}

	restarted := newTestEdge(t, feed.edge.settings)
	down := newScriptedFeed()
	down.failAll()
	feed.start(t, feed.deps(down, restarted), restarted)
	awaitServed(t, restarted, last)
	if texts := edgeTxt(t, restarted, "a"); !slices.Equal(texts, []string{"kept"}) {
		t.Errorf("a %v", texts)
	}
	feed.stateLock.Lock()
	defer feed.stateLock.Unlock()
	if len(feed.interfaces) != 2 || len(feed.interfaces[1]) != 2 {
		t.Errorf("the restarted edge's interfaces %v", feed.interfaces)
	}
}

// A view that fails the self-check never serves: the last good one keeps serving.
func TestFeedLoopKeepsServingWhenAViewFailsItsSelfCheck(t *testing.T) {
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	// a write taking the apex's SOA, which no view may serve without
	feed.write(t, nil, []dnsservice.DnsRecordKey{{Owner: edgeTestRoot, Type: dns.TypeSOA}})
	advanceUntil(t, feed.edge.clock, loop, "a failed self-check", func() bool {
		return feed.edge.host.Metrics.Value("urnetwork_dnsedge_self_checks_total", "fail") != 0
	})
	if serial, _ := feed.edge.edge.ServedSerial(edgeTestRoot); serial != 1 || !feed.edge.edge.Ready() {
		t.Errorf("served %d", serial)
	}
}

// Across a restore: the block answers reload once the restore transaction has run, the edge swaps in
// the snapshot at restore_serial whole, and the view it replaced, older than restore_serial, is kept
// until the block takes its diff, which names each RRset that differs.
func TestFeedLoopReloadsAcrossARestoreAndPostsItsDiff(t *testing.T) {
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	dump, err := feed.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	lost := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("lost", "after the dump")}, nil)
	awaitServed(t, feed.edge, lost)

	// every post fails until the plan is cleared, so the replaced snapshot stays. The loop posts again
	// at the top of its next turn, at once after the reload, so a plan for one post alone would leave
	// the check below racing that retry.
	if _, err := feed.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: sidecartest.FaultDnsFeedReloadDiff, Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	if err := feed.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	feed.store.LoadDump(edgeTestRoot, dump)
	restoreSerial, err := feed.store.CommitRestore(t.Context(), edgeTestRoot, sidecar.NewId(), lost)
	if err != nil {
		t.Fatal(err)
	}
	awaitServed(t, feed.edge, restoreSerial)
	if texts := edgeTxt(t, feed.edge, "lost"); len(texts) != 0 {
		t.Errorf("a record the restore lost %v", texts)
	}
	replacedPaths := func() []string {
		paths, err := filepath.Glob(filepath.Join(feed.dir, "zone.example", "replaced-*"))
		if err != nil {
			t.Fatal(err)
		}
		return paths
	}
	if paths := replacedPaths(); len(paths) != 1 {
		t.Errorf("replaced %v after a failed post", paths)
	}
	// the next post after the block takes them again, at the latest once the hold ends, lands
	feed.faults.Clear()
	var diffs []*dnsservice.DnsReloadDiff
	advanceUntil(t, feed.edge.clock, loop, "a posted diff", func() bool {
		diffs, err = feed.store.ReloadDiffs(t.Context(), edgeTestRoot)
		return err == nil && len(diffs) != 0
	})
	if len(diffs) != 1 || diffs[0].ReplacedSerial != lost || diffs[0].Serial != restoreSerial {
		t.Errorf("diffs %v", diffs)
	}
	want := []dnsservice.DnsRecordKey{{Owner: "lost.net1." + edgeTestRoot, Type: dns.TypeTXT}}
	if !slices.Equal(diffs[0].Rrsets, want) {
		t.Errorf("rrsets %v", diffs[0].Rrsets)
	}
	advanceUntil(t, feed.edge.clock, loop, "the replaced snapshot gone", func() bool {
		return len(replacedPaths()) == 0
	})
	if posted := feed.edge.host.Metrics.Value("urnetwork_dnsedge_reload_diffs_total", "posted"); posted != 1 {
		t.Errorf("posted %v", posted)
	}
}

// A replaced snapshot whose diff the block never takes is gone feed.replaced_keep_s after its reload.
func TestFeedLoopDeletesAReplacedSnapshotAtItsKeep(t *testing.T) {
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	dump, err := feed.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	lost := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("lost", "after the dump")}, nil)
	awaitServed(t, feed.edge, lost)
	if _, err := feed.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: sidecartest.FaultDnsFeedReloadDiff, Result: sidecartest.FailBeforeApply, Repeat: -1}); err != nil {
		t.Fatal(err)
	}
	if err := feed.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	feed.store.LoadDump(edgeTestRoot, dump)
	restoreSerial, err := feed.store.CommitRestore(t.Context(), edgeTestRoot, sidecar.NewId(), lost)
	if err != nil {
		t.Fatal(err)
	}
	awaitServed(t, feed.edge, restoreSerial)
	replaced := filepath.Join(feed.dir, "zone.example", "replaced-*")
	if paths, _ := filepath.Glob(replaced); len(paths) != 1 {
		t.Fatalf("replaced %v", paths)
	}
	feed.edge.clock.Advance(time.Duration(feed.edge.settings.Feed.ReplacedKeepSeconds-60) * time.Second)
	if paths, _ := filepath.Glob(replaced); len(paths) != 1 {
		t.Errorf("replaced %v before its keep", paths)
	}
	advanceUntil(t, feed.edge.clock, loop, "the replaced snapshot gone at its keep", func() bool {
		paths, _ := filepath.Glob(replaced)
		return len(paths) == 0
	})
	if expired := feed.edge.host.Metrics.Value("urnetwork_dnsedge_reload_diffs_total", "expired"); expired != 1 {
		t.Errorf("expired %v", expired)
	}
}

// A reload that is no restore's, after the journal's purge left a gap, replaces the view and keeps
// nothing of it: no replaced snapshot and no diff.
func TestFeedLoopKeepsNothingOfAViewAReloadWithNoRestoreReplaced(t *testing.T) {
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	loop.Close()

	feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "while away")}, nil)
	last := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("b", "while away")}, nil)
	if _, err := feed.store.PurgeJournal(t.Context(), edgeTestRoot, feed.edge.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	restarted := newTestEdge(t, feed.edge.settings)
	feed.start(t, feed.deps(feed.feed, restarted), restarted)
	awaitServed(t, restarted, last)
	if paths, _ := filepath.Glob(filepath.Join(feed.dir, "zone.example", "replaced-*")); len(paths) != 0 {
		t.Errorf("replaced %v", paths)
	}
	if diffs, _ := feed.store.ReloadDiffs(t.Context(), edgeTestRoot); len(diffs) != 0 {
		t.Errorf("diffs %v", diffs)
	}
	if reloads := restarted.host.Metrics.Value("urnetwork_dnsedge_feed_polls_total", "reload"); reloads != 1 {
		t.Errorf("reloads %v", reloads)
	}
}

// A local snapshot that does not read whole is discarded, and the edge stays not ready until the
// block gives it a view.
func TestFeedLoopDiscardsACorruptLocalSnapshot(t *testing.T) {
	feed := newTestFeed(t)
	directory := filepath.Join(feed.dir, "zone.example")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "snapshot.ndjson")
	if err := os.WriteFile(path, []byte(`{"format":1,"root":"zone.example.","serial":9}`+"\n"+`{"owner":`), 0o600); err != nil {
		t.Fatal(err)
	}
	down := newScriptedFeed()
	down.failAll()
	feed.start(t, feed.deps(down, feed.edge), feed.edge)
	down.awaitPolls(t, 1)
	if feed.edge.edge.Ready() {
		t.Error("ready on a corrupt snapshot")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the corrupt snapshot stayed: %v", err)
	}
	if refused := feed.edge.host.Metrics.Value("urnetwork_dnsedge_feed_refused_total", "malformed"); refused != 1 {
		t.Errorf("refused %v", refused)
	}
}

// --require-reload: a stopped NS serves nothing from its local snapshot, and serves again only once
// a reload has swapped in the block's; its local snapshot, older than restore_serial, is the replaced
// one whose diff goes to the block.
func TestFeedLoopRequireReloadServesOnlyFromAReload(t *testing.T) {
	feed := newTestFeed(t)
	loop := feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	dump, err := feed.store.TakeDump(edgeTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	lost := feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("lost", "after the dump")}, nil)
	awaitServed(t, feed.edge, lost)
	loop.Close()

	if err := feed.store.SetRestoring(t.Context(), edgeTestRoot, true); err != nil {
		t.Fatal(err)
	}
	feed.store.LoadDump(edgeTestRoot, dump)
	restoreSerial, err := feed.store.CommitRestore(t.Context(), edgeTestRoot, sidecar.NewId(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := feed.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: sidecartest.FaultDnsFeedSnapshot, Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	stopped := newTestEdge(t, feed.edge.settings)
	deps := feed.deps(feed.feed, stopped)
	deps.RequireReload = true
	stoppedLoop := feed.start(t, deps, stopped)
	advanceUntil(t, stopped.clock, stoppedLoop, "a snapshot asked for", func() bool {
		return len(feed.faults.Unfired()) == 0
	})
	if stopped.edge.Ready() {
		t.Error("a stopped NS served its local snapshot")
	}
	advanceUntil(t, stopped.clock, stoppedLoop, "a reload", stopped.edge.Ready)
	awaitServed(t, stopped, restoreSerial)
	if texts := edgeTxt(t, stopped, "lost"); len(texts) != 0 {
		t.Errorf("a record the restore lost %v", texts)
	}
	// the diff goes just after the swap
	var diffs []*dnsservice.DnsReloadDiff
	advanceUntil(t, stopped.clock, stoppedLoop, "a posted diff", func() bool {
		diffs, err = feed.store.ReloadDiffs(t.Context(), edgeTestRoot)
		return err == nil && len(diffs) != 0
	})
	if len(diffs) != 1 || diffs[0].ReplacedSerial != lost || diffs[0].Serial != restoreSerial {
		t.Errorf("diffs %v", diffs)
	}
}

// A new key window the block names swaps in once it passes the self-check, and one that fails leaves
// the window that serves.
func TestFeedLoopTakesAKeyWindowOnlyWhenItChecks(t *testing.T) {
	feed := newTestFeed(t)
	feed.start(t, feed.deps(feed.feed, feed.edge), feed.edge)
	awaitServed(t, feed.edge, 1)
	dnskeyExpiration := func() uint32 {
		conn := feed.edge.serveUdp(t)
		conn.send(t, edgeTestQuery(edgeTestRoot, dns.TypeDNSKEY, true), "198.51.100.1")
		reply, _ := conn.receive(t)
		for _, record := range reply.Answer {
			if rrsig, ok := record.(*dns.RRSIG); ok {
				return rrsig.Expiration
			}
		}
		t.Fatalf("no window signature %v", reply)
		return 0
	}
	keys := feed.edge.keys
	start := sidecartest.DefaultClockStart()
	bad := edgeTestWindow(t, edgeTestRoot, start.Add(-time.Hour), start.Add(20*24*time.Hour), edgeTestKey(t, edgeTestOtherHex), keys.kskRecord, keys.zskRecord)
	feed.feed.SetKeyWindow(bad)
	feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "one")}, nil)
	awaitServed(t, feed.edge, 2)
	if expiration := dnskeyExpiration(); expiration != uint32(keys.window.NotAfter.Unix()) {
		t.Errorf("a window that fails its check serves: %d", expiration)
	}
	good := edgeTestWindow(t, edgeTestRoot, start.Add(-time.Hour), start.Add(20*24*time.Hour), keys.ksk, keys.kskRecord, keys.zskRecord)
	feed.feed.SetKeyWindow(good)
	feed.write(t, []dnsservice.DnsRecordSet{feedTestTxt("a", "two")}, nil)
	awaitServed(t, feed.edge, 3)
	if expiration := dnskeyExpiration(); expiration != uint32(good.NotAfter.Unix()) {
		t.Errorf("a window that checks does not serve: %d", expiration)
	}
}

// Rows the feed never applies: a gap past the next serial, a serial at or below the one served, and a
// format this release does not read. Each is refused and counted, and the last good view serves.
func TestFeedLoopRefusesRowsItCannotApply(t *testing.T) {
	feed := newTestFeed(t)
	scripted := newScriptedFeed()
	loop := feed.start(t, feed.deps(scripted, feed.edge), feed.edge)
	answer := func(rows ...dnsservice.DnsJournalRow) *dnsservice.DnsFeedAnswer {
		return &dnsservice.DnsFeedAnswer{
			Format:    dnsservice.DnsFormat,
			Root:      edgeTestRoot,
			Serial:    100,
			Rows:      rows,
			KeyWindow: feed.edge.keys.window,
		}
	}
	row := func(serial uint64, format int, set dnsservice.DnsRecordSet) dnsservice.DnsJournalRow {
		return dnsservice.DnsJournalRow{Format: format, Root: edgeTestRoot, Serial: serial, Upserts: []dnsservice.DnsRecordSet{set}}
	}
	first := []dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 1, Upserts: edgeTestRows()}}
	scripted.queue(answer(first...), nil)
	awaitServed(t, feed.edge, 1)
	scripted.queue(answer(row(3, dnsservice.DnsFormat, feedTestTxt("gap", "x"))), nil)
	scripted.queue(answer(row(1, dnsservice.DnsFormat, feedTestTxt("lower", "x"))), nil)
	scripted.queue(answer(row(2, dnsservice.DnsFormat+1, feedTestTxt("newer", "x"))), nil)
	scripted.queue(answer(row(2, dnsservice.DnsFormat, feedTestTxt("good", "x"))), nil)
	advanceUntil(t, feed.edge.clock, loop, "the good row served", func() bool {
		serial, _ := feed.edge.edge.ServedSerial(edgeTestRoot)
		return serial == 2
	})
	metrics := feed.edge.host.Metrics
	for _, reason := range []string{"gap", "lower", "format"} {
		if refused := metrics.Value("urnetwork_dnsedge_feed_refused_total", reason); refused != 1 {
			t.Errorf("%s refused %v", reason, refused)
		}
	}
	for _, label := range []string{"gap", "lower", "newer"} {
		if texts := edgeTxt(t, feed.edge, label); len(texts) != 0 {
			t.Errorf("%s served %v", label, texts)
		}
	}
	if texts := edgeTxt(t, feed.edge, "good"); !slices.Equal(texts, []string{"x"}) {
		t.Errorf("good %v", texts)
	}
}

// advanceUntil moves the clock only to a timer set, and not at all while none is. The loop parks in a
// poll the block holds 7 s with the writer's first write done, so the hold's end is the one timer, and
// the clock reads its start and then that end. The helper used to move a second at a time on bare
// parked flags: on a loaded machine it spent all 200,000 moves before a woken loop ran, failing
// "... never held".
func TestAdvanceUntilMovesTheClockOnlyToATimerSet(t *testing.T) {
	feed := newTestFeed(t)
	scripted := newScriptedFeed()
	loop := feed.start(t, feed.deps(scripted, feed.edge), feed.edge)
	clock := feed.edge.clock
	scripted.queue(&dnsservice.DnsFeedAnswer{
		Format:    dnsservice.DnsFormat,
		Root:      edgeTestRoot,
		Serial:    1,
		Rows:      []dnsservice.DnsJournalRow{{Format: dnsservice.DnsFormat, Root: edgeTestRoot, Serial: 1, Upserts: edgeTestRows()}},
		KeyWindow: feed.edge.keys.window,
	}, nil)
	awaitServed(t, feed.edge, 1)
	// with the loop polling, the writer's interval is the one timer set; once it writes, it parks
	// with none
	if err := clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Duration(feed.edge.settings.Feed.SnapshotWriteSeconds) * time.Second)
	awaitWritten(t, loop, 1)

	start := clock.Now()
	holdEnd := start.Add(7 * time.Second)
	scripted.queueHeld(clock.After(holdEnd.Sub(start)), &dnsservice.DnsFeedAnswer{
		Format:    dnsservice.DnsFormat,
		Root:      edgeTestRoot,
		Serial:    1,
		KeyWindow: feed.edge.keys.window,
	})
	readings := []time.Time{}
	advanceUntil(t, clock, loop, "the held poll answered", func() bool {
		if now := clock.Now(); len(readings) == 0 || !readings[len(readings)-1].Equal(now) {
			readings = append(readings, now)
		}
		return feed.edge.host.Metrics.Value("urnetwork_dnsedge_feed_polls_total", "empty") == 1
	})
	if !slices.EqualFunc(readings, []time.Time{start, holdEnd}, time.Time.Equal) {
		t.Errorf("the clock read %d times, %v to %v, want %v and then the hold's end %v", len(readings), readings[0], readings[len(readings)-1], start, holdEnd)
	}
}

// RrsetDiff names each RRset in one view and not the other, or in both and changed, sorted.
func TestRrsetDiff(t *testing.T) {
	settings := edgeTestSettings(t)
	before := edgeTestView(t, settings, 5, append(edgeTestRows(), feedTestTxt("same", "x"), feedTestTxt("changed", "old"), feedTestTxt("gone", "x")))
	after := edgeTestView(t, settings, 9, append(edgeTestRows(), feedTestTxt("same", "x"), feedTestTxt("changed", "new"), feedTestTxt("added", "x")))
	diff := dnsservice.RrsetDiff(before, after)
	want := []dnsservice.DnsRecordKey{
		{Owner: "added.net1." + edgeTestRoot, Type: dns.TypeTXT},
		{Owner: "changed.net1." + edgeTestRoot, Type: dns.TypeTXT},
		{Owner: "gone.net1." + edgeTestRoot, Type: dns.TypeTXT},
	}
	if diff.Root != edgeTestRoot || diff.ReplacedSerial != 5 || diff.Serial != 9 || !slices.Equal(diff.Rrsets, want) {
		t.Errorf("diff %+v", diff)
	}
}

// One scripted answer, given only once hold fires when it has one.
type scriptedAnswer struct {
	answer *dnsservice.DnsFeedAnswer
	err    error
	hold   <-chan time.Time
}

// A DnsFeed a test drives: each poll takes the next answer queued, waiting for one, or fails at once
// once failAll is set. Snapshot and ReloadDiff fail.
type scriptedFeed struct {
	answers chan scriptedAnswer
	polls   *sidecar.MonitorValue[int]

	stateLock sync.Mutex
	failing   bool
}

func newScriptedFeed() *scriptedFeed {
	return &scriptedFeed{answers: make(chan scriptedAnswer, 64), polls: sidecar.NewMonitorValue(0)}
}

func (self *scriptedFeed) queue(answer *dnsservice.DnsFeedAnswer, err error) {
	self.answers <- scriptedAnswer{answer: answer, err: err}
}

// Queues answer for the poll that takes it to give once hold fires, as the block gives an answer at
// the end of its hold.
func (self *scriptedFeed) queueHeld(hold <-chan time.Time, answer *dnsservice.DnsFeedAnswer) {
	self.answers <- scriptedAnswer{answer: answer, hold: hold}
}

func (self *scriptedFeed) failAll() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.failing = true
}

// Waits until count polls have come in.
func (self *scriptedFeed) awaitPolls(t testing.TB, count int) {
	t.Helper()
	for {
		current, changed := self.polls.Get()
		if count <= current {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("polls %d", current)
		}
	}
}

var errScriptedFeedDown = errors.New("the block is down")

func (self *scriptedFeed) Journal(ctx context.Context, root string, after uint64) (*dnsservice.DnsFeedAnswer, error) {
	self.polls.Update(func(count int) int { return count + 1 })
	failing := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.failing
	}()
	if failing {
		return nil, errScriptedFeedDown
	}
	select {
	case answer := <-self.answers:
		if answer.hold != nil {
			select {
			case <-answer.hold:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return answer.answer, answer.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (self *scriptedFeed) Snapshot(ctx context.Context, root string) (dnsservice.DnsSnapshotRows, error) {
	return nil, errScriptedFeedDown
}

func (self *scriptedFeed) ReloadDiff(ctx context.Context, diff *dnsservice.DnsReloadDiff) error {
	return errScriptedFeedDown
}
