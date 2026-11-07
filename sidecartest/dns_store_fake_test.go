package sidecartest

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

const fakeDnsTestRoot = "zone.example."

func newFakeDnsTestStore(t *testing.T) (context.Context, *FakeClock, *FakeDnsStore) {
	t.Helper()
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeDnsStore(clock, nil)
	ctx := t.Context()
	if err := store.EnsureRoot(ctx, fakeDnsTestRoot); err != nil {
		t.Fatal(err)
	}
	return ctx, clock, store
}

func TestFakeDnsStoreConforms(t *testing.T) {
	RunDnsStoreSuite(t, NewFakeDnsStore(nil, nil))
}

// A caller's copy changing after a write changes nothing the store holds, and reads hand out copies.
func TestFakeDnsStoreSharesNothing(t *testing.T) {
	ctx, _, store := newFakeDnsTestStore(t)
	write := dnsSuiteWrite(fakeDnsTestRoot, "a", "one")
	if _, err := store.Write(ctx, write); err != nil {
		t.Fatal(err)
	}
	write.Upserts[0].Rdata[0] = `"changed"`
	read, err := store.Journal(ctx, fakeDnsTestRoot, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if read.Rows[0].Upserts[0].Rdata[0] != `"one"` {
		t.Errorf("journal row %+v", read.Rows[0])
	}
	read.Rows[0].Upserts[0].Rdata[0] = `"changed"`
	rows, err := store.Snapshot(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	sets, err := readAllDnsSnapshotRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 || sets[0].Rdata[0] != `"one"` {
		t.Errorf("snapshot %+v", sets)
	}
	read, err = store.Journal(ctx, fakeDnsTestRoot, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if read.Rows[0].Upserts[0].Rdata[0] != `"one"` {
		t.Errorf("journal row after a change to a read %+v", read.Rows[0])
	}
}

// Rows older than the bound go and younger ones stay, on the injected clock.
func TestFakeDnsStorePurgesByCommitTime(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one")); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7 * 24 * time.Hour)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "b", "two")); err != nil {
		t.Fatal(err)
	}
	purgedCount, err := store.PurgeJournal(ctx, fakeDnsTestRoot, clock.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if purgedCount != 1 {
		t.Errorf("purged %d rows", purgedCount)
	}
	read, err := store.Journal(ctx, fakeDnsTestRoot, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if read.Gap || len(read.Rows) != 1 {
		t.Errorf("read %+v", read)
	}
}

// The window §12.6 leaves for a lost raise: the row is committed and readable, the key is behind it.
func TestFakeDnsStoreLostRaiseLeavesAReadableRow(t *testing.T) {
	ctx, _, store := newFakeDnsTestStore(t)
	if _, err := store.Faults().Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: FaultDnsRaise, Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	serial, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one"))
	if err != nil {
		t.Fatal(err)
	}
	raised, err := store.RaisedSerial(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if serial != 1 || raised != 0 {
		t.Errorf("serial %d, raised %d", serial, raised)
	}
	if err := wantDnsJournalRows(ctx, store, fakeDnsTestRoot, 0, 1); err != nil {
		t.Error(err)
	}
}

// A crash between the commit and the raise: the call never returns, and the row stands.
func TestFakeDnsStoreCrashAfterCommitLeavesAReadableRow(t *testing.T) {
	ctx, _, store := newFakeDnsTestStore(t)
	if _, err := store.Faults().Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: FaultDnsWrite, Result: CrashAfterApply}); err != nil {
		t.Fatal(err)
	}
	returned := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one"))
		returned <- true
	}()
	<-done
	select {
	case <-returned:
		t.Error("the call returned past its crash")
	default:
	}
	if err := wantDnsSerial(ctx, store, fakeDnsTestRoot, 1); err != nil {
		t.Error(err)
	}
	raised, err := store.RaisedSerial(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if raised != 0 {
		t.Errorf("raised %d", raised)
	}
}

// §19.10's load: the serial and rows go back to the dump's, the journal is empty, and the key stays
// where it was, which is what the restore's max needs.
func TestFakeDnsStoreLoadDump(t *testing.T) {
	ctx, _, store := newFakeDnsTestStore(t)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "dumped")); err != nil {
		t.Fatal(err)
	}
	dump, err := store.TakeDump(fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "lost")); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRestoring(ctx, fakeDnsTestRoot, true); err != nil {
		t.Fatal(err)
	}
	store.LoadDump(fakeDnsTestRoot, dump)
	state, err := store.RootState(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if state.Serial != 1 || !state.Restoring {
		t.Errorf("state %+v", state)
	}
	if err := wantDnsJournalRows(ctx, store, fakeDnsTestRoot, 0, 0); err != nil {
		t.Error(err)
	}
	raised, err := store.RaisedSerial(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if raised != 2 {
		t.Errorf("raised %d", raised)
	}
	rows, err := store.Snapshot(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	sets, err := readAllDnsSnapshotRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 || sets[0].Rdata[0] != `"dumped"` {
		t.Errorf("rows %+v", sets)
	}
	restoreSerial, err := store.CommitRestore(ctx, fakeDnsTestRoot, sidecar.NewId(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if restoreSerial != 2+dnsservice.DnsRestoreSerialJump {
		t.Errorf("restore serial %d", restoreSerial)
	}
}

func TestFakeDnsFeedAnswersRowsAtOnce(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	interfaces := []dnsservice.DnsLbInterface{{Name: "edge-1/eth0", Ipv4: netip.MustParseAddr("192.0.2.10")}}
	feed.SetInterfaces(interfaces)
	feed.SetKeyWindow(&dnsservice.DnsKeyWindow{Root: fakeDnsTestRoot})
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one")); err != nil {
		t.Fatal(err)
	}
	answer, err := feed.Journal(ctx, fakeDnsTestRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := answer.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(answer.Rows) != 1 || answer.Serial != 1 || answer.Reload {
		t.Errorf("answer %+v", answer)
	}
	if len(answer.Interfaces) != 1 || answer.Interfaces[0].Name != "edge-1/eth0" || answer.KeyWindow == nil {
		t.Errorf("answer %+v", answer)
	}
}

// Starts a poll, returning what it answers, once it has reached its hold.
func startFakeDnsPoll(t *testing.T, ctx context.Context, clock *FakeClock, feed *FakeDnsFeed, after uint64) <-chan *dnsservice.DnsFeedAnswer {
	t.Helper()
	answers := make(chan *dnsservice.DnsFeedAnswer, 1)
	go func() {
		answer, err := feed.Journal(ctx, fakeDnsTestRoot, after)
		if err != nil {
			t.Error(err)
		}
		answers <- answer
	}()
	if err := clock.AwaitTimers(ctx, len(clock.PendingTimers())+1); err != nil {
		t.Fatal(err)
	}
	return answers
}

func TestFakeDnsFeedHoldEndsOnARaise(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	answers := startFakeDnsPoll(t, ctx, clock, feed, 0)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one")); err != nil {
		t.Fatal(err)
	}
	if answer := <-answers; answer == nil || len(answer.Rows) != 1 {
		t.Errorf("answer %+v", answer)
	}
}

func TestFakeDnsFeedHoldEndsEmpty(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	answers := startFakeDnsPoll(t, ctx, clock, feed, 0)
	clock.Advance(25 * time.Second)
	if answer := <-answers; answer == nil || len(answer.Rows) != 0 || answer.Reload {
		t.Errorf("answer %+v", answer)
	}
}

// A lost raise costs one hold and no write.
func TestFakeDnsFeedHoldEndCatchesALostRaise(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	if _, err := store.Faults().Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: FaultDnsRaise, Result: FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	answers := startFakeDnsPoll(t, ctx, clock, feed, 0)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one")); err != nil {
		t.Fatal(err)
	}
	select {
	case answer := <-answers:
		t.Errorf("the poll ended with no raise: %+v", answer)
	default:
	}
	clock.Advance(25 * time.Second)
	if answer := <-answers; answer == nil || len(answer.Rows) != 1 {
		t.Errorf("answer %+v", answer)
	}
}

func TestFakeDnsFeedHoldEndsWithItsContext(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	pollCtx, cancel := context.WithCancel(ctx)
	errs := make(chan error, 1)
	go func() {
		_, err := feed.Journal(pollCtx, fakeDnsTestRoot, 0)
		errs <- err
	}()
	if err := clock.AwaitTimers(ctx, 1); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-errs; !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

// Reading 8: a caller ahead of a restored database holds, and is never told to reload down.
func TestFakeDnsFeedHoldsACallerAhead(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one")); err != nil {
		t.Fatal(err)
	}
	answers := startFakeDnsPoll(t, ctx, clock, feed, 50)
	clock.Advance(25 * time.Second)
	if answer := <-answers; answer == nil || answer.Reload || len(answer.Rows) != 0 {
		t.Errorf("answer %+v", answer)
	}
}

func TestFakeDnsFeedReloadsAfterAGap(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	if _, err := dnsSuiteWrites(ctx, store, fakeDnsTestRoot, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PurgeJournal(ctx, fakeDnsTestRoot, dnsSuiteFarFuture); err != nil {
		t.Fatal(err)
	}
	answer, err := feed.Journal(ctx, fakeDnsTestRoot, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Reload || len(answer.Rows) != 0 {
		t.Errorf("answer %+v", answer)
	}
}

// Reading 8: a caller below a loaded dump's serial waits for the restore's transaction, then reloads.
func TestFakeDnsFeedReloadWaitsForTheRestoreTransaction(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	if _, err := dnsSuiteWrites(ctx, store, fakeDnsTestRoot, 2); err != nil {
		t.Fatal(err)
	}
	dump, err := store.TakeDump(fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetRestoring(ctx, fakeDnsTestRoot, true); err != nil {
		t.Fatal(err)
	}
	store.LoadDump(fakeDnsTestRoot, dump)
	answers := startFakeDnsPoll(t, ctx, clock, feed, 1)
	clock.Advance(25 * time.Second)
	if answer := <-answers; answer == nil || answer.Reload {
		t.Errorf("a reload before the transaction: %+v", answer)
	}
	restoreSerial, err := store.CommitRestore(ctx, fakeDnsTestRoot, sidecar.NewId(), 0)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := feed.Journal(ctx, fakeDnsTestRoot, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Reload || answer.RestoreSerial != restoreSerial {
		t.Errorf("answer %+v", answer)
	}
}

func TestFakeDnsFeedSnapshotAndDiffReachTheStore(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	feed := NewFakeDnsFeed(store, clock, nil, nil)
	if _, err := store.Write(ctx, dnsSuiteWrite(fakeDnsTestRoot, "a", "one")); err != nil {
		t.Fatal(err)
	}
	rows, err := feed.Snapshot(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if serial := rows.Snapshot().Serial; serial != 1 {
		t.Errorf("snapshot at %d", serial)
	}
	sets, err := readAllDnsSnapshotRows(rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 {
		t.Errorf("rows %+v", sets)
	}
	diff := &dnsservice.DnsReloadDiff{
		Root:   fakeDnsTestRoot,
		Serial: 1,
		Rrsets: []dnsservice.DnsRecordKey{{Owner: "a." + fakeDnsTestRoot, Type: dns.TypeTXT}},
	}
	if err := feed.ReloadDiff(ctx, diff); err != nil {
		t.Fatal(err)
	}
	diffs, err := store.ReloadDiffs(ctx, fakeDnsTestRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(diffs) != 1 {
		t.Errorf("diffs %+v", diffs)
	}
}

func TestFakeDnsFeedTakesItsFaults(t *testing.T) {
	ctx, clock, store := newFakeDnsTestStore(t)
	faults := NewFaultQueue()
	feed := NewFakeDnsFeed(store, clock, faults, nil)
	for _, key := range []string{FaultDnsFeedJournal, FaultDnsFeedSnapshot, FaultDnsFeedReloadDiff} {
		if _, err := faults.Add(&FaultPlan{Op: FaultOpHost, KeyPrefix: key, Result: FailBeforeApply}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := feed.Journal(ctx, fakeDnsTestRoot, 0); !errors.Is(err, errHostTransport) {
		t.Errorf("Journal: %v", err)
	}
	if _, err := feed.Snapshot(ctx, fakeDnsTestRoot); !errors.Is(err, errHostTransport) {
		t.Errorf("Snapshot: %v", err)
	}
	if err := feed.ReloadDiff(ctx, &dnsservice.DnsReloadDiff{Root: fakeDnsTestRoot}); !errors.Is(err, errHostTransport) {
		t.Errorf("ReloadDiff: %v", err)
	}
}
