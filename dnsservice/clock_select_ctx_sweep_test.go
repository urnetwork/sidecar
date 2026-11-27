package dnsservice_test

// The restore step's waits end with their context (clock-select-ctx-sweep). Each of its three polls, for the NS to
// serve restore_serial, for their diffs and for the interfaces' map reports, selected on ctx's end beside the poll's
// timer and the wait's bound, and went on whenever select took a timer as ctx ended: the NS poll read every NS's SOA
// again and could start a stopped NS on the dead context, the diff and map polls read their stores again, and a
// bound taken as ctx ended answered what it had as though the wait were over, so the step's later writes followed.
// Each now answers ctx's end whatever else was ready. The proof is sidecartest.EndingClock, which ends the step's
// context as a poll's timer fires, over 64 rounds; the stores and NS are restore_test.go's.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The zone store as the step reads it, counting its reads of the posted diffs, a dead context's included.
type clockSelectDiffCountingStore struct {
	dnsservice.DnsStore
	readCount atomic.Int64
}

func (self *clockSelectDiffCountingStore) ReloadDiffs(ctx context.Context, root string) ([]*dnsservice.DnsReloadDiff, error) {
	self.readCount.Add(1)
	return self.DnsStore.ReloadDiffs(ctx, root)
}

// A step over test's stores, store the zone's, and NS on clock, with maps as its custom-host map store when it is not
// nil.
func newClockSelectRestoreStep(t *testing.T, test *restoreTest, store dnsservice.DnsStore, clock *sidecartest.EndingClock, maps *sidecartest.FakeDnsCustomHostMapStore) *dnsservice.RestoreStep {
	t.Helper()
	deps := &dnsservice.RestoreStepDeps{
		Store:     store,
		Restore:   test.restore,
		SoaReader: test.ns,
		Clock:     clock,
	}
	if maps != nil {
		deps.CustomHostMaps = maps
	}
	step, err := dnsservice.NewRestoreStep(test.settings, deps)
	if err != nil {
		t.Fatal(err)
	}
	return step
}

// The poll's own clock: counting the polls alone, so the waits' bounds never fire.
func newClockSelectRestoreClock(test *restoreTest) *sidecartest.EndingClock {
	return sidecartest.NewEndingClock(test.clock.Now(), sidecartest.EndingClockCounts(time.Duration(test.settings.Restore.PollSeconds)*time.Second))
}

// The NS poll reads no SOA once ctx has ended: with ns2 silent and no NS state to keep, restoring waits for it, and
// an end landing as the second poll's timer fires ends the step with ctx's error after the six reads before it (two
// before the transaction, two at each of the two looks), in each of 64 rounds. A poll that took the timer's case read
// every NS again on the dead context, and would have started a stopped one that served.
func TestRestoreStepReadsNoSoaAfterItsContextEnds(t *testing.T) {
	for round := range 64 {
		test := newRestoreTest(t)
		test.restore.SetNsStateUnavailable(true)
		test.writeMany(t, 2)
		test.takeDump(t)
		test.loseAndLoad(t)
		test.ns.serve("ns1", 7)
		test.ns.follow("ns1", nil, nil)
		test.ns.silence("ns2")
		clock := newClockSelectRestoreClock(test)
		step := newClockSelectRestoreStep(t, test, test.store, clock, nil)
		ctx, cancel := context.WithCancel(t.Context())
		clock.Arm(2, cancel)
		clock.Open()
		_, err := step.Run(ctx, edgeTestRoot, sidecar.NewId())
		cancel()
		if reads, _ := test.ns.readCount.Get(); !errors.Is(err, context.Canceled) || reads != 6 || clock.Waits() != 2 {
			t.Fatalf("round %d: %v after %d SOA reads and %d polls, want the cancel after 6 reads and 2 polls", round, err, reads, clock.Waits())
		}
	}
}

// The diff poll reads nothing once ctx has ended: both NS serve restore_serial, ns2 posting no diff, so the step waits
// for it, and an end landing as the second poll's timer fires ends the step with ctx's error after the two reads and
// two polls, in each of 64 rounds. A poll that took the timer's case read the diffs again on the dead context, which a
// store that does not hold to ctx serves, and its answer would have led the step on.
func TestRestoreStepReadsNoDiffAfterItsContextEnds(t *testing.T) {
	for round := range 64 {
		test := newRestoreTest(t)
		test.writeMany(t, 2)
		test.takeDump(t)
		test.loseAndLoad(t)
		test.ns.serve("ns1", 7)
		test.ns.serve("ns2", 7)
		test.ns.follow("ns1", nil, nil)
		test.ns.follow("ns2", nil, nil)
		// ns2 reloads at restore_serial with its diff taken as posted, so none comes
		func() {
			test.ns.stateLock.Lock()
			defer test.ns.stateLock.Unlock()
			test.ns.posted["ns2"] = true
		}()
		clock := newClockSelectRestoreClock(test)
		store := &clockSelectDiffCountingStore{DnsStore: test.store}
		step := newClockSelectRestoreStep(t, test, store, clock, nil)
		ctx, cancel := context.WithCancel(t.Context())
		clock.Arm(2, cancel)
		clock.Open()
		progress, err := step.Run(ctx, edgeTestRoot, sidecar.NewId())
		cancel()
		// a read at the wait's start and one after the first poll
		if reads := store.readCount.Load(); !errors.Is(err, context.Canceled) || reads != 2 || clock.Waits() != 2 || progress == nil || progress.DiffCount != 1 {
			t.Fatalf("round %d: %+v, %v after %d diff reads and %d polls, want the cancel after 2 of each with 1 diff", round, progress, err, reads, clock.Waits())
		}
		if !test.state(t).Restoring {
			t.Fatalf("round %d: restoring cleared with a diff still owed", round)
		}
	}
}

// The map poll reads nothing once ctx has ended: no interface has reported the restored map, so the step waits for
// their reports, and an end landing as the second poll's timer fires ends the step with ctx's error after the two
// reads before it, in each of 64 rounds. A poll that took the timer's case read the reports again on the dead context.
func TestRestoreStepReadsNoMapReportAfterItsContextEnds(t *testing.T) {
	for round := range 64 {
		test := newRestoreMapTest(t)
		clock := newClockSelectRestoreClock(test.restoreTest)
		step := newClockSelectRestoreStep(t, test.restoreTest, test.store, clock, test.maps)
		ctx, cancel := context.WithCancel(t.Context())
		clock.Arm(2, cancel)
		clock.Open()
		progress, err := step.Run(ctx, edgeTestRoot, sidecar.NewId())
		cancel()
		if reads, _ := test.maps.RestoreReportReads(); !errors.Is(err, context.Canceled) || reads != 2 || clock.Waits() != 2 || progress == nil || progress.Done {
			t.Fatalf("round %d: %+v, %v after %d report reads and %d polls, want the cancel after 2 of each", round, progress, err, reads, clock.Waits())
		}
	}
}
