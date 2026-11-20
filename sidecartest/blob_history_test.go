package sidecartest

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

func sha256Of(body []byte) []byte {
	sum := sha256.Sum256(body)
	return sum[:]
}

type recordedFixture struct {
	*blobFixture
	recorder *BlobRecorder
	recorded sidecar.BlobCluster
}

func newRecordedFixture(t *testing.T) *recordedFixture {
	fixture := newBlobFixture(t)
	recorder := NewBlobRecorder(fixture.store, fixture.clock, nil)
	recorded, err := recorder.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	return &recordedFixture{blobFixture: fixture, recorder: recorder, recorded: recorded}
}

func TestRecorderKeepsEachRequestWithItsOutcome(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	etag, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v2"), nil); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Fatal(err)
	}
	if _, err := fixture.recorded.Head(ctx, "head/a/_"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.recorded.Head(ctx, "head/b/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatal(err)
	}

	history := fixture.recorder.History()
	want := []BlobOutcome{BlobOutcomeOk, BlobOutcomePrecondition, BlobOutcomeOk, BlobOutcomeNotFound}
	if len(history) != len(want) {
		t.Fatalf("history %v", history)
	}
	for i := range want {
		if history[i].Outcome != want[i] {
			t.Errorf("entry %d: %s", i, history[i])
		}
	}
	if history[0].WriteEtag != etag {
		t.Errorf("the recorder's etag %q, the store's %q", history[0].WriteEtag, etag)
	}
	if history[2].ReadEtag != etag {
		t.Errorf("read %q", history[2].ReadEtag)
	}
	if err := CheckBlobHistory(history, nil); err != nil {
		t.Error(err)
	}
}

func TestHistoryWithALostResponseHasAnOrder(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: ApplyThenDrop})
	if _, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil); err == nil {
		t.Fatal("the plan did not fire")
	}
	if _, err := fixture.recorded.Head(ctx, "head/a/_"); err != nil {
		t.Fatal(err)
	}
	if err := CheckBlobHistory(fixture.recorder.History(), nil); err != nil {
		t.Error(err)
	}
}

func TestHistoryWithAFailedRequestHasAnOrder(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: FailBeforeApply})
	if _, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil); err == nil {
		t.Fatal("the plan did not fire")
	}
	if _, err := fixture.recorded.Head(ctx, "head/a/_"); !errors.Is(err, sidecar.ErrBlobNotFound) {
		t.Fatal(err)
	}
	if err := CheckBlobHistory(fixture.recorder.History(), nil); err != nil {
		t.Error(err)
	}
}

func TestHistoryChecksConcurrentRequestsOnTheFake(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	etag, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v0"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for racer := range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			fixture.recorded.PutIfMatch(ctx, "head/a/_", etag, []byte{byte(racer)}, nil)
			fixture.recorded.Head(ctx, "head/a/_")
		}()
	}
	wait.Wait()
	if err := CheckBlobHistory(fixture.recorder.History(), nil); err != nil {
		t.Error(err)
	}
}

func historyAt(start time.Time, entries ...*BlobHistoryEntry) []*BlobHistoryEntry {
	for index, entry := range entries {
		entry.ClusterId = "meta-1"
		if entry.Key == "" {
			entry.Key = "head/a/_"
		}
		if entry.InvokeSeq == 0 {
			entry.InvokeSeq = uint64(2*index + 1)
			entry.ReturnSeq = uint64(2*index + 2)
		}
		if entry.Invoked.IsZero() {
			entry.Invoked = start
		}
	}
	return entries
}

// The check's reason to exist: each of these is a store breaking FI-30, and the check must say so.
func TestHistoryCheckRefusesWhatAStoreMayNotDo(t *testing.T) {
	start := DefaultClockStart()
	cases := []struct {
		name    string
		entries []*BlobHistoryEntry
	}{
		{name: "a read missing an acknowledged write", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryHead, Outcome: BlobOutcomeNotFound},
		)},
		{name: "a stale read after an overwrite", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryPutIfMatch, IfEtag: "e1", WriteEtag: "e2", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryGet, ReadEtag: "e1", Outcome: BlobOutcomeOk},
		)},
		{name: "two winners of one create", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e2", Outcome: BlobOutcomeOk},
		)},
		{name: "a stale etag passing", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryPutIfMatch, IfEtag: "e1", WriteEtag: "e2", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryPutIfMatch, IfEtag: "e1", WriteEtag: "e3", Outcome: BlobOutcomeOk},
		)},
		{name: "a precondition failing on a key that matched", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryPutIfMatch, IfEtag: "e1", WriteEtag: "e2", Outcome: BlobOutcomePrecondition},
		)},
		{name: "a resurrection after a delete", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryDelete, Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryHead, ReadEtag: "e1", Outcome: BlobOutcomeOk},
		)},
		{name: "a read of bytes nobody wrote", entries: historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryGet, ReadEtag: "e9", Outcome: BlobOutcomeOk},
		)},
	}
	for _, c := range cases {
		if err := CheckBlobHistory(c.entries, nil); err == nil {
			t.Errorf("%s passed", c.name)
		}
	}
}

// A write of unknown outcome may land late, but never past its deadline (§19.6): a read past the
// deadline that misses it means it never landed, so a later read cannot find it.
func TestHistoryLetsAnUnknownWriteLandOnlyBeforeItsDeadline(t *testing.T) {
	start := DefaultClockStart()
	deadline := start.Add(10 * time.Second)
	entries := func(missedAt time.Time, foundAt time.Time) []*BlobHistoryEntry {
		return historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeUnknown, Deadline: deadline},
			&BlobHistoryEntry{Op: BlobHistoryHead, Outcome: BlobOutcomeNotFound, Invoked: missedAt},
			&BlobHistoryEntry{Op: BlobHistoryHead, ReadEtag: "e1", Outcome: BlobOutcomeOk, Invoked: foundAt},
		)
	}
	if err := CheckBlobHistory(entries(start.Add(1*time.Second), start.Add(9*time.Second)), nil); err != nil {
		t.Errorf("landing within its deadline: %v", err)
	}
	// it may have landed just before the deadline, whenever a later read finds it
	if err := CheckBlobHistory(entries(start.Add(1*time.Second), start.Add(1*time.Hour)), nil); err != nil {
		t.Errorf("found after landing in time: %v", err)
	}
	if err := CheckBlobHistory(entries(deadline, start.Add(1*time.Hour)), nil); err == nil {
		t.Error("a write landed at its deadline")
	}
	if err := CheckBlobHistory(entries(start.Add(1*time.Minute), start.Add(1*time.Hour)), nil); err == nil {
		t.Error("a write landed past its deadline")
	}
}

func TestHistoryCheckLetsAnUnknownWriteNeverLand(t *testing.T) {
	start := DefaultClockStart()
	entries := historyAt(start,
		&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeUnknown, Deadline: start.Add(10 * time.Second)},
		&BlobHistoryEntry{Op: BlobHistoryHead, Outcome: BlobOutcomeNotFound, Invoked: start.Add(1 * time.Hour)},
	)
	if err := CheckBlobHistory(entries, nil); err != nil {
		t.Error(err)
	}
}

func TestHistoryCheckSeesAWriteIssuedPastItsDeadlineAsNothing(t *testing.T) {
	start := DefaultClockStart()
	entries := historyAt(start,
		&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeUnknown, Deadline: start},
		&BlobHistoryEntry{Op: BlobHistoryHead, ReadEtag: "e1", Outcome: BlobOutcomeOk},
	)
	if err := CheckBlobHistory(entries, nil); err == nil {
		t.Error("a read found a write no store took")
	}
}

func TestHistoryCheckStartsFromWhatAKeyHeld(t *testing.T) {
	start := DefaultClockStart()
	entries := historyAt(start,
		&BlobHistoryEntry{Op: BlobHistoryHead, ReadEtag: "e0", Outcome: BlobOutcomeOk},
	)
	if err := CheckBlobHistory(entries, map[string]string{"head/a/_": "e0"}); err != nil {
		t.Error(err)
	}
}

func TestHistoryCheckNamesTheKeyAndItsRequests(t *testing.T) {
	entries := historyAt(DefaultClockStart(),
		&BlobHistoryEntry{Op: BlobHistoryGet, ReadEtag: "e9", Outcome: BlobOutcomeOk, Actor: "evs1"},
	)
	err := CheckBlobHistory(entries, nil)
	if err == nil || !strings.Contains(err.Error(), "head/a/_") || !strings.Contains(err.Error(), "evs1") {
		t.Errorf("err %v", err)
	}
}

func TestHistoryOfAnInFlightWriteIsSeenAsUnknown(t *testing.T) {
	fixture := newRecordedFixture(t)
	fixture.arm(t, &FaultPlan{Op: FaultOpPut, Result: Delay})
	answered := make(chan error, 1)
	go func() {
		_, err := fixture.recorded.PutIfNoneMatch(t.Context(), "head/a/_", []byte("v1"), nil)
		answered <- err
	}()
	if err := fixture.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := CheckBlobHistory(fixture.recorder.History(), nil); err != nil {
		t.Errorf("mid-flight: %v", err)
	}
	if _, err := fixture.recorded.Head(t.Context(), "head/a/_"); err != nil {
		t.Fatal(err)
	}
	if err := <-answered; err != nil {
		t.Fatal(err)
	}
	if err := CheckBlobHistory(fixture.recorder.History(), nil); err != nil {
		t.Errorf("at the end: %v", err)
	}
}

// FI-30: none the store took past its deadline takes effect, so an acknowledgement of one is a store
// breaking it, whatever a later read finds.
func TestHistoryCheckRefusesAWriteAcknowledgedPastItsDeadline(t *testing.T) {
	start := DefaultClockStart()
	late := start.Add(-1 * time.Millisecond)
	for _, entries := range [][]*BlobHistoryEntry{
		historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk, Deadline: late},
			&BlobHistoryEntry{Op: BlobHistoryHead, ReadEtag: "e1", Outcome: BlobOutcomeOk},
		),
		historyAt(start,
			&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
			&BlobHistoryEntry{Op: BlobHistoryDelete, Outcome: BlobOutcomeOk, Deadline: late},
			&BlobHistoryEntry{Op: BlobHistoryHead, Outcome: BlobOutcomeNotFound},
		),
	} {
		err := CheckBlobHistory(entries, nil)
		if err == nil || !strings.Contains(err.Error(), "past its deadline") {
			t.Errorf("err %v", err)
		}
	}
}

// A read issued past its deadline is still an answer the store gave, and is held to it.
func TestHistoryCheckHoldsALateReadToWhatItSaw(t *testing.T) {
	start := DefaultClockStart()
	entries := historyAt(start,
		&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
		&BlobHistoryEntry{Op: BlobHistoryHead, Outcome: BlobOutcomeNotFound, Deadline: start.Add(-1 * time.Millisecond)},
	)
	if err := CheckBlobHistory(entries, nil); err == nil {
		t.Error("a late read missing an acknowledged write passed")
	}
}

func listEntry(listedKeyEtags map[string]string) *BlobHistoryEntry {
	return &BlobHistoryEntry{Op: BlobHistoryList, Key: "head/", ListedKeyEtags: listedKeyEtags, Outcome: BlobOutcomeOk}
}

// A LIST reads every key it covers, as a GET would (FI-30: as every request on its key sees it).
func TestHistoryCheckRefusesAWrongList(t *testing.T) {
	start := DefaultClockStart()
	put := func() *BlobHistoryEntry {
		return &BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk}
	}
	cases := []struct {
		name    string
		entries []*BlobHistoryEntry
	}{
		{name: "a LIST missing an acknowledged write", entries: historyAt(start, put(), listEntry(map[string]string{}))},
		{name: "a LIST showing a deleted key", entries: historyAt(start,
			put(),
			&BlobHistoryEntry{Op: BlobHistoryDelete, Outcome: BlobOutcomeOk},
			listEntry(map[string]string{"head/a/_": "e1"}),
		)},
		{name: "a LIST showing a stale etag", entries: historyAt(start,
			put(),
			&BlobHistoryEntry{Op: BlobHistoryPutIfMatch, IfEtag: "e1", WriteEtag: "e2", Outcome: BlobOutcomeOk},
			listEntry(map[string]string{"head/a/_": "e1"}),
		)},
	}
	for _, c := range cases {
		if err := CheckBlobHistory(c.entries, nil); err == nil {
			t.Errorf("%s passed", c.name)
		}
	}
}

// The twin: a LIST is held only to the keys it covers.
func TestHistoryCheckTakesAListThatCoversWhatItShould(t *testing.T) {
	start := DefaultClockStart()
	put := func() *BlobHistoryEntry {
		return &BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk}
	}
	pastTheKey := listEntry(map[string]string{})
	pastTheKey.StartAfter = "head/a/_"
	truncatedBeforeIt := listEntry(map[string]string{"head/0/_": "e0"})
	truncatedBeforeIt.ListTruncated = true
	otherPrefix := listEntry(map[string]string{})
	otherPrefix.Key = "seg/"
	failed := listEntry(nil)
	failed.Outcome = BlobOutcomeFailed
	for _, entries := range [][]*BlobHistoryEntry{
		historyAt(start, put(), listEntry(map[string]string{"head/a/_": "e1"})),
		historyAt(start, listEntry(map[string]string{}), put()),
		historyAt(start, put(), pastTheKey),
		historyAt(start, put(), truncatedBeforeIt),
		historyAt(start, put(), otherPrefix),
		historyAt(start, put(), failed),
	} {
		if err := CheckBlobHistory(entries, nil); err != nil {
			t.Error(err)
		}
	}
}

// What the recorder keeps of a LIST is what the check needs: what it listed, from where, and whether
// more followed. Changing that answer to show a deleted key fails the check.
func TestRecorderKeepsWhatAListAnswered(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	for _, key := range []string{"head/a/_", "head/b/_"} {
		if _, err := fixture.recorded.PutIfNoneMatch(ctx, key, []byte("v1"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := fixture.recorded.Delete(ctx, "head/a/_"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.recorded.List(ctx, "head/", "", 10); err != nil {
		t.Fatal(err)
	}
	history := fixture.recorder.History()
	list := history[len(history)-1]
	if list.Op != BlobHistoryList || len(list.ListedKeyEtags) != 1 || list.ListedKeyEtags["head/b/_"] == "" || list.ListTruncated {
		t.Fatalf("list entry %s %v", list, list.ListedKeyEtags)
	}
	if err := CheckBlobHistory(history, nil); err != nil {
		t.Fatal(err)
	}
	list.ListedKeyEtags = map[string]string{"head/a/_": history[0].WriteEtag, "head/b/_": list.ListedKeyEtags["head/b/_"]}
	if err := CheckBlobHistory(history, nil); err == nil {
		t.Error("a LIST showing a deleted key passed")
	}
}

// A copy History hands out is the caller's own, down to what a LIST listed: a caller building a mutant
// from its copy, as a check's twin does, changes no other copy.
func TestHistoryCopiesAreTheCallersOwn(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	if _, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.recorded.List(ctx, "head/", "", 10); err != nil {
		t.Fatal(err)
	}
	mutated := fixture.recorder.History()
	mutated[1].ListedKeyEtags["head/b/_"] = "e9"
	if listed := fixture.recorder.History()[1].ListedKeyEtags; len(listed) != 1 {
		t.Errorf("a change to one copy's LIST reached the recorder: %v", listed)
	}
}

// An oracle reads History while requests are in flight, as fault's Run does after every step, so a
// request's entry changes in two steps, each under the recorder's lock: begin publishes it with
// everything its call holds, and end writes its whole answer. Between them History holds each request
// as called, with none of its answer. A LIST's StartAfter once went in after begin had published it,
// which FS-1's T2 rows met under -race as a History copy read it.
func TestRecorderHoldsEachRequestWholeBetweenItsSteps(t *testing.T) {
	fixture := newRecordedFixture(t)
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	ctx := NewActorTable(fixture.clock, driver).Actor(t.Context(), "evs1").Context()
	// what History held of each request at each of its steps, by InvokeSeq
	stepEntries := map[uint64][]*BlobHistoryEntry{}
	fixture.recorder.stepHook = func(invokeSeq uint64) {
		for _, entry := range fixture.recorder.History() {
			if entry.InvokeSeq == invokeSeq {
				stepEntries[invokeSeq] = append(stepEntries[invokeSeq], entry)
			}
		}
	}

	// every op, each with every field its call sets
	etag, err := fixture.recorded.PutIfNoneMatch(ctx, "head/a/_", []byte("v1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.recorded.PutIfMatch(ctx, "head/a/_", etag, []byte("v2"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.recorded.PutStream(ctx, "seg/r/s", strings.NewReader("v1"), 2, sha256Of([]byte("v1"))); err != nil {
		t.Fatal(err)
	}
	object, err := fixture.recorded.Get(ctx, "head/a/_")
	if err != nil {
		t.Fatal(err)
	}
	object.Body.Close()
	object, err = fixture.recorded.GetRange(ctx, "head/a/_", 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	object.Body.Close()
	if _, err := fixture.recorded.Head(ctx, "head/a/_"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.recorded.List(ctx, "head/", "head/0/_", 10); err != nil {
		t.Fatal(err)
	}
	if err := fixture.recorded.Delete(sidecar.WithBlobUnmodified(ctx, fixture.clock.Now()), "seg/r/s"); err != nil {
		t.Fatal(err)
	}

	history := fixture.recorder.History()
	ops := []BlobHistoryOp{}
	for _, entry := range history {
		ops = append(ops, entry.Op)
	}
	wantOps := []BlobHistoryOp{
		BlobHistoryPutIfNoneMatch, BlobHistoryPutIfMatch, BlobHistoryPutStream, BlobHistoryGet,
		BlobHistoryGetRange, BlobHistoryHead, BlobHistoryList, BlobHistoryDelete,
	}
	if !slices.Equal(ops, wantOps) {
		t.Fatalf("ops %v, want %v", ops, wantOps)
	}
	// the fields a late write could miss are set, so a step missing one differs from the call
	for _, entry := range history {
		if entry.Actor != "evs1" || entry.Invoked.IsZero() || entry.Deadline.IsZero() != (entry.Op == BlobHistoryPutStream) {
			t.Errorf("%s: actor %q, invoked %v, deadline %v", entry, entry.Actor, entry.Invoked, entry.Deadline)
		}
	}
	if history[1].IfEtag != etag || history[6].StartAfter != "head/0/_" || len(history[6].ListedKeyEtags) != 1 || history[7].Unmodified.IsZero() {
		t.Errorf("if %q, start after %q, listed %v, unmodified %v", history[1].IfEtag, history[6].StartAfter, history[6].ListedKeyEtags, history[7].Unmodified)
	}

	for _, entry := range history {
		// the request as called: everything but its answer
		called := *entry
		called.ReadEtag = ""
		called.Outcome = ""
		called.ListedKeyEtags = nil
		called.ListTruncated = false
		called.ReturnSeq = 0
		called.Returned = time.Time{}
		steps := stepEntries[entry.InvokeSeq]
		if len(steps) != 2 {
			t.Errorf("%s: History looked at %d times, want at both its steps", entry, len(steps))
			continue
		}
		for index, step := range steps {
			if !reflect.DeepEqual(step, &called) {
				t.Errorf("%s at its step %d: History held\n  %+v\nwant\n  %+v", entry.Op, index+1, *step, called)
			}
		}
	}
	if err := CheckBlobHistory(history, nil); err != nil {
		t.Error(err)
	}
}

// A DELETE that named its object and got a 412 took no effect (§19.6): FI-30's oracle holds the next
// read to the object that stood, and refuses a history in which the refused DELETE removed it.
func TestHistoryTakesARefusedNamedDeleteAsNoEffect(t *testing.T) {
	fixture := newRecordedFixture(t)
	ctx := t.Context()
	if _, err := fixture.recorded.PutIfNoneMatch(ctx, "seg/r/s", []byte("v1"), nil); err != nil {
		t.Fatal(err)
	}
	older := sidecar.WithBlobUnmodified(ctx, fixture.clock.Now().Add(-49*time.Hour))
	if err := fixture.recorded.Delete(older, "seg/r/s"); !errors.Is(err, sidecar.ErrBlobPrecondition) {
		t.Fatalf("a DELETE naming an older object: %v", err)
	}
	if _, err := fixture.recorded.Head(ctx, "seg/r/s"); err != nil {
		t.Fatal(err)
	}
	if err := CheckBlobHistory(fixture.recorder.History(), nil); err != nil {
		t.Error(err)
	}

	start := DefaultClockStart()
	removed := historyAt(start,
		&BlobHistoryEntry{Op: BlobHistoryPutIfNoneMatch, WriteEtag: "e1", Outcome: BlobOutcomeOk},
		&BlobHistoryEntry{Op: BlobHistoryDelete, Outcome: BlobOutcomePrecondition},
		&BlobHistoryEntry{Op: BlobHistoryHead, Outcome: BlobOutcomeNotFound},
	)
	if err := CheckBlobHistory(removed, nil); err == nil {
		t.Error("a refused DELETE that removed its object passed")
	}
}
