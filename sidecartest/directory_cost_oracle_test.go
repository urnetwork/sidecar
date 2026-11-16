//go:build !ios_extension

package sidecartest

import (
	"context"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// Runs the days at the Team limit and at 5,000 members with a following daemon on the real client, which folds the
// day's entries at every sync and takes minutes at 2,000 members and far longer at 5,000, and the stress case's cold
// desktop and cold phone, which take minutes more. Without it the Team limit's day runs its writers, the oracle over
// every reader, the cold desktop and the cold phone, and the stress case's its writers and the oracle alone.
var directoryLoadFull = flag.Bool("directory-load-full", false, "run the 2,000 and 5,000 member directory days with a real following daemon")

// 2027-01-15T08:00:00Z, which a plan moves on to the next UTC midnight.
const directoryLoadTestStartMillis = int64(1_800_000_000_000)

func directoryCostTestCost(requestCount int64, pathReadCount int64, byteCount int64) *DirectoryCost {
	return &DirectoryCost{RequestCount: requestCount, PathReadCount: pathReadCount, ByteCount: byteCount}
}

// The one reader-day of costs, failing the test when there is not exactly one.
func directoryCostTestOnlyDay(t *testing.T, costs *DirectoryCosts) *DirectoryCost {
	t.Helper()
	if len(costs.ReaderDays) != 1 {
		t.Fatalf("%d reader-days, not one", len(costs.ReaderDays))
	}
	for _, cost := range costs.ReaderDays {
		return cost
	}
	return nil
}

func directoryCostTestExpect(t *testing.T, what string, got *DirectoryCost, want *DirectoryCost) {
	t.Helper()
	if got == nil || *got != *want {
		t.Fatalf("%s: %v, not %v", what, got, want)
	}
}

// By hand, with a statement at 800 bytes and a listed ref at 64. Two writers; the reader syncs after the first two
// versions and again after a third and a notice.
//
//	first   cards: 1 request, 1 path read, nothing after the pin
//	        listing: every ref, the two streams: 1 request, 1 path read, 128 bytes
//	        streams: both in one request, 2 path reads, 2 x (800 + 1,500) bytes
//	        = 3 requests, 4 path reads, 4,728 bytes
//	later   cards: 1 request, 1 + 1 path reads, 800 + 256 bytes
//	        listing: the refs that moved, one stream and the cards ref: 1 request, 1 path read, 128 bytes
//	        streams: 1 request, 1 path read, 800 + 1,000 bytes
//	        = 3 requests, 4 path reads, 2,984 bytes
func TestDirectoryCostOracleCountsAFirstAndALaterSync(t *testing.T) {
	writerA := sidecar.NewId()
	writerB := sidecar.NewId()
	events := []*DirectoryCostEvent{
		{TimeMillis: 1000, Kind: DirectoryCostEventStream, WriterSidecarId: writerA, ByteCount: 1500},
		{TimeMillis: 2000, Kind: DirectoryCostEventStream, WriterSidecarId: writerB, ByteCount: 1500},
		{TimeMillis: 3000, Kind: DirectoryCostEventStream, WriterSidecarId: writerA, ByteCount: 1000},
		{TimeMillis: 4000, Kind: DirectoryCostEventNotice, ByteCount: 256},
	}
	oracle := NewDirectoryCostOracle(nil)
	readerId := sidecar.NewId()

	first, err := oracle.Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: []int64{2500}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "the first sync", directoryCostTestOnlyDay(t, first), directoryCostTestCost(3, 4, 4728))

	both, err := oracle.Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: []int64{2500, 5000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "both syncs", directoryCostTestOnlyDay(t, both), directoryCostTestCost(6, 8, 7712))

	// an event at a sync's own time is seen by that sync
	atOnce, err := oracle.Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: []int64{2000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "a sync at an event's time", directoryCostTestOnlyDay(t, atOnce), directoryCostTestCost(3, 4, 4728))
}

// 130 writers with one version of 100 bytes each, read cold: the cards ref and the listing are a request each, and
// the streams go 64, 64 and 2 to a request. 5 requests; 1 + 1 + 130 path reads; 130 x 64 listed bytes and
// 130 x 900 read.
func TestDirectoryCostOracleReadsStreamsSixtyFourToARequest(t *testing.T) {
	events := []*DirectoryCostEvent{}
	for i := range 130 {
		events = append(events, &DirectoryCostEvent{TimeMillis: int64(i + 1), Kind: DirectoryCostEventStream, WriterSidecarId: sidecar.NewId(), ByteCount: 100})
	}
	costs, err := NewDirectoryCostOracle(nil).Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: sidecar.NewId(), SyncMillis: []int64{1000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "130 streams", directoryCostTestOnlyDay(t, costs), directoryCostTestCost(5, 132, 130*64+130*900))
}

// One writer with 150 versions of 10 bytes, read cold: the stream answers 64 versions and more twice, so it is asked
// three times. 1 + 1 + 3 requests; 1 + 1 + 150 path reads; 64 listed bytes and 150 x 810 read.
func TestDirectoryCostOracleAsksAgainForAStreamPastAFrame(t *testing.T) {
	writerId := sidecar.NewId()
	events := []*DirectoryCostEvent{}
	for i := range 150 {
		events = append(events, &DirectoryCostEvent{TimeMillis: int64(i + 1), Kind: DirectoryCostEventStream, WriterSidecarId: writerId, ByteCount: 10})
	}
	costs, err := NewDirectoryCostOracle(nil).Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: sidecar.NewId(), SyncMillis: []int64{1000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "150 versions of one stream", directoryCostTestOnlyDay(t, costs), directoryCostTestCost(5, 152, 64+150*810))
}

// The same stream with a window of 100 versions and log pages of 40: the read answers behind, and the reader pages
// the log four times. 1 + 1 + 1 + 4 requests; 1 + 1 + 150 + 4 path reads; the same bytes.
func TestDirectoryCostOraclePagesAStreamBehindItsWindow(t *testing.T) {
	settings := DefaultDirectoryCostOracleSettings()
	settings.StreamWindowVersionCount = 100
	settings.StreamLogPageCount = 40
	writerId := sidecar.NewId()
	events := []*DirectoryCostEvent{}
	for i := range 150 {
		events = append(events, &DirectoryCostEvent{TimeMillis: int64(i + 1), Kind: DirectoryCostEventStream, WriterSidecarId: writerId, ByteCount: 10})
	}
	costs, err := NewDirectoryCostOracle(settings).Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: sidecar.NewId(), SyncMillis: []int64{1000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "a stream behind its window", directoryCostTestOnlyDay(t, costs), directoryCostTestCost(7, 156, 64+150*810))
}

// One version on day 0, then two syncs on day 1 with nothing new: the day's first lists every ref, 64 bytes for the
// one stream, and the second lists only what moved, nothing. Day 0 is 3 requests, 3 path reads and 64 + 800 + 500
// bytes; day 1 is 4 requests, 4 path reads and 64 bytes.
func TestDirectoryCostOracleListsEveryRefAtADaysFirstSync(t *testing.T) {
	dayMillis := (24 * time.Hour).Milliseconds()
	readerId := sidecar.NewId()
	costs, err := NewDirectoryCostOracle(nil).Expected(&DirectoryCostSchedule{
		Events:  []*DirectoryCostEvent{{TimeMillis: 1000, Kind: DirectoryCostEventStream, WriterSidecarId: sidecar.NewId(), ByteCount: 500}},
		Readers: []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: []int64{2000, dayMillis + 1000, dayMillis + 2000}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(costs.ReaderDays) != 2 {
		t.Fatalf("%d reader-days, not two", len(costs.ReaderDays))
	}
	directoryCostTestExpect(t, "day 0", costs.ReaderDays[DirectoryCostDay{SidecarId: readerId, Day: 0}], directoryCostTestCost(3, 3, 1364))
	directoryCostTestExpect(t, "day 1", costs.ReaderDays[DirectoryCostDay{SidecarId: readerId, Day: 1}], directoryCostTestCost(4, 4, 64))
	// a team-day sums its readers
	team := costs.TeamDays(nil)
	directoryCostTestExpect(t, "team day 1", team[1], directoryCostTestCost(4, 4, 64))
}

// An ERASE of 100 bytes and a notice's removal, read cold: the cards ref's one statement (1 request, 2 path reads,
// 800 bytes), the listing of the cards ref and the erasure ref (1, 1, 128), and the erasure ref (1, 1 + 1, 900).
func TestDirectoryCostOracleReadsTheErasureRefWhenItMoved(t *testing.T) {
	readerId := sidecar.NewId()
	events := []*DirectoryCostEvent{
		{TimeMillis: 1000, Kind: DirectoryCostEventErasure, ByteCount: 100},
		{TimeMillis: 1500, Kind: DirectoryCostEventNoticeRemoved},
	}
	oracle := NewDirectoryCostOracle(nil)
	costs, err := oracle.Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: []int64{2000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "an ERASE and a removal", directoryCostTestOnlyDay(t, costs), directoryCostTestCost(3, 5, 1828))

	// a later sync with neither moved reads the erasure ref no more: the cards ref and an empty listing
	costs, err = oracle.Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: []int64{2000, 3000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "with an idle sync after", directoryCostTestOnlyDay(t, costs), directoryCostTestCost(5, 7, 1828))
}

// Five notices of 256 bytes with the cards ref read two statements to a request: three requests for the cards ref,
// 3 + 5 path reads and 5 x 1,056 bytes, and the listing of the one ref.
func TestDirectoryCostOraclePagesTheCardsRef(t *testing.T) {
	settings := DefaultDirectoryCostOracleSettings()
	settings.CardsPageCount = 2
	events := []*DirectoryCostEvent{}
	for i := range 5 {
		events = append(events, &DirectoryCostEvent{TimeMillis: int64(i + 1), Kind: DirectoryCostEventNotice, ByteCount: 256})
	}
	costs, err := NewDirectoryCostOracle(settings).Expected(&DirectoryCostSchedule{Events: events, Readers: []*DirectoryCostReader{{SidecarId: sidecar.NewId(), SyncMillis: []int64{1000}}}})
	if err != nil {
		t.Fatal(err)
	}
	directoryCostTestExpect(t, "five notices", directoryCostTestOnlyDay(t, costs), directoryCostTestCost(4, 9, 5*1056+64))
}

func TestDirectoryCostOracleRefusesAScheduleItCannotWalk(t *testing.T) {
	oracle := NewDirectoryCostOracle(nil)
	readerId := sidecar.NewId()
	reader := func(syncMillis ...int64) []*DirectoryCostReader {
		return []*DirectoryCostReader{{SidecarId: readerId, SyncMillis: syncMillis}}
	}
	cases := []struct {
		name     string
		schedule *DirectoryCostSchedule
	}{
		{name: "no schedule"},
		{name: "events out of order", schedule: &DirectoryCostSchedule{Events: []*DirectoryCostEvent{
			{TimeMillis: 2000, Kind: DirectoryCostEventNotice}, {TimeMillis: 1000, Kind: DirectoryCostEventNotice},
		}, Readers: reader(3000)}},
		{name: "an event of no kind", schedule: &DirectoryCostSchedule{Events: []*DirectoryCostEvent{{TimeMillis: 1000}}, Readers: reader(3000)}},
		{name: "negative bytes", schedule: &DirectoryCostSchedule{Events: []*DirectoryCostEvent{{TimeMillis: 1000, Kind: DirectoryCostEventNotice, ByteCount: -1}}, Readers: reader(3000)}},
		{name: "syncs out of order", schedule: &DirectoryCostSchedule{Readers: reader(3000, 2000)}},
		{name: "a reader twice", schedule: &DirectoryCostSchedule{Readers: append(reader(1000), reader(2000)...)}},
	}
	for _, c := range cases {
		if _, err := oracle.Expected(c.schedule); err == nil {
			t.Fatalf("%s: the oracle computed an expectation", c.name)
		}
	}
}

// Check holds a measure to its expectation both ways: 1.25 times above fails as a client costing more than the table
// allows, 1.25 times below as a reader that did not read what the schedule gave it, and a reader-day one side lacks
// fails too. A count within two of its expectation passes whatever the ratio.
func TestDirectoryCostOracleCheckHoldsAMeasureBothWays(t *testing.T) {
	oracle := NewDirectoryCostOracle(nil)
	readerId := sidecar.NewId()
	costs := func(days ...*DirectoryCost) *DirectoryCosts {
		costs := NewDirectoryCosts()
		for day, cost := range days {
			if cost != nil {
				costs.Charge(readerId, int64(day)*(24*time.Hour).Milliseconds(), cost)
			}
		}
		return costs
	}
	expected := costs(directoryCostTestCost(100, 1000, 10000))
	cases := []struct {
		name     string
		measured *DirectoryCosts
		// what the first error names; empty when the check passes
		refusal string
	}{
		{name: "equal", measured: costs(directoryCostTestCost(100, 1000, 10000))},
		{name: "at the tolerance above", measured: costs(directoryCostTestCost(125, 1250, 12500))},
		{name: "at the tolerance below", measured: costs(directoryCostTestCost(80, 800, 8000))},
		{name: "requests above", measured: costs(directoryCostTestCost(128, 1000, 10000)), refusal: "requests"},
		{name: "path reads above", measured: costs(directoryCostTestCost(100, 1251, 10000)), refusal: "path reads"},
		{name: "bytes above", measured: costs(directoryCostTestCost(100, 1000, 12501)), refusal: "bytes"},
		{name: "bytes below", measured: costs(directoryCostTestCost(100, 1000, 7999)), refusal: "bytes"},
		{name: "a day the schedule has no sync in", measured: costs(directoryCostTestCost(100, 1000, 10000), directoryCostTestCost(1, 1, 1)), refusal: "expects no sync"},
		{name: "nothing measured", measured: costs(), refusal: "nothing was measured"},
	}
	for _, c := range cases {
		errs := oracle.Check(expected, c.measured)
		switch {
		case c.refusal == "" && 0 < len(errs):
			t.Fatalf("%s: %v", c.name, errs)
		case c.refusal != "" && len(errs) == 0:
			t.Fatalf("%s: the check passed", c.name)
		case c.refusal != "" && !strings.Contains(errs[0].Error(), c.refusal):
			t.Fatalf("%s: %v, not a failure naming %q", c.name, errs[0], c.refusal)
		}
	}

	// a reader-day the measure lacks
	two := costs(directoryCostTestCost(100, 1000, 10000), directoryCostTestCost(100, 1000, 10000))
	if errs := oracle.Check(two, costs(directoryCostTestCost(100, 1000, 10000))); len(errs) == 0 || !strings.Contains(errs[0].Error(), "nothing measured") {
		t.Fatalf("a missing reader-day: %v", errs)
	}
	// two requests against three is within the slack, though 1.5 times
	if errs := oracle.Check(costs(directoryCostTestCost(2, 2, 2)), costs(directoryCostTestCost(3, 3, 3))); 0 < len(errs) {
		t.Fatalf("within the slack: %v", errs)
	}
}

// §16.11's model row at 500 members: 750 announcing sidecars, 600 following daemons and 1,250 admissions; a day's
// 5,000 run starts with as many ends but those past midnight, 5,150 renewals, 1,000 coordination entries with 150
// request and 150 decision entries, and 150 notices created, rewritten and removed; 80% of arrivals in the nine
// working hours, the peak hour at 1.5 times their mean rate; about 60 syncs a following daemon a day.
func TestDirectoryLoadPlanFollowsTheModel(t *testing.T) {
	settings := DefaultDirectoryLoadSettings()
	plan, err := NewDirectoryLoadPlan(settings, directoryLoadTestStartMillis)
	if err != nil {
		t.Fatal(err)
	}
	dayMillis := (24 * time.Hour).Milliseconds()
	if plan.StartMillis%dayMillis != 0 || plan.StartMillis < directoryLoadTestStartMillis || plan.EndMillis != plan.StartMillis+dayMillis {
		t.Fatalf("the plan runs %d to %d, not one UTC day from the next midnight", plan.StartMillis, plan.EndMillis)
	}
	announcing, following := plan.Counts()
	// two more admissions are the cold desktop and the cold phone
	if announcing != 750 || following != 600 || len(plan.Sidecars) != 1252 {
		t.Fatalf("%d announcing, %d following, %d admitted", announcing, following, len(plan.Sidecars))
	}
	if plan.Sidecars[plan.ColdDesktop].Follows || plan.Sidecars[plan.ColdDesktop].Announces || plan.Sidecars[plan.ColdPhone].Follows || plan.Sidecars[plan.ColdPhone].Announces {
		t.Fatal("a cold reader announces or follows")
	}
	counts := map[DirectoryLoadPushKind]int{}
	working := 0
	peak := 0
	sampled := 0
	lastMillis := int64(0)
	for _, push := range plan.Pushes {
		if push.TimeMillis < lastMillis || push.TimeMillis < plan.StartMillis || plan.EndMillis <= push.TimeMillis {
			t.Fatalf("a push at %d is out of order or outside the plan", push.TimeMillis)
		}
		lastMillis = push.TimeMillis
		counts[push.Kind] += 1
		if !plan.Sidecars[push.Sidecar].Announces {
			t.Fatalf("a %s by a sidecar that does not announce", push.Kind)
		}
		// the arrivals the day's shape places: starts and renewals
		if push.Kind == DirectoryLoadPushRunStart || push.Kind == DirectoryLoadPushRenewal {
			sampled += 1
			offset := time.Duration(push.TimeMillis-plan.StartMillis) * time.Millisecond
			if settings.WorkStart <= offset && offset < settings.WorkStart+settings.WorkDuration {
				working += 1
			}
			if peakStart := settings.WorkStart + settings.PeakStart; peakStart <= offset && offset < peakStart+settings.PeakDuration {
				peak += 1
			}
		}
	}
	if counts[DirectoryLoadPushRunStart] != 5000 || counts[DirectoryLoadPushRenewal] != 5150 || counts[DirectoryLoadPushEntry] != 1300 {
		t.Fatalf("pushes %v", counts)
	}
	if ends := counts[DirectoryLoadPushRunEnd]; ends < 4900 || 5000 < ends {
		t.Fatalf("%d run ends for 5,000 starts", ends)
	}
	if counts[DirectoryLoadPushNoticeCreate] != 150 || counts[DirectoryLoadPushNoticeRewrite] < 145 || counts[DirectoryLoadPushNoticeRemove] < 145 {
		t.Fatalf("notices %v", counts)
	}
	// 10,150 arrivals: a share's standard deviation is under half a percent
	if share := float64(working) / float64(sampled); share < 0.78 || 0.82 < share {
		t.Fatalf("%.3f of arrivals in the working hours, not 0.8", share)
	}
	// 0.8 x 1.5 / 9
	if share := float64(peak) / float64(sampled); share < 0.118 || 0.148 < share {
		t.Fatalf("%.3f of arrivals in the peak hour, not 0.133", share)
	}
	syncCount := 0
	for _, planned := range plan.Sidecars {
		if planned.Follows != (0 < len(planned.SyncMillis)) {
			t.Fatal("a sidecar syncs without following, or follows without a sync")
		}
		syncCount += len(planned.SyncMillis)
	}
	if mean := float64(syncCount) / float64(following); mean < 50 || 70 < mean {
		t.Fatalf("%.1f syncs a following daemon a day, not about 60", mean)
	}

	// one seed, one plan
	again, err := NewDirectoryLoadPlan(settings, directoryLoadTestStartMillis)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Pushes) != len(plan.Pushes) {
		t.Fatalf("the same seed planned %d pushes, then %d", len(plan.Pushes), len(again.Pushes))
	}
	for i, push := range plan.Pushes {
		if other := again.Pushes[i]; *other != *push {
			t.Fatalf("push %d differs under the same seed: %+v, %+v", i, push, other)
		}
	}
}

func TestDirectoryLoadPlanRefusesAModelThatDoesNotFitADay(t *testing.T) {
	cases := []struct {
		name string
		set  func(settings *DirectoryLoadSettings)
	}{
		{name: "no members", set: func(settings *DirectoryLoadSettings) { settings.MemberCount = 0 }},
		{name: "no days", set: func(settings *DirectoryLoadSettings) { settings.DayCount = 0 }},
		{name: "no sync interval", set: func(settings *DirectoryLoadSettings) { settings.IdleSyncInterval = 0 }},
		{name: "working hours past midnight", set: func(settings *DirectoryLoadSettings) { settings.WorkStart = 20 * time.Hour }},
		{name: "a peak outside the working hours", set: func(settings *DirectoryLoadSettings) { settings.PeakStart = 9 * time.Hour }},
		{name: "a peak holding more than the working hours", set: func(settings *DirectoryLoadSettings) { settings.PeakFactor = 10 }},
		{name: "a share above one", set: func(settings *DirectoryLoadSettings) { settings.WorkShare = 1.5 }},
	}
	for _, c := range cases {
		settings := DefaultDirectoryLoadSettings()
		c.set(settings)
		if _, err := NewDirectoryLoadPlan(settings, directoryLoadTestStartMillis); err == nil {
			t.Fatalf("%s: a plan was made", c.name)
		}
	}
}

// One day of settings on the fakes.
func directoryLoadTestRun(t *testing.T, settings *DirectoryLoadSettings, store *DirectoryLoadStoreSettings, options *DirectoryLoadOptions) (*DirectoryLoad, *DirectoryLoadResult) {
	t.Helper()
	ctx := context.Background()
	plan, err := NewDirectoryLoadPlan(settings, directoryLoadTestStartMillis)
	if err != nil {
		t.Fatal(err)
	}
	fakes, err := NewDirectoryLoadFakes(ctx, plan, nil, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	load, err := NewDirectoryLoad(plan, fakes.Seams(), options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := load.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if violations := fakes.Streams.Violations(); 0 < len(violations) {
		t.Fatalf("the streams' store was violated: %v", violations)
	}
	return load, result
}

// Every check a day at a column of §16.11's table is held to.
func directoryLoadTestCheckDay(t *testing.T, load *DirectoryLoad, result *DirectoryLoadResult) {
	t.Helper()
	t.Log(result)
	failed := false
	report := func(what string, errs []error) {
		for _, err := range errs {
			failed = true
			t.Errorf("%s: %s", what, err)
		}
	}
	report("the oracle", result.CheckOracle(load.Oracle()))
	report("the ceilings", result.CheckCeilings(DefaultDirectoryLoadCeilings()))
	report("the table", result.CheckTable(DefaultDirectoryCostTableM6(), DefaultDirectoryLoadCeilings()))
	report("the phone", result.CheckPhone(load.Oracle(), nil))
	if failed {
		t.FailNow()
	}
}

// FS-86's M6 case at the table's first column, a day on the fake clock: 500 members' announce entries and notices,
// a following daemon on the real client measured against the oracle per reader-day and per team-day, the day
// within the table's M6 row and its ceilings, a cold desktop within the table's bytes, and a cold phone, whose state
// passes 8 MiB, showing partial coverage and then completing.
func TestDirectoryLoadDayAtFiveHundredMembers(t *testing.T) {
	settings := DefaultDirectoryLoadSettings()
	settings.SampledReaderCount = 1
	load, result := directoryLoadTestRun(t, settings, nil, nil)
	directoryLoadTestCheckDay(t, load, result)
	if len(result.ReaderIds) != 1 || len(result.Measured.ReaderDays) != 1 {
		t.Fatalf("%d readers measured over %d reader-days", len(result.ReaderIds), len(result.Measured.ReaderDays))
	}
	if !result.WholeTeam || len(result.Expected.ReaderDays) != 600 {
		t.Fatalf("the oracle holds %d reader-days, not the team's 600", len(result.Expected.ReaderDays))
	}
	if result.Phone.Metered.Complete || result.Phone.Metered.Waiting != sidecar.DirectoryCoverageWaitingMetered {
		t.Fatalf("a phone whose state is %d bytes shows %+v", result.StreamByteCount, result.Phone.Metered)
	}
}

// The day at members, a column of the table too large to fold at every sync in a default run's time: its writers and
// the oracle over every following daemon held to the table and the ceilings, and, where cold is set, the cold desktop
// and the cold phone on the real client; with -directory-load-full, those and one following daemon on the real client
// as well.
func directoryLoadTestLargeDay(t *testing.T, members int, cold bool) {
	t.Helper()
	settings := DefaultDirectoryLoadSettings()
	settings.MemberCount = members
	settings.SampledReaderCount = 1
	cold = cold || *directoryLoadFull
	load, result := directoryLoadTestRun(t, settings, nil, &DirectoryLoadOptions{NoReaders: !*directoryLoadFull, NoCold: !cold})
	_, following := result.Plan.Counts()
	if !result.WholeTeam || len(result.Expected.ReaderDays) != following {
		t.Fatalf("the oracle holds %d reader-days, not the team's %d", len(result.Expected.ReaderDays), following)
	}
	if cold {
		directoryLoadTestCheckDay(t, load, result)
		if result.ColdDesktopMeasured == nil || result.ColdDesktopMeasured.ByteCount == 0 {
			t.Fatal("no cold desktop was measured")
		}
		return
	}
	// nothing ran the client here: the day's plan, its writers' real entries and the oracle's arithmetic are held to
	// the table's column, and the oracle's own check, with nothing measured, must not pass
	t.Log(result)
	for _, err := range append(result.CheckCeilings(DefaultDirectoryLoadCeilings()), result.CheckTable(DefaultDirectoryCostTableM6(), DefaultDirectoryLoadCeilings())...) {
		t.Error(err)
	}
	if errs := result.CheckOracle(load.Oracle()); len(errs) == 0 {
		t.Fatal("a day no client ran in passed the oracle's check")
	}
}

// The Team limit, 2,000 members and 5,000 admissions: a miss here blocks the gate.
func TestDirectoryLoadDayAtTheTeamLimit(t *testing.T) {
	directoryLoadTestLargeDay(t, 2000, true)
}

// The stress case, 5,000 members and 12,500 admissions.
func TestDirectoryLoadDayAtFiveThousandMembers(t *testing.T) {
	directoryLoadTestLargeDay(t, 5000, false)
}

// A team small enough to run a day in a second, with every following daemon's cadence and the 64-stream requests
// still in play: 90 streams.
func directoryLoadTestSmallSettings() *DirectoryLoadSettings {
	settings := DefaultDirectoryLoadSettings()
	settings.MemberCount = 60
	return settings
}

// The three mutants FS-86's M6 case names, one at a time: each fails the oracle's check where the client as it is
// passes on the same plan.
func directoryLoadTestMutantFails(t *testing.T, mutant DirectoryLoadMutant, names string) {
	t.Helper()
	load, result := directoryLoadTestRun(t, directoryLoadTestSmallSettings(), nil, &DirectoryLoadOptions{NoCold: true})
	if errs := result.CheckOracle(load.Oracle()); 0 < len(errs) {
		t.Fatalf("the client as it is: %v", errs)
	}
	load, result = directoryLoadTestRun(t, directoryLoadTestSmallSettings(), nil, &DirectoryLoadOptions{NoCold: true, Mutant: mutant})
	errs := result.CheckOracle(load.Oracle())
	if len(errs) == 0 {
		t.Fatalf("%s passed the oracle's check: a reader-day %s", mutant, result.MeanReaderDay())
	}
	named := false
	for _, err := range errs {
		named = named || strings.Contains(err.Error(), names)
	}
	if !named {
		t.Fatalf("%s failed on %v, not on its %s", mutant, errs[0], names)
	}
	// the mutant costs more and reads nothing wrong: no reader alarmed
	if 0 < len(result.Alarms) {
		t.Fatalf("%s raised %d alarms", mutant, len(result.Alarms))
	}
}

func TestDirectoryLoadMutantOneReadPerMovedStreamFails(t *testing.T) {
	directoryLoadTestMutantFails(t, DirectoryLoadMutantOneReadPerStream, "requests")
}

func TestDirectoryLoadMutantRereadingUnmovedStreamsFails(t *testing.T) {
	directoryLoadTestMutantFails(t, DirectoryLoadMutantRereadUnmovedStreams, "requests")
}

func TestDirectoryLoadMutantRefetchingUnchangedNoticesFails(t *testing.T) {
	directoryLoadTestMutantFails(t, DirectoryLoadMutantRefetchUnchangedNotices, "bytes")
}

// An injected 200 ms delay on every head PUT fails the run on the stream pushes' p99, which the same plan meets
// without it.
func TestDirectoryLoadInjectedHeadPutDelaysFailTheRun(t *testing.T) {
	ceilings := DefaultDirectoryLoadCeilings()
	_, result := directoryLoadTestRun(t, directoryLoadTestSmallSettings(), nil, &DirectoryLoadOptions{NoCold: true})
	if errs := result.CheckCeilings(ceilings); 0 < len(errs) {
		t.Fatalf("with no delay: %v", errs)
	}
	if len(result.StreamPushLatencies) == 0 {
		t.Fatal("no stream push was timed")
	}

	store := DefaultDirectoryLoadStoreSettings()
	store.HeadPutDelay = 200 * time.Millisecond
	_, delayed := directoryLoadTestRun(t, directoryLoadTestSmallSettings(), store, &DirectoryLoadOptions{NoCold: true})
	errs := delayed.CheckCeilings(ceilings)
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "p99") {
		t.Fatalf("a 200 ms delay on head PUTs passed the ceilings: p99 %s, %v", DirectoryLoadP99(delayed.StreamPushLatencies), errs)
	}
	if len(delayed.StreamPushLatencies) != len(result.StreamPushLatencies) {
		t.Fatalf("the delayed run timed %d pushes, the other %d", len(delayed.StreamPushLatencies), len(result.StreamPushLatencies))
	}
}

// A ref's commits queue: two pushes arriving together on one stream finish one commit apart, where two on two
// streams finish together, and the p99 is taken over every stream push.
func TestDirectoryLoadQueuesAPushBehindItsRefsCommit(t *testing.T) {
	ctx := context.Background()
	settings := DefaultDirectoryLoadSettings()
	settings.MemberCount = 2
	settings.AnnouncingSidecarsPerMember = 1
	plan, err := NewDirectoryLoadPlan(settings, directoryLoadTestStartMillis)
	if err != nil {
		t.Fatal(err)
	}
	announcing := []int{}
	for index, planned := range plan.Sidecars {
		if planned.Announces {
			announcing = append(announcing, index)
		}
	}
	if len(announcing) != 2 {
		t.Fatalf("%d announcing sidecars", len(announcing))
	}
	at := plan.StartMillis + time.Hour.Milliseconds()
	plan.Pushes = []*DirectoryLoadPush{
		{TimeMillis: at, Kind: DirectoryLoadPushRunStart, Sidecar: announcing[0], Run: 0, Request: -1},
		{TimeMillis: at, Kind: DirectoryLoadPushEntry, Sidecar: announcing[0], Run: -1, Request: -1},
		{TimeMillis: at, Kind: DirectoryLoadPushEntry, Sidecar: announcing[1], Run: -1, Request: -1},
	}
	fakes, err := NewDirectoryLoadFakes(ctx, plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	load, err := NewDirectoryLoad(plan, fakes.Seams(), &DirectoryLoadOptions{NoCold: true})
	if err != nil {
		t.Fatal(err)
	}
	result, err := load.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	commit := fakes.Store.CommitDuration()
	if commit != 120*time.Millisecond {
		t.Fatalf("a commit of %s on the default store model", commit)
	}
	want := []time.Duration{commit, 2 * commit, commit}
	if len(result.StreamPushLatencies) != len(want) {
		t.Fatalf("%d pushes timed", len(result.StreamPushLatencies))
	}
	for i, latency := range result.StreamPushLatencies {
		if latency != want[i] {
			t.Fatalf("push %d took %s, not %s", i, latency, want[i])
		}
	}
	if p99 := DirectoryLoadP99(result.StreamPushLatencies); p99 != 2*commit {
		t.Fatalf("p99 %s", p99)
	}
	if errs := result.CheckOracle(load.Oracle()); 0 < len(errs) {
		t.Fatalf("the oracle: %v", errs)
	}
}

// The cold phone surrogate through the reader's metered view (RECORD-M6-27), with the cap lowered so a small team's
// state passes it: partial coverage that names what is left and is neither complete nor empty, a stop near the cap,
// and a complete view once the metered bytes are allowed, every version read once. With the cap above the state the
// first fetch completes.
func TestDirectoryLoadColdPhoneShowsPartialCoverage(t *testing.T) {
	settings := directoryLoadTestSmallSettings()
	directory := sidecar.DefaultSidecarSettings().Directory
	directory.PhoneMeteredByteCount = 256 * 1024
	settings.Directory = directory
	load, result := directoryLoadTestRun(t, settings, nil, nil)
	if errs := result.CheckPhone(load.Oracle(), directory); 0 < len(errs) {
		t.Fatalf("the phone: %v", errs)
	}
	if result.StreamByteCount <= directory.PhoneMeteredByteCount {
		t.Fatalf("the state of %d bytes does not pass the cap", result.StreamByteCount)
	}
	metered := result.Phone.Metered
	if metered.Complete || metered.Waiting != sidecar.DirectoryCoverageWaitingMetered || len(metered.LeftSidecarIds) == 0 || len(metered.FetchedSidecarIds) == 0 {
		t.Fatalf("the metered view: %d fetched, %d left, complete %t, waiting %q", len(metered.FetchedSidecarIds), len(metered.LeftSidecarIds), metered.Complete, metered.Waiting)
	}
	if result.Phone.MeteredItemCount == 0 {
		t.Fatal("the partial view lists nothing")
	}
	if !result.Phone.Complete.Complete || result.Phone.Complete.FetchedByteCount < metered.FetchedByteCount {
		t.Fatalf("the allowed view: %+v", result.Phone.Complete)
	}
	// from where it stopped: the phone's requests carried each version once
	if cost := result.Phone.Cost; !load.Oracle().within(result.ColdDesktopMeasured.ByteCount, cost.ByteCount) {
		t.Fatalf("the phone transferred %d bytes where a cold desktop transfers %d", cost.ByteCount, result.ColdDesktopMeasured.ByteCount)
	}
	if errs := result.CheckOracle(load.Oracle()); 0 < len(errs) {
		t.Fatalf("the oracle: %v", errs)
	}

	// a phone whose state fits the cap
	load, result = directoryLoadTestRun(t, directoryLoadTestSmallSettings(), nil, nil)
	if errs := result.CheckPhone(load.Oracle(), nil); 0 < len(errs) {
		t.Fatalf("the phone under the cap: %v", errs)
	}
	if !result.Phone.Metered.Complete {
		t.Fatalf("a state of %d bytes under the cap shows %+v", result.StreamByteCount, result.Phone.Metered)
	}
}

// A run with nothing measured does not pass: no readers and no cold reader, and a sample the oracle is told to keep
// to with no reader in it.
func TestDirectoryLoadRefusesARunThatMeasuresNothing(t *testing.T) {
	load, result := directoryLoadTestRun(t, directoryLoadTestSmallSettings(), nil, &DirectoryLoadOptions{NoReaders: true, NoCold: true})
	if errs := result.CheckOracle(load.Oracle()); len(errs) == 0 {
		t.Fatal("a run that measured nothing passed the oracle's check")
	}
	if errs := result.CheckPhone(load.Oracle(), nil); len(errs) == 0 {
		t.Fatal("a run with no phone passed the phone's check")
	}
	settings := directoryLoadTestSmallSettings()
	settings.MemberCount = 7
	_, result = directoryLoadTestRun(t, settings, nil, &DirectoryLoadOptions{NoCold: true})
	if errs := result.CheckTable(DefaultDirectoryCostTableM6(), DefaultDirectoryLoadCeilings()); len(errs) == 0 {
		t.Fatal("a team the table has no column for passed the table's check")
	}

	ctx := context.Background()
	plan, err := NewDirectoryLoadPlan(directoryLoadTestSmallSettings(), directoryLoadTestStartMillis)
	if err != nil {
		t.Fatal(err)
	}
	fakes, err := NewDirectoryLoadFakes(ctx, plan, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	load, err = NewDirectoryLoad(plan, fakes.Seams(), &DirectoryLoadOptions{NoReaders: true, SampleOracleOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := load.Run(ctx); err == nil {
		t.Fatal("a run with no reader and no oracle ran")
	}
	if _, err := NewDirectoryLoad(plan, &DirectoryLoadSeams{}, nil); err == nil {
		t.Fatal("a load with no seams was made")
	}
}
