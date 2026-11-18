//go:build !ios_extension

package sidecartest

import (
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// FS-86's card case on the oracle and on sidecartest's directory load (RECORD-M10-07; §16.11's cost table and sync
// row, D-MCP-31, D-TEST-17): the oracle's arithmetic for cards by hand, a small team's day in M10's form against it,
// the three mutants the card case names, the cards ref's commits on the store model at the peak rate, at 3x bursts and
// under an injected head PUT delay, and a day at each column of the table's M10 rows.

// One reader of events synced at syncMillis, by settings, nil for the defaults: each reader-day's cost in day order.
func directoryCostTestCardDays(t *testing.T, settings *DirectoryCostOracleSettings, events []*DirectoryCostEvent, syncMillis ...int64) []*DirectoryCost {
	t.Helper()
	costs, err := NewDirectoryCostOracle(settings).Expected(&DirectoryCostSchedule{
		Events: events, Readers: []*DirectoryCostReader{{SidecarId: sidecar.NewId(), SyncMillis: syncMillis}},
	})
	if err != nil {
		t.Fatal(err)
	}
	days := []*DirectoryCost{}
	for _, day := range costs.Days() {
		days = append(days, costs.ReaderDays[day])
	}
	return days
}

// By hand, with a statement at 800 bytes, a listed ref at 64 and a card stored at 2,048. One card written at 1 s,
// renewed at 2 s and changed at 3 s, a second card written at 4 s, and a reader that syncs once an hour on:
//
//	cards    one page of 4 statements: 1 request, 1 + 4 path reads, 4 x 800 bytes
//	fetched  each card's newest version alone, the two earlier versions of the first purged a minute after its
//	         newest landed: 2 cards in one read, 1 request, 2 path reads, 2 x 2,048 bytes
//	listing  the cards ref: 1 request, 1 path read, 64 bytes
//	= 3 requests, 8 path reads, 7,360 bytes
//
// A reader that syncs 30 s after the last of them is still carried the replaced versions, the purge not yet run: 4
// cards fetched, 10 path reads and 11,456 bytes.
func TestDirectoryCostOracleFetchesEachChangedCardsNewestVersion(t *testing.T) {
	first, second := "d/aa/first", "d/bb/second"
	events := []*DirectoryCostEvent{
		{TimeMillis: 1000, Kind: DirectoryCostEventCard, WriterSidecarId: sidecar.NewId(), ByteCount: 2048, Path: first, IndexEntry: true},
		{TimeMillis: 2000, Kind: DirectoryCostEventCard, ByteCount: 2048, Path: first},
		{TimeMillis: 3000, Kind: DirectoryCostEventCard, ByteCount: 2048, Path: first, IndexEntry: true},
		{TimeMillis: 4000, Kind: DirectoryCostEventCard, ByteCount: 2048, Path: second, IndexEntry: true},
	}
	hour := time.Hour.Milliseconds()
	days := directoryCostTestCardDays(t, nil, events, hour)
	directoryCostTestExpect(t, "an hour on", days[0], directoryCostTestCost(3, 8, 4*800+2*2048+64))
	days = directoryCostTestCardDays(t, nil, events, 34_000)
	directoryCostTestExpect(t, "30 s on", days[0], directoryCostTestCost(3, 10, 4*800+4*2048+64))

	// a reader that synced between the writes fetched what was newest then, and the newest again
	days = directoryCostTestCardDays(t, nil, events, 1500, hour)
	directoryCostTestExpect(t, "two syncs", days[0], directoryCostTestCost(3+3, (1+1+1+1)+(1+3+2+1), (800+2048+64)+(3*800+2*2048+64)))
}

// 130 cards changed since a reader's sync, read 64 to a request: 1 request for the statements, 3 for the cards, 1
// for the listing; 1 + 130 + 130 + 1 path reads. With the statements read 100 to a page, the cards each page named go
// in that page's reads: 2 requests for the statements and 2 + 1 for the cards.
func TestDirectoryCostOracleReadsCardsSixtyFourToARequest(t *testing.T) {
	events := []*DirectoryCostEvent{}
	for i := range 130 {
		events = append(events, &DirectoryCostEvent{TimeMillis: int64(i + 1), Kind: DirectoryCostEventCard, ByteCount: 2048, Path: "d/00/" + sidecar.NewId().String(), IndexEntry: true})
	}
	hour := time.Hour.Milliseconds()
	days := directoryCostTestCardDays(t, nil, events, hour)
	directoryCostTestExpect(t, "130 cards", days[0], directoryCostTestCost(1+3+1, 1+130+130+1, 130*(800+2048)+64))
	paged := DefaultDirectoryCostOracleSettings()
	paged.CardsPageCount = 100
	days = directoryCostTestCardDays(t, paged, events, hour)
	directoryCostTestExpect(t, "130 cards in two pages", days[0], directoryCostTestCost(2+2+1+1, 2+130+130+1, 130*(800+2048)+64))
}

// A removed card carries its statement alone and purges what it replaced; a notice in M10's form rides its statement
// at its newest version alone; and a card event that names no path, or a stream event that names one, is refused.
func TestDirectoryCostOracleCardRemovalsAndVersionlessNotices(t *testing.T) {
	card, notice := "d/aa/card", "q/bb/target/request"
	events := []*DirectoryCostEvent{
		{TimeMillis: 1000, Kind: DirectoryCostEventCard, ByteCount: 2048, Path: card, IndexEntry: true},
		{TimeMillis: 2000, Kind: DirectoryCostEventNotice, ByteCount: 256, Path: notice},
		{TimeMillis: 3000, Kind: DirectoryCostEventNotice, ByteCount: 256, Path: notice},
		{TimeMillis: 4000, Kind: DirectoryCostEventCardRemoved, Path: card},
	}
	days := directoryCostTestCardDays(t, nil, events, time.Hour.Milliseconds())
	// 4 statements and the one notice version that stands: no card is fetched
	directoryCostTestExpect(t, "a removal and a rewritten notice", days[0], directoryCostTestCost(2, 1+4+1, 4*800+256+64))
	oracle := NewDirectoryCostOracle(nil)
	for _, bad := range []*DirectoryCostEvent{
		{TimeMillis: 1, Kind: DirectoryCostEventCard, ByteCount: 2048},
		{TimeMillis: 1, Kind: DirectoryCostEventStream, WriterSidecarId: sidecar.NewId(), Path: card},
	} {
		if _, err := oracle.Expected(&DirectoryCostSchedule{Events: []*DirectoryCostEvent{bad}}); err == nil {
			t.Fatalf("an event of kind %d naming %q was walked", bad.Kind, bad.Path)
		}
	}
	if settings := DefaultDirectoryCostOracleSettings(); settings.CardStoredByteCount(1) != 2048 || settings.CardStoredByteCount(2048) != 2048 || settings.CardStoredByteCount(2049) != 4096 {
		t.Fatal("a card's stored bytes are not its next 2 KiB step")
	}
}

// A small team's day in M10's form.
func directoryLoadTestSmallCardSettings() *DirectoryLoadSettings {
	settings := directoryLoadTestSmallSettings()
	settings.Cards = true
	return settings
}

// A small team's day on cards: every measured reader-day and the team-day within 1.25 times the oracle's, no reader
// alarming; every run push a card on the cards ref and none an announce entry; the cold desktop within the oracle's
// bytes; and the cards ref's commits within the table's ceilings at the peak rate and at 3x bursts.
func TestDirectoryLoadCardDayHoldsToTheOracle(t *testing.T) {
	load, result := directoryLoadTestRun(t, directoryLoadTestSmallCardSettings(), nil, &DirectoryLoadOptions{NoPhone: true})
	t.Log(result)
	for _, err := range result.CheckOracle(load.Oracle()) {
		t.Error(err)
	}
	for _, err := range append(result.CheckCeilings(DefaultDirectoryLoadCeilings()), result.CheckCardCeilings(DefaultDirectoryLoadCeilings())...) {
		t.Error(err)
	}
	cards, changes, streams := 0, 0, 0
	for _, event := range result.Schedule.Events {
		switch event.Kind {
		case DirectoryCostEventCard:
			cards += 1
			if event.IndexEntry {
				changes += 1
			}
		case DirectoryCostEventStream:
			streams += 1
		}
	}
	runPushes := result.PushCounts[DirectoryLoadPushRunStart] + result.PushCounts[DirectoryLoadPushRunEnd] + result.PushCounts[DirectoryLoadPushRenewal]
	if cards != runPushes || streams != result.PushCounts[DirectoryLoadPushEntry] || changes < result.PushCounts[DirectoryLoadPushRunStart]+result.PushCounts[DirectoryLoadPushRunEnd] || cards <= changes {
		t.Fatalf("%d card pushes of %d run pushes, %d of them content changes, and %d stream pushes of %d entries", cards, runPushes, changes, streams, result.PushCounts[DirectoryLoadPushEntry])
	}
	if result.ColdDesktopMeasured == nil || result.ColdDesktopMeasured.ByteCount == 0 || len(result.CardPushArrivalMillis) != cards+
		result.PushCounts[DirectoryLoadPushNoticeCreate]+result.PushCounts[DirectoryLoadPushNoticeRewrite]+result.PushCounts[DirectoryLoadPushNoticeRemove] {
		t.Fatalf("the cold desktop read %v, and %d pushes arrived on the cards ref", result.ColdDesktopMeasured, len(result.CardPushArrivalMillis))
	}
}

// The three mutants FS-86's card case names, one at a time: each fails the oracle's check where the client as it is
// passes on the same plan, on the count the mechanism saves, and reads nothing wrong.
func directoryLoadTestCardMutantFails(t *testing.T, settings *DirectoryLoadSettings, mutant DirectoryLoadMutant, names string) {
	t.Helper()
	load, result := directoryLoadTestRun(t, settings, nil, &DirectoryLoadOptions{NoCold: true})
	if errs := result.CheckOracle(load.Oracle()); 0 < len(errs) {
		t.Fatalf("the client as it is: %v", errs)
	}
	load, result = directoryLoadTestRun(t, settings, nil, &DirectoryLoadOptions{NoCold: true, Mutant: mutant})
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
	if 0 < len(result.Alarms) {
		t.Fatalf("%s raised %d alarms", mutant, len(result.Alarms))
	}
}

// Coalescing saves where a card changed more than once between a reader's syncs, which a daemon that syncs every 15
// minutes rarely sees and one that was away for hours sees at every card: the readers here sync every four hours and at
// no view.
func TestDirectoryLoadCardMutantNoCoalescingFails(t *testing.T) {
	settings := directoryLoadTestSmallCardSettings()
	settings.SessionSyncInterval = 4 * time.Hour
	settings.IdleSyncInterval = 4 * time.Hour
	settings.ViewSyncsPerDaemonDay = 0
	directoryLoadTestCardMutantFails(t, settings, DirectoryLoadMutantNoCardCoalescing, "bytes")
}

func TestDirectoryLoadCardMutantNoHeadReproductionFails(t *testing.T) {
	directoryLoadTestCardMutantFails(t, directoryLoadTestSmallCardSettings(), DirectoryLoadMutantNoHeadReproduction, "bytes")
}

func TestDirectoryLoadCardMutantRefetchingUnchangedCardsFails(t *testing.T) {
	directoryLoadTestCardMutantFails(t, directoryLoadTestSmallCardSettings(), DirectoryLoadMutantRefetchUnchangedCards, "bytes")
}

// Every check a day in M10's form at a column of §16.11's table is held to. The cold phone is M8's and not run. At
// the stress case a miss of the 3x bursts' ceilings is logged and fails nothing: D-TEST-17 blocks the gate on a miss at
// the Team limit, the store model's durations are a stand-in, and the burst is T3's physical peak hour to measure.
func directoryLoadTestCheckCardDay(t *testing.T, load *DirectoryLoad, result *DirectoryLoadResult, measured bool, stress bool) {
	t.Helper()
	t.Log(result)
	ceilings := DefaultDirectoryLoadCeilings()
	peak, burst := result.CardCommits(1), result.CardCommits(ceilings.CardBurstFactor)
	t.Logf("the cards ref at the peak rate: %d commits, p99 %s, %.3f reruns a commit, %d BUSY; at %.0fx bursts: p99 %s, %.3f reruns a commit, %d BUSY",
		len(peak.Latencies), DirectoryLoadP99(peak.Latencies), peak.RerunMean(), peak.BusyCount,
		ceilings.CardBurstFactor, DirectoryLoadP99(burst.Latencies), burst.RerunMean(), burst.BusyCount)
	failed := false
	report := func(what string, errs []error) {
		for _, err := range errs {
			failed = true
			t.Errorf("%s: %s", what, err)
		}
	}
	if measured {
		report("the oracle", result.CheckOracle(load.Oracle()))
	}
	report("the ceilings", result.CheckCeilings(ceilings))
	report("the cards ref's commits", result.CheckCardPeakCeilings(ceilings))
	if stress {
		for _, err := range result.CheckCardBurstCeilings(ceilings) {
			t.Logf("the stress case on the store model, recorded and not gating: %s", err)
		}
	} else {
		report("the cards ref's commits", result.CheckCardBurstCeilings(ceilings))
	}
	report("the table", result.CheckTable(DefaultDirectoryCostTableM10(), ceilings))
	if failed {
		t.FailNow()
	}
}

// FS-86's card case at the table's first column, a day on the fake clock: 500 members' cards, stream entries and
// notices, a following daemon on the real client measured against the oracle per reader-day and per team-day, the day
// within the table's M10 row, the cards ref's commits within its ceilings at the peak rate and at 3x bursts, and a cold
// desktop within the table's bytes.
func TestDirectoryLoadCardDayAtFiveHundredMembers(t *testing.T) {
	settings := DefaultDirectoryLoadSettings()
	settings.Cards = true
	settings.SampledReaderCount = 1
	load, result := directoryLoadTestRun(t, settings, nil, &DirectoryLoadOptions{NoPhone: true})
	directoryLoadTestCheckCardDay(t, load, result, true, false)
	if len(result.ReaderIds) != 1 || !result.WholeTeam || len(result.Expected.ReaderDays) != 600 {
		t.Fatalf("%d readers measured and %d reader-days expected", len(result.ReaderIds), len(result.Expected.ReaderDays))
	}
	if result.ColdDesktopMeasured == nil || result.ColdDesktopMeasured.ByteCount == 0 {
		t.Fatal("no cold desktop was measured")
	}
}

// The day in M10's form at members, as directoryLoadTestLargeDay runs M6's: its writers and the oracle over every
// following daemon held to the table and the ceilings, a cold desktop on the real client where cold is set, and with
// -directory-load-full one following daemon on the real client as well.
func directoryLoadTestLargeCardDay(t *testing.T, members int, cold bool, stress bool) {
	t.Helper()
	settings := DefaultDirectoryLoadSettings()
	settings.Cards = true
	settings.MemberCount = members
	settings.SampledReaderCount = 1
	cold = cold || *directoryLoadFull
	load, result := directoryLoadTestRun(t, settings, nil, &DirectoryLoadOptions{NoReaders: !*directoryLoadFull, NoCold: !cold, NoPhone: true})
	_, following := result.Plan.Counts()
	if !result.WholeTeam || len(result.Expected.ReaderDays) != following {
		t.Fatalf("the oracle holds %d reader-days, not the team's %d", len(result.Expected.ReaderDays), following)
	}
	// the oracle's check holds what ran the client: the cold desktop, and a following daemon with -directory-load-full
	directoryLoadTestCheckCardDay(t, load, result, cold, stress)
	if cold && (result.ColdDesktopMeasured == nil || result.ColdDesktopMeasured.ByteCount == 0) {
		t.Fatal("no cold desktop was measured")
	}
	if !cold {
		// nothing ran the client: the oracle's own check, with nothing measured, must not pass
		if errs := result.CheckOracle(load.Oracle()); len(errs) == 0 {
			t.Fatal("a day no client ran in passed the oracle's check")
		}
	}
}

// The Team limit, 2,000 members and 5,000 admissions: a miss here blocks the gate.
func TestDirectoryLoadCardDayAtTheTeamLimit(t *testing.T) {
	directoryLoadTestLargeCardDay(t, 2000, true, false)
}

// The stress case, 5,000 members and 12,500 admissions, 5.8 pushes a second on the cards ref at its peak.
func TestDirectoryLoadCardDayAtFiveThousandMembers(t *testing.T) {
	directoryLoadTestLargeCardDay(t, 5000, false, true)
}

// The cards ref's queue by hand, on the store model's 2 body PUTs and a head PUT of 40 ms each. Two pushes arriving
// together: both read the head at 80 ms, the first commits at 120 ms and the second, finding that commit ahead of it,
// reruns once and commits at 160 ms. A push a second later finds nothing ahead: 120 ms and no rerun.
func TestDirectoryLoadCardQueueCountsARerunBehindACommit(t *testing.T) {
	commits := directoryLoadCardQueue([]int64{0, 0, 1000}, DefaultDirectoryLoadStoreSettings())
	want := []time.Duration{120 * time.Millisecond, 160 * time.Millisecond, 120 * time.Millisecond}
	if len(commits.Latencies) != 3 || commits.Latencies[0] != want[0] || commits.Latencies[1] != want[1] || commits.Latencies[2] != want[2] {
		t.Fatalf("latencies %v, not %v", commits.Latencies, want)
	}
	if commits.RerunCount != 1 || commits.BusyCount != 0 || commits.RerunMean() != 1.0/3 || commits.BusyShare() != 0 {
		t.Fatalf("%d reruns and %d BUSY", commits.RerunCount, commits.BusyCount)
	}
}

// Ten pushes arriving together with 8 commits allowed to wait on the head: the ninth and tenth are answered 429 BUSY,
// sent again a second later and commit then, the first within 1 s + 80 ms + 40 ms of arriving and the second a head PUT
// behind it. With 200 ms on every head PUT the same ten take 240 ms a commit.
func TestDirectoryLoadCardQueueAnswersBusyPastItsWaitingCommits(t *testing.T) {
	store := DefaultDirectoryLoadStoreSettings()
	commits := directoryLoadCardQueue(make([]int64, 10), store)
	if commits.BusyCount != 2 || len(commits.Latencies) != 10 || len(commits.RetryLatencies) != 2 {
		t.Fatalf("%d BUSY of %d commits, %d retried", commits.BusyCount, len(commits.Latencies), len(commits.RetryLatencies))
	}
	if commits.RetryLatencies[0] != 1120*time.Millisecond || commits.RetryLatencies[1] != 1160*time.Millisecond {
		t.Fatalf("the retries committed %v after they arrived", commits.RetryLatencies)
	}
	// the first eight wait on 0 to 7 commits and the tenth on the ninth's
	if commits.RerunCount != 28+1 || commits.BusyShare() != 0.2 {
		t.Fatalf("%d reruns, a BUSY share of %v", commits.RerunCount, commits.BusyShare())
	}
	store.HeadPutDelay = 200 * time.Millisecond
	commits = directoryLoadCardQueue([]int64{0, 0}, store)
	if commits.Latencies[0] != 320*time.Millisecond || commits.Latencies[1] != 560*time.Millisecond {
		t.Fatalf("latencies %v under a 200 ms head PUT delay", commits.Latencies)
	}
}

// 200 ms injected on every head PUT fails the cards ref's p99 ceiling where the day as it is meets it, at the table's
// first column: a commit alone takes 320 ms.
func TestDirectoryLoadCardCommitsFailUnderAnInjectedHeadDelay(t *testing.T) {
	settings := DefaultDirectoryLoadSettings()
	settings.Cards = true
	store := DefaultDirectoryLoadStoreSettings()
	store.HeadPutDelay = 200 * time.Millisecond
	_, result := directoryLoadTestRun(t, settings, store, &DirectoryLoadOptions{NoReaders: true, NoCold: true})
	errs := result.CheckCardCeilings(DefaultDirectoryLoadCeilings())
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "p99") {
		t.Fatalf("200 ms on every head PUT passed the cards ref's ceilings: %v", errs)
	}
}

// The directory's pushes as §11.13's rows price them for format 2's computed write gate: every push of the day in a
// row, a card's content change at 55 KiB and a renewal at 37, an entry at 96 with its 28 KiB companion, and their sum
// the day's NVMe bytes a drive.
func TestDirectoryLoadDrivePushesPriceEveryPush(t *testing.T) {
	_, result := directoryLoadTestRun(t, directoryLoadTestSmallCardSettings(), nil, &DirectoryLoadOptions{NoReaders: true, NoCold: true})
	ceilings := DefaultDirectoryLoadCeilings()
	rows := result.DrivePushes(ceilings)
	pushes, priced := 0, int64(0)
	byName := map[string]*DirectoryDrivePushRow{}
	for _, row := range rows {
		byName[row.Name] = row
		priced += int64(row.PushCount) * row.DriveByteCount
		if row.Name != "companion push" {
			pushes += row.PushCount
		}
	}
	total := 0
	for _, count := range result.PushCounts {
		total += count
	}
	if pushes != total || priced != result.DriveByteCount(ceilings) || priced == 0 {
		t.Fatalf("%d of %d pushes priced at %d bytes, the day's %d", pushes, total, priced, result.DriveByteCount(ceilings))
	}
	if byName["card content change"].DriveByteCount != 55*1024 || byName["card renewal"].DriveByteCount != 37*1024 || byName["stream entry"].DriveByteCount != 96*1024 ||
		byName["companion push"].DriveByteCount != 28*1024 || byName["companion push"].PushCount != byName["stream entry"].PushCount || byName["card renewal"].PushCount == 0 {
		t.Fatalf("the rows are %v", byName)
	}
	// M6's form prices by its own rows
	_, m6 := directoryLoadTestRun(t, directoryLoadTestSmallSettings(), nil, &DirectoryLoadOptions{NoReaders: true, NoCold: true})
	if m6.DrivePushes(ceilings) != nil {
		t.Fatal("a day on announce entries answered card rows")
	}
}
