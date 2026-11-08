// §9.7's steps as tables and §22.5's one-dialer case in pure form. scheduler_oracle_test.go holds the
// simulated groups.

package socketsservice

import (
	"reflect"
	"slices"
	"testing"

	"github.com/urnetwork/connect"
)

// Where the tables stand on the clock.
const testNowMillis = int64(1_000_000)

// A synthetic id that sorts by index.
func testId(index int) connect.Id {
	return connect.Id{14: byte(index >> 8), 15: byte(index)}
}

// The dialer of a test's Find.
var testDialerId = testId(0xd1)

// A listener any Find takes: live, serving, empty, of the default weight and max_streams.
func testCandidate(index int) *SocketCandidate {
	return &SocketCandidate{
		ListenerClientId:     testId(index),
		ListenId:             testId(0x100 + index),
		Protocol:             "tcp",
		Version:              1,
		Weight:               100,
		MaxStreams:           256,
		Serving:              true,
		LeaseExpireMillis:    testNowMillis + 45_000,
		ReportMillis:         testNowMillis - 1_000,
		DialerClientIdShares: map[connect.Id]*SocketDialerShare{},
	}
}

// A Find that asks for nothing in particular, from testDialerId.
func testRequest() *SocketPickRequest {
	return &SocketPickRequest{
		DialerClientId: testDialerId,
		NowMillis:      testNowMillis,
	}
}

// Sets candidate's est by its report, with no tickets.
func testLoad(candidate *SocketCandidate, est int) *SocketCandidate {
	candidate.ReportedInflight = est
	return candidate
}

// Records one primary ticket the way a store does after a pick.
func testIssue(candidate *SocketCandidate, dialerId connect.Id, nowMillis int64) {
	share := candidate.DialerClientIdShares[dialerId]
	if share == nil {
		share = &SocketDialerShare{}
		candidate.DialerClientIdShares[dialerId] = share
	}
	share.PrimaryIssueMillis = append(share.PrimaryIssueMillis, nowMillis)
}

// Fails unless the pick came to what the test wants of it: indexes name testCandidate's ids, -1 none.
func testWantPick(t *testing.T, name string, result *SocketPickResult, outcome SocketPickOutcome, primary int, backup int) {
	t.Helper()
	if result.Outcome != outcome {
		t.Errorf("%s: outcome %d, want %d", name, result.Outcome, outcome)
		return
	}
	check := func(role string, got *SocketCandidate, index int) {
		t.Helper()
		switch {
		case index < 0 && got != nil:
			t.Errorf("%s: %s %v, want none", name, role, got.ListenerClientId)
		case 0 <= index && (got == nil || got.ListenerClientId != testId(index)):
			t.Errorf("%s: %s %+v, want %d", name, role, got, index)
		}
	}
	check("primary", result.Primary, primary)
	check("backup", result.Backup, backup)
}

func TestFilterRefusesEachUnfitListener(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	cases := []struct {
		name    string
		unfit   func(candidate *SocketCandidate)
		request func(request *SocketPickRequest)
		outcome SocketPickOutcome
	}{
		{name: "lease ended this millisecond", unfit: func(c *SocketCandidate) { c.LeaseExpireMillis = testNowMillis }, outcome: SocketPickNoListener},
		{name: "lease long over", unfit: func(c *SocketCandidate) { c.LeaseExpireMillis = 1 }, outcome: SocketPickNoListener},
		{name: "not serving", unfit: func(c *SocketCandidate) { c.Serving = false }, outcome: SocketPickNoListener},
		{name: "draining", unfit: func(c *SocketCandidate) { c.Draining = true }, outcome: SocketPickNoListener},
		{name: "no weight", unfit: func(c *SocketCandidate) { c.Weight = 0 }, outcome: SocketPickNoListener},
		{name: "another protocol", request: func(r *SocketPickRequest) { r.Protocol = "tls" }, outcome: SocketPickNoListener},
		{name: "an older version", request: func(r *SocketPickRequest) { r.MinVersion = 2 }, outcome: SocketPickNoListener},
		{name: "no offered alpn served", unfit: func(c *SocketCandidate) { c.Alpns = []string{"h2"} }, request: func(r *SocketPickRequest) { r.Alpns = []string{"http/1.1", "smtp"} }, outcome: SocketPickNoListener},
		{name: "alpn offered to a listener serving none", request: func(r *SocketPickRequest) { r.Alpns = []string{"h2"} }, outcome: SocketPickNoListener},
		{name: "est at max_streams", unfit: func(c *SocketCandidate) { testLoad(c, 256) }, outcome: SocketPickBusy},
		{name: "est past max_streams", unfit: func(c *SocketCandidate) { testLoad(c, 300) }, outcome: SocketPickBusy},
	}
	for _, c := range cases {
		request := testRequest()
		if c.request != nil {
			c.request(request)
		}
		unfit := testCandidate(1)
		if c.unfit != nil {
			c.unfit(unfit)
		}
		testWantPick(t, c.name, PickSocketListeners([]*SocketCandidate{unfit}, request, settings), c.outcome, -1, -1)

		// a fit listener beside it gets the Find alone, so no backup comes from the unfit one
		fit := testCandidate(2)
		fit.Protocol = request.Protocol
		fit.Version = max(1, request.MinVersion)
		fit.Alpns = request.Alpns
		testWantPick(t, c.name, PickSocketListeners([]*SocketCandidate{unfit, fit}, request, settings), SocketPickFound, 2, -1)
	}
}

// The positive twin of each row above.
func TestFilterKeepsEachFitListener(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	cases := []struct {
		name    string
		fit     func(candidate *SocketCandidate)
		request func(request *SocketPickRequest)
	}{
		{name: "lease a millisecond from its end", fit: func(c *SocketCandidate) { c.LeaseExpireMillis = testNowMillis + 1 }},
		{name: "the protocol named", request: func(r *SocketPickRequest) { r.Protocol = "tcp" }},
		{name: "no protocol named, whatever the group's", fit: func(c *SocketCandidate) { c.Protocol = "smtp-starttls" }},
		{name: "the least version", request: func(r *SocketPickRequest) { r.MinVersion = 1 }},
		{name: "no least version", fit: func(c *SocketCandidate) { c.Version = 0 }},
		{name: "a newer version", fit: func(c *SocketCandidate) { c.Version = 7 }, request: func(r *SocketPickRequest) { r.MinVersion = 2 }},
		{name: "the one alpn", fit: func(c *SocketCandidate) { c.Alpns = []string{"h2"} }, request: func(r *SocketPickRequest) { r.Alpns = []string{"h2"} }},
		{name: "one offered alpn of several", fit: func(c *SocketCandidate) { c.Alpns = []string{"http/1.1", "h2"} }, request: func(r *SocketPickRequest) { r.Alpns = []string{"acme-tls/1", "h2"} }},
		{name: "no alpn offered to a listener serving some", fit: func(c *SocketCandidate) { c.Alpns = []string{"h2"} }},
		{name: "no alpn offered to a listener serving none"},
		{name: "est one below max_streams", fit: func(c *SocketCandidate) { testLoad(c, 255) }},
	}
	for _, c := range cases {
		request := testRequest()
		if c.request != nil {
			c.request(request)
		}
		fit := testCandidate(1)
		if c.fit != nil {
			c.fit(fit)
		}
		testWantPick(t, c.name, PickSocketListeners([]*SocketCandidate{fit}, request, settings), SocketPickFound, 1, -1)
	}
}

func TestOutcomes(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	notServing := testCandidate(1)
	notServing.Serving = false
	draining := testCandidate(2)
	draining.Draining = true
	full := testLoad(testCandidate(3), 256)
	otherFull := testLoad(testCandidate(4), 1000)
	ejected := testLoad(testCandidate(5), 256)
	ejected.Ejection = SocketEjectionState{ConsecutiveCount: 1, StartMillis: testNowMillis}

	cases := []struct {
		name       string
		candidates []*SocketCandidate
		outcome    SocketPickOutcome
	}{
		{name: "no listeners", candidates: nil, outcome: SocketPickNoListener},
		{name: "none live and matching", candidates: []*SocketCandidate{notServing, draining}, outcome: SocketPickNoListener},
		{name: "only est excludes", candidates: []*SocketCandidate{full, otherFull}, outcome: SocketPickBusy},
		{name: "est excludes the only match", candidates: []*SocketCandidate{notServing, full, draining}, outcome: SocketPickBusy},
		{name: "ignoring ejections leaves est", candidates: []*SocketCandidate{ejected}, outcome: SocketPickBusy},
	}
	for _, c := range cases {
		testWantPick(t, c.name, PickSocketListeners(c.candidates, testRequest(), settings), c.outcome, -1, -1)
	}
}

// §9.7's step 1: ejections and exclusions stand until they would leave nothing, and then only they
// give way.
func TestEjectionsAndExclusionsGiveWayOnlyWhenNothingElseRemains(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	eject := func(candidate *SocketCandidate) *SocketCandidate {
		candidate.Ejection = SocketEjectionState{ConsecutiveCount: 1, StartMillis: testNowMillis}
		return candidate
	}
	exclude := func(candidate *SocketCandidate, dialerId connect.Id) *SocketCandidate {
		candidate.DialerClientIdShares[dialerId] = &SocketDialerShare{Exclusion: SocketEjectionState{ConsecutiveCount: 1, StartMillis: testNowMillis}}
		return candidate
	}
	draining := testCandidate(3)
	draining.Draining = true

	cases := []struct {
		name       string
		candidates []*SocketCandidate
		primary    int
		backup     int
	}{
		{name: "ejected beside a clean one", candidates: []*SocketCandidate{eject(testCandidate(1)), testCandidate(2)}, primary: 2, backup: -1},
		{name: "excluded beside a clean one", candidates: []*SocketCandidate{exclude(testCandidate(1), testDialerId), testCandidate(2)}, primary: 2, backup: -1},
		// a clean listener with no room is no reason to keep refusing one that has it
		{name: "ejected beside a full one", candidates: []*SocketCandidate{eject(testCandidate(1)), testLoad(testCandidate(2), 256)}, primary: 1, backup: -1},
		{name: "excluded beside a full one", candidates: []*SocketCandidate{exclude(testCandidate(1), testDialerId), testLoad(testCandidate(2), 256)}, primary: 1, backup: -1},
		{name: "every one ejected", candidates: []*SocketCandidate{eject(testCandidate(1)), eject(testCandidate(2))}, primary: 1, backup: 2},
		{name: "one ejected and one excluded", candidates: []*SocketCandidate{eject(testCandidate(1)), exclude(testCandidate(2), testDialerId)}, primary: 1, backup: 2},
		// nothing else gives way with them
		{name: "ejected beside a draining one", candidates: []*SocketCandidate{eject(testCandidate(1)), draining}, primary: 1, backup: -1},
		// another dialer's exclusion is that dialer's
		{name: "excluded for someone else", candidates: []*SocketCandidate{exclude(testCandidate(1), testId(0xd2)), testCandidate(2)}, primary: 1, backup: 2},
	}
	for _, c := range cases {
		testWantPick(t, c.name, PickSocketListeners(c.candidates, testRequest(), settings), SocketPickFound, c.primary, c.backup)
	}
}

func TestAnEjectionThatEndedExcludesNothing(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	ejected := testCandidate(1)
	ejected.Ejection = SocketEjectionState{ConsecutiveCount: 1, StartMillis: testNowMillis - 30_000}
	excluded := testCandidate(2)
	excluded.DialerClientIdShares[testDialerId] = &SocketDialerShare{Exclusion: SocketEjectionState{ConsecutiveCount: 2, StartMillis: testNowMillis - 60_000}}
	testWantPick(t, "both over", PickSocketListeners([]*SocketCandidate{ejected, excluded}, testRequest(), settings), SocketPickFound, 1, 2)

	request := testRequest()
	request.NowMillis -= 1
	clean := testCandidate(3)
	testWantPick(t, "one millisecond earlier", PickSocketListeners([]*SocketCandidate{ejected, excluded, clean}, request, settings), SocketPickFound, 3, -1)
}

func TestPickTakesTheLowerLoadPerWeight(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	cases := []struct {
		name    string
		weights [2]int
		ests    [2]int
		primary int
		backup  int
	}{
		{name: "equal weights, lower est", weights: [2]int{100, 100}, ests: [2]int{10, 20}, primary: 1, backup: 2},
		{name: "equal weights, lower est second", weights: [2]int{100, 100}, ests: [2]int{20, 10}, primary: 2, backup: 1},
		{name: "a heavier listener carries more", weights: [2]int{100, 1000}, ests: [2]int{10, 20}, primary: 2, backup: 1},
		{name: "a heavier listener's load is still load", weights: [2]int{100, 1000}, ests: [2]int{1, 50}, primary: 1, backup: 2},
		// (0 + 1) / 1 against (0 + 1) / 1000: the + 1 is what makes an idle pair a choice by weight
		{name: "idle, by weight", weights: [2]int{1, 1000}, ests: [2]int{0, 0}, primary: 2, backup: 1},
		// 31 / 100 against 62 / 200, equal only as cross multiplied integers
		{name: "exact ratios tie", weights: [2]int{100, 200}, ests: [2]int{30, 61}, primary: -1, backup: -1},
	}
	for _, c := range cases {
		group := []*SocketCandidate{testLoad(testCandidate(1), c.ests[0]), testLoad(testCandidate(2), c.ests[1])}
		group[0].Weight = c.weights[0]
		group[1].Weight = c.weights[1]
		for draw := uint32(0); draw < 300; draw += 1 {
			request := testRequest()
			request.FirstDraw = draw
			request.SecondDraw = draw
			result := PickSocketListeners(group, request, settings)
			if c.primary < 0 {
				// a tie goes to the one sampled first, and with two the draw decides which
				first := group[drawSocketCandidate([]*SocketCandidate{group[0], group[1]}, draw, -1)]
				if result.Primary != first {
					t.Errorf("%s, draw %d: primary %v", c.name, draw, result.Primary.ListenerClientId)
				}
				continue
			}
			testWantPick(t, c.name, result, SocketPickFound, c.primary, c.backup)
		}
	}
}

// Each candidate takes exactly its weight's part of the draws, with or without one skipped.
func TestDrawsFollowWeightExactly(t *testing.T) {
	pool := []*SocketCandidate{testCandidate(1), testCandidate(2), testCandidate(3), testCandidate(4)}
	weights := []int{1, 2, 3, 994}
	for index, weight := range weights {
		pool[index].Weight = weight
	}
	for _, skip := range []int{-1, 0, 1, 2, 3} {
		totalWeight := 0
		for index, weight := range weights {
			if index != skip {
				totalWeight += weight
			}
		}
		counts := make([]int, len(pool))
		for draw := range totalWeight * 3 {
			counts[drawSocketCandidate(pool, uint32(draw), skip)] += 1
		}
		for index, weight := range weights {
			want := weight * 3
			if index == skip {
				want = 0
			}
			if counts[index] != want {
				t.Errorf("skip %d: candidate %d drawn %d times, want %d", skip, index, counts[index], want)
			}
		}
	}
}

func TestTwoCandidatesAreAlwaysDistinct(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	group := []*SocketCandidate{testCandidate(1), testCandidate(2), testCandidate(3), testCandidate(4), testCandidate(5)}
	seenPrimaries := map[connect.Id]bool{}
	seenBackups := map[connect.Id]bool{}
	for firstDraw := uint32(0); firstDraw < 500; firstDraw += 50 {
		for secondDraw := uint32(0); secondDraw < 500; secondDraw += 50 {
			request := testRequest()
			request.FirstDraw = firstDraw
			request.SecondDraw = secondDraw
			result := PickSocketListeners(group, request, settings)
			if result.Primary == nil || result.Backup == nil || result.Primary == result.Backup {
				t.Fatalf("draws %d, %d: %+v", firstDraw, secondDraw, result)
			}
			seenPrimaries[result.Primary.ListenerClientId] = true
			seenBackups[result.Backup.ListenerClientId] = true
		}
	}
	// weighted sampling reaches every listener (§9.7's fairness)
	if len(seenPrimaries) != len(group) || len(seenBackups) != len(group) {
		t.Errorf("reached %d primaries and %d backups of %d", len(seenPrimaries), len(seenBackups), len(group))
	}
}

// The pick a store has to repeat: these pin the draws' arithmetic and the order of the candidates,
// so a change here is a change to what the Lua script must match.
func TestFixedPicks(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	build := func() []*SocketCandidate {
		group := []*SocketCandidate{testCandidate(3), testCandidate(1), testCandidate(2), testCandidate(4)}
		for index, est := range []int{5, 40, 0, 10} {
			testLoad(group[index], est)
		}
		for index, weight := range []int{200, 100, 300, 400} {
			group[index].Weight = weight
		}
		return group
	}
	// by id: 1 weighs 100 with est 40, 2 weighs 300 with est 0, 3 weighs 200 with est 5, 4 weighs 400
	// with est 10; a first draw of d lands at d % 1000, and a second at d % (1000 - the first's weight)
	cases := []struct {
		firstDraw  uint32
		secondDraw uint32
		primary    int
		backup     int
	}{
		// 0 lands on 1 and 0 of the rest on 2: 41/100 against 1/300
		{firstDraw: 0, secondDraw: 0, primary: 2, backup: 1},
		// 99 lands on 1 and 299 of the rest on 2, 300 on 3
		{firstDraw: 99, secondDraw: 299, primary: 2, backup: 1},
		{firstDraw: 99, secondDraw: 300, primary: 3, backup: 1},
		// 100 lands on 2 and 100 of the rest on 3: 1/300 against 6/200
		{firstDraw: 100, secondDraw: 100, primary: 2, backup: 3},
		// 600 lands on 4 and 0 of the rest on 1: 11/400 against 41/100
		{firstDraw: 600, secondDraw: 0, primary: 4, backup: 1},
		// 999 lands on 4 and 599 of the rest on 3: 11/400 against 6/200
		{firstDraw: 999, secondDraw: 599, primary: 4, backup: 3},
		// past the total the draw wraps: 1600 is 600 again
		{firstDraw: 1600, secondDraw: 600, primary: 4, backup: 1},
		// the top of a draw's range: 4294967295 % 1000 is 295, on 2, and 4294967295 % 700 is 395, on 4
		{firstDraw: 4294967295, secondDraw: 4294967295, primary: 2, backup: 4},
	}
	for _, c := range cases {
		request := testRequest()
		request.FirstDraw = c.firstDraw
		request.SecondDraw = c.secondDraw
		testWantPick(t, "fixed", PickSocketListeners(build(), request, settings), SocketPickFound, c.primary, c.backup)
	}
}

func TestPickIgnoresTheOrderOfItsCandidates(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	group := []*SocketCandidate{testCandidate(1), testCandidate(2), testCandidate(3), testCandidate(4)}
	for index, candidate := range group {
		candidate.Weight = 100 * (index + 1)
		testLoad(candidate, index*3)
	}
	reversed := slices.Clone(group)
	slices.Reverse(reversed)
	rotated := append(slices.Clone(group[2:]), group[:2]...)
	for draw := uint32(0); draw < 2_000; draw += 7 {
		request := testRequest()
		request.FirstDraw = draw
		request.SecondDraw = draw * 31
		want := PickSocketListeners(group, request, settings)
		for _, other := range [][]*SocketCandidate{reversed, rotated} {
			if got := PickSocketListeners(other, request, settings); !reflect.DeepEqual(got, want) {
				t.Errorf("draw %d: %+v, want %+v", draw, got, want)
			}
		}
	}
}

// A pick is a function: the caller records the ticket, and nothing it passed in moves.
func TestPickChangesNothing(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	build := func() []*SocketCandidate {
		group := []*SocketCandidate{testCandidate(2), testCandidate(1), testCandidate(3)}
		testIssue(group[0], testDialerId, testNowMillis)
		group[1].Ejection = SocketEjectionState{ConsecutiveCount: 1, StartMillis: testNowMillis}
		group[2].Alpns = []string{"h2"}
		return group
	}
	group := build()
	request := testRequest()
	PickSocketListeners(group, request, settings)
	if !reflect.DeepEqual(group, build()) {
		t.Error("a pick changed its candidates or their order")
	}
	if !reflect.DeepEqual(request, testRequest()) {
		t.Error("a pick changed its request")
	}
}

func TestClampCount(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	cases := []struct {
		maxStreams int
		clampCount int
	}{
		{maxStreams: 0, clampCount: 4},
		{maxStreams: 1, clampCount: 4},
		{maxStreams: 16, clampCount: 4},
		{maxStreams: 49, clampCount: 4},
		{maxStreams: 50, clampCount: 5},
		{maxStreams: 59, clampCount: 5},
		{maxStreams: 60, clampCount: 6},
		{maxStreams: 100, clampCount: 10},
		{maxStreams: 256, clampCount: 25},
		{maxStreams: 259, clampCount: 25},
		{maxStreams: 260, clampCount: 26},
		{maxStreams: 1_000, clampCount: 100},
	}
	for _, c := range cases {
		if got := SocketClampCount(c.maxStreams, settings); got != c.clampCount {
			t.Errorf("max_streams %d: c %d, want %d", c.maxStreams, got, c.clampCount)
		}
	}
}

func TestEstimate(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	otherDialerId := testId(0xd2)
	issue := func(candidate *SocketCandidate, dialerId connect.Id, count int, issueMillis int64) {
		for range count {
			testIssue(candidate, dialerId, issueMillis)
		}
	}
	cases := []struct {
		name string
		load func(candidate *SocketCandidate)
		est  int
	}{
		{name: "nothing", load: func(c *SocketCandidate) {}, est: 0},
		{name: "a report alone", load: func(c *SocketCandidate) { c.ReportedInflight = 7 }, est: 7},
		{name: "a negative report", load: func(c *SocketCandidate) { c.ReportedInflight = -7 }, est: 0},
		{name: "tickets on a report", load: func(c *SocketCandidate) {
			c.ReportedInflight = 7
			issue(c, testDialerId, 3, testNowMillis)
		}, est: 10},
		{name: "one dialer up to c", load: func(c *SocketCandidate) { issue(c, testDialerId, 25, testNowMillis) }, est: 25},
		{name: "one dialer past c", load: func(c *SocketCandidate) { issue(c, testDialerId, 26, testNowMillis) }, est: 25},
		{name: "one dialer far past c", load: func(c *SocketCandidate) { issue(c, testDialerId, 500, testNowMillis) }, est: 25},
		{name: "each dialer has its own c", load: func(c *SocketCandidate) {
			issue(c, testDialerId, 500, testNowMillis)
			issue(c, otherDialerId, 3, testNowMillis)
		}, est: 28},
		{name: "c follows max_streams", load: func(c *SocketCandidate) {
			c.MaxStreams = 16
			issue(c, testDialerId, 100, testNowMillis)
		}, est: 4},
		{name: "before the report", load: func(c *SocketCandidate) { issue(c, testDialerId, 5, testNowMillis-1_001) }, est: 0},
		{name: "in the report's millisecond", load: func(c *SocketCandidate) { issue(c, testDialerId, 5, testNowMillis-1_000) }, est: 5},
		{name: "some before and some since", load: func(c *SocketCandidate) {
			issue(c, testDialerId, 5, testNowMillis-2_000)
			issue(c, testDialerId, 2, testNowMillis)
		}, est: 2},
		{name: "a ticket's last millisecond", load: func(c *SocketCandidate) {
			c.ReportMillis = testNowMillis - 40_000
			issue(c, testDialerId, 5, testNowMillis-29_999)
		}, est: 5},
		{name: "as old as a ticket lives", load: func(c *SocketCandidate) {
			c.ReportMillis = testNowMillis - 40_000
			issue(c, testDialerId, 5, testNowMillis-30_000)
		}, est: 0},
		{name: "only the live ones count toward c", load: func(c *SocketCandidate) {
			c.ReportMillis = testNowMillis - 40_000
			issue(c, testDialerId, 100, testNowMillis-30_000)
			issue(c, testDialerId, 3, testNowMillis-1)
		}, est: 3},
		{name: "a dialer with only an exclusion", load: func(c *SocketCandidate) {
			c.DialerClientIdShares[testDialerId] = &SocketDialerShare{Exclusion: SocketEjectionState{ConsecutiveCount: 1, StartMillis: testNowMillis}}
		}, est: 0},
	}
	for _, c := range cases {
		candidate := testCandidate(1)
		c.load(candidate)
		if est := SocketEstimate(candidate, testNowMillis, settings); est != c.est {
			t.Errorf("%s: est %d, want %d", c.name, est, c.est)
		}
	}
}

// §22.5's one-dialer case in pure form, on a stepped clock: the bucket's burst of 500 and then its 50
// a second, each connection lasting 100 ms, to one 256-stream listener reporting every 15 s. Every
// ticket is issued, and between reports that dialer moves est by at most c. A clamp that held tickets
// back would stop this one at about 25 per report (D-SOCK-5; meta review CC-06).
func TestOneDialersShortConnectionsAreNeverHeldByTheClamp(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	const (
		burstCount       = 500
		ticketGapMillis  = 20
		connectionMillis = 100
		reportGapMillis  = 15_000
		runMillis        = 60_000
	)
	listener := testCandidate(1)
	listener.ReportMillis = 0
	listener.LeaseExpireMillis = runMillis + 45_000
	clampCount := SocketClampCount(listener.MaxStreams, settings)
	if clampCount != 25 {
		t.Fatalf("c is %d", clampCount)
	}

	connectionEnds := []int64{}
	issuedCount := 0
	offeredCount := 0
	find := func(nowMillis int64) {
		offeredCount += 1
		result := PickSocketListeners([]*SocketCandidate{listener}, &SocketPickRequest{DialerClientId: testDialerId, NowMillis: nowMillis}, settings)
		if result.Outcome != SocketPickFound || result.Primary != listener {
			t.Fatalf("at %d ms: outcome %d", nowMillis, result.Outcome)
		}
		issuedCount += 1
		testIssue(listener, testDialerId, nowMillis)
		connectionEnds = append(connectionEnds, nowMillis+connectionMillis)
		if added := SocketEstimate(listener, nowMillis, settings) - listener.ReportedInflight; clampCount < added {
			t.Fatalf("at %d ms: the dialer added %d to est", nowMillis, added)
		}
	}
	for range burstCount {
		find(0)
	}
	addedAtPeak := SocketEstimate(listener, 0, settings) - listener.ReportedInflight
	if addedAtPeak != clampCount {
		t.Errorf("the burst added %d", addedAtPeak)
	}
	for nowMillis := int64(ticketGapMillis); nowMillis < runMillis; nowMillis += ticketGapMillis {
		if nowMillis%reportGapMillis == 0 {
			connectionEnds = slices.DeleteFunc(connectionEnds, func(endMillis int64) bool { return endMillis <= nowMillis })
			// short connections never move in-flight enough for an eager report, so this is the
			// heartbeat, and est alone leaves the tickets it covers behind
			listener.ReportedInflight = len(connectionEnds)
			listener.ReportMillis = nowMillis
		}
		find(nowMillis)
	}
	if issuedCount != offeredCount || issuedCount != burstCount+runMillis/ticketGapMillis-1 {
		t.Errorf("%d issued of %d offered", issuedCount, offeredCount)
	}
}

// §22.5's other half: a dialer that takes tickets and opens nothing moves est by at most c, however
// many it takes, and the tickets fade when they expire even if no report comes.
func TestADialerThatRedeemsNothingMovesEstByAtMostTheClamp(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	idleDialerId := testId(0xd2)
	listener := testCandidate(1)
	clampCount := SocketClampCount(listener.MaxStreams, settings)
	for range clampCount {
		testIssue(listener, testDialerId, testNowMillis)
	}
	before := SocketEstimate(listener, testNowMillis, settings)

	for range 500 {
		result := PickSocketListeners([]*SocketCandidate{listener}, &SocketPickRequest{DialerClientId: idleDialerId, NowMillis: testNowMillis}, settings)
		if result.Outcome != SocketPickFound {
			t.Fatalf("outcome %d", result.Outcome)
		}
		testIssue(listener, idleDialerId, testNowMillis)
	}
	if moved := SocketEstimate(listener, testNowMillis, settings) - before; moved != clampCount {
		t.Errorf("the idle dialer moved est by %d", moved)
	}
	expiredMillis := testNowMillis + settings.TicketLifetime.Milliseconds()
	if est := SocketEstimate(listener, expiredMillis-1, settings); est != 2*clampCount {
		t.Errorf("est %d in the tickets' last millisecond", est)
	}
	if est := SocketEstimate(listener, expiredMillis, settings); est != 0 {
		t.Errorf("est %d once the tickets expired", est)
	}
}

// What does hold a dialer: est reaching max_streams, by step 1. Ten dialers at c and six tickets of an
// eleventh's fill a 256-stream listener's est, and the next Find is busy, with no count of anything
// capped along the way.
func TestOnlyEstAtMaxStreamsHoldsADialer(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	listener := testCandidate(1)
	clampCount := SocketClampCount(listener.MaxStreams, settings)
	for dialerIndex := range 10 {
		for range clampCount {
			result := PickSocketListeners([]*SocketCandidate{listener}, testRequest(), settings)
			if result.Outcome != SocketPickFound {
				t.Fatalf("dialer %d: outcome %d", dialerIndex, result.Outcome)
			}
			testIssue(listener, testId(0x200+dialerIndex), testNowMillis)
		}
	}
	for range 6 {
		if result := PickSocketListeners([]*SocketCandidate{listener}, testRequest(), settings); result.Outcome != SocketPickFound {
			t.Fatalf("est %d: outcome %d", SocketEstimate(listener, testNowMillis, settings), result.Outcome)
		}
		testIssue(listener, testId(0x300), testNowMillis)
	}
	if est := SocketEstimate(listener, testNowMillis, settings); est != 256 {
		t.Fatalf("est %d", est)
	}
	testWantPick(t, "full", PickSocketListeners([]*SocketCandidate{listener}, testRequest(), settings), SocketPickBusy, -1, -1)
}

// Every tunable the pick reads comes from its settings.
func TestSettingsMoveThePick(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	settings.ClampFloorCount = 1
	settings.ClampPercent = 50
	if got := SocketClampCount(100, settings); got != 50 {
		t.Errorf("c %d", got)
	}
	if got := SocketClampCount(1, settings); got != 1 {
		t.Errorf("c %d", got)
	}
	settings.TicketLifetime = 5_000_000
	listener := testCandidate(1)
	testIssue(listener, testDialerId, testNowMillis)
	if got := SocketEstimate(listener, testNowMillis+4, settings); got != 1 {
		t.Errorf("est %d", got)
	}
	if got := SocketEstimate(listener, testNowMillis+5, settings); got != 0 {
		t.Errorf("est %d", got)
	}
}
