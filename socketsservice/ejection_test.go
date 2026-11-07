// §9.6's ladder, the half-group cap, and the two-network rule, on stepped time.

package socketsservice

import (
	"testing"
)

// §9.6: 30 s per consecutive ejection, up to 300 s. Each ejection here comes the moment the one before
// it ends, which keeps the run going until the top of the ladder outlasts its own record.
func TestEjectionLadder(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	state := SocketEjectionState{}
	nowMillis := testNowMillis
	for _, wantSeconds := range []int64{30, 60, 90, 120, 150, 180, 210, 240, 270, 300} {
		next, ok := state.Eject(nowMillis, 0, 10, settings)
		if !ok {
			t.Fatalf("the %d s ejection did not take", wantSeconds)
		}
		state = next
		endMillis := nowMillis + wantSeconds*1_000
		if !state.Active(endMillis-1, settings) {
			t.Errorf("the %d s ejection ended early", wantSeconds)
		}
		if state.Active(endMillis, settings) {
			t.Errorf("the %d s ejection ran past its end", wantSeconds)
		}
		nowMillis = endMillis
	}
	if state.ConsecutiveCount != 10 {
		t.Errorf("a run of %d", state.ConsecutiveCount)
	}
}

func TestEjectionNeverLastsPastTheMax(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	for _, consecutiveCount := range []int{10, 11, 100, 1_000_000} {
		state := SocketEjectionState{ConsecutiveCount: consecutiveCount, StartMillis: testNowMillis}
		if !state.Active(testNowMillis+299_999, settings) {
			t.Errorf("%d: over before 300 s", consecutiveCount)
		}
		if state.Active(testNowMillis+300_000, settings) {
			t.Errorf("%d: still going at 300 s", consecutiveCount)
		}
	}
}

// A run ends with the record §2.8 lets the store keep, so 300 s after an ejection began the next one
// starts again at 30 s, and a full 300 s ejection takes its run with it.
func TestARunEndsWithItsRecord(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	state := SocketEjectionState{ConsecutiveCount: 3, StartMillis: testNowMillis}

	next, ok := state.Eject(testNowMillis+299_999, 0, 10, settings)
	if !ok || next.ConsecutiveCount != 4 {
		t.Errorf("inside the record: %+v %v", next, ok)
	}
	next, ok = state.Eject(testNowMillis+300_000, 0, 10, settings)
	if !ok || next.ConsecutiveCount != 1 {
		t.Errorf("past the record: %+v %v", next, ok)
	}

	top := SocketEjectionState{ConsecutiveCount: 10, StartMillis: testNowMillis}
	next, ok = top.Eject(testNowMillis+300_000, 0, 10, settings)
	if !ok || next.ConsecutiveCount != 1 {
		t.Errorf("after the top of the ladder: %+v %v", next, ok)
	}
}

func TestTheZeroStateIsNoEjection(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	for _, nowMillis := range []int64{0, 1, testNowMillis} {
		if (SocketEjectionState{}).Active(nowMillis, settings) {
			t.Errorf("active at %d", nowMillis)
		}
	}
	next, ok := SocketEjectionState{}.Eject(testNowMillis, 0, 10, settings)
	if !ok || next.ConsecutiveCount != 1 || next.StartMillis != testNowMillis {
		t.Errorf("the first ejection: %+v %v", next, ok)
	}
}

// A late report changes nothing while an ejection holds, so reporters cannot lengthen one.
func TestAnEjectionThatHoldsCannotBeExtended(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	state := SocketEjectionState{ConsecutiveCount: 2, StartMillis: testNowMillis}
	for _, nowMillis := range []int64{testNowMillis, testNowMillis + 1, testNowMillis + 59_999} {
		next, ok := state.Eject(nowMillis, 0, 10, settings)
		if ok || next != state {
			t.Errorf("at %d: %+v %v", nowMillis, next, ok)
		}
	}
	if next, ok := state.Eject(testNowMillis+60_000, 0, 10, settings); !ok || next.ConsecutiveCount != 3 {
		t.Errorf("once it ended: %+v %v", next, ok)
	}
}

// §9.6: at most half a group, rounded down.
func TestEjectionIsCappedAtHalfTheGroup(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	cases := []struct {
		ejectedCount int
		groupCount   int
		allowed      bool
	}{
		{ejectedCount: 0, groupCount: 0, allowed: false},
		{ejectedCount: 0, groupCount: 1, allowed: false},
		{ejectedCount: 0, groupCount: 2, allowed: true},
		{ejectedCount: 1, groupCount: 2, allowed: false},
		{ejectedCount: 0, groupCount: 3, allowed: true},
		{ejectedCount: 1, groupCount: 3, allowed: false},
		{ejectedCount: 1, groupCount: 4, allowed: true},
		{ejectedCount: 2, groupCount: 4, allowed: false},
		{ejectedCount: 2, groupCount: 5, allowed: false},
		{ejectedCount: 2, groupCount: 6, allowed: true},
		{ejectedCount: 49, groupCount: 100, allowed: true},
		{ejectedCount: 50, groupCount: 100, allowed: false},
		{ejectedCount: 51, groupCount: 100, allowed: false},
	}
	for _, c := range cases {
		state := SocketEjectionState{}
		next, ok := state.Eject(testNowMillis, c.ejectedCount, c.groupCount, settings)
		if ok != c.allowed {
			t.Errorf("%d of %d: %v", c.ejectedCount, c.groupCount, ok)
		}
		if !ok && next != state {
			t.Errorf("%d of %d: a refused ejection changed the state", c.ejectedCount, c.groupCount)
		}
	}
}

// Filling a group one report at a time stops at half of it, and the half left serves.
func TestEjectingAGroupLeavesHalfOfItServing(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	group := []*SocketCandidate{}
	for index := range 10 {
		group = append(group, testCandidate(index+1))
	}
	ejectedCount := 0
	for _, candidate := range group {
		next, ok := candidate.Ejection.Eject(testNowMillis, ejectedCount, len(group), settings)
		if ok {
			candidate.Ejection = next
			ejectedCount += 1
		}
	}
	if ejectedCount != 5 {
		t.Fatalf("%d ejected", ejectedCount)
	}
	for draw := uint32(0); draw < 1_000; draw += 13 {
		request := testRequest()
		request.FirstDraw = draw
		request.SecondDraw = draw + 1
		result := PickSocketListeners(group, request, settings)
		if result.Primary.Ejection.Active(testNowMillis, settings) || result.Backup.Ejection.Active(testNowMillis, settings) {
			t.Fatalf("draw %d reached an ejected listener", draw)
		}
	}
}

// An exclusion is one dialer's run, on the same ladder.
func TestAnExclusionLastsAsAnEjectionDoes(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	listener := testCandidate(1)
	beside := testCandidate(2)
	listener.LeaseExpireMillis = testNowMillis * 2
	beside.LeaseExpireMillis = testNowMillis * 2
	share := &SocketDialerShare{}
	listener.DialerClientIdShares[testDialerId] = share
	for _, wantSeconds := range []int64{30, 60, 90} {
		nowMillis := share.Exclusion.StartMillis + share.Exclusion.durationMillis(settings)
		if share.Exclusion.ConsecutiveCount == 0 {
			nowMillis = testNowMillis
		}
		next, ok := share.Exclusion.Eject(nowMillis, 0, 2, settings)
		if !ok {
			t.Fatalf("the %d s exclusion did not take", wantSeconds)
		}
		share.Exclusion = next
		request := testRequest()
		request.NowMillis = nowMillis + wantSeconds*1_000 - 1
		testWantPick(t, "excluded", PickSocketListeners([]*SocketCandidate{listener, beside}, request, settings), SocketPickFound, 2, -1)
		request.NowMillis = nowMillis + wantSeconds*1_000
		if result := PickSocketListeners([]*SocketCandidate{listener, beside}, request, settings); result.Backup == nil {
			t.Errorf("the %d s exclusion ran past its end", wantSeconds)
		}
	}
}

func TestReportersEject(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	networkA := testId(0xa1)
	networkB := testId(0xb1)
	networkC := testId(0xc1)
	cases := []struct {
		name    string
		reports []*SocketFailureReport
		eject   bool
	}{
		{name: "no reports", reports: nil, eject: false},
		{name: "one report", reports: []*SocketFailureReport{{DialerNetworkId: networkA, ReportMillis: testNowMillis}}, eject: false},
		{name: "two of one network", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkA, ReportMillis: testNowMillis - 1},
		}, eject: false},
		{name: "many of one network", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkA, ReportMillis: testNowMillis - 1},
			{DialerNetworkId: networkA, ReportMillis: testNowMillis - 2},
			{DialerNetworkId: networkA, ReportMillis: testNowMillis - 3},
		}, eject: false},
		{name: "two networks at once", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis},
		}, eject: true},
		{name: "two networks, the older at the window's end", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis - 30_000},
		}, eject: true},
		{name: "two networks, the older just outside", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis - 30_001},
		}, eject: false},
		{name: "both outside", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis - 40_000},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis - 31_000},
		}, eject: false},
		{name: "an old network does not count beside a new one's many", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkA, ReportMillis: testNowMillis - 10},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis - 30_001},
		}, eject: false},
		{name: "three networks", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis - 10},
			{DialerNetworkId: networkC, ReportMillis: testNowMillis - 20},
		}, eject: true},
		{name: "a report from past now", reports: []*SocketFailureReport{
			{DialerNetworkId: networkA, ReportMillis: testNowMillis},
			{DialerNetworkId: networkB, ReportMillis: testNowMillis + 1},
		}, eject: false},
	}
	for _, c := range cases {
		if got := SocketReportersEject(c.reports, testNowMillis, settings); got != c.eject {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// §22.5's reading of the same rule end to end: one lying network excludes only for itself and ejects
// nothing, and a second network's report is what reaches everyone.
func TestALyingReporterHarmsOnlyItself(t *testing.T) {
	settings := DefaultSocketSchedulerSettings()
	liarNetworkId := testId(0xa1)
	honestNetworkId := testId(0xb1)
	liarDialerId := testId(0xa2)
	otherDialerId := testId(0xb2)
	listener := testCandidate(1)
	beside := testCandidate(2)
	group := []*SocketCandidate{listener, beside}

	share := &SocketDialerShare{}
	listener.DialerClientIdShares[liarDialerId] = share
	next, ok := share.Exclusion.Eject(testNowMillis, 0, len(group), settings)
	if !ok {
		t.Fatal("the report excluded nothing")
	}
	share.Exclusion = next
	reports := []*SocketFailureReport{{DialerNetworkId: liarNetworkId, ReportMillis: testNowMillis}}
	if SocketReportersEject(reports, testNowMillis, settings) {
		t.Fatal("one network ejected")
	}

	liarRequest := testRequest()
	liarRequest.DialerClientId = liarDialerId
	testWantPick(t, "the liar", PickSocketListeners(group, liarRequest, settings), SocketPickFound, 2, -1)
	otherRequest := testRequest()
	otherRequest.DialerClientId = otherDialerId
	if result := PickSocketListeners(group, otherRequest, settings); result.Backup == nil {
		t.Error("another dialer lost the listener")
	}

	reports = append(reports, &SocketFailureReport{DialerNetworkId: honestNetworkId, ReportMillis: testNowMillis + 1})
	if !SocketReportersEject(reports, testNowMillis+1, settings) {
		t.Error("two networks did not eject")
	}
}
