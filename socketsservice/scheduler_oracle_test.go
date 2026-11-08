// §22.5's P2C against a stale-load oracle. These simulate a group whose true in-flight only the
// harness knows, while the scheduler sees what the service sees: reports up to a heartbeat old and
// the clamped issued count. The oracle is the true load set beside what each chooser did with the
// stale view, and the chooser it is set against is least-loaded, which herds: every Find between
// two reports sees one lowest listener and goes there (Mitzenmacher, IEEE TPDS 11(1), 2000).
//
// Everything is integers from fixed seeds, so a run is the same on every leg and every run.

package socketsservice

import (
	"container/heap"
	"math/rand/v2"
	"testing"

	"github.com/urnetwork/connect"
)

// A stale-load run's shape.
type oracleRun struct {
	weights    []int
	maxStreams int
	// How many dialers the Finds come from. One is the harshest: its issued count clamps at c, so est
	// is little fresher than the reports.
	dialerCount int
	// A Find every this long on average, a stream this long on average, and a heartbeat this often,
	// 20% either way (§9.5).
	findGapMillis    int64
	connectionMillis int64
	reportMillis     int64
	// §9.5's eager reports, on an in-flight move of max(8, 25% of max_streams) at most every 2 s. Off,
	// nothing freshens the view between heartbeats.
	eagerReports bool
	warmupMillis int64
	runMillis    int64
}

// What a run came to.
type oracleOutcome struct {
	// The highest any listener's true in-flight rose above its fair share of the group's true
	// in-flight at that moment: 1.0 is perfectly balanced.
	peakOverFair float64
	// Each listener's share of the true in-flight, over the run.
	inflightShares []float64
	// Finds nothing could take.
	busyCount int
	findCount int
}

// One stream's end.
type oracleConnection struct {
	endMillis     int64
	listenerIndex int
}

// Streams by end time.
type oracleConnections []oracleConnection

func (self oracleConnections) Len() int           { return len(self) }
func (self oracleConnections) Less(i, j int) bool { return self[i].endMillis < self[j].endMillis }
func (self oracleConnections) Swap(i, j int)      { self[i], self[j] = self[j], self[i] }

// Takes a stream.
func (self *oracleConnections) Push(item any) { *self = append(*self, item.(oracleConnection)) }

// Gives back the last stream.
func (self *oracleConnections) Pop() any {
	old := *self
	last := old[len(old)-1]
	*self = old[:len(old)-1]
	return last
}

// How a simulated Find chooses, from what the service sees. nil is nothing to choose.
type oracleChooser func(candidates []*SocketCandidate, request *SocketPickRequest, settings *SocketSchedulerSettings) *SocketCandidate

// The real thing.
func oracleChooseP2c(candidates []*SocketCandidate, request *SocketPickRequest, settings *SocketSchedulerSettings) *SocketCandidate {
	return PickSocketListeners(candidates, request, settings).Primary
}

// What §9.7 rejects: the lowest est per weight, the same answer for every Find until the view moves.
func oracleChooseLeastLoaded(candidates []*SocketCandidate, request *SocketPickRequest, settings *SocketSchedulerSettings) *SocketCandidate {
	var lowest *SocketCandidate
	lowestLoad := int64(0)
	for _, candidate := range candidates {
		est := SocketEstimate(candidate, request.NowMillis, settings)
		if candidate.MaxStreams <= est {
			continue
		}
		load := int64(est + 1)
		if lowest == nil || load*int64(lowest.Weight) < lowestLoad*int64(candidate.Weight) {
			lowest = candidate
			lowestLoad = load
		}
	}
	return lowest
}

// Runs choose over one trace. A seed fixes the whole trace, the arrivals, stream times, dialers and
// report times, apart from the draws, so two choosers on one seed face the same Finds.
func (self *oracleRun) simulate(choose oracleChooser, seed uint64) *oracleOutcome {
	settings := DefaultSocketSchedulerSettings()
	trace := rand.New(rand.NewPCG(seed, 1))
	draws := rand.New(rand.NewPCG(seed, 2))

	totalWeight := 0
	candidates := []*SocketCandidate{}
	candidateIndexes := map[*SocketCandidate]int{}
	reportDueMillis := make([]int64, len(self.weights))
	for index, weight := range self.weights {
		totalWeight += weight
		candidate := &SocketCandidate{
			ListenerClientId:     testId(index + 1),
			Protocol:             "tcp",
			Weight:               weight,
			MaxStreams:           self.maxStreams,
			Serving:              true,
			LeaseExpireMillis:    self.runMillis * 2,
			DialerClientIdShares: map[connect.Id]*SocketDialerShare{},
		}
		candidates = append(candidates, candidate)
		candidateIndexes[candidate] = index
		// heartbeats start spread over the interval, and each keeps its own jitter after that
		reportDueMillis[index] = trace.Int64N(self.reportMillis)
	}

	reportedInflights := make([]int, len(candidates))
	reportMillis := make([]int64, len(candidates))
	inflights := make([]int, len(candidates))
	inflightSums := make([]int64, len(candidates))
	connections := &oracleConnections{}
	outcome := &oracleOutcome{}
	nowMillis := int64(0)
	sampleDueMillis := self.warmupMillis
	for nowMillis < self.runMillis {
		nowMillis += 1 + trace.Int64N(2*self.findGapMillis-1)
		streamMillis := self.connectionMillis/2 + trace.Int64N(self.connectionMillis)
		dialerId := testId(0x1000 + trace.IntN(self.dialerCount))

		for connections.Len() > 0 && (*connections)[0].endMillis <= nowMillis {
			inflights[heap.Pop(connections).(oracleConnection).listenerIndex] -= 1
		}
		for index, candidate := range candidates {
			moved := inflights[index] - reportedInflights[index]
			eager := self.eagerReports && max(8, candidate.MaxStreams/4) <= max(moved, -moved) && reportMillis[index]+2_000 <= nowMillis
			if reportDueMillis[index] <= nowMillis || eager {
				candidate.ReportedInflight = inflights[index]
				candidate.ReportMillis = nowMillis
				reportedInflights[index] = inflights[index]
				reportMillis[index] = nowMillis
				clear(candidate.DialerClientIdShares)
				if reportDueMillis[index] <= nowMillis {
					jitterMillis := self.reportMillis / 5
					reportDueMillis[index] = nowMillis + self.reportMillis - jitterMillis + trace.Int64N(2*jitterMillis)
				}
			}
		}

		request := &SocketPickRequest{
			DialerClientId: dialerId,
			NowMillis:      nowMillis,
			FirstDraw:      draws.Uint32(),
			SecondDraw:     draws.Uint32(),
		}
		outcome.findCount += 1
		chosen := choose(candidates, request, settings)
		if chosen == nil {
			outcome.busyCount += 1
			continue
		}
		index := candidateIndexes[chosen]
		inflights[index] += 1
		heap.Push(connections, oracleConnection{endMillis: nowMillis + streamMillis, listenerIndex: index})
		share := chosen.DialerClientIdShares[dialerId]
		if share == nil {
			share = &SocketDialerShare{}
			chosen.DialerClientIdShares[dialerId] = share
		}
		share.PrimaryIssueMillis = append(share.PrimaryIssueMillis, nowMillis)
		// only the newest c can count, so that is all a store keeps
		if clampCount := SocketClampCount(chosen.MaxStreams, settings); clampCount < len(share.PrimaryIssueMillis) {
			share.PrimaryIssueMillis = share.PrimaryIssueMillis[1:]
		}

		if nowMillis < self.warmupMillis {
			continue
		}
		totalInflight := 0
		for _, inflight := range inflights {
			totalInflight += inflight
		}
		fair := float64(totalInflight) * float64(chosen.Weight) / float64(totalWeight)
		outcome.peakOverFair = max(outcome.peakOverFair, float64(inflights[index])/fair)
		if sampleDueMillis <= nowMillis {
			sampleDueMillis += 1_000
			for sampleIndex, inflight := range inflights {
				inflightSums[sampleIndex] += int64(inflight)
			}
		}
	}

	sumTotal := int64(0)
	for _, inflightSum := range inflightSums {
		sumTotal += inflightSum
	}
	outcome.inflightShares = make([]float64, len(inflightSums))
	for index, inflightSum := range inflightSums {
		outcome.inflightShares[index] = float64(inflightSum) / float64(sumTotal)
	}
	return outcome
}

// N equal weights.
func oracleEqualWeights(count int) []int {
	weights := make([]int, count)
	for index := range weights {
		weights[index] = 100
	}
	return weights
}

// The stale-load oracle itself. With a report every 15 s or 45 s and one dialer, so that est is little
// fresher than the reports, least-loaded sends a listener about 25 times its fair share, as every Find
// between two reports sees the same lowest listener. P2C stays near twice it on the same Finds. These
// bounds sit between what the two did on these seeds, so either side moving much fails.
func TestP2cHoldsLoadOnStaleReportsWhereLeastLoadedHerds(t *testing.T) {
	cases := []struct {
		dialerCount  int
		reportMillis int64
		p2cMost      float64
		herdLeast    float64
	}{
		{dialerCount: 1, reportMillis: 15_000, p2cMost: 3, herdLeast: 15},
		{dialerCount: 1, reportMillis: 45_000, p2cMost: 3, herdLeast: 15},
		{dialerCount: 8, reportMillis: 45_000, p2cMost: 3, herdLeast: 3.5},
	}
	for _, c := range cases {
		run := &oracleRun{
			weights:          oracleEqualWeights(32),
			maxStreams:       256,
			dialerCount:      c.dialerCount,
			findGapMillis:    5,
			connectionMillis: 10_000,
			reportMillis:     c.reportMillis,
			warmupMillis:     45_000,
			runMillis:        150_000,
		}
		for seed := uint64(1); seed <= 2; seed += 1 {
			p2c := run.simulate(oracleChooseP2c, seed)
			herd := run.simulate(oracleChooseLeastLoaded, seed)
			if p2c.busyCount != 0 || herd.busyCount != 0 {
				t.Errorf("%d dialers, %d ms, seed %d: %d and %d Finds busy", c.dialerCount, c.reportMillis, seed, p2c.busyCount, herd.busyCount)
			}
			if c.p2cMost < p2c.peakOverFair {
				t.Errorf("%d dialers, %d ms, seed %d: P2C peaked at %.2f of a fair share", c.dialerCount, c.reportMillis, seed, p2c.peakOverFair)
			}
			if herd.peakOverFair < c.herdLeast {
				t.Errorf("%d dialers, %d ms, seed %d: least-loaded peaked at only %.2f", c.dialerCount, c.reportMillis, seed, herd.peakOverFair)
			}
		}
	}
}

// The control: on reports fresh enough, least-loaded balances as well as P2C, so what the test above
// shows is staleness, not a poor least-loaded.
func TestFreshReportsBalanceEitherWay(t *testing.T) {
	run := &oracleRun{
		weights:          oracleEqualWeights(32),
		maxStreams:       256,
		dialerCount:      1,
		findGapMillis:    5,
		connectionMillis: 10_000,
		reportMillis:     2_000,
		warmupMillis:     45_000,
		runMillis:        150_000,
	}
	for seed := uint64(1); seed <= 2; seed += 1 {
		for name, choose := range map[string]oracleChooser{"P2C": oracleChooseP2c, "least-loaded": oracleChooseLeastLoaded} {
			if outcome := run.simulate(choose, seed); 1.5 < outcome.peakOverFair {
				t.Errorf("%s, seed %d: peaked at %.2f of a fair share", name, seed, outcome.peakOverFair)
			}
		}
	}
}

// §22.8's in-flight share, within 25% of weight, here over simulated groups with §9.5's eager reports.
// max_streams sits well above the load, which keeps §9.7's est filter out of what this measures
// (TestEnoughShortDialersFillEstWithAListenerNearlyIdle is that filter).
func TestInflightShareFollowsWeight(t *testing.T) {
	cases := []struct {
		weights     []int
		dialerCount int
	}{
		{weights: []int{50, 100, 100, 200, 400, 1000}, dialerCount: 1},
		{weights: []int{50, 100, 100, 200, 400, 1000}, dialerCount: 200},
		{weights: []int{100, 300}, dialerCount: 1},
		{weights: []int{100, 300}, dialerCount: 200},
		{weights: []int{100, 100, 200, 200, 400, 400, 800, 800}, dialerCount: 1},
		{weights: []int{100, 100, 200, 200, 400, 400, 800, 800}, dialerCount: 200},
		{weights: oracleEqualWeights(32), dialerCount: 8},
	}
	for _, c := range cases {
		run := &oracleRun{
			weights:          c.weights,
			maxStreams:       4_096,
			dialerCount:      c.dialerCount,
			findGapMillis:    5,
			connectionMillis: 10_000,
			reportMillis:     15_000,
			eagerReports:     true,
			warmupMillis:     45_000,
			runMillis:        300_000,
		}
		outcome := run.simulate(oracleChooseP2c, 1)
		if outcome.busyCount != 0 {
			t.Errorf("%v: %d Finds busy", c.weights, outcome.busyCount)
		}
		totalWeight := 0
		for _, weight := range c.weights {
			totalWeight += weight
		}
		for index, weight := range c.weights {
			weightShare := float64(weight) / float64(totalWeight)
			if ratio := outcome.inflightShares[index] / weightShare; ratio < 0.75 || 1.25 < ratio {
				t.Errorf("%v with %d dialers: listener %d holds %.2f of its share", c.weights, c.dialerCount, index, ratio)
			}
		}
	}
}

// §9.7 as written, and what question sock-pure-est-reach asks about. est gives no credit for a stream
// that ended, so between reports it counts every ticket up to c per dialer, and step 1 turns a listener
// away once those reach max_streams. Ten dialers at c add 250, which at this load stays under a
// 256-stream listener's line. An eleventh crosses it, and the listener is busy for most of each report
// interval with about 5 streams really in flight, since short streams never move in-flight enough for
// an eager report to help.
func TestEnoughShortDialersFillEstWithAListenerNearlyIdle(t *testing.T) {
	cases := []struct {
		dialerCount int
		held        bool
	}{
		{dialerCount: 1, held: false},
		{dialerCount: 10, held: false},
		{dialerCount: 11, held: true},
		{dialerCount: 20, held: true},
	}
	for _, c := range cases {
		run := &oracleRun{
			weights:          oracleEqualWeights(1),
			maxStreams:       256,
			dialerCount:      c.dialerCount,
			findGapMillis:    20,
			connectionMillis: 100,
			reportMillis:     15_000,
			eagerReports:     true,
			warmupMillis:     15_000,
			runMillis:        60_000,
		}
		outcome := run.simulate(oracleChooseP2c, 1)
		if held := outcome.busyCount != 0; held != c.held {
			t.Errorf("%d dialers: %d of %d Finds busy", c.dialerCount, outcome.busyCount, outcome.findCount)
		}
		if c.held && outcome.busyCount*2 < outcome.findCount {
			t.Errorf("%d dialers: only %d of %d Finds busy", c.dialerCount, outcome.busyCount, outcome.findCount)
		}
	}
}
