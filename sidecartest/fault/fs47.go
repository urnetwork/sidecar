// FS-47 (§20.7, FI-13 (c); EVSB-M2-15) on a Net, the gate's pacing clauses: evs's QuotaGate over the Net's fake Quota
// and clock at a network's storage limit, k erasers each asking for one ?closure=1 upload at a time and asking again at
// its refusal's retry_after_ms. Each is served once every k/R s, R being evs_closure_uploads_per_s, none starves, and
// obedient erasers get equal turns. Each schedule's erasers ask as one step on the gate's actor, which the clock moves a
// step at a time, so no barrier is passed and the explorer's seeds each take the one order there is.
//
// The registered case, Fs47ErasersAreServedInEqualTurns, with k = 8 erasers at R = 4; the clause beside it
// (clauses.go), one eraser alone keeping its own 60 a minute. The push kinds at the exact limit and while spent run in
// evsservice's quota_gate_test.go, outside the registry; the record-class file, its CLOSURE and ERASE, and the mail case
// are EVS1's and MAIL's. FI-13 (c) is QUOTA-M2-13's oracle and unbound (fault.FI(13) fails closed), and these
// schedules store nothing for it to count, so each checks the row's pacing bound after every step instead (pacing):
// the network takes at most R closure uploads in any second of the clock, and no eraser more than its 60 in any minute.
// FS-47's T3 run is server's quotahost's.

package fault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

var Fs47 = Register("FS-47", "", []Tier{TierT2}, Fs47ErasersAreServedInEqualTurns)

// The network's closure upload limits a schedule sets, and the times each of its erasers was served, which its pacing
// check reads.
type fs47Served struct {
	// R, the network's closure uploads a second: 4.
	uploadsPerSecond int
	// An eraser's own closure uploads a minute: 60.
	uploadsPerMinute int

	stateLock sync.Mutex
	times     [][]time.Time
}

// R at 4 and an eraser's 60 a minute, as the row's pacing clauses run.
func newFs47Served() *fs47Served {
	return &fs47Served{uploadsPerSecond: 4, uploadsPerMinute: 60}
}

// The row's pacing bound, after every step: at most R uploads in each second of the clock, and no eraser past its own
// a minute, each window turning on the clock's second and minute as the gate's windows do.
func (self *fs47Served) check() Invariant {
	return NewInvariant("pacing", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		secondCounts := map[time.Time]int{}
		for eraser, times := range self.times {
			minuteCounts := map[time.Time]int{}
			for _, served := range times {
				secondCounts[served.Truncate(time.Second)] += 1
				minuteCounts[served.Truncate(time.Minute)] += 1
			}
			for minute, count := range minuteCounts {
				if self.uploadsPerMinute < count {
					return fmt.Errorf("eraser %d was served %d in the minute from %s, past its %d", eraser, count, minute, self.uploadsPerMinute)
				}
			}
		}
		for second, count := range secondCounts {
			if self.uploadsPerSecond < count {
				return fmt.Errorf("the network took %d uploads in the second from %s, past R %d", count, second, self.uploadsPerSecond)
			}
		}
		return nil
	})
}

// A step action: eraserCount erasers at the network's storage limit for span of the Net's clock, each asking whenever
// its last answer allows, at the gate's ask step of fake time, the times each was served kept in into; check reads them.
func fs47ServeErasers(into *fs47Served, eraserCount int, span time.Duration, check func(served [][]time.Time) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		quota := net.Fakes().Quota
		clock := net.Clock()
		networkId := connect.NewId()
		quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
			"evs_closure_uploads_per_s":   int64(into.uploadsPerSecond),
			"evs_closure_uploads_per_min": int64(into.uploadsPerMinute),
			"evs_closure_bytes_per_day":   1024 * 1024 * 1024,
			"evs_closure_bytes_floor":     4 * 1024 * 1024,
		}})
		quota.SetStorageRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1000, Used: 1000})
		gate, err := evsservice.NewQuotaGate(ctx, net.Host(), nil)
		if err != nil {
			return err
		}
		defer gate.Close()
		// the gate's first read is done once its next read's timer is set
		for !gate.Over(networkId) {
			_, added := clock.WatchTimers()
			if gate.Over(networkId) {
				break
			}
			select {
			case <-added:
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// rate windows are fixed, turning on the minute, so the run starts on one
		clock.AdvanceTo(clock.Now().Truncate(time.Minute).Add(time.Minute))
		erasers := make([]connect.Id, eraserCount)
		nextAsks := make([]time.Time, eraserCount)
		served := make([][]time.Time, eraserCount)
		start := clock.Now()
		for index := range erasers {
			erasers[index] = connect.NewId()
			nextAsks[index] = start
		}
		step := 50 * time.Millisecond
		for clock.Now().Sub(start) < span {
			now := clock.Now()
			for index, eraser := range erasers {
				if now.Before(nextAsks[index]) {
					continue
				}
				refusal, err := gate.ChargeClosure(ctx, networkId, eraser, 1024, connect.NewId())
				if err != nil {
					return err
				}
				if refusal == nil {
					served[index] = append(served[index], now)
					into.stateLock.Lock()
					into.times = served
					into.stateLock.Unlock()
					continue
				}
				if refusal.RetryAfterMs == 0 {
					return fmt.Errorf("a refusal with no retry_after_ms: %+v", refusal)
				}
				nextAsks[index] = now.Add(time.Duration(refusal.RetryAfterMs) * time.Millisecond)
			}
			clock.Advance(step)
		}
		return check(served)
	}
}

// See the file header: k = 8 erasers at R = 4 are each served once every 2 s, none waits past a turn and an ask's step,
// and in 4 minutes each has its equal share of the 960 turns.
func Fs47ErasersAreServedInEqualTurns(net *Net) *Schedule {
	eraserCount := 8
	span := 4 * time.Minute
	served := newFs47Served()
	turn := time.Duration(eraserCount) * time.Second / time.Duration(served.uploadsPerSecond)
	steps := []*Step{
		{Actor: "gate", Action: fs47ServeErasers(served, eraserCount, span, func(served [][]time.Time) error {
			least, most := len(served[0]), len(served[0])
			for index, times := range served {
				least = min(least, len(times))
				most = max(most, len(times))
				if len(times) == 0 {
					return fmt.Errorf("eraser %d starved", index)
				}
				// past its first turn, no eraser waits more than its turn and one ask's step
				for next := 2; next < len(times); next += 1 {
					if gap := times[next].Sub(times[next-1]); turn+100*time.Millisecond < gap {
						return fmt.Errorf("eraser %d waited %s between turns %d and %d", index, gap, next-1, next)
					}
				}
			}
			// the run's first and last turns fall unevenly, and nothing else does
			if 2 < most-least {
				return fmt.Errorf("turns ranged from %d to %d among obedient erasers", least, most)
			}
			if want := int(span / turn); least < want-2 {
				return fmt.Errorf("each eraser had %d turns in %s, want about %d", least, span, want)
			}
			return nil
		})},
	}
	return &Schedule{Id: "FS-47", Steps: steps, Check: []Invariant{served.check()}}
}

// One eraser alone is served at its own 60 a minute, in the minute's first 15 s at R a second.
func Fs47OneEraserKeepsItsOwnRate(net *Net) *Schedule {
	served := newFs47Served()
	steps := []*Step{
		{Actor: "gate", Action: fs47ServeErasers(served, 1, time.Minute, func(served [][]time.Time) error {
			if count := len(served[0]); count != 60 {
				return fmt.Errorf("one eraser had %d turns in a minute, want its 60", count)
			}
			if spread := served[0][59].Sub(served[0][0]); spread < 14*time.Second {
				return fmt.Errorf("60 turns in %s, faster than R a second", spread)
			}
			return nil
		})},
	}
	return &Schedule{Id: "FS-47 one eraser keeps its own rate", Steps: steps, Check: []Invariant{served.check()}}
}
