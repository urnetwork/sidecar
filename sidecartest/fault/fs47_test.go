package fault

// FS-47 (§20.7, FI-13 (c); EVSB-M2-15), the gate's pacing clauses on T2: evs's QuotaGate over the fake Quota
// at a network's storage limit, k erasers each asking for one ?closure=1 upload at a time and asking again at
// its refusal's retry_after_ms. Each is served once every k/R s, R being evs_closure_uploads_per_s, none
// starves, and obedient erasers get equal turns. The push kinds at the exact limit and while spent run in
// evsservice's quota_gate_test.go; the record-class file, its CLOSURE and ERASE, and the mail case are
// EVS1's and MAIL's.

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// k erasers at the limit for a span of fake time, each asking whenever its last answer allows: the times each
// was served.
func fs47ServeErasers(t *testing.T, eraserCount int, span time.Duration) [][]time.Time {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	networkId := connect.NewId()
	host.Quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
		"evs_closure_uploads_per_s":   4,
		"evs_closure_uploads_per_min": 60,
		"evs_closure_bytes_per_day":   1024 * 1024 * 1024,
		"evs_closure_bytes_floor":     4 * 1024 * 1024,
	}})
	host.Quota.SetStorageRefusal(networkId, &sidecar.QuotaRefusal{LimitKey: "storage", Limit: 1000, Used: 1000})
	gate, err := evsservice.NewQuotaGate(ctx, host.ServiceHost(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	// the gate's first read is done once its next read's timer is set
	for !gate.Over(networkId) {
		_, added := clock.WatchTimers()
		if gate.Over(networkId) {
			break
		}
		select {
		case <-added:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}

	// rate windows are fixed, turning on the minute, so the run starts on one
	clock.AdvanceTo(clock.Now().Truncate(time.Minute).Add(time.Minute))
	erasers := make([]connect.Id, eraserCount)
	nextAsks := make([]time.Time, eraserCount)
	served := make([][]time.Time, eraserCount)
	start := clock.Now()
	for i := range erasers {
		erasers[i] = connect.NewId()
		nextAsks[i] = start
	}
	step := 50 * time.Millisecond
	for clock.Now().Sub(start) < span {
		now := clock.Now()
		for i, eraser := range erasers {
			if now.Before(nextAsks[i]) {
				continue
			}
			refusal, err := gate.ChargeClosure(ctx, networkId, eraser, 1024, connect.NewId())
			if err != nil {
				t.Fatal(err)
			}
			if refusal == nil {
				served[i] = append(served[i], now)
				continue
			}
			if refusal.RetryAfterMs == 0 {
				t.Fatalf("a refusal with no retry_after_ms: %+v", refusal)
			}
			nextAsks[i] = now.Add(time.Duration(refusal.RetryAfterMs) * time.Millisecond)
		}
		clock.Advance(step)
	}
	return served
}

// k = 8 erasers at R = 4: each is served once every 2 s, none waits past a turn and a step, and in 4 minutes
// each has its equal share of the 960 turns.
func TestFs47ErasersAreServedInEqualTurns(t *testing.T) {
	const eraserCount = 8
	span := 4 * time.Minute
	served := fs47ServeErasers(t, eraserCount, span)
	turn := time.Duration(eraserCount) * time.Second / 4
	least, most := len(served[0]), len(served[0])
	for i, times := range served {
		least = min(least, len(times))
		most = max(most, len(times))
		if len(times) == 0 {
			t.Fatalf("eraser %d starved", i)
		}
		// past its first turn, no eraser waits more than its turn and one ask's step
		for j := 2; j < len(times); j += 1 {
			if gap := times[j].Sub(times[j-1]); turn+100*time.Millisecond < gap {
				t.Errorf("eraser %d waited %s between turns %d and %d", i, gap, j-1, j)
			}
		}
	}
	// the run's first and last turns fall unevenly, and nothing else does
	if 2 < most-least {
		t.Fatalf("turns ranged from %d to %d among obedient erasers", least, most)
	}
	if want := int(span / turn); least < want-2 {
		t.Fatalf("each eraser had %d turns in %s, want about %d", least, span, want)
	}
}

// One eraser alone is served at its own 60 a minute, in the minute's first 15 s at R a second.
func TestFs47OneEraserKeepsItsOwnRate(t *testing.T) {
	served := fs47ServeErasers(t, 1, time.Minute)
	if count := len(served[0]); count != 60 {
		t.Fatalf("one eraser had %d turns in a minute, want its 60", count)
	}
	if spread := served[0][59].Sub(served[0][0]); spread < 14*time.Second {
		t.Fatalf("60 turns in %s, faster than R a second", spread)
	}
}
