package controller

// §9.9's states as the sidecar repo sees them (BAL-M12-12): the table a review moves an account by, the floor, burn and
// the scaling under them, each in exact integer arithmetic. The reviews on real PostgreSQL and Redis, the projection
// and the notices, run in server/computet3/compute_state_t3_test.go.

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/model"
)

// The state a balance moves an account to, row by row of §9.9's table: active at 24 h of burn and T, low under either,
// grace at or under zero, suspended at or under minus the floor (never at the floor itself), suspended once grace is
// older than its hour, held suspended until the balance is above zero again, held suspended by a chargeback whatever
// the balance, and closed for good.
func TestComputeStateTargetFollowsTheTable(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	usd := func(dollars int64) int64 {
		return dollars * model.ComputeCreditNanoUsd
	}
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	graceSince := now.Add(-settings.GraceMaxAge + time.Minute)
	graceLong := now.Add(-settings.GraceMaxAge)
	type row struct {
		name       string
		current    model.ComputeAccountState
		balance    int64
		lowBelow   int64
		below      int64
		floor      int64
		stateTime  *time.Time
		chargeback bool
		want       model.ComputeAccountState
	}
	for _, r := range []row{
		{name: "a day of burn and T", current: model.ComputeAccountStateActive, balance: usd(30), lowBelow: usd(24), below: usd(5), want: model.ComputeAccountStateActive},
		{name: "under a day of burn", current: model.ComputeAccountStateActive, balance: usd(20), lowBelow: usd(24), below: usd(5), want: model.ComputeAccountStateLow},
		{name: "under T", current: model.ComputeAccountStateActive, balance: usd(4), below: usd(5), want: model.ComputeAccountStateLow},
		{name: "a cent", current: model.ComputeAccountStateLow, balance: 10_000_000, below: usd(5), want: model.ComputeAccountStateLow},
		{name: "zero, a floor", current: model.ComputeAccountStateLow, balance: 0, below: usd(5), floor: usd(5), want: model.ComputeAccountStateGrace},
		{name: "between zero and minus the floor", current: model.ComputeAccountStateGrace, balance: -usd(4), floor: usd(5), stateTime: &graceSince, want: model.ComputeAccountStateGrace},
		{name: "at minus the floor", current: model.ComputeAccountStateGrace, balance: -usd(5), floor: usd(5), stateTime: &graceSince, want: model.ComputeAccountStateSuspended},
		{name: "at the floor, above zero", current: model.ComputeAccountStateLow, balance: usd(5), below: usd(5), floor: usd(5), want: model.ComputeAccountStateActive},
		{name: "zero, no floor", current: model.ComputeAccountStateLow, balance: 0, below: usd(5), want: model.ComputeAccountStateSuspended},
		{name: "grace past its hour", current: model.ComputeAccountStateGrace, balance: -usd(1), floor: usd(5), stateTime: &graceLong, want: model.ComputeAccountStateSuspended},
		{name: "suspended stays below zero", current: model.ComputeAccountStateSuspended, balance: -usd(1), floor: usd(5), want: model.ComputeAccountStateSuspended},
		{name: "suspended lifted above zero", current: model.ComputeAccountStateSuspended, balance: usd(30), lowBelow: usd(24), below: usd(5), want: model.ComputeAccountStateActive},
		{name: "a chargeback whatever the balance", current: model.ComputeAccountStateSuspended, balance: usd(100), below: usd(5), chargeback: true, want: model.ComputeAccountStateSuspended},
		{name: "closed for good", current: model.ComputeAccountStateClosed, balance: usd(100), want: model.ComputeAccountStateClosed},
	} {
		got := computeStateTarget(settings, r.current, r.balance, r.lowBelow, r.below, r.floor, r.stateTime, now, r.chargeback)
		if got != r.want {
			t.Errorf("%s: %s, want %s", r.name, got, r.want)
		}
	}
}

// The floor is the smaller of the settings' $5 and an hour of the running enclaves' rates: zero with none running, an
// hour's rate below $5, $5 above it.
func TestComputeFloorIsTheSmallerOfFiveDollarsAndAnHour(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	for _, c := range []struct {
		hourly int64
		want   int64
	}{
		{hourly: 0, want: 0},
		{hourly: 1_500_000_000, want: 1_500_000_000},
		{hourly: 5_000_000_000, want: 5_000_000_000},
		{hourly: 19 * 6 * 1_000_000_000, want: settings.FloorMaxNanoUsd},
	} {
		if got := computeFloorOf(settings, c.hourly); got != c.want {
			t.Errorf("an hourly rate of %d: a floor of %d, want %d", c.hourly, got, c.want)
		}
	}
}

// Burn is the trailing 24 h of charges, or the running enclaves' hourly rates times 24 if larger.
func TestComputeBurnTakesTheLarger(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	if got := computeBurnOf(settings, 30_000_000_000, 1_000_000_000); got != 30_000_000_000 {
		t.Errorf("charges above the rates: %d", got)
	}
	if got := computeBurnOf(settings, 3_000_000_000, 1_000_000_000); got != 24_000_000_000 {
		t.Errorf("rates above the charges: %d", got)
	}
	if got := computeBurnOf(settings, 0, 0); got != 0 {
		t.Errorf("nothing charged and nothing running: %d", got)
	}
}

// Scaling is exact integer arithmetic, rounded down, never past int64, and zero for a ratio it cannot take.
func TestComputeScaleNanoUsdIsExact(t *testing.T) {
	if got := computeScaleNanoUsd(7, time.Hour, 3*time.Hour); got != 2 {
		t.Errorf("7 × 1/3 is %d", got)
	}
	if got := computeScaleNanoUsd(10_000_000_000_000, 24*time.Hour, time.Hour); got != 240_000_000_000_000 {
		t.Errorf("$10,000 a day of hours is %d", got)
	}
	if got := computeScaleNanoUsd(int64(^uint64(0)>>1), 24*time.Hour, time.Hour); got != int64(^uint64(0)>>1) {
		t.Errorf("past int64 is %d", got)
	}
	for _, got := range []int64{computeScaleNanoUsd(5, time.Hour, 0), computeScaleNanoUsd(-5, time.Hour, time.Hour), computeScaleNanoUsd(5, 0, time.Hour)} {
		if got != 0 {
			t.Errorf("a ratio it cannot take scales to %d", got)
		}
	}
}

// A move into low, grace or suspended owes a notice, and none other does; the ranks order the states from paying.
func TestComputeStateNoticesAndRanks(t *testing.T) {
	for state, want := range map[model.ComputeAccountState]ComputeNoticeKind{
		model.ComputeAccountStateActive:    "",
		model.ComputeAccountStateLow:       ComputeNoticeLow,
		model.ComputeAccountStateGrace:     ComputeNoticeGrace,
		model.ComputeAccountStateSuspended: ComputeNoticeSuspended,
		model.ComputeAccountStateClosed:    "",
	} {
		if got := computeStateNoticeKind(state); got != want {
			t.Errorf("%s owes %q", state, got)
		}
	}
	ranks := []int{}
	for state := model.ComputeAccountStateActive; state <= model.ComputeAccountStateClosed; state += 1 {
		ranks = append(ranks, computeStateRank(state))
	}
	for i := 1; i < len(ranks); i += 1 {
		if ranks[i] <= ranks[i-1] {
			t.Fatalf("the ranks %v do not rise with the states", ranks)
		}
	}
}
