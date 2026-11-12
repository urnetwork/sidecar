//go:build sidecar_testhooks

// §22.8's clocks ±10 min on a push's time bound (TEST-M2-16; §11.8's 5b), on the evs world: a writer and a reader whose
// clocks each run 10 min fast, 10 min slow or true, against evs on the shared clock, which chrony holds within 50 ms of
// UTC (§19.6). Every pairing commits, the reader verifies what the writer wrote, and no device alarms, since 5b's bound
// takes a time_ms within 10 min either way. Past the bound nothing commits and nothing is silent: a writer 1 s past it
// behind is refused TIME_STALE, recorded, at each rebuild its client makes under a fresh push id, and then waits once the
// head's refusal records are full; one 1 s past it ahead gets 429 TIME_AHEAD, which refuses nothing, until its retries run
// out. The schedules hold no barrier, but the world's rows build with sidecar_testhooks, and so does this.

package fault

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs build's schedule for pairing on a Net of its own, failing t with the pairing and the trace.
func runClockSkewPairing(t *testing.T, pairing *ClockSkewPairing, build func(net *Net, pairing *ClockSkewPairing) *Schedule) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), sidecartest.DefaultNetSettings())
	defer net.Close()
	if result := Run(t.Context(), build(net, pairing), net); result.Err != nil {
		t.Errorf("pairing %s: %s", pairing, result)
	}
}

// writerA writes and overwrites a path on its clock and the reader verifies each version on its own: the repo is set up
// on the shared clock, and only then are the device clocks offset.
func clockSkewPushSchedule(net *Net, pairing *ClockSkewPairing) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	steps = append(steps, ClockSkewSteps(pairing)...)
	steps = append(steps,
		&Step{Actor: "writerA", Action: world.Write("writerA", "skew.txt", EvsWorldContent("skew first", 300))},
		&Step{Actor: "reader", Action: world.Verify("reader", "skew.txt")},
		&Step{Actor: "writerA", Action: world.Write("writerA", "skew.txt", EvsWorldContent("skew second", 300))},
		&Step{Actor: "reader", Action: world.Verify("reader", "skew.txt")},
		&Step{Actor: "check", Action: world.ExpectCommitted("writerA", "skew.txt")},
	)
	return &Schedule{Id: "skew push " + pairing.String(), Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

func TestClockSkewPushTimeBoundHoldsInEveryPairing(t *testing.T) {
	skew, err := NewClockSkew(nil, "writerA", "reader")
	if err != nil {
		t.Fatal(err)
	}
	pairings := skew.Pairings()
	if len(pairings) != 9 || !pairings[0].Unskewed() {
		t.Fatalf("pairings %v", pairings)
	}
	for _, pairing := range pairings {
		runClockSkewPairing(t, pairing, clockSkewPushSchedule)
	}
}

// A writer whose clock is offset past 5b's bound: its write commits nothing, every answer it got is an explicit one
// naming the bound, code (TIME_STALE behind, which records each statement's refusal and has the client rebuild under a
// new push id, TIME_AHEAD ahead, which refuses nothing and has it retry the same bytes), or a 429 that refuses nothing
// once the head's refusal records are full, and the head does not move.
func clockSkewPastTheBoundSchedule(net *Net, offset time.Duration) *Schedule {
	world := NewEvsWorld(net, nil)
	code := protocol.EvsRefusalCode_EVS_REFUSAL_TIME_AHEAD
	status := http.StatusTooManyRequests
	if offset < 0 {
		code = protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE
		status = http.StatusConflict
	}
	// the head and writerA's pushes before the skewed write
	headVersion := uint64(0)
	pushCount := 0
	readHead := func(ctx context.Context) (uint64, error) {
		head, err := world.Head(ctx)
		if err != nil || head == nil {
			return 0, err
		}
		return head.GetVersion(), nil
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "kept.txt", EvsWorldContent("skew kept", 300))},
		{Actor: "check", Action: world.Expect("the head before the skewed write", func(ctx context.Context) error {
			version, err := readHead(ctx)
			headVersion = version
			pushCount = len(world.DevicePushes("writerA"))
			return err
		})},
		{Actor: "writerA", ClockOffset: offset},
		{Actor: "writerA", Action: world.WriteAny("writerA", "skewed.txt", EvsWorldContent("skew past the bound", 300))},
		{Actor: "check", Action: world.Expect("the skewed write committed nothing, and its answers name the bound", func(ctx context.Context) error {
			world.stateLock.Lock()
			writes := world.pathWrites["skewed.txt"]
			world.stateLock.Unlock()
			if len(writes) != 1 {
				return fmt.Errorf("the ledger holds %d writes of the skewed path", len(writes))
			}
			if writes[0].state == evsWorldWriteCommitted {
				return fmt.Errorf("the skewed write committed at v%d", writes[0].version)
			}
			if _, ok := sidecar.EvsErrorOf(writes[0].err); !ok {
				return fmt.Errorf("the skewed write ended %v, not an answer of evs's", writes[0].err)
			}
			namedCount := 0
			for _, push := range world.DevicePushes("writerA")[pushCount:] {
				for _, answer := range push.Answers {
					switch {
					case answer.Status == http.StatusOK:
						return fmt.Errorf("an answer %s committed a statement past the bound", answer)
					case answer.Status == status && answer.Code == code:
						namedCount += 1
					case answer.Status == http.StatusTooManyRequests:
						// the head's refusal records are full: a wait that refuses nothing
					default:
						return fmt.Errorf("an answer %s that names neither the bound nor a wait", answer)
					}
				}
			}
			if namedCount == 0 {
				return fmt.Errorf("no answer was %d %s", status, code)
			}
			return nil
		})},
		{Actor: "check", Action: world.Expect("the head did not move", func(ctx context.Context) error {
			version, err := readHead(ctx)
			if err != nil {
				return err
			}
			if version != headVersion {
				return fmt.Errorf("the head moved from v%d to v%d", headVersion, version)
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "kept.txt")},
	}
	return &Schedule{Id: fmt.Sprintf("skew push past the bound %s", offset), Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

func TestClockSkewPushPastTheBoundCommitsNothing(t *testing.T) {
	bound := DefaultClockSkewSettings().Skew
	for _, offset := range []time.Duration{-(bound + time.Second), bound + time.Second} {
		net := sidecartest.NewNet(t.Context(), sidecartest.DefaultNetSettings())
		result := Run(t.Context(), clockSkewPastTheBoundSchedule(net, offset), net)
		net.Close()
		if result.Err != nil {
			t.Errorf("offset %s: %s", offset, result)
		}
	}
}
