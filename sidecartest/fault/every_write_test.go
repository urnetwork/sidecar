// §22.8's unknown rule on the fake hosts' writing calls (QD-1155): EveryWrite loses a host write's answer as it loses
// a store write's, so a caller that resends under the same id passes and one that takes the unknown outcome for a
// failure fails its row, a host read is never lost, and FS-44's and FS-45's reports count their host writes.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

func everyWriteBatch(networkId connect.Id, byteCount int64) *sidecar.UsageBatch {
	return &sidecar.UsageBatch{
		BatchId:  connect.NewId(),
		Producer: sidecar.QuotaProducerEvs,
		Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterEvs, TransferByteCount: byteCount}},
	}
}

// A producer sending one batch of 100 bytes to the Net's fake Quota, at most three times while it answers an error: the
// same batch again when it trusts no answer it never got, or a new batch in its place when blind, taking a lost answer
// for a failure. That the network is debited no more than was metered is checked after every step.
func everyWriteUsage(blind bool) Builder {
	return func(net *Net) *Schedule {
		quota := net.Fakes().Quota
		networkId := connect.NewId()
		debited := func() int64 {
			balances := quota.Balances(networkId)
			if len(balances) == 0 {
				return 0
			}
			return 1000 - balances[0].ByteCount
		}
		steps := []*Step{
			{Actor: "check", Action: func(ctx context.Context, net *Net) error {
				quota.SetBalance(networkId, 1000)
				return nil
			}},
			{Actor: "producer", Action: func(ctx context.Context, net *Net) error {
				batch := everyWriteBatch(networkId, 100)
				for range 3 {
					if err := quota.ReportUsage(ctx, batch); err == nil {
						return nil
					}
					if blind {
						batch = everyWriteBatch(networkId, 100)
					}
				}
				return errors.New("the batch was never answered")
			}},
			{Actor: "check", Action: func(ctx context.Context, net *Net) error {
				if got := debited(); got != 100 {
					return fmt.Errorf("%d debited, want 100", got)
				}
				return nil
			}},
		}
		return &Schedule{Id: "toy-usage", Steps: steps, Check: []Invariant{NewInvariant("debited-at-most-once", func(ctx context.Context, oracle *Oracle) error {
			if got := debited(); 100 < got {
				return fmt.Errorf("%d debited of 100 metered", got)
			}
			return nil
		})}}
	}
}

// The one ReportUsage is a write, so the rule reruns the schedule with its answer lost: the batch applied, the caller
// told nothing. A caller that sends the batch again under its id debits once.
func TestEveryWriteLosesAHostWritesAnswer(t *testing.T) {
	failures, lostWrites := EveryWrite(t.Context(), everyWriteUsage(false), nil)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
	if want := []LostWrite{{Op: sidecartest.FaultOpHost, Nth: 1}}; !slices.Equal(lostWrites, want) {
		t.Errorf("lost %v, want %v", lostWrites, want)
	}
}

// A caller that takes the lost answer for a failure and sends a new batch in its place debits twice, which the rerun
// catches; with every answer given, the same caller passes.
func TestEveryWriteCatchesACallerThatTakesALostHostAnswerForAFailure(t *testing.T) {
	if result := runBuilt(t.Context(), everyWriteUsage(true), nil, nil); result.Err != nil {
		t.Fatalf("the blind caller failed with every answer given: %s", result)
	}
	failures, _ := EveryWrite(t.Context(), everyWriteUsage(true), nil)
	if len(failures) == 0 {
		t.Fatal("no lost answer caught the blind resend")
	}
	if !strings.Contains(failures[0].Err.Error(), "200 debited of 100 metered") || !strings.Contains(failures[0].Id, "host write 1's response lost") {
		t.Errorf("failed on something else: %s", failures[0])
	}
}

// Limits and OverLimit read: the dry run counts no write of theirs, and nothing reruns.
func TestEveryWriteLosesNoHostRead(t *testing.T) {
	builds := 0
	failures, lostWrites := EveryWrite(t.Context(), func(net *Net) *Schedule {
		builds += 1
		quota := net.Fakes().Quota
		return &Schedule{Id: "toy-reads", Steps: []*Step{
			{Actor: "evs1", Action: func(ctx context.Context, net *Net) error {
				if _, err := quota.Limits(ctx, connect.NewId()); err != nil {
					return err
				}
				_, err := quota.OverLimit(ctx)
				return err
			}},
		}}
	}, nil)
	for _, failure := range failures {
		t.Errorf("%s", failure)
	}
	if len(lostWrites) != 0 || builds != 1 {
		t.Errorf("lost %v over %d builds, want none over the dry run alone", lostWrites, builds)
	}
}

// FS-44's registered case sends one batch, and FS-45's settles each contract by one ReportUsage: each report counts
// those host writes among the writes run with their answers lost, and every rerun passes.
func TestFs44AndFs45ReportTheirHostWrites(t *testing.T) {
	for _, c := range []struct {
		registration *Registration
		// how many host writes, or zero for at least one
		want int
	}{
		{registration: Fs44, want: 1},
		{registration: Fs45},
	} {
		report := CheckRow(t.Context(), c.registration, nil)
		if report.Failed() {
			t.Errorf("%s", report)
			continue
		}
		hostWrites := 0
		for _, lost := range report.LostWrites {
			if lost.Op == sidecartest.FaultOpHost {
				hostWrites += 1
			}
		}
		if hostWrites == 0 || (c.want != 0 && hostWrites != c.want) {
			t.Errorf("%s: %d host writes lost, want %d (zero meaning at least one)", report, hostWrites, c.want)
		}
		if !strings.Contains(report.String(), fmt.Sprintf(" %d writes run with their responses lost.", len(report.LostWrites))) {
			t.Errorf("the report does not say what it lost: %s", report)
		}
	}
}
