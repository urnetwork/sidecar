package quotasuite

import (
	"context"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// FakeQuota as a target, wrapped by wrap when it is not nil.
func newFakeTarget(wrap func(quota *sidecartest.FakeQuota) sidecar.Quota) NewTarget {
	return func(t *testing.T) *Target {
		clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
		faults := sidecartest.NewFaultQueue()
		settings := sidecartest.DefaultFakeQuotaSettings()
		quota := sidecartest.NewFakeQuota(clock, faults, settings)
		var underTest sidecar.Quota = quota
		if wrap != nil {
			underTest = wrap(quota)
		}
		return &Target{
			Quota:  underTest,
			Clock:  clock,
			Faults: faults,
			SetLimits: func(networkId connect.Id, limits *sidecar.QuotaLimits) error {
				quota.SetLimits(networkId, limits)
				return nil
			},
			SetBalances: func(networkId connect.Id, balances []*sidecartest.QuotaBalance) error {
				quota.SetBalances(networkId, balances)
				return nil
			},
			ReadBalances: func(networkId connect.Id) ([]*sidecartest.QuotaBalance, error) {
				return quota.Balances(networkId), nil
			},
			LoseRedis: func() error {
				quota.LoseRedis()
				return nil
			},
			SetRedisFailing: func(failing bool) error {
				quota.SetRedisFailing(failing)
				return nil
			},
			LeaseDrawByteCount:          settings.LeaseDrawByteCount,
			CommunityLeaseDrawByteCount: settings.CommunityLeaseDrawByteCount,
			LeaseRenewFraction:          settings.LeaseRenewFraction,
		}
	}
}

// T2's half of §22.4's rule: the fake passes the suite server's Quota runs at T3.
func TestFakeQuotaConforms(t *testing.T) {
	Run(t, newFakeTarget(nil))
}

// Forgets every debit and batch id it is given, as a Quota that keys nothing would.
type forgetfulQuota struct {
	*sidecartest.FakeQuota
}

func (self *forgetfulQuota) CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	return self.FakeQuota.CountRate(ctx, networkId, keyAmounts, connect.NewId())
}

func (self *forgetfulQuota) ReportUsage(ctx context.Context, batch *sidecar.UsageBatch) error {
	copied := *batch
	copied.BatchId = connect.NewId()
	return self.FakeQuota.ReportUsage(ctx, &copied)
}

// The suite fails a Quota that counts a retried debit or batch twice, and one that re-asks the window
// on a replayed refusal, so passing it means something.
func TestTheSuiteCatchesAQuotaThatForgetsIds(t *testing.T) {
	newTarget := newFakeTarget(func(quota *sidecartest.FakeQuota) sidecar.Quota {
		return &forgetfulQuota{FakeQuota: quota}
	})
	for _, c := range []*suiteCase{
		{name: "a-debit-counts-once-across-a-lost-response", run: caseADebitCountsOnce},
		{name: "a-replayed-debit-answers-its-first-result", run: caseAReplayAnswersItsFirstResult},
		{name: "a-batch-applies-once-across-a-lost-response", run: caseABatchAppliesOnce},
	} {
		if err := c.run(t.Context(), newTarget(t)); err == nil {
			t.Errorf("%s passed a Quota that forgets ids", c.name)
		}
	}
}

// Answers every CountRate with nothing counted and no refusal, as a script that never ran would.
type openQuota struct {
	*sidecartest.FakeQuota
}

func (self *openQuota) CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	return nil, nil
}

// The rate cases fail a Quota that never refuses: every limit, allowance and turn is checked, not
// assumed.
func TestTheSuiteCatchesAQuotaThatNeverRefuses(t *testing.T) {
	newTarget := newFakeTarget(func(quota *sidecartest.FakeQuota) sidecar.Quota {
		return &openQuota{FakeQuota: quota}
	})
	for _, c := range rateCases() {
		if err := c.run(t.Context(), newTarget(t)); err == nil {
			t.Errorf("%s passed a Quota that never refuses", c.name)
		}
	}
}
