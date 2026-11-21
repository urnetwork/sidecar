// FS-45 (§20.6's relayed bytes, FI-13 (a); QUOTA-M2-13) on a Net. sidecar.Quota carries no relayed reservation: the
// grant rule and its Redis tokens are server's (QUOTA-M2-08, QUOTA-M2-09), and they run this row at T3 in server's
// quotahost, whose test is FS-45's T3 run. Here the row runs on a twin of that rule over the Net's fake Quota's
// balances, each schedule a step at a time, with FI-13's oracle checked after every step: FI-13's binding is
// QUOTA-M2-13's and unbound (fault.FI(13) fails closed), so the check is the twin's own (FI-13/fs45), the oracle told
// what each pair used and what a Redis loss forgot.
//
// The registered case, Fs45GrantsShrinkAndSpendingStopsAtTheBalance: pairs on a network near empty get grants that
// shrink from an eighth to the floor and stop at the balance, the refusal marks the network spent, a spent network
// refuses the next contract, and every pair using its whole grant leaves the balance at or above zero. The clauses
// beside it (clauses.go): a pair bound to a stream reserves and debits nothing on a spent network; a contract settles
// one debit however often its close is replayed, capped at its grant; and with the reservations lost the next grants
// over-admit by no more than the grants then outstanding, as a lease's loss is bounded by its draws.
//
// FS-45 is on §22.8's unknown list, and the fake Quota's ReportUsage is a write (QD-1155), so on T2 the rule loses each
// settlement's answer in turn (every_write.go): the twin's settlement, which cannot tell a lost answer from a failed
// one, replays the close under its contract id until it is answered, as either side or the deadline does, and the
// debit stays one.

package fault

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs45 = Register("FS-45", "", []Tier{TierT2}, Fs45GrantsShrinkAndSpendingStopsAtTheBalance)

// The relayed reservation rule's figures, as §20.6 gives them.
type Fs45TwinSettings struct {
	// What a pair asks for: 64 MiB.
	RequestByteCount int64
	// The least grant, and the unreserved room below which a contract is refused: 1 MiB.
	FloorByteCount int64
	// A grant is at most the unreserved room over this: 8, an eighth.
	GrantShare int64
	// Grants a schedule asks for before it calls the run of them endless: 400.
	GrantLimit int
	// How many times the settlement sends one close's debit before it fails, sending it again under the contract id
	// while it answers an error: 3, past the one answer §22.8's unknown rule loses a run.
	SettleAttemptCount int
}

func DefaultFs45TwinSettings() *Fs45TwinSettings {
	return &Fs45TwinSettings{
		RequestByteCount:   64 * 1024 * 1024,
		FloorByteCount:     1024 * 1024,
		GrantShare:         8,
		GrantLimit:         400,
		SettleAttemptCount: 3,
	}
}

// The relayed reservation rule (§20.6) over the Net's fake Quota: a grant is the request, cut to a share of what the
// balance has unreserved and raised to the floor; with less than the floor unreserved the contract is refused and the
// network marked spent. The settlement debits what was used, capped at the grant, once per contract id.
type fs45Twin struct {
	settings  *Fs45TwinSettings
	quota     *sidecartest.FakeQuota
	oracle    *sidecartest.QuotaOracle
	networkId connect.Id

	stateLock sync.Mutex
	// Redis: what each open contract holds
	contractHeldByteCounts map[connect.Id]int64
	// Postgres: each contract's grant, kept across a Redis loss
	contractGrantByteCounts map[connect.Id]int64
	// the schedule's contracts, in the order granted
	contractIds []connect.Id
	// the grants outstanding when Redis was lost
	forgottenByteCount int64
}

func newFs45Twin(net *Net, settings *Fs45TwinSettings) *fs45Twin {
	if settings == nil {
		settings = DefaultFs45TwinSettings()
	}
	quota := net.Fakes().Quota
	return &fs45Twin{
		settings:                settings,
		quota:                   quota,
		oracle:                  sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		networkId:               connect.NewId(),
		contractHeldByteCounts:  map[connect.Id]int64{},
		contractGrantByteCounts: map[connect.Id]int64{},
	}
}

// FI-13 (a)'s upper bound as the twin reads it, after every step.
func (self *fs45Twin) check() Invariant {
	return NewInvariant("FI-13/fs45", func(ctx context.Context, oracle *Oracle) error {
		return self.oracle.Check(ctx)
	})
}

// A step action: the network's one balance of byteCount, told to the oracle.
func (self *fs45Twin) setup(byteCount int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.quota.SetBalance(self.networkId, byteCount)
		self.oracle.Grant(self.networkId, byteCount)
		return nil
	}
}

func (self *fs45Twin) left() int64 {
	return self.quota.Balances(self.networkId)[0].ByteCount
}

func (self *fs45Twin) heldWithLock() (held int64) {
	for _, byteCount := range self.contractHeldByteCounts {
		held += byteCount
	}
	return
}

func (self *fs45Twin) spent(ctx context.Context) (bool, error) {
	overLimit, err := self.quota.OverLimit(sidecartest.InspectContext(ctx))
	if err != nil {
		return false, err
	}
	return overLimit.SpentNetworkIdRefusals[self.networkId] != nil, nil
}

// CreateContract for one pair: the contract and its grant, or a refusal.
func (self *fs45Twin) reserve(streamBound bool) (contractId connect.Id, grant int64, ok bool) {
	contractId = connect.NewId()
	if streamBound {
		// P2P bytes never count: nothing reserved, no payer
		return contractId, self.settings.RequestByteCount, true
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	available := self.left() - self.heldWithLock()
	if available < self.settings.FloorByteCount {
		self.quota.SetSpentRefusal(self.networkId, &sidecar.QuotaRefusal{LimitKey: "data", Upgrade: true})
		return contractId, 0, false
	}
	grant = min(self.settings.RequestByteCount, max(self.settings.FloorByteCount, available/self.settings.GrantShare))
	self.contractHeldByteCounts[contractId] = grant
	self.contractGrantByteCounts[contractId] = grant
	self.contractIds = append(self.contractIds, contractId)
	return contractId, grant, true
}

// The contract's close, replayed or not: the debit is one usage keyed by the contract id, sent again while it answers
// an error, and the rest of the reservation returns once it is answered.
func (self *fs45Twin) settle(ctx context.Context, contractId connect.Id, usedByteCount int64) error {
	self.stateLock.Lock()
	grant, ok := self.contractGrantByteCounts[contractId]
	self.stateLock.Unlock()
	if !ok {
		// a stream-bound pair: no payer, no debit
		return nil
	}
	batch := &sidecar.UsageBatch{
		BatchId:  contractId,
		Producer: sidecar.QuotaProducerTaskworker,
		Events:   []*sidecar.UsageEvent{{NetworkId: self.networkId, Meter: sidecar.QuotaMeterRelay, TransferByteCount: min(usedByteCount, grant)}},
	}
	var err error
	for range self.settings.SettleAttemptCount {
		if err = self.quota.ReportUsage(ctx, batch); err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.contractHeldByteCounts, contractId)
	return nil
}

// A step action: contracts granted until one is refused, the grants each a step's worth of the schedule's record;
// check reads them in order.
func (self *fs45Twin) reserveUntilRefused(check func(grants []int64) error) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		grants := []int64{}
		for range self.settings.GrantLimit {
			_, grant, ok := self.reserve(false)
			if !ok {
				if check == nil {
					return nil
				}
				return check(grants)
			}
			grants = append(grants, grant)
		}
		return fmt.Errorf("no refusal after %d grants", self.settings.GrantLimit)
	}
}

// A step action: every contract granted uses its whole grant and settles, each close sent closeCount times, the
// oracle told of each pair's bytes as they move.
func (self *fs45Twin) settleAll(closeCount int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		contractIds := append([]connect.Id{}, self.contractIds...)
		self.stateLock.Unlock()
		for _, contractId := range contractIds {
			self.stateLock.Lock()
			grant := self.contractGrantByteCounts[contractId]
			self.stateLock.Unlock()
			self.oracle.Meter(self.networkId, sidecar.QuotaMeterRelay, grant)
			for range closeCount {
				if err := self.settle(ctx, contractId, grant); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

// A step action: FI-13 (a) whole, with nothing in flight: every byte a pair used and no loss forgot has debited, once.
func (self *fs45Twin) settled(ctx context.Context, net *Net) error {
	return self.oracle.CheckSettled(sidecartest.InspectContext(ctx))
}

// See the file header. The network has 100 MiB.
func Fs45GrantsShrinkAndSpendingStopsAtTheBalance(net *Net) *Schedule {
	twin := newFs45Twin(net, nil)
	room := int64(100 * 1024 * 1024)
	total := int64(0)
	steps := []*Step{
		{Actor: "check", Action: twin.setup(room)},
		{Actor: "relay", Action: twin.reserveUntilRefused(func(grants []int64) error {
			for index := 1; index < len(grants); index++ {
				if grants[index-1] < grants[index] {
					return fmt.Errorf("grant %d grew: %v", index, grants)
				}
			}
			if len(grants) == 0 || grants[0] != room/twin.settings.GrantShare || grants[len(grants)-1] != twin.settings.FloorByteCount {
				return fmt.Errorf("grants did not shrink from a share to the floor: %v", grants)
			}
			for _, grant := range grants {
				total += grant
			}
			if room < total || twin.settings.FloorByteCount <= room-total {
				return fmt.Errorf("grants of %d stopped short of or past the balance of %d", total, room)
			}
			return nil
		})},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			spent, err := twin.spent(ctx)
			if err != nil {
				return err
			}
			if !spent {
				return errors.New("the refusal left the network unmarked")
			}
			return nil
		}},
		// spent refuses CreateContract until a balance has room
		{Actor: "relay", Action: func(ctx context.Context, net *Net) error {
			if _, _, ok := twin.reserve(false); ok {
				return errors.New("a spent network was granted a contract")
			}
			return nil
		}},
		{Actor: "relay", Action: twin.settleAll(1)},
		{Actor: "check", Action: twin.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			if left := twin.left(); left < 0 || left != room-total {
				return fmt.Errorf("%d left of %d after %d granted and spent", left, room, total)
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-45", Steps: steps, Check: []Invariant{twin.check()}}
}

// A P2P-bound pair is unaffected: it is granted its request on a spent network, and its close debits nothing.
func Fs45StreamBoundPairIsUnaffected(net *Net) *Schedule {
	twin := newFs45Twin(net, nil)
	room := twin.settings.FloorByteCount / 2
	steps := []*Step{
		{Actor: "check", Action: twin.setup(room)},
		{Actor: "relay", Action: func(ctx context.Context, net *Net) error {
			if _, _, ok := twin.reserve(false); ok {
				return errors.New("a relayed pair was granted past the balance")
			}
			contractId, grant, ok := twin.reserve(true)
			if !ok || grant != twin.settings.RequestByteCount {
				return fmt.Errorf("the stream-bound pair was granted %d, %t", grant, ok)
			}
			return twin.settle(ctx, contractId, grant)
		}},
		{Actor: "check", Action: twin.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			if left := twin.left(); left != room {
				return fmt.Errorf("%d left of %d", left, room)
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-45 stream-bound pair is unaffected", Steps: steps, Check: []Invariant{twin.check()}}
}

// One debit per contract_id: a close replayed, by either side or by the deadline, debits once, capped at the grant.
func Fs45OneDebitPerContract(net *Net) *Schedule {
	twin := newFs45Twin(net, nil)
	room := int64(1024 * 1024 * 1024)
	var used int64
	steps := []*Step{
		{Actor: "check", Action: twin.setup(room)},
		{Actor: "relay", Action: func(ctx context.Context, net *Net) error {
			contractId, grant, ok := twin.reserve(false)
			if !ok || grant != twin.settings.RequestByteCount {
				return fmt.Errorf("grant %d, %t", grant, ok)
			}
			used = grant / 2
			twin.oracle.Meter(twin.networkId, sidecar.QuotaMeterRelay, used)
			for range 3 {
				if err := twin.settle(ctx, contractId, used); err != nil {
					return err
				}
			}
			return nil
		}},
		{Actor: "check", Action: twin.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			if left := twin.left(); left != room-used {
				return fmt.Errorf("%d left, want %d", left, room-used)
			}
			twin.stateLock.Lock()
			defer twin.stateLock.Unlock()
			if held := twin.heldWithLock(); held != 0 {
				return fmt.Errorf("%d still reserved after the close", held)
			}
			return nil
		}},
		// a pair reporting past its grant debits the grant
		{Actor: "relay", Action: func(ctx context.Context, net *Net) error {
			contractId, grant, ok := twin.reserve(false)
			if !ok {
				return errors.New("the second contract was refused")
			}
			twin.oracle.Meter(twin.networkId, sidecar.QuotaMeterRelay, grant)
			if err := twin.settle(ctx, contractId, 3*grant); err != nil {
				return err
			}
			if left := twin.left(); left != room-used-grant {
				return fmt.Errorf("%d left after an over-report, want %d", left, room-used-grant)
			}
			return nil
		}},
		{Actor: "check", Action: twin.settled},
	}
	return &Schedule{Id: "FS-45 one debit per contract", Steps: steps, Check: []Invariant{twin.check()}}
}

// Redis loss over-admits at most as for leases: the grants outstanding at the loss are forgotten, the next grants are
// judged against the whole balance, and every contract still debits once, its close replayed after the loss, so the
// balance ends no further below zero than the grants the loss forgot.
func Fs45RedisLossOverAdmitsByTheOutstandingGrants(net *Net) *Schedule {
	twin := newFs45Twin(net, nil)
	room := int64(100 * 1024 * 1024)
	steps := []*Step{
		{Actor: "check", Action: twin.setup(room)},
		{Actor: "relay", Action: twin.reserveUntilRefused(nil)},
		{Actor: "redis", Action: func(ctx context.Context, net *Net) error {
			twin.stateLock.Lock()
			twin.forgottenByteCount = twin.heldWithLock()
			twin.contractHeldByteCounts = map[connect.Id]int64{}
			twin.stateLock.Unlock()
			twin.quota.LoseRedis()
			twin.quota.SetSpentRefusal(twin.networkId, nil)
			return nil
		}},
		{Actor: "relay", Action: twin.reserveUntilRefused(nil)},
		// each close and its replay after the loss: Postgres kept the debit's id
		{Actor: "relay", Action: twin.settleAll(2)},
		{Actor: "check", Action: twin.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			twin.stateLock.Lock()
			forgotten := twin.forgottenByteCount
			twin.stateLock.Unlock()
			if left := twin.left(); 0 <= left || left < -forgotten {
				return fmt.Errorf("%d left: the loss forgot %d, which bounds the over-admission", left, forgotten)
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-45 redis loss over-admits by the outstanding grants", Steps: steps, Check: []Invariant{twin.check()}}
}
