// ServiceHost.Quota in memory (§20.6, §20.7), keeping each rule a test can see: rate windows on the
// injected clock; all-or-none counts, a debit id that passed answering pass again and a refused one judged
// afresh (DESIGN-DETAILS 13.2.1); the closure pacing by seat, asked only when no other counter refused; each
// eraser's allowance, never under its floor; leases that reserve on balances in escrow's
// draw order, the credit line last, and give back in reverse; batches applied once by id; the
// over-limit maps; and what losing Redis, a failing Redis or a lost response does. Rate keys resolve
// through sidecar.ParseQuotaRateKey, as server's {sq_} script does, and quotasuite runs one body on this
// and on server's Quota, so the two cannot drift apart unseen.
//
// What a real Quota reads from pro.yml, Postgres and the nightly count, a test sets by hand: limits,
// balances and the storage refusal. Money moves as §20.6 and DESIGN-DETAILS 13.2.2 have it (QD-653): a
// lease reserves and spends with no I/O, the batches of the lease's process carve its spent bytes into
// debits, evs's bytes debit when their batch applies, and a lease's reservation lives while its process
// does, as the real lease extends its tokens, and lapses LeaseTokenLifetime after a killed process was
// last seen alive, with no debit. No lease byte is debited without a live reservation: a carve's bytes
// whose reservation lapsed or was lost with Redis, and a lease meter's bytes past what its process's
// leases spent, are counted unbilled, never debited at apply. A carve debits at once here, where the real
// one holds its bytes in a carved token for the flush, so the carved token's 24 h is not seen.
//
// A lease belongs to its caller's process: the actor its ctx carries, or none outside a schedule. One
// process shares one lease per network and meter, the last handle's Close settling it
// (plan-QUOTA-small-readings reading 16), and a restarted actor gets a lease of its own. Safe for
// concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

type FakeQuotaSettings struct {
	// Bytes a lease reserves at a time: §20.6's 64 MiB.
	LeaseDrawByteCount int64
	// Bytes a lease reserves at a time on Community: §20.6's 16 MiB.
	CommunityLeaseDrawByteCount int64
	// The fraction of a draw spent before a lease reserves the next: §20.6's 75%.
	LeaseRenewFraction float64
	// How long a lease's own reservation lasts once its process stops extending it: QD-653's 15 min. A
	// live process's lease keeps its reservations, as the real lease extends its tokens every 5 min; a
	// killed process's come back this long after the fake last saw it alive, with no debit (FS-46).
	LeaseTokenLifetime time.Duration
	// How long a debit id answers its first result: §20.7's 48 h keys.
	DebitIdLifetime time.Duration
	// How long an applied batch's id is remembered: service_usage_batch's 24 h (§20.14).
	BatchIdLifetime time.Duration
}

func DefaultFakeQuotaSettings() *FakeQuotaSettings {
	return &FakeQuotaSettings{
		LeaseDrawByteCount:          64 * 1024 * 1024,
		CommunityLeaseDrawByteCount: 16 * 1024 * 1024,
		LeaseRenewFraction:          0.75,
		LeaseTokenLifetime:          15 * time.Minute,
		DebitIdLifetime:             48 * time.Hour,
		BatchIdLifetime:             24 * time.Hour,
	}
}

// One transfer balance, as a test gives it to a Quota and reads it back.
type QuotaBalance struct {
	BalanceId connect.Id
	// What is left: the grant less every debit. A debit past every balance's room overdraws the last in
	// draw order, so it may read below zero (plan-QUOTA-small-readings reading 5).
	ByteCount int64
	// A team_credit line, drawn after every other balance (D-QUOTA-9).
	Credit bool
	// When it may be drawn. A zero time leaves that side open.
	StartTime time.Time
	EndTime   time.Time
	// Read back only: what live reservations hold of it.
	ReservedByteCount int64
}

// Whether at falls in the balance's window.
func (self *QuotaBalance) inWindow(at time.Time) bool {
	return (self.StartTime.IsZero() || !at.Before(self.StartTime)) && (self.EndTime.IsZero() || at.Before(self.EndTime))
}

// escrowDrawLess's order (§20.9) as a comparison: the credit line last, then by end time, start time and
// balance id. An open end sorts after every end, an open start before every start.
func compareQuotaBalanceDraw(a *QuotaBalance, b *QuotaBalance) int {
	if a.Credit != b.Credit {
		if !a.Credit {
			return -1
		}
		return 1
	}
	compareTime := func(a time.Time, b time.Time, zeroLast bool) int {
		switch {
		case a.IsZero() && b.IsZero():
			return 0
		case a.IsZero():
			if zeroLast {
				return 1
			}
			return -1
		case b.IsZero():
			if zeroLast {
				return -1
			}
			return 1
		}
		return a.Compare(b)
	}
	if c := compareTime(a.EndTime, b.EndTime, true); c != 0 {
		return c
	}
	if c := compareTime(a.StartTime, b.StartTime, false); c != 0 {
		return c
	}
	return bytes.Compare(a.BalanceId[:], b.BalanceId[:])
}

// What a Quota answers while its Redis fails: CountRate passes, and a lease cannot reserve.
var errFakeQuotaRedisFailing = errors.New("the quota's Redis is failing")

type fakeQuotaRateCounter struct {
	windowIndex int64
	used        int64
}

type fakeQuotaNetwork struct {
	limits *sidecar.QuotaLimits
	// what Redis holds: rate counters by key, each passed debit id with when it counted, the pacing
	rateCounters    map[string]*fakeQuotaRateCounter
	debitCountTimes map[connect.Id]time.Time
	pacing          *sidecar.QuotaClosurePacing
	// what Postgres holds, in draw order
	balances          []*QuotaBalance
	transferUsed      map[string]int64
	storedDelta       int64
	unbilledByteCount int64
	storageRefusal    *sidecar.QuotaRefusal
	spentRefusal      *sidecar.QuotaRefusal
}

// See the file header.
type FakeQuota struct {
	clock    Clock
	faults   *FaultQueue
	settings *FakeQuotaSettings

	stateLock sync.Mutex
	networks  map[connect.Id]*fakeQuotaNetwork
	// applied batches' ids, with when they applied
	batchIdApplyTimes map[connect.Id]time.Time
	batches           []*sidecar.UsageBatch
	// every batch that reached the store, refused ones too: what a server saw (CC3)
	sentBatches []*sidecar.UsageBatch
	// every lease, oldest first: the open ones, and closed ones still owed a carve
	leaseEntries []*fakeQuotaLeaseEntry
	// bumped by LoseRedis: reservations made under an older one are gone
	redisEpoch        uint64
	redisFailing      bool
	rateFailOpenCount int
}

// clock nil is a fake clock of its own, at DefaultClockStart, and settings nil the defaults.
func NewFakeQuota(clock Clock, faults *FaultQueue, settings *FakeQuotaSettings) *FakeQuota {
	if clock == nil {
		clock = NewFakeClock(DefaultClockStart())
	}
	if faults == nil {
		faults = NewFaultQueue()
	}
	if settings == nil {
		settings = DefaultFakeQuotaSettings()
	}
	return &FakeQuota{
		clock:             clock,
		faults:            faults,
		settings:          settings,
		networks:          map[connect.Id]*fakeQuotaNetwork{},
		batchIdApplyTimes: map[connect.Id]time.Time{},
	}
}

func (self *FakeQuota) networkWithLock(networkId connect.Id) *fakeQuotaNetwork {
	network, ok := self.networks[networkId]
	if !ok {
		network = &fakeQuotaNetwork{
			limits:          &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{}},
			rateCounters:    map[string]*fakeQuotaRateCounter{},
			debitCountTimes: map[connect.Id]time.Time{},
			pacing:          sidecar.NewQuotaClosurePacing(),
			transferUsed:    map[string]int64{},
		}
		self.networks[networkId] = network
	}
	return network
}

// What Limits answers. A key not set here reads 0, not included, as §20.5 defines it.
func (self *FakeQuota) SetLimits(networkId connect.Id, limits *sidecar.QuotaLimits) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).limits = &sidecar.QuotaLimits{Tier: limits.Tier, Limits: maps.Clone(limits.Limits)}
}

// Replaces the network's balances with one open, non-credit balance of byteCount.
func (self *FakeQuota) SetBalance(networkId connect.Id, byteCount int64) {
	self.SetBalances(networkId, []*QuotaBalance{{BalanceId: connect.NewId(), ByteCount: byteCount}})
}

// Replaces the network's balances. A balance with no id takes a new one.
func (self *FakeQuota) SetBalances(networkId connect.Id, balances []*QuotaBalance) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	network.balances = nil
	for _, balance := range balances {
		copied := *balance
		copied.ReservedByteCount = 0
		if copied.BalanceId == (connect.Id{}) {
			copied.BalanceId = connect.NewId()
		}
		network.balances = append(network.balances, &copied)
	}
	slices.SortFunc(network.balances, compareQuotaBalanceDraw)
}

// The network's balances in draw order, each with what live reservations hold of it.
func (self *FakeQuota) Balances(networkId connect.Id) []*QuotaBalance {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reserved := self.reservedByBalanceWithLock(self.clock.Now())
	balances := []*QuotaBalance{}
	for _, balance := range self.networkWithLock(networkId).balances {
		copied := *balance
		copied.ReservedByteCount = reserved[balance]
		balances = append(balances, &copied)
	}
	return balances
}

// The bytes a lease may still reserve: each in-window balance's rest less what reservations hold.
func (self *FakeQuota) Balance(networkId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	reserved := self.reservedByBalanceWithLock(now)
	total := int64(0)
	for _, balance := range self.networkWithLock(networkId).balances {
		if balance.inWindow(now) {
			total += max(0, balance.ByteCount-reserved[balance])
		}
	}
	return total
}

// Marks a network over its storage limit: OverLimit carries the refusal until it is cleared by nil.
func (self *FakeQuota) SetStorageRefusal(networkId connect.Id, refusal *sidecar.QuotaRefusal) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).storageRefusal = refusal
}

// Marks a network spent: OverLimit carries the refusal until it is cleared by nil, or a lease draws.
func (self *FakeQuota) SetSpentRefusal(networkId connect.Id, refusal *sidecar.QuotaRefusal) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).spentRefusal = refusal
}

// Bytes reported on a meter, counted once per batch.
func (self *FakeQuota) TransferUsed(networkId connect.Id, meter string) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).transferUsed[meter]
}

// The sum of stored-byte deltas reported.
func (self *FakeQuota) StoredDelta(networkId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).storedDelta
}

// Bytes a batch reported for a network with no in-window balance at all, which nothing bills
// (plan-QUOTA-small-readings reading 5's urnetwork_quota_unbilled_bytes_total).
func (self *FakeQuota) UnbilledByteCount(networkId connect.Id) int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.networkWithLock(networkId).unbilledByteCount
}

// Every batch applied, once each.
func (self *FakeQuota) Batches() []*sidecar.UsageBatch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.batches)
}

// Every batch that reached the store, refused and replayed ones too.
func (self *FakeQuota) SentBatches() []*sidecar.UsageBatch {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.sentBatches)
}

// Loses Redis, as a failover with no replica does: every rate counter, debit id and pacing seat is
// forgotten, so a debit id counts again, and every reservation is gone while live leases keep spending
// what they hold, the over-admission §20.15 bounds by the lease size. Postgres keeps balances, debits,
// batch ids and the spent marks.
func (self *FakeQuota) LoseRedis() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.redisEpoch += 1
	for _, network := range self.networks {
		network.rateCounters = map[string]*fakeQuotaRateCounter{}
		network.debitCountTimes = map[connect.Id]time.Time{}
		network.pacing = sidecar.NewQuotaClosurePacing()
	}
}

// Makes Redis fail, or work again: while it fails, CountRate passes everything and counts nothing,
// open for as long as it fails (§20.7), and a lease can neither start nor renew.
func (self *FakeQuota) SetRedisFailing(failing bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.redisFailing = failing
}

// How many CountRate calls passed because Redis failed: urnetwork_quota_rate_fail_open_total.
func (self *FakeQuota) RateFailOpenCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.rateFailOpenCount
}

// host_quota.go's rule: a zero id names no one's limits or balance, and two calls sharing one would read
// as one retried, the second counting nothing.
func checkQuotaId(what string, id connect.Id) error {
	if id == (connect.Id{}) {
		return fmt.Errorf("a zero %s id", what)
	}
	return nil
}

func (self *FakeQuota) Limits(ctx context.Context, networkId connect.Id) (*sidecar.QuotaLimits, error) {
	if err := checkQuotaId("network", networkId); err != nil {
		return nil, err
	}
	var limits *sidecar.QuotaLimits
	err := hostCall(ctx, self.faults, "quota.Limits", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		network := self.networkWithLock(networkId)
		limits = &sidecar.QuotaLimits{Tier: network.limits.Tier, Limits: maps.Clone(network.limits.Limits)}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return limits, nil
}

// The counter for key in the window numbered windowIndex, emptied when its window turned.
func (self *fakeQuotaNetwork) rateCounterWithLock(key string, windowIndex int64) *fakeQuotaRateCounter {
	counter, ok := self.rateCounters[key]
	if !ok {
		counter = &fakeQuotaRateCounter{windowIndex: windowIndex}
		self.rateCounters[key] = counter
	}
	if counter.windowIndex != windowIndex {
		counter.windowIndex = windowIndex
		counter.used = 0
	}
	return counter
}

func cloneQuotaRefusal(refusal *sidecar.QuotaRefusal) *sidecar.QuotaRefusal {
	if refusal == nil {
		return nil
	}
	copied := *refusal
	return &copied
}

// An unknown key, a negative amount, or a paced key counted other than once, is the caller's bug: an
// error, with nothing counted. A paced key belongs in a call with no other paced key.
func (self *FakeQuota) CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	if err := checkQuotaId("network", networkId); err != nil {
		return nil, err
	}
	if err := checkQuotaId("debit", debitId); err != nil {
		return nil, err
	}
	keys := slices.Sorted(maps.Keys(keyAmounts))
	keyRules := map[string]*sidecar.QuotaRateRule{}
	pacedCount := 0
	for _, key := range keys {
		rule, err := sidecar.ParseQuotaRateKey(key)
		if err != nil {
			return nil, err
		}
		amount := keyAmounts[key]
		if amount < 0 {
			return nil, fmt.Errorf("a negative count %d of %s", amount, key)
		}
		if rule.Paced {
			if amount != 1 {
				return nil, fmt.Errorf("%s counts one upload, not %d", key, amount)
			}
			pacedCount += 1
		}
		keyRules[key] = rule
	}
	if 1 < pacedCount {
		return nil, fmt.Errorf("%d paced keys in one call", pacedCount)
	}
	var refusal *sidecar.QuotaRefusal
	err := hostCall(ctx, self.faults, "quota.CountRate", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.redisFailing {
			self.rateFailOpenCount += 1
			return nil
		}
		now := self.clock.Now()
		network := self.networkWithLock(networkId)
		if countTime, ok := network.debitCountTimes[debitId]; ok && now.Sub(countTime) < self.settings.DebitIdLifetime {
			// a debit that passed answers pass again and counts nothing, touching no seat
			return nil
		}
		limits := network.limits
		perS := sidecar.QuotaClosurePacingPerS(limits)
		// judge every counter before counting any; the pacing is asked only when none refused, so an
		// eraser its own rate or allowance refuses is given no seat (DESIGN-DETAILS 13.2.1)
		var first *sidecar.QuotaRefusal
		var pacedRule *sidecar.QuotaRateRule
		for _, key := range keys {
			rule := keyRules[key]
			amount := keyAmounts[key]
			counter := network.rateCounterWithLock(key, rule.Window.Index(now))
			limit := rule.Limit(limits)
			if first == nil && limit != -1 && limit < counter.used+amount {
				first = rule.Refusal(limits, counter.used, now)
			}
			if rule.Paced {
				pacedRule = rule
			}
		}
		if first == nil && pacedRule != nil {
			ok, seatTime, takenThisSecond := network.pacing.Ask(pacedRule.SubjectId, now, perS)
			if !ok {
				first = sidecar.QuotaClosurePacingRefusal(limits, takenThisSecond, network.pacing.Clock(), seatTime)
			}
		}
		if first != nil {
			// a refusal counted nothing and records nothing, so its debit id is judged afresh
			refusal = first
			return nil
		}
		for _, key := range keys {
			rule := keyRules[key]
			network.rateCounterWithLock(key, rule.Window.Index(now)).used += keyAmounts[key]
		}
		if pacedRule != nil {
			network.pacing.Take(pacedRule.SubjectId, now, perS)
		}
		network.debitCountTimes[debitId] = now
		return nil
	})
	if err != nil {
		return nil, err
	}
	return refusal, nil
}

// One reservation a lease made on one balance. Its bytes are the lease's drawn range from offset, so
// the lease's bytes spend, and its carves debit, in draw order, and its rest goes back in reverse.
type fakeQuotaDraw struct {
	balance    *QuotaBalance
	offset     int64
	byteCount  int64
	redisEpoch uint64
	expireTime time.Time
}

// One process's lease on one network and meter, shared by its handles.
type fakeQuotaLeaseEntry struct {
	quota         *FakeQuota
	actor         *Actor
	networkId     connect.Id
	meter         string
	drawByteCount int64
	// what Spend may take, the one field touched without the lock
	available atomic.Int64

	// the rest under quota.stateLock
	draws           []*fakeQuotaDraw
	drawnByteCount  int64
	carvedByteCount int64
	handleCount     int
	closed          bool
	// what was spent when the last handle closed: the bytes still owed a carve
	closedSpentByteCount int64
}

// Where the bytes still reserved end: past them, a closed lease gave its rest back.
func (self *fakeQuotaLeaseEntry) reservedEndWithLock() int64 {
	if self.closed {
		return self.closedSpentByteCount
	}
	return self.drawnByteCount
}

func (self *fakeQuotaLeaseEntry) spentWithLock() int64 {
	if self.closed {
		return self.closedSpentByteCount
	}
	return self.drawnByteCount - self.available.Load()
}

// Keeps the lease's live reservations from lapsing, as a real lease extends its tokens.
func (self *fakeQuotaLeaseEntry) rollWithLock(now time.Time) {
	for _, draw := range self.draws {
		if self.drawLiveWithLock(draw, now) {
			draw.expireTime = now.Add(self.quota.settings.LeaseTokenLifetime)
		}
	}
}

// Whether the entry's process lives: one a schedule killed stops extending its lease's tokens.
func (self *fakeQuotaLeaseEntry) processLives() bool {
	return self.actor == nil || !self.actor.Killed()
}

// Whether a draw's reservation is still held: Redis has not lost it, and it has not lapsed. An open lease
// of a live process extends its draws however long nobody looks, as the real lease's goroutine does; a
// closed one's last LeaseTokenLifetime past its close or its last carve, as the real lease's do until it
// gives up what no batch carved; a killed process's lapse that long after the fake last saw it alive.
func (self *fakeQuotaLeaseEntry) drawLiveWithLock(draw *fakeQuotaDraw, now time.Time) bool {
	if draw.redisEpoch != self.quota.redisEpoch {
		return false
	}
	return (!self.closed && self.processLives()) || now.Before(draw.expireTime)
}

// Rolls every live process's leases, as their goroutines extend them while they run. Under the lock.
func (self *FakeQuota) rollLiveLeasesWithLock(now time.Time) {
	for _, entry := range self.leaseEntries {
		if entry.processLives() {
			entry.rollWithLock(now)
		}
	}
}

// What every live reservation holds of each balance: the part of each draw not yet carved or given back.
func (self *FakeQuota) reservedByBalanceWithLock(now time.Time) map[*QuotaBalance]int64 {
	self.rollLiveLeasesWithLock(now)
	reserved := map[*QuotaBalance]int64{}
	for _, entry := range self.leaseEntries {
		end := entry.reservedEndWithLock()
		for _, draw := range entry.draws {
			if !entry.drawLiveWithLock(draw, now) {
				continue
			}
			from := max(entry.carvedByteCount, draw.offset)
			to := min(end, draw.offset+draw.byteCount)
			if from < to {
				reserved[draw.balance] += to - from
			}
		}
	}
	return reserved
}

// Reserves up to one draw for entry from the network's in-window balances in draw order, answering
// how much it reserved.
func (self *FakeQuota) drawWithLock(entry *fakeQuotaLeaseEntry, now time.Time) int64 {
	network := self.networkWithLock(entry.networkId)
	reserved := self.reservedByBalanceWithLock(now)
	drawn := int64(0)
	for _, balance := range network.balances {
		if entry.drawByteCount <= drawn {
			break
		}
		if !balance.inWindow(now) {
			continue
		}
		take := min(balance.ByteCount-reserved[balance], entry.drawByteCount-drawn)
		if take <= 0 {
			continue
		}
		entry.draws = append(entry.draws, &fakeQuotaDraw{
			balance:    balance,
			offset:     entry.drawnByteCount,
			byteCount:  take,
			redisEpoch: self.redisEpoch,
			expireTime: now.Add(self.settings.LeaseTokenLifetime),
		})
		entry.drawnByteCount += take
		entry.available.Add(take)
		drawn += take
	}
	return drawn
}

// The caller's open lease on networkId and meter, or nil.
func (self *FakeQuota) openLeaseEntryWithLock(actor *Actor, networkId connect.Id, meter string) *fakeQuotaLeaseEntry {
	for _, entry := range self.leaseEntries {
		if !entry.closed && entry.actor == actor && entry.networkId == networkId && entry.meter == meter {
			return entry
		}
	}
	return nil
}

// Drops leases that are closed and owed nothing more.
func (self *FakeQuota) forgetSettledLeasesWithLock() {
	self.leaseEntries = slices.DeleteFunc(self.leaseEntries, func(entry *fakeQuotaLeaseEntry) bool {
		return entry.closed && entry.closedSpentByteCount <= entry.carvedByteCount
	})
}

func fakeQuotaSpentRefusal(meter string) *sidecar.QuotaRefusal {
	return &sidecar.QuotaRefusal{LimitKey: meter, Upgrade: true}
}

func (self *FakeQuota) Lease(ctx context.Context, networkId connect.Id, meter string) (sidecar.QuotaLease, *sidecar.QuotaRefusal, error) {
	if err := checkQuotaId("network", networkId); err != nil {
		return nil, nil, err
	}
	if !sidecar.IsQuotaLeaseMeter(meter) {
		// evs's and relay's bytes draw at apply: no lease spends them
		return nil, nil, fmt.Errorf("no lease spends meter %q", meter)
	}
	var lease *fakeQuotaLease
	var refusal *sidecar.QuotaRefusal
	err := hostCall(ctx, self.faults, "quota.Lease", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.redisFailing {
			return errFakeQuotaRedisFailing
		}
		now := self.clock.Now()
		network := self.networkWithLock(networkId)
		actor := ActorFromContext(ctx)
		entry := self.openLeaseEntryWithLock(actor, networkId, meter)
		if entry == nil {
			drawByteCount := self.settings.LeaseDrawByteCount
			if network.limits.Tier == "free" {
				drawByteCount = self.settings.CommunityLeaseDrawByteCount
			}
			entry = &fakeQuotaLeaseEntry{quota: self, actor: actor, networkId: networkId, meter: meter, drawByteCount: drawByteCount}
			if self.drawWithLock(entry, now) == 0 {
				// a refused lease holds nothing and marks the network spent (host_quota.go)
				refusal = fakeQuotaSpentRefusal(meter)
				network.spentRefusal = refusal
				return nil
			}
			self.leaseEntries = append(self.leaseEntries, entry)
		} else if entry.available.Load() <= 0 && self.drawWithLock(entry, now) == 0 {
			refusal = fakeQuotaSpentRefusal(meter)
			network.spentRefusal = refusal
			return nil
		}
		entry.handleCount += 1
		entry.rollWithLock(now)
		network.spentRefusal = nil
		lease = &fakeQuotaLease{entry: entry}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if refusal != nil {
		return nil, cloneQuotaRefusal(refusal), nil
	}
	return lease, nil, nil
}

// Moves up to byteCount of entry's spent bytes into debits, in draw order, answering how many it took.
// Only bytes a live reservation holds are debited: a draw that lapsed or was lost with Redis gives its
// bytes up, counted unbilled (QD-653).
func (self *FakeQuota) carveWithLock(entry *fakeQuotaLeaseEntry, byteCount int64, now time.Time) int64 {
	self.rollLiveLeasesWithLock(now)
	carve := min(byteCount, entry.spentWithLock()-entry.carvedByteCount)
	if carve <= 0 {
		return 0
	}
	from := entry.carvedByteCount
	to := from + carve
	network := self.networkWithLock(entry.networkId)
	for _, draw := range entry.draws {
		partFrom := max(from, draw.offset)
		partTo := min(to, draw.offset+draw.byteCount)
		if partFrom < partTo {
			if entry.drawLiveWithLock(draw, now) {
				draw.balance.ByteCount -= partTo - partFrom
			} else {
				network.unbilledByteCount += partTo - partFrom
			}
		}
	}
	entry.carvedByteCount = to
	entry.rollWithLock(now)
	return carve
}

// evs's bytes, debited when their batch applies, in draw order. Past every
// balance's room they overdraw the last in-window balance; with none at all they go unbilled; either
// way the network is spent (plan-QUOTA-small-readings reading 5).
func (self *FakeQuota) debitAtApplyWithLock(network *fakeQuotaNetwork, meter string, byteCount int64, now time.Time) {
	balances := []*QuotaBalance{}
	for _, balance := range network.balances {
		if balance.inWindow(now) {
			balances = append(balances, balance)
		}
	}
	if len(balances) == 0 {
		network.unbilledByteCount += byteCount
		network.spentRefusal = fakeQuotaSpentRefusal(meter)
		return
	}
	remaining := byteCount
	for _, balance := range balances {
		take := min(remaining, max(0, balance.ByteCount))
		balance.ByteCount -= take
		remaining -= take
	}
	if 0 < remaining {
		balances[len(balances)-1].ByteCount -= remaining
		network.spentRefusal = fakeQuotaSpentRefusal(meter)
	}
}

// What api refuses whole, applying none of it (QUOTA-M2-05).
func checkUsageBatch(batch *sidecar.UsageBatch) error {
	if err := checkQuotaId("batch", batch.BatchId); err != nil {
		return err
	}
	if !sidecar.IsQuotaProducer(batch.Producer) {
		return fmt.Errorf("no producer %q", batch.Producer)
	}
	if sidecar.QuotaUsageBatchMaxEventCount < len(batch.Events) {
		return fmt.Errorf("%d events, past %d", len(batch.Events), sidecar.QuotaUsageBatchMaxEventCount)
	}
	for _, event := range batch.Events {
		if err := checkQuotaId("network", event.NetworkId); err != nil {
			return err
		}
		if !sidecar.IsQuotaMeter(event.Meter) {
			return fmt.Errorf("no meter %q", event.Meter)
		}
		if event.TransferByteCount < 0 {
			return fmt.Errorf("a negative transfer %d", event.TransferByteCount)
		}
	}
	return nil
}

// A batch from a process carves that process's leases on each event's network and meter first, oldest
// first; the rest of evs's bytes debit at once, and the rest of a lease meter's are unbilled (QD-653).
func (self *FakeQuota) ReportUsage(ctx context.Context, batch *sidecar.UsageBatch) error {
	if batch == nil {
		return errors.New("no batch")
	}
	return hostCall(ctx, self.faults, "quota.ReportUsage", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sentBatches = append(self.sentBatches, batch)
		if err := checkUsageBatch(batch); err != nil {
			return err
		}
		now := self.clock.Now()
		if applyTime, ok := self.batchIdApplyTimes[batch.BatchId]; ok && now.Sub(applyTime) < self.settings.BatchIdLifetime {
			return nil
		}
		self.batchIdApplyTimes[batch.BatchId] = now
		self.batches = append(self.batches, batch)
		actor := ActorFromContext(ctx)
		for _, event := range batch.Events {
			network := self.networkWithLock(event.NetworkId)
			network.transferUsed[event.Meter] += event.TransferByteCount
			network.storedDelta += event.StoredByteDelta
			remaining := event.TransferByteCount
			for _, entry := range self.leaseEntries {
				if remaining <= 0 {
					break
				}
				if entry.actor == actor && entry.networkId == event.NetworkId && entry.meter == event.Meter {
					remaining -= self.carveWithLock(entry, remaining, now)
				}
			}
			if 0 < remaining {
				if sidecar.IsQuotaLeaseMeter(event.Meter) {
					// bytes no lease of the process spent: no carve covers them, so nothing debits them
					network.unbilledByteCount += remaining
				} else {
					self.debitAtApplyWithLock(network, event.Meter, remaining, now)
				}
			}
		}
		self.forgetSettledLeasesWithLock()
		return nil
	})
}

func (self *FakeQuota) OverLimit(ctx context.Context) (*sidecar.QuotaOverLimit, error) {
	overLimit := &sidecar.QuotaOverLimit{
		StorageNetworkIdRefusals: map[connect.Id]*sidecar.QuotaRefusal{},
		SpentNetworkIdRefusals:   map[connect.Id]*sidecar.QuotaRefusal{},
	}
	err := hostCall(ctx, self.faults, "quota.OverLimit", func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for networkId, network := range self.networks {
			if network.storageRefusal != nil {
				overLimit.StorageNetworkIdRefusals[networkId] = cloneQuotaRefusal(network.storageRefusal)
			}
			if network.spentRefusal != nil {
				overLimit.SpentNetworkIdRefusals[networkId] = cloneQuotaRefusal(network.spentRefusal)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return overLimit, nil
}

// One handle on a process's lease.
type fakeQuotaLease struct {
	entry  *fakeQuotaLeaseEntry
	closed atomic.Bool
}

// Atomic, with no I/O at the store: renewing at §20.6's fraction moves bytes between two counters here,
// on the spender's goroutine, which a real lease leaves to a goroutine of its own.
func (self *fakeQuotaLease) Spend(byteCount int64) bool {
	if byteCount < 0 || self.closed.Load() {
		return false
	}
	entry := self.entry
	for {
		available := entry.available.Load()
		if available < byteCount {
			drawn, redisFailing := entry.renew()
			if 0 < drawn {
				continue
			}
			if !redisFailing {
				entry.markSpent()
			}
			return false
		}
		if entry.available.CompareAndSwap(available, available-byteCount) {
			break
		}
	}
	renewAt := (1 - entry.quota.settings.LeaseRenewFraction) * float64(entry.drawByteCount)
	if float64(entry.available.Load()) <= renewAt {
		entry.renew()
	}
	return true
}

// Reserves one more draw, unless the lease closed or Redis fails.
func (self *fakeQuotaLeaseEntry) renew() (drawn int64, redisFailing bool) {
	quota := self.quota
	quota.stateLock.Lock()
	defer quota.stateLock.Unlock()
	if self.closed {
		return 0, false
	}
	if quota.redisFailing {
		return 0, true
	}
	now := quota.clock.Now()
	drawn = quota.drawWithLock(self, now)
	self.rollWithLock(now)
	return drawn, false
}

// A lease run out with nothing left to reserve: the network is spent until a new Lease says otherwise
// (host_quota.go).
func (self *fakeQuotaLeaseEntry) markSpent() {
	quota := self.quota
	quota.stateLock.Lock()
	defer quota.stateLock.Unlock()
	if self.closed {
		return
	}
	quota.networkWithLock(self.networkId).spentRefusal = fakeQuotaSpentRefusal(self.meter)
}

// The last handle's Close gives back the unused rest, the tail of the drawn range and so in reverse draw
// order, and leaves the spent bytes reserved until a batch carves them. Spend then refuses on this
// handle.
func (self *fakeQuotaLease) Close() {
	if self.closed.Swap(true) {
		return
	}
	entry := self.entry
	quota := entry.quota
	quota.stateLock.Lock()
	defer quota.stateLock.Unlock()
	entry.handleCount -= 1
	if 0 < entry.handleCount {
		return
	}
	// its tokens are extended to the close, and then lapse unless a batch carves them
	entry.rollWithLock(quota.clock.Now())
	entry.closed = true
	rest := entry.available.Swap(0)
	entry.closedSpentByteCount = entry.drawnByteCount - rest
	quota.forgetSettledLeasesWithLock()
}

func (self *fakeQuotaLease) String() string {
	return fmt.Sprintf("lease on %s", self.entry.meter)
}

// A Quota whose calls take host plans from faults as FakeQuota's do, by FaultOpHost and
// "quota.<Method>": how a T3 target puts server's Quota under quotasuite's lost responses and crash
// points. Leases are the wrapped Quota's own: a lease whose answer a plan drops is lost to its caller and
// left to lapse, as one lost on the wire is.
func NewFaultQuota(quota sidecar.Quota, faults *FaultQueue) sidecar.Quota {
	return &faultQuota{quota: quota, faults: faults}
}

type faultQuota struct {
	quota  sidecar.Quota
	faults *FaultQueue
}

func (self *faultQuota) Limits(ctx context.Context, networkId connect.Id) (*sidecar.QuotaLimits, error) {
	var limits *sidecar.QuotaLimits
	err := hostCall(ctx, self.faults, "quota.Limits", func() error {
		var err error
		limits, err = self.quota.Limits(ctx, networkId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return limits, nil
}

func (self *faultQuota) CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*sidecar.QuotaRefusal, error) {
	var refusal *sidecar.QuotaRefusal
	err := hostCall(ctx, self.faults, "quota.CountRate", func() error {
		var err error
		refusal, err = self.quota.CountRate(ctx, networkId, keyAmounts, debitId)
		return err
	})
	if err != nil {
		return nil, err
	}
	return refusal, nil
}

func (self *faultQuota) Lease(ctx context.Context, networkId connect.Id, meter string) (sidecar.QuotaLease, *sidecar.QuotaRefusal, error) {
	var lease sidecar.QuotaLease
	var refusal *sidecar.QuotaRefusal
	err := hostCall(ctx, self.faults, "quota.Lease", func() error {
		var err error
		lease, refusal, err = self.quota.Lease(ctx, networkId, meter)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return lease, refusal, nil
}

func (self *faultQuota) ReportUsage(ctx context.Context, batch *sidecar.UsageBatch) error {
	return hostCall(ctx, self.faults, "quota.ReportUsage", func() error {
		return self.quota.ReportUsage(ctx, batch)
	})
}

func (self *faultQuota) OverLimit(ctx context.Context) (*sidecar.QuotaOverLimit, error) {
	var overLimit *sidecar.QuotaOverLimit
	err := hostCall(ctx, self.faults, "quota.OverLimit", func() error {
		var err error
		overLimit, err = self.quota.OverLimit(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return overLimit, nil
}
