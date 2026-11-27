//go:build !ios_extension && !sidecar_http

// BudgetLedger (DESIGN-COMPUTE §16.4; D-CACL-6, IC-6, IC-11; CACL-M12-05): the daemon's own tallies of the budgets it can
// see, its agents', its grants' and its runs' and its own calls', by budget and UTC day, UTC month or run, from each
// call's hold and settlement, kept in the sidecar's store so a restart resets nothing.
//
//	check    a budget's room, its cap less what settled and what is held in its current period, below the call's
//	         worst case refuses before the broker is asked: ErrBudgetExceeded, naming the budget and its period, for
//	         the router's insufficient_quota reason budget and §7.4's offer of kind 21
//	hold     the check, then the worst case held in each budget the device counts, under the call's id, atomically
//	settle   the charge the broker answered settled in each budget the hold counted, in the period it was held in, the
//	         hold dropped; a call that failed releases its hold
//	window   a UTC day (d:YYYYMMDD), a UTC month (m:YYYYMM) or a run (r:<run id>), at the ledger clock's time
//
// A member's budget across devices and the network's are the broker's alone: the ledger counts none (ComputeBudget's
// DeviceCounts). The check is advisory and never skips the broker, which enforces every budget (IC-6). Until BAL's call
// results feed it (BAL C§9.7) nothing holds or settles in production, so the check sees what this device recorded and
// no more.
//
// The ledger is one file in the sidecar's network store, rewritten whole at each change (SidecarStore's commit swaps
// it in at once), its tallies pruned past BudgetSettings.LedgerRetention. Safe for concurrent use. Device legs only.

package sidecar

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

// The ledger's file in its store.
const budgetLedgerFileName = "ledger.json"

// The ledger file's version.
const budgetLedgerVersion = 1

// The budgets component's name, and its store's.
const budgetComponentName = "budgets"

var (
	// A budget's room is below the call's worst case: ComputeBudgetExceededError names which.
	ErrBudgetExceeded = errors.New("compute budget exceeded")
	// The ledger holds as many holds or tallies as its settings allow.
	ErrBudgetLedgerFull = errors.New("compute budget ledger full")
	// A hold under the call's id stands already.
	ErrBudgetHoldExists = errors.New("compute budget hold exists")
	// The ledger's file does not read.
	ErrBudgetLedgerUnreadable = errors.New("compute budget ledger unreadable")
)

// A refusal naming the budget and its period, never an amount another subject holds.
type ComputeBudgetExceededError struct {
	Budget string
	Period ComputeBudgetPeriod
	// What is left of it, which is below the call's worst case.
	RoomNanoUsd uint64
}

// The budget, its period and its room.
func (self *ComputeBudgetExceededError) Error() string {
	return fmt.Sprintf("%s: the %s budget's %s has %d nano-USD left", ErrBudgetExceeded, self.Budget, self.Period, self.RoomNanoUsd)
}

// ErrBudgetExceeded.
func (self *ComputeBudgetExceededError) Unwrap() error {
	return ErrBudgetExceeded
}

// One budget's tally in one window.
type budgetLedgerTally struct {
	Budget         string `json:"budget"`
	Window         string `json:"window"`
	HeldNanoUsd    uint64 `json:"held_nano_usd"`
	SettledNanoUsd uint64 `json:"settled_nano_usd"`
	// When the window ends, ms since the epoch, which pruning reads; 0 for a run's, kept until its run's budget is
	// gone from every hold for LedgerRetention.
	EndsMs int64 `json:"ends_ms"`
	// The newest change, ms since the epoch.
	ChangedMs int64 `json:"changed_ms"`
}

// One call's hold: the tallies it counts in, and the amount held in each.
type budgetLedgerHold struct {
	Call          string   `json:"call"`
	Tallies       []string `json:"tallies"`
	AmountNanoUsd uint64   `json:"amount_nano_usd"`
	HeldMs        int64    `json:"held_ms"`
}

// The ledger's file.
type budgetLedgerState struct {
	Version int                  `json:"version"`
	Tallies []*budgetLedgerTally `json:"tallies"`
	Holds   []*budgetLedgerHold  `json:"holds"`
}

// A tally's key: its budget's and its window.
func budgetLedgerTallyKey(budget string, window string) string {
	return budget + "@" + window
}

// What a ledger is built on.
type BudgetLedgerArgs struct {
	// The sidecar's network store's directory for budgets.
	Store    SidecarStore
	Settings *BudgetSettings
	Clock    Clock
}

// The daemon's tallies. See the file header.
type BudgetLedger struct {
	store    SidecarStore
	settings *BudgetSettings
	clock    Clock

	stateLock sync.Mutex
	state     *budgetLedgerState
}

// The ledger its store holds, empty where it holds none; ErrBudgetLedgerUnreadable for a file that does not read,
// which a caller refuses on rather than start from nothing, so no restart resets a tally.
func NewBudgetLedger(args *BudgetLedgerArgs) (*BudgetLedger, error) {
	if args == nil || args.Store == nil || args.Clock == nil {
		return nil, errors.New("budget ledger: no store or clock")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultBudgetSettings()
	}
	ledger := &BudgetLedger{store: args.Store, settings: settings, clock: args.Clock}
	state, err := ledger.load()
	if err != nil {
		return nil, err
	}
	ledger.state = state
	return ledger, nil
}

// The file as stored, or an empty ledger where there is none.
func (self *BudgetLedger) load() (*budgetLedgerState, error) {
	reader, err := self.store.Open(budgetLedgerFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return &budgetLedgerState{Version: budgetLedgerVersion, Tallies: []*budgetLedgerTally{}, Holds: []*budgetLedgerHold{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBudgetLedgerUnreadable, err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(self.settings.LedgerMaxByteCount)+1))
	if err != nil || self.settings.LedgerMaxByteCount < len(data) {
		return nil, fmt.Errorf("%w: the file does not read whole within its bound", ErrBudgetLedgerUnreadable)
	}
	state := &budgetLedgerState{}
	if err := json.Unmarshal(data, state); err != nil || state.Version != budgetLedgerVersion {
		return nil, fmt.Errorf("%w: the file is not version %d's", ErrBudgetLedgerUnreadable, budgetLedgerVersion)
	}
	if state.Tallies == nil {
		state.Tallies = []*budgetLedgerTally{}
	}
	if state.Holds == nil {
		state.Holds = []*budgetLedgerHold{}
	}
	return state, nil
}

// Writes state whole, then installs it. Under stateLock.
func (self *BudgetLedger) save(state *budgetLedgerState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if self.settings.LedgerMaxByteCount < len(data) {
		return fmt.Errorf("%w: the file would pass its bound", ErrBudgetLedgerFull)
	}
	writer, err := self.store.Create(budgetLedgerFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.state = state
	return nil
}

// A deep copy of the state, which a change edits before it saves. Under stateLock.
func (self *BudgetLedger) copyState() *budgetLedgerState {
	state := &budgetLedgerState{Version: budgetLedgerVersion, Tallies: []*budgetLedgerTally{}, Holds: []*budgetLedgerHold{}}
	for _, tally := range self.state.Tallies {
		copied := *tally
		state.Tallies = append(state.Tallies, &copied)
	}
	for _, hold := range self.state.Holds {
		copied := *hold
		copied.Tallies = slices.Clone(hold.Tallies)
		state.Holds = append(state.Holds, &copied)
	}
	return state
}

// A budget's window at now, and when it ends in ms since the epoch, 0 for a run's.
func budgetLedgerWindow(budget *ComputeBudget, now time.Time) (string, int64) {
	now = now.UTC()
	switch budget.Period {
	case ComputeBudgetPeriodDay:
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		return "d:" + now.Format("20060102"), start.AddDate(0, 0, 1).UnixMilli()
	case ComputeBudgetPeriodMonth:
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		return "m:" + now.Format("200601"), start.AddDate(0, 1, 0).UnixMilli()
	}
	return "r:" + hex.EncodeToString(budget.SubjectId.Bytes()), 0
}

// The tally keyed key in state, nil for none.
func (self *budgetLedgerState) tally(key string) *budgetLedgerTally {
	index := slices.IndexFunc(self.Tallies, func(tally *budgetLedgerTally) bool {
		return budgetLedgerTallyKey(tally.Budget, tally.Window) == key
	})
	if index < 0 {
		return nil
	}
	return self.Tallies[index]
}

// What is left of budget in its current window at now: its cap less what settled and what is held there.
func (self *budgetLedgerState) room(budget *ComputeBudget, now time.Time) uint64 {
	window, _ := budgetLedgerWindow(budget, now)
	tally := self.tally(budgetLedgerTallyKey(budget.Key(), window))
	if tally == nil {
		return budget.CapNanoUsd
	}
	used := tally.HeldNanoUsd + tally.SettledNanoUsd
	if used < tally.HeldNanoUsd || budget.CapNanoUsd <= used {
		return 0
	}
	return budget.CapNanoUsd - used
}

// The first budget the device counts whose room is below worstCase, as a ComputeBudgetExceededError; nil where every one
// has room.
func (self *budgetLedgerState) check(budgets []*ComputeBudget, worstCase uint64, now time.Time) error {
	for _, budget := range budgets {
		if !budget.DeviceCounts {
			continue
		}
		if room := self.room(budget, now); room < worstCase {
			return &ComputeBudgetExceededError{Budget: budget.Name, Period: budget.Period, RoomNanoUsd: room}
		}
	}
	return nil
}

// Nil where every budget the device counts has room for worstCase now, else ErrBudgetExceeded naming the budget and
// its period. Reads only.
func (self *BudgetLedger) Check(budgets []*ComputeBudget, worstCase uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state.check(budgets, worstCase, self.clock.Now())
}

// What is left of budget now, its cap where the device does not count it.
func (self *BudgetLedger) Room(budget *ComputeBudget) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !budget.DeviceCounts {
		return budget.CapNanoUsd
	}
	return self.state.room(budget, self.clock.Now())
}

// Checks, then holds worstCase in each budget the device counts under callId, durably, so a restart keeps it.
// ErrBudgetExceeded where one has no room, ErrBudgetHoldExists for a call held already, ErrBudgetLedgerFull past the
// settings' bounds; nothing is held then.
func (self *BudgetLedger) Hold(callId Id, budgets []*ComputeBudget, worstCase uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	if err := self.state.check(budgets, worstCase, now); err != nil {
		return err
	}
	call := hex.EncodeToString(callId.Bytes())
	if slices.ContainsFunc(self.state.Holds, func(hold *budgetLedgerHold) bool { return hold.Call == call }) {
		return ErrBudgetHoldExists
	}
	if self.settings.LedgerHoldMaxCount <= len(self.state.Holds) {
		return fmt.Errorf("%w: %d holds open", ErrBudgetLedgerFull, len(self.state.Holds))
	}
	state := self.copyState()
	hold := &budgetLedgerHold{Call: call, Tallies: []string{}, AmountNanoUsd: worstCase, HeldMs: now.UnixMilli()}
	for _, budget := range budgets {
		if !budget.DeviceCounts {
			continue
		}
		window, endsMs := budgetLedgerWindow(budget, now)
		key := budgetLedgerTallyKey(budget.Key(), window)
		tally := state.tally(key)
		if tally == nil {
			if self.settings.LedgerTallyMaxCount <= len(state.Tallies) {
				return fmt.Errorf("%w: %d tallies kept", ErrBudgetLedgerFull, len(state.Tallies))
			}
			tally = &budgetLedgerTally{Budget: budget.Key(), Window: window, EndsMs: endsMs}
			state.Tallies = append(state.Tallies, tally)
		}
		tally.HeldNanoUsd += worstCase
		tally.ChangedMs = now.UnixMilli()
		hold.Tallies = append(hold.Tallies, key)
	}
	state.Holds = append(state.Holds, hold)
	self.prune(state, now)
	return self.save(state)
}

// Settles callId's hold at chargeNanoUsd, the broker's charge, in each tally it counted in, the hold dropped; a charge
// past the hold is settled whole, since it was spent. A call with no hold here settles nothing and answers nil, as a
// settlement repeated after a restart does.
func (self *BudgetLedger) Settle(callId Id, chargeNanoUsd uint64) error {
	return self.end(callId, &chargeNanoUsd)
}

// Drops callId's hold with nothing settled: a call that failed before any charge.
func (self *BudgetLedger) Release(callId Id) error {
	return self.end(callId, nil)
}

// Ends callId's hold, settling charge where one is given.
func (self *BudgetLedger) end(callId Id, chargeNanoUsd *uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	call := hex.EncodeToString(callId.Bytes())
	index := slices.IndexFunc(self.state.Holds, func(hold *budgetLedgerHold) bool { return hold.Call == call })
	if index < 0 {
		return nil
	}
	now := self.clock.Now()
	state := self.copyState()
	hold := state.Holds[index]
	for _, key := range hold.Tallies {
		tally := state.tally(key)
		if tally == nil {
			continue
		}
		tally.HeldNanoUsd -= min(tally.HeldNanoUsd, hold.AmountNanoUsd)
		if chargeNanoUsd != nil {
			tally.SettledNanoUsd += *chargeNanoUsd
		}
		tally.ChangedMs = now.UnixMilli()
	}
	state.Holds = slices.Delete(state.Holds, index, index+1)
	self.prune(state, now)
	return self.save(state)
}

// Drops tallies whose window ended LedgerRetention before now and that no hold counts in; a run's when it last changed
// that long ago.
func (self *BudgetLedger) prune(state *budgetLedgerState, now time.Time) {
	held := map[string]bool{}
	for _, hold := range state.Holds {
		for _, key := range hold.Tallies {
			held[key] = true
		}
	}
	cutoff := now.Add(-self.settings.LedgerRetention).UnixMilli()
	state.Tallies = slices.DeleteFunc(state.Tallies, func(tally *budgetLedgerTally) bool {
		ended := tally.EndsMs
		if ended == 0 {
			ended = tally.ChangedMs
		}
		return !held[budgetLedgerTallyKey(tally.Budget, tally.Window)] && ended < cutoff
	})
}

// A gateway grant's or a Harness agent's budget for period, as asked, held to the default for its agent unless a kind-21
// raise in force lifts it (§8.6, IC-11): the default day's for a day or a run, the month's for a month.
func (self *BudgetLedger) ClampGrant(requestedNanoUsd uint64, period ComputeBudgetPeriod, raise *ComputeBudgetRaise) uint64 {
	return ComputeBudgetClampGrant(self.settings, requestedNanoUsd, period, raise, self.clock.Now())
}

// ClampGrant's rule, apart from a ledger.
func ComputeBudgetClampGrant(settings *BudgetSettings, requestedNanoUsd uint64, period ComputeBudgetPeriod, raise *ComputeBudgetRaise, now time.Time) uint64 {
	if settings == nil {
		settings = DefaultBudgetSettings()
	}
	capNanoUsd := settings.AgentDayNanoUsd
	if period == ComputeBudgetPeriodMonth {
		capNanoUsd = settings.AgentMonthNanoUsd
	}
	if raise != nil && raise.Period == period && now.Before(raise.NotAfter) && capNanoUsd < raise.CapNanoUsd {
		capNanoUsd = raise.CapNanoUsd
	}
	return min(requestedNanoUsd, capNanoUsd)
}

// The budgets component on a Sidecar: one ledger a network, built at its first use over the network's store.
type sidecarBudgets struct {
	sidecar *Sidecar

	stateLock sync.Mutex
	ledgers   map[Id]*BudgetLedger
}

// The ledger of networkId, built from its store at its first use.
func (self *sidecarBudgets) ledger(networkId Id) (*BudgetLedger, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ledger := self.ledgers[networkId]; ledger != nil {
		return ledger, nil
	}
	store, err := self.sidecar.instance.Store(&networkId).Directory(budgetComponentName, budgetComponentName)
	if err != nil {
		return nil, err
	}
	ledger, err := NewBudgetLedger(&BudgetLedgerArgs{Store: store, Settings: self.sidecar.settings.Budget, Clock: self.sidecar.clock})
	if err != nil {
		return nil, err
	}
	self.ledgers[networkId] = ledger
	return ledger, nil
}

// This sidecar's ledger in its current network.
func (self *Sidecar) BudgetLedger() (*BudgetLedger, error) {
	budgets, err := sidecarComputeComponent[sidecarBudgets](self, budgetComponentName)
	if err != nil {
		return nil, err
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	return budgets.ledger(identity.NetworkId)
}

// What a call from this sidecar is, for its budgets at now: its identity, its admission's tags and member, the
// compute block's budgets that bind it, and the agent the call names. ErrComputePolicyUnread where the device has
// read no head, so no call passes a budget it has not read.
func (self *Sidecar) computeBudgetCall(agentId *Id, now time.Time) (*ComputeBudgetCall, error) {
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	follower := self.ConfigFollower()
	if follower == nil {
		return nil, ErrComputePolicyUnread
	}
	configState := follower.VerifiedState()
	engine := follower.AclEngine()
	if configState == nil || engine == nil {
		return nil, ErrComputePolicyUnread
	}
	aclState := engine.State()
	if aclState == nil {
		return nil, ErrComputePolicyUnread
	}
	call := &ComputeBudgetCall{SidecarId: identity.SidecarId, AgentId: agentId}
	if row := configState.SidecarRow(identity.SidecarId); row != nil {
		call.Tagged = 0 < len(row.GetTagIds())
		if memberId, err := IdFromBytes(row.GetMemberId()); err == nil && !call.Tagged {
			call.MemberId = memberId
		}
	}
	call.Policy = ComputePolicyBudgetsBinding(aclState, AclSidecarSubject(identity.SidecarId), now)
	return call, nil
}

// What a remote call holds at its worst (§9.7): its model's context window at the input price and its most output at
// the output price, each per million tokens, rounded up to the nano-USD; false where the catalog gives no price or the
// product passes 64 bits, which no budget then admits.
func computeBudgetWorstCase(entry *InferCatalogEntry) (uint64, bool) {
	if entry == nil || entry.Remote == nil || entry.ContextWindow < 0 || entry.MaxOutput < 0 ||
		entry.Remote.InputNanoUsdPerMillion < 0 || entry.Remote.OutputNanoUsdPerMillion < 0 {
		return 0, false
	}
	const tokensPerPriceUnit = 1_000_000
	input, inputOk := computeBudgetProduct(uint64(entry.ContextWindow), uint64(entry.Remote.InputNanoUsdPerMillion))
	output, outputOk := computeBudgetProduct(uint64(entry.MaxOutput), uint64(entry.Remote.OutputNanoUsdPerMillion))
	if !inputOk || !outputOk || input+output < input {
		return 0, false
	}
	sum := input + output
	return sum/tokensPerPriceUnit + min(sum%tokensPerPriceUnit, 1), true
}

// a times b, and false where it passes 64 bits.
func computeBudgetProduct(a uint64, b uint64) (uint64, bool) {
	if a != 0 && b > ^uint64(0)/a {
		return 0, false
	}
	return a * b, true
}

// The device's budget check for INFER's router (InferBudgetGate): the budgets a call from this sidecar spends, defaults
// and the policy's, checked against the ledger at the call's worst case. A call's run budget is its Harness's or
// grant's, which their holders check against their own budget. Every refusal is insufficient_quota, reason budget.
type sidecarBudgetGate struct {
	sidecar *Sidecar
}

// See InferBudgetGate.
func (self *sidecarBudgetGate) Admit(ctx context.Context, call *InferCall) error {
	refuse := func(message string) error {
		return &InferError{Code: InferErrorInsufficientQuota, Model: call.Name, Reason: InferQuotaReasonBudget, Message: message}
	}
	if call.Entry != nil && call.Entry.Kind == InferCatalogKindLocal {
		// a local model's call touches no budget (CO-9)
		return nil
	}
	worstCase, priced := computeBudgetWorstCase(call.Entry)
	if !priced {
		return refuse("the model's worst case does not read, so no budget admits it")
	}
	now := self.sidecar.clock.Now()
	budgetCall, err := self.sidecar.computeBudgetCall(call.Request.AgentId, now)
	if err != nil {
		return refuse(fmt.Sprintf("the device's budgets do not read: %s", err))
	}
	ledger, err := self.sidecar.BudgetLedger()
	if err != nil {
		return refuse(fmt.Sprintf("the device's budget ledger does not read: %s", err))
	}
	if err := ledger.Check(ComputeBudgetsFor(budgetCall, self.sidecar.settings.Budget, now), worstCase); err != nil {
		return refuse(err.Error())
	}
	return nil
}

// What is left of an agent's day and month budgets on this device, for compute_balance (BAL's ComputeBudgetLeftSource):
// the budgets a call naming the agent spends, the tightest in each period; the run's is its Harness's, unknown here.
func sidecarComputeBudgetLeft(ctx context.Context, sidecar *Sidecar, agentId Id) (*ComputeBudgetLeft, error) {
	now := sidecar.clock.Now()
	call, err := sidecar.computeBudgetCall(&agentId, now)
	if err != nil {
		return nil, err
	}
	ledger, err := sidecar.BudgetLedger()
	if err != nil {
		return nil, err
	}
	left := &ComputeBudgetLeft{}
	for _, budget := range ComputeBudgetsFor(call, sidecar.settings.Budget, now) {
		if !budget.DeviceCounts {
			continue
		}
		capNanoUsd, room := int64(budget.CapNanoUsd), int64(ledger.Room(budget))
		period := &left.Day
		if budget.Period == ComputeBudgetPeriodMonth {
			period = &left.Month
		} else if budget.Period != ComputeBudgetPeriodDay {
			continue
		}
		if *period == nil || room < *(*period).LeftNanoUsd {
			*period = &ComputeBudgetPeriodLeft{CapNanoUsd: &capNanoUsd, LeftNanoUsd: &room}
		}
	}
	return left, nil
}

// Wires the budgets: the component, the router's device-side check (§6.4's step 3) and compute_balance's view.
func init() {
	registerComputeComponent(budgetComponentName, func(sidecar *Sidecar) (*sidecarBudgets, error) {
		return &sidecarBudgets{sidecar: sidecar, ledgers: map[Id]*BudgetLedger{}}, nil
	}, nil)
	registerInferCheckSources("cacl-budgets", func(sidecar *Sidecar, sources *InferCheckSources) error {
		sources.Budgets = &sidecarBudgetGate{sidecar: sidecar}
		return nil
	})
	RegisterComputeBudgetLeftSource(sidecarComputeBudgetLeft)
}
