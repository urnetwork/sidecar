// §7.9's state by pin. A reader judges a push, a delivery, a commit or a decision at the pin it carries, never at the
// tip (§10.9's judged row, FS-104), so ConfigLog.StateAt serves S(k) for any k from the previous base to the tip:
// gkm's client through GkmAuthView.At, ACL's VerifyHeadSigner and VerifyRepoMember (ACL-M2-09) and MCP's spendable at
// gates, on devices and gates alike.
//
//	above       a pin above the state waits (ErrConfigPinAhead): nothing about it is known yet
//	held        S(k) when the pin's chain value is the A_k this log holds; another is a pin off this chain, a fork
//	            alarm (ErrConfigPinOffChain), and the log itself goes on, since the pin is evidence about whoever
//	            presented it
//	before      a pin before the previous base is unjudged and never allowed (ErrConfigPinNotRetained), unless this
//	            reader still holds an A_k there or a base's (n, A_n) that the pin contradicts, which is the fork alarm
//
// The log keeps S(k) at each base and every ConfigLogSettings.StateAtCheckpointInterval positions between, beside the
// tip, and rebuilds the rest on demand: from the nearest kept state below, each kept entry's effect applies again as
// it first applied, its verdict kept, so a rebuilt S(k) is the state the log published at k. A window kept whole would
// hold a copy of each map an entry wrote, about two fold spans of them (§7.9's fold), which a gate holding many
// networks cannot afford.
//
// A log restored at a base (RestoreConfigLog, a new device or a gate's cold start) never built the states before it,
// so its window starts at that base until the next base moves the window past it.
//
// Safe for concurrent use: the window is an immutable view swapped atomically by the log's one applying goroutine,
// and a rebuild reads only immutable states and kept entries. Nothing here creates, derives or unwraps a key, so
// nothing calls testHookSecret.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The pin is above the state's position: wait until the log reaches it.
	ErrConfigPinAhead = fmt.Errorf("config pin ahead of the state: %w", ErrGkmAuthAhead)
	// The pin is before the previous base, or before what this reader built: unjudged, and never allowed.
	ErrConfigPinNotRetained = fmt.Errorf("config pin before what the reader retains: %w", ErrGkmAuthNotRetained)
	// The pin's chain value is not this log's at its position: a fork alarm. ConfigForkError beside it carries the
	// evidence.
	ErrConfigPinOffChain = fmt.Errorf("config pin off the chain: %w", ErrGkmAuthOffChain)
)

// The states a log keeps for StateAt, shared by every state of that log, so ConfigState.At reaches back along the
// log as it is now.
type configStateHistory struct {
	settings  *ConfigLogSettings
	networkId Id
	log       Logger

	view atomic.Pointer[configHistoryView]

	// rebuilt states, most recent last, at most settings.StateAtCacheCount
	stateLock     sync.Mutex
	rebuiltStates []*ConfigState
}

// One window of the log, immutable once published: positions from to tip. A later view may share its slices and
// append past their ends, which this view never reads.
type configHistoryView struct {
	from uint64
	// states[i] is S(from+i) where kept, nil where it is rebuilt
	states []*ConfigState
	// entries[i] is the entry kept at from+i, nil for S(0), which no entry made
	entries []*configKeptEntry
	// the newest state, kept whatever the interval says
	tip *ConfigState
}

// A history whose window is S(0) alone, or start alone for a log restored at a base.
func newConfigStateHistory(settings *ConfigLogSettings, networkId Id, log Logger) *configStateHistory {
	return &configStateHistory{
		settings:  settings,
		networkId: networkId,
		log:       log,
	}
}

// Starts the window at state, the entry that made it beside it (nil for S(0)).
func (self *configStateHistory) reset(state *ConfigState, kept *configKeptEntry) {
	self.view.Store(&configHistoryView{
		from:    state.n,
		states:  []*ConfigState{state},
		entries: []*configKeptEntry{kept},
		tip:     state,
	})
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.rebuiltStates = nil
	}()
}

// Whether the state at position n is one the window keeps rather than rebuilds: each base's, and every interval
// positions.
func (self *configStateHistory) checkpoint(state *ConfigState, kept *configKeptEntry) bool {
	if kept == nil || kept.entry.GetKind() == bridge.AuthEntryKindBase {
		return true
	}
	interval := uint64(max(self.settings.StateAtCheckpointInterval, 1))
	return state.n%interval == 0
}

// Adds the state the entry kept made, the new tip, and moves the window's start to the previous base when the entry
// is a base. For the log's one applying goroutine, before it publishes state.
func (self *configStateHistory) push(state *ConfigState, kept *configKeptEntry) {
	view := self.view.Load()
	if view == nil || view.tip.n+1 != state.n {
		// a window that does not end just below this state cannot hold it: start again here
		self.reset(state, kept)
		return
	}
	var checkpointState *ConfigState
	if self.checkpoint(state, kept) {
		checkpointState = state
	}
	next := &configHistoryView{
		from:    view.from,
		states:  append(view.states, checkpointState),
		entries: append(view.entries, kept),
		tip:     state,
	}
	if kept.entry.GetKind() == bridge.AuthEntryKindBase && state.previousBase != nil && next.from < state.previousBase.n {
		dropCount := state.previousBase.n - next.from
		next.from = state.previousBase.n
		next.states = next.states[dropCount:]
		next.entries = next.entries[dropCount:]
	}
	self.view.Store(next)
}

// S(k) from the window, false when k is outside it or a rebuild cannot reach it.
func (self *configStateHistory) stateAt(k uint64) (*ConfigState, bool) {
	view := self.view.Load()
	if view == nil || k < view.from || view.tip.n < k {
		return nil, false
	}
	if k == view.tip.n {
		return view.tip, true
	}
	if state := view.states[k-view.from]; state != nil {
		return state, true
	}
	if state := self.rebuilt(k, view); state != nil {
		return state, true
	}
	state, err := self.rebuild(view, k)
	if err != nil {
		// a kept entry that does not apply again as it first applied is a bug, never a verdict
		self.log.Errorf("[config]%s state %d does not rebuild: %v", self.networkId, k, err)
		return nil, false
	}
	self.keepRebuilt(state)
	return state, true
}

// A rebuilt S(k) kept from an earlier call, when it is the one in view's window.
func (self *configStateHistory) rebuilt(k uint64, view *configHistoryView) *ConfigState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i := len(self.rebuiltStates) - 1; 0 <= i; i -= 1 {
		state := self.rebuiltStates[i]
		if state.n != k {
			continue
		}
		if entry := view.entries[k-view.from]; entry != nil && entry.chain != state.chain {
			return nil
		}
		return state
	}
	return nil
}

// Keeps a rebuilt state for the next call, dropping the oldest past the cache's count.
func (self *configStateHistory) keepRebuilt(state *ConfigState) {
	count := self.settings.StateAtCacheCount
	if count <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rebuiltStates = append(self.rebuiltStates, state)
	if count < len(self.rebuiltStates) {
		self.rebuiltStates = append([]*ConfigState(nil), self.rebuiltStates[len(self.rebuiltStates)-count:]...)
	}
}

// S(k) from the nearest kept state below it: each kept entry from there to k applies its effect again on a builder,
// a statement or tick that took effect as it took effect at its own position, and a refused one as nothing.
func (self *configStateHistory) rebuild(view *configHistoryView, k uint64) (*ConfigState, error) {
	c := k
	for view.states[c-view.from] == nil {
		if c == view.from {
			return nil, fmt.Errorf("no kept state at or below %d", k)
		}
		c -= 1
	}
	// a copy whose chains end where its own do, so the rebuild appends to an array of its own and never writes into
	// the one the log's later states share
	start := configCopyState(view.states[c-view.from])
	start.chains = start.chains[:len(start.chains):len(start.chains)]
	start.ring = start.ring[:len(start.ring):len(start.ring)]
	state := start
	for j := c + 1; j <= k; j += 1 {
		kept := view.entries[j-view.from]
		if kept == nil || kept.n != j {
			return nil, fmt.Errorf("no kept entry at %d", j)
		}
		next := newConfigStateBuilder(state, kept.n, kept.chain, kept.entry.GetTimeMs())
		if kept.verdict.Accepted() {
			switch kept.entry.GetKind() {
			case bridge.AuthEntryKindStatement:
				if kept.statement == nil {
					return nil, fmt.Errorf("the statement at %d took effect and is not kept", j)
				}
				if err := configApplyStatement(next, kept.statement, false); err != nil {
					return nil, fmt.Errorf("the statement at %d: %w", j, err)
				}
				configAdvanceShrinks(state, next, configEntryEffects(kept.statement, nil))
				next.addRing(kept.n, kept.statement.id)
			case bridge.AuthEntryKindTick:
				if kept.tick == nil {
					return nil, fmt.Errorf("the tick at %d took effect and is not kept", j)
				}
				if err := configApplyTick(next, kept.tick, kept.activations); err != nil {
					return nil, fmt.Errorf("the tick at %d: %w", j, err)
				}
				configAdvanceShrinks(state, next, configEntryEffects(nil, kept.activations))
			default:
				return nil, fmt.Errorf("a base at %d, which the window keeps", j)
			}
		}
		state = next.finish()
	}
	return state, nil
}

// The state at pin: S(k) for a pin from the previous base to this state's own position, the one this log published
// at k, when its A_k is the pin's. A pin above this state is ErrConfigPinAhead; one before the window is
// ErrConfigPinNotRetained, unjudged and never allowed; and one whose chain value is not this log's is
// ErrConfigPinOffChain with a ConfigForkError beside it, a fork alarm about whoever presented it. The caller must not
// change the state.
func (self *ConfigState) StateAt(pin *bridge.AuthPin) (*ConfigState, error) {
	if pin == nil || len(pin.GetChain()) != sha256.Size {
		return nil, fmt.Errorf("%w: a pin of %d bytes", ErrConfigPinOffChain, len(pin.GetChain()))
	}
	k := pin.GetVersion()
	offChain := func(local [sha256.Size]byte, hasLocal bool) error {
		fork := &ConfigForkError{N: k, LocalChain: local, HasLocalChain: hasLocal, RemoteChain: [sha256.Size]byte(pin.GetChain()),
			Reason: "a pin off this chain"}
		if self.history != nil {
			self.history.log.Warningf("[config]%s pin %d is off this chain", self.networkId, k)
		}
		return fmt.Errorf("%w: %w", ErrConfigPinOffChain, fork)
	}
	switch {
	case self.n < k:
		return nil, fmt.Errorf("%w: %d above %d", ErrConfigPinAhead, k, self.n)
	case k == self.n:
		if !bytes.Equal(self.chain[:], pin.GetChain()) {
			return nil, offChain(self.chain, true)
		}
		return self, nil
	}
	if self.history != nil {
		if state, ok := self.history.stateAt(k); ok {
			if !bytes.Equal(state.chain[:], pin.GetChain()) {
				return nil, offChain(state.chain, true)
			}
			return state, nil
		}
	}
	// before the window: a chain value this state still holds there can still contradict the pin
	if self.OnChain(pin) {
		return nil, fmt.Errorf("%w: %d", ErrConfigPinNotRetained, k)
	}
	if chain, ok := self.chainAt(k); ok {
		return nil, offChain(chain, true)
	}
	for _, basePin := range self.basePins {
		if basePin.n == k {
			return nil, offChain(basePin.chain, true)
		}
	}
	return nil, fmt.Errorf("%w: %d", ErrConfigPinNotRetained, k)
}

// The state at pin, as ConfigState.StateAt answers it at the tip: any pin from the previous base to the tip. Safe for
// concurrent use, with no lock but a rebuild cache's.
func (self *ConfigLog) StateAt(pin *bridge.AuthPin) (*ConfigState, error) {
	return self.state.Load().StateAt(pin)
}

// Replaces the tip with a state at its own position: the window's last state, kept or not.
func (self *configStateHistory) replaceTip(state *ConfigState) {
	view := self.view.Load()
	if view == nil || view.tip.n != state.n {
		return
	}
	next := &configHistoryView{
		from:    view.from,
		states:  view.states[:len(view.states):len(view.states)],
		entries: view.entries,
		tip:     state,
	}
	if last := len(next.states) - 1; 0 <= last && next.states[last] != nil {
		next.states = append(next.states[:last:last], state)
	}
	self.view.Store(next)
}

// Judges again, with the BridgeBodyJudge's keys as they are now, each unfolded route or map filing whose verdict is
// Unopened at a generation the judge now holds, for a daemon that gained a generation late (DESIGN-DETAILS 12.2.3): an
// entry above the newest base on S(k-1) from StateAt; one in that base's tail on R_b(k-1), which re-applying the tail
// over the base's retained rows rebuilds, as the base itself did. Publishes the tip again at its own pin, its bridge
// part carrying the new verdicts, and answers how many changed. States before the tip keep the verdicts they were built
// with; the entries after the tip build on the new ones, and the next base judges its tail again. For the log's one
// applying goroutine, as Apply.
func (self *ConfigLog) RejudgeBridgeBodies() (int, error) {
	judge := self.settings.BridgeBodyJudge
	tip := self.state.Load()
	if judge == nil || tip.Bridge().Len() == 0 {
		return 0, nil
	}
	held := func(statement *BridgeLogStatement) bool {
		verdict := statement.Approval
		return statement.filesRule() && verdict != nil && verdict.Kind == BridgeBodyUnopened && judge.repoKeyAt()(verdict.Generation) != nil
	}
	if !slices.ContainsFunc(tip.Bridge().Statements(), held) {
		return 0, nil
	}
	base := tip.base
	var tailVerdicts map[[sha256.Size]byte]*BridgeBodyVerdict
	if base != nil && slices.ContainsFunc(tip.Bridge().Statements(), func(statement *BridgeLogStatement) bool {
		return held(statement) && statement.N < base.n
	}) {
		var err error
		if tailVerdicts, err = self.bridgeTailVerdicts(tip); err != nil {
			return 0, err
		}
	}
	changedCount := 0
	statements := slices.Clone(tip.Bridge().Statements())
	for i, statement := range statements {
		if !held(statement) {
			continue
		}
		var verdict *BridgeBodyVerdict
		if base != nil && statement.N < base.n {
			verdict = tailVerdicts[statement.StatementId]
		} else {
			chain, ok := tip.chainAt(statement.N - 1)
			if !ok {
				continue
			}
			before, err := tip.StateAt(&bridge.AuthPin{Version: statement.N - 1, Chain: chain[:]})
			if err != nil {
				return changedCount, err
			}
			verdict = judge.Judge(bridgeStateBefore(before, statement.N, statement.TimeMs), statement)
		}
		if verdict == nil || verdict.Kind == BridgeBodyUnopened {
			continue
		}
		rejudged := *statement
		rejudged.Approval = verdict
		statements[i] = &rejudged
		changedCount += 1
	}
	if changedCount == 0 {
		return 0, nil
	}
	next := configCopyState(tip)
	next.bridge = NewBridgeLog(statements)
	barrierKey := self.networkId.String()
	testHookBarrier("config.bridge_rejudge.before", barrierKey)
	self.history.replaceTip(next)
	self.state.Store(next)
	testHookBarrier("config.bridge_rejudge", barrierKey)
	return changedCount, nil
}

// The verdicts the newest base's tail gets with the judge's keys as they are now, by statement id: the tail re-applied
// over the base's retained rows, as the base itself re-applied it, on a builder of its own.
func (self *ConfigLog) bridgeTailVerdicts(tip *ConfigState) (map[[sha256.Size]byte]*BridgeBodyVerdict, error) {
	base := tip.base
	kept := self.keptEntry(base.n)
	rowsBytes, found := self.baseRows[[sha256.Size]byte(base.header.GetRowsSha256())]
	if kept == nil || !found {
		return nil, fmt.Errorf("base %d's entry or rows are not kept", base.n)
	}
	baseState, ok := self.history.stateAt(base.n)
	if !ok {
		return nil, fmt.Errorf("S(%d) is not kept", base.n)
	}
	// a copy whose arrays end where its own do, so the rebuild appends to arrays of its own and never writes into the
	// ones the log's later states share
	previous := configCopyState(baseState)
	previous.chains = previous.chains[:len(previous.chains):len(previous.chains)]
	previous.ring = previous.ring[:len(previous.ring):len(previous.ring)]
	next, _, err := self.stateFromBase(previous, kept, base.header, rowsBytes)
	if err != nil {
		return nil, err
	}
	foldedThrough := base.header.GetFoldedThrough()
	verdicts, err := configDecodeTailVerdicts(base.header.GetTailVerdicts(), base.n-foldedThrough-1)
	if err != nil {
		return nil, err
	}
	if err := self.reapplyTail(next, foldedThrough, base.n, verdicts, false); err != nil {
		return nil, err
	}
	tailVerdicts := map[[sha256.Size]byte]*BridgeBodyVerdict{}
	for _, statement := range next.state.Bridge().Statements() {
		if statement.Approval != nil {
			tailVerdicts[statement.StatementId] = statement.Approval
		}
	}
	return tailVerdicts, nil
}
