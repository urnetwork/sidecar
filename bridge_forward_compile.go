// The Forwarder's transient compile (BRIDGE-M8-05; DESIGN-DETAILS 4.2.4, 4.2.5's Compile, 12.7): tier 2. It captures
// the newest stored entry, and then
//
//	0 admission  the estimate against the cap and the heap ceiling; refused or deferred raises its alarm and keeps the
//	             state
//	1 judge      a rows-only ConfigLog restored from the store at its newest base, its tail re-applied by the base's
//	             tail_verdicts, then the entries after the base through ApplyRun, CompileApplyRunCount at a time: the
//	             code api and the gates judge by, with a BridgeBodyJudge over the generations the store holds
//	2 keys       the generations a sealed body names and the store lacks, by DelegationWrap (bridge_forward_keys.go)
//	3 head       the head the base names, from the store or its reader, held to the base: the anchored genesis, the
//	             rows' settings equal to its ServiceSettings, and the rows' has_document equal to whether it holds a
//	             policy. The Forwarder does not re-compile rows from it: a full reader's check, the app's sidecar role's
//	4 compile    NewAclState and CompileBridgeState for its sidecar, over the bindings it holds
//	5 hand       the sink's SetState with the log run from the base through the captured pin
//	6 release    the compile's record kept, the store trimmed to the base's retention point, every reference
//	             dropped, and on the mobile classes the memory returned to the OS
//
// An error at any step changes nothing: the sink is called only with a whole state, and a compile refused, deferred or
// failed leaves the state in force and nothing pending (QD-621). A failed or deferred compile is wanted again after
// CompileRetryInterval, doubling to CompileRetryMaxInterval. A generation that arrived in step 2 left its bodies
// unjudged in this compile's judge, and a binding the compile waited for is fetched after it, off its memory: each
// wants one more compile.
//
// The judge holds the rows decoded and the head's files whole for the compile's life, which is what the admission
// estimate counts. Reading both from the sealed store a row at a time is the review phase's storage-backed compile
// (QD-641).

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compiled record's format: a reader refuses a higher one rather than misread it.
const forwarderCompiledFormat = 1

// The newest compile the sink took, as the store keeps it across restarts: what the signer signs by once the sink
// shows its state in force, the next estimate's state term, and D-BRIDGE-16's previous block.
type forwarderCompiled struct {
	Format     int    `json:"format"`
	PinVersion uint64 `json:"pin_version"`
	PinChain   []byte `json:"pin_chain"`
	Digest     []byte `json:"digest"`
	// Every sidecar the state names in a link, ascending.
	LinkTargets    []Id  `json:"link_targets"`
	StateByteCount int64 `json:"state_byte_count"`
	// The block in force, a marshalled BridgeBlock, empty for none.
	Block []byte `json:"block,omitempty"`
	// The sidecar's forwarding Delegation live at the state, empty for none.
	ForwardDelegationId []byte `json:"forward_delegation_id,omitempty"`
}

// The stored compile record, nil for none.
func (self *forwarderRecords) compiled() (*forwarderCompiled, error) {
	data, err := self.read(forwarderCompiledName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	compiled := &forwarderCompiled{}
	if err := json.Unmarshal(data, compiled); err != nil {
		return nil, err
	}
	if compiled.Format != forwarderCompiledFormat {
		return nil, fmt.Errorf("a compile record of format %d", compiled.Format)
	}
	return compiled, nil
}

// How one compile ended.
type forwarderCompileOutcome int

const (
	// The sink took the state, or dropped it for one it already holds at or above.
	forwarderCompileHanded forwarderCompileOutcome = iota + 1
	// Nothing to compile from: no entry stored, or the sink is legacy or forked.
	forwarderCompileIdle
	// The cap refused it: never on this device at this size.
	forwarderCompileRefused
	// The heap ceiling deferred it, or a step failed: wanted again after the retry interval.
	forwarderCompileRetry
)

// Runs one compile and schedules what follows it. On run's goroutine.
func (self *Forwarder) compileNow() {
	self.compileWanted = false
	self.compileLastAt = self.clock.Now()
	outcome, again := self.compile()
	if self.settings.FreeMemoryAfterCompile {
		debug.FreeOSMemory()
	}
	switch outcome {
	case forwarderCompileRetry:
		if self.ctx.Err() != nil {
			return
		}
		if again {
			// what arrived during the compile is compiled at once, and the wait it left is retried from there
			self.wantCompile()
			return
		}
		self.compileWanted = true
		self.compileWantedAt = self.clock.Now()
		self.compileRetryAt = self.compileWantedAt.Add(self.settings.CompileRetryTimeout(self.compileRetryCount))
		self.compileRetryCount += 1
		return
	case forwarderCompileHanded:
		self.compileRetryCount = 0
		self.compileRetryAt = time.Time{}
	}
	if again {
		self.wantCompile()
	}
}

// One compile (the file's comment): its outcome, and whether one more is wanted for what arrived during it.
func (self *Forwarder) compile() (forwarderCompileOutcome, bool) {
	decision := self.readDecision()
	if decision.State == BridgeSinkLegacy || decision.Fork {
		// no anchor to compile for, or a fork the app's sidecar role reported: no compile runs until a witness clears it
		return forwarderCompileIdle, false
	}
	from, through, err := self.records.logRange()
	if err != nil || through == 0 {
		if err != nil {
			self.followWanted = true
		}
		return forwarderCompileIdle, false
	}
	stored, err := self.records.entries(from, through)
	if err != nil {
		return self.compileFailed(through, err), false
	}

	// the newest base among the stored entries, and what the admission rule reads of it
	baseIndex := -1
	var baseHeader *bridge.ProjectionHeader
	size := ForwarderCompileSize{}
	for i, entryBytes := range stored {
		size.TailByteCount += int64(len(entryBytes))
		entry := &bridge.AuthEntry{}
		if proto.Unmarshal(entryBytes, entry) != nil || entry.GetKind() != bridge.AuthEntryKindBase {
			continue
		}
		if _, header, err := configParseBase(entry); err == nil {
			baseIndex, baseHeader = i, header
		}
	}
	if baseHeader != nil {
		size.RowsByteCount = int64(baseHeader.GetRowsByteCount())
		size.HeadByteCount = self.records.headByteCount(baseHeader.GetConfigVersion(), baseHeader.GetConfigHeadSha256())
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.compiled != nil {
			size.StateByteCount = self.compiled.StateByteCount
		}
	}()
	if outcome, admitted := self.admit(through, size); !admitted {
		return outcome, false
	}

	// 1 judge
	signedGenesis, err := self.records.read(forwarderGenesisName)
	if err != nil {
		// a store with entries and no genesis starts again from the anchor
		if resetErr := self.records.resetLog(); resetErr == nil {
			self.followWanted = true
		}
		return self.compileFailed(through, fmt.Errorf("the stored genesis: %w", err)), false
	}
	held, err := self.loadGenerations()
	if err != nil {
		return self.compileFailed(through, err), false
	}
	repoKeyAt := func(generation uint64) *EvsRepoKey {
		if opened := held[generation]; opened != nil {
			return opened.key
		}
		return nil
	}
	logSettings := DefaultConfigLogSettings()
	if self.settings.ConfigLog != nil {
		copied := *self.settings.ConfigLog
		logSettings = &copied
	}
	if logSettings.Log == nil {
		logSettings.Log = self.log
	}
	// the head's rows are taken, never checked against a fold (4.2.1): no ReadHead
	logSettings.BridgeBodyJudge = &BridgeBodyJudge{RepoKeyAt: repoKeyAt, Settings: self.settings.Ledger}
	rowsSource := ConfigRowsOnlySource(func(networkId Id, rowsSha256 []byte) ([]byte, error) {
		reader, err := self.records.openRows(rowsSha256)
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	})
	testHookBarrier("bridge_forward.compile.judge", self.args.NetworkId.String())
	log, err := self.judge(logSettings, signedGenesis, stored, baseIndex, rowsSource, decision.Pin)
	if err != nil {
		var runError *ConfigRunError
		if errors.Is(err, ErrConfigFork) || errors.Is(err, ErrConfigEntryMalformed) || errors.Is(err, ErrConfigRowsUnavailable) || errors.As(err, &runError) {
			// what the store holds is no log this network's rule table accepts: it starts again from api's retention
			// point, and the posture keeps what it has verified
			if resetErr := self.records.resetLog(); resetErr == nil {
				self.followWanted = true
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.tip = nil
				}()
			}
		}
		self.raiseAlarm(BridgeAlarm{Reason: SidecarBridgeAlarmStateUnverified, N: through, Detail: "the stored log did not judge: the state in force stands"})
		return self.compileFailed(through, err), false
	}
	state := log.State()
	pin := state.Pin()
	if self.ctx.Err() != nil {
		return forwarderCompileRetry, false
	}

	// 2 keys
	wanted := slices.Clone(self.wantedGenerations)
	for _, statement := range state.Bridge().Statements() {
		if verdict := statement.Approval; verdict != nil && verdict.Kind == BridgeBodyUnopened && !slices.Contains(wanted, verdict.Generation) {
			wanted = append(wanted, verdict.Generation)
		}
	}
	opened, err := self.openGenerations(self.ctx, state, held, wanted)
	if err != nil {
		// gkm unreachable: the generations held still compile, and the retry asks again
		self.log.Warningf("[forward]%s the config's generations did not read at %d: %v", self.args.NetworkId, pin.GetVersion(), err)
	}
	keysWait := err != nil || 0 < len(self.keyWaits)
	if self.ctx.Err() != nil {
		return forwarderCompileRetry, false
	}

	// 3 head
	var head *ConfigHead
	if base := state.Base(); base != nil {
		if head, err = self.compileHead(state, base); err != nil {
			return self.compileFailed(through, err), 0 < opened
		}
		if size.HeadByteCount == 0 {
			// a head read for the first time is counted now that its size is known
			for _, file := range head.Files() {
				size.HeadByteCount += int64(len(file))
			}
			if outcome, admitted := self.admit(through, size); !admitted {
				return outcome, false
			}
		}
	}
	if self.ctx.Err() != nil {
		return forwarderCompileRetry, false
	}

	// 4 compile
	if !self.bindingsLoaded {
		self.bindingsLoaded = true
		if err := self.bindings.Load(forwarderBindingStore{ForwarderStore: self.args.Store}, self.args.NetworkId, state.IdentityKey); err != nil {
			self.log.Warningf("[forward]%s the binding cache did not load: %v", self.args.NetworkId, err)
		}
	}
	var aclLocal *AclLocalPolicy
	if head != nil && head.File(ConfigHeadPolicyPath) != nil {
		if input, err := NewAclCompileInput(head, ConfigCompileRowsOf(state)); err != nil {
			self.log.Warningf("[forward]%s the head's local policy did not read, ports stay closed for its rules: %v", self.args.NetworkId, err)
		} else if aclLocal, err = CompileAclLocal(input); err != nil {
			self.log.Warningf("[forward]%s the head's local policy did not compile, ports stay closed for its rules: %v", self.args.NetworkId, err)
		}
	}
	view, err := NewBridgeConfigView(state, head, aclLocal, repoKeyAt, self.settings.Ledger)
	if err != nil {
		return self.compileFailed(through, err), 0 < opened
	}
	local := &BridgeCompileLocal{
		SidecarId: self.args.SidecarId,
		Bindings:  self.bindings.Snapshot(),
		NameZones: self.args.NameZones,
		Settings:  self.settings.Compile,
	}
	if self.args.PublishedNames != nil {
		local.PublishedNames = self.args.PublishedNames()
	}
	var previous *forwarderCompiled
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		previous = self.compiled
	}()
	if previous != nil && 0 < len(previous.Block) {
		block := &bridge.BridgeBlock{}
		if proto.Unmarshal(previous.Block, block) == nil {
			local.PreviousBlock = block
		}
	}
	testHookBarrier("bridge_forward.compile.state", self.args.NetworkId.String())
	compiled, err := CompileBridgeState(view, local, self.settings.Ledger)
	if compiled != nil {
		self.raiseCompileAlarms(compiled.Alarms)
	}
	if err != nil {
		return self.compileFailed(through, err), 0 < opened
	}
	stateBytes, err := forwarderMarshal(compiled.State)
	if err != nil {
		return self.compileFailed(through, err), 0 < opened
	}

	// 5 hand: the run from the newest base through the captured pin, or with no base yet from the store's first entry
	run := &BridgeStateLog{Entries: stored[max(baseIndex, 0):], OpenRows: self.records.openRows}
	if self.ctx.Err() != nil {
		return forwarderCompileRetry, false
	}
	testHookBarrier("bridge_forward.compile.hand", self.args.NetworkId.String())
	if err := self.args.Sink.SetState(compiled.State, run); err != nil {
		self.readDecision()
		return self.compileFailed(through, fmt.Errorf("the device role refused the state: %w", err)), 0 < opened
	}
	after := self.readDecision()

	// 6 release: the record, then what the store no longer needs. A kill before the record leaves a state in force the
	// Forwarder signs for only after its next compile.
	record := &forwarderCompiled{
		Format:         forwarderCompiledFormat,
		PinVersion:     pin.GetVersion(),
		PinChain:       bytes.Clone(pin.GetChain()),
		Digest:         compiled.Digest[:],
		LinkTargets:    slices.Clone(compiled.LinkTargets),
		StateByteCount: int64(len(stateBytes)),
	}
	if compiled.Block != nil {
		record.Block, _ = forwarderMarshal(compiled.Block)
	}
	if delegationId, _, ok := state.ForwardingKey(self.args.SidecarId); ok {
		record.ForwardDelegationId = delegationId
	}
	// the sink dropped the state when it holds a newer one: the newer one's compile is the record
	taken := after.StatePin.GetVersion() == pin.GetVersion() && bytes.Equal(after.StatePin.GetChain(), pin.GetChain())
	if taken {
		recordBytes, err := json.Marshal(record)
		if err == nil {
			testHookBarrier("bridge_forward.compile.record", self.args.NetworkId.String())
			err = self.records.write(forwarderCompiledName, recordBytes)
		}
		if err != nil {
			self.log.Warningf("[forward]%s the compile's record was not kept: %v", self.args.NetworkId, err)
		}
	}
	self.wantedGenerations = self.wantedGenerations[:0]
	bindingWants := []forwarderBindingWant{}
	for _, wait := range compiled.Waits {
		switch wait.Kind {
		case BridgeCompileWaitGeneration:
			self.wantedGenerations = append(self.wantedGenerations, wait.Generation)
		case BridgeCompileWaitBinding:
			if identityKey := state.IdentityKey(wait.SidecarId); 0 < len(identityKey) {
				bindingWants = append(bindingWants, forwarderBindingWant{sidecarId: wait.SidecarId, identityKey: identityKey})
			}
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if taken {
			self.compiled = record
		}
		self.waits = slices.Clone(compiled.Waits)
		self.compileCount += 1
	}()
	self.clearAlarm(SidecarBridgeAlarmStateUnverified)
	self.trimStore(state, baseHeader)

	// what arrived during the compile, off its memory
	log, state, view, compiled, stored, held = nil, nil, nil, nil, nil, nil
	if self.settings.FreeMemoryAfterCompile {
		debug.FreeOSMemory()
	}
	again := 0 < opened
	if self.fetchBindings(bindingWants) {
		again = true
	}
	if keysWait {
		// a generation still waits for its wrap: the retry asks late and compiles what it then opens
		return forwarderCompileRetry, again
	}
	return forwarderCompileHanded, again
}

// The admission rule for a compile of size (DESIGN-DETAILS 4.2.4): whether it may run, and the outcome when it may
// not, with its alarm. Either way the state in force stands.
func (self *Forwarder) admit(through uint64, size ForwarderCompileSize) (forwarderCompileOutcome, bool) {
	admission := self.settings.CompileAdmission(size, self.heapInUse())
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.admission = admission
		if admission != ForwarderCompileAdmitted {
			self.compileRefused += 1
		}
	}()
	now := self.clock.Now()
	switch admission {
	case ForwarderCompileAdmitted:
		self.deferredSince = time.Time{}
		self.clearAlarm(SidecarBridgeAlarm(ForwarderAlarmCompileOverBudget))
		self.clearAlarm(SidecarBridgeAlarm(ForwarderAlarmCompileDeferred))
		return 0, true
	case ForwarderCompileOverBudget:
		self.deferredSince = time.Time{}
		self.raiseAlarm(BridgeAlarm{
			Reason: SidecarBridgeAlarm(ForwarderAlarmCompileOverBudget),
			N:      through,
			Detail: fmt.Sprintf("a compile estimated at %d bytes is past this device's %d: the state in force stands", self.settings.CompileEstimate(size), self.settings.CompileMemoryMaxByteCount),
		})
		return forwarderCompileRefused, false
	default:
		if self.deferredSince.IsZero() {
			self.deferredSince = now
		}
		if self.settings.CompileDeferredAlarmTimeout <= now.Sub(self.deferredSince) {
			self.raiseAlarm(BridgeAlarm{
				Reason: SidecarBridgeAlarm(ForwarderAlarmCompileDeferred),
				N:      through,
				Detail: fmt.Sprintf("the heap ceiling has deferred a compile for %s: the state in force stands", now.Sub(self.deferredSince)),
			})
		}
		return forwarderCompileRetry, false
	}
}

// Step 1: the rows-only log at the newest base among the stored entries, baseIndex, with every entry after it applied
// in runs, held to floor, the sink's pin. With no base stored the log starts at the genesis, which the entries must
// reach back to.
func (self *Forwarder) judge(settings *ConfigLogSettings, signedGenesis []byte, stored [][]byte, baseIndex int, rowsSource ConfigRowsSource, floor *bridge.AuthPin) (*ConfigLog, error) {
	var log *ConfigLog
	var err error
	if baseIndex < 0 {
		if log, err = NewConfigLogRowsOnly(settings, signedGenesis); err != nil {
			return nil, err
		}
	} else {
		retained := &ConfigRetained{SignedGenesis: signedGenesis, Entries: stored[:baseIndex+1]}
		if log, err = RestoreConfigLogRowsOnly(settings, retained, rowsSource, nil); err != nil {
			return nil, err
		}
	}
	rest := stored[baseIndex+1:]
	for 0 < len(rest) {
		run := rest[:min(len(rest), self.settings.CompileApplyRunCount)]
		if _, err := log.ApplyRun(run, rowsSource); err != nil {
			return nil, err
		}
		rest = rest[len(run):]
	}
	if fork := log.Fork(); fork != nil {
		return nil, fork
	}
	if uint64(len(stored)) != 0 && log.Pin().GetVersion() == 0 {
		return nil, fmt.Errorf("%w: the stored entries do not reach back to the genesis and hold no base", ErrConfigEntryMalformed)
	}
	if err := log.checkFloor(floor); err != nil {
		return nil, err
	}
	return log, nil
}

// Step 3: the head the base names, from the store or its reader, held to the base (the file's comment), and kept. A
// head that cannot be read now is an error the compile retries; one that is not the base's is head_alarm.
func (self *Forwarder) compileHead(state *ConfigState, base *bridge.ProjectionHeader) (*ConfigHead, error) {
	name := forwarderHeadName(base.GetConfigVersion(), base.GetConfigHeadSha256())
	var head *ConfigHead
	stored := false
	if data, err := self.records.read(name); err == nil {
		if files, err := forwarderDecodeHead(data); err == nil {
			if head, err = NewConfigHead(files); err == nil {
				stored = true
			}
		}
		if !stored {
			// a record that no longer reads is read again from its reader
			head = nil
			if err := self.args.Store.Remove(name); err != nil {
				return nil, err
			}
		}
	} else if !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, err
	}
	if head == nil {
		if self.args.Heads == nil {
			return nil, fmt.Errorf("%w: no head reader", ErrConfigHeadUnavailable)
		}
		ctx, cancel := context.WithTimeout(self.ctx, self.settings.FetchTimeout)
		defer cancel()
		testHookBarrier("bridge_forward.compile.head", self.args.NetworkId.String())
		read, err := self.args.Heads.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
		if err != nil {
			if errors.Is(err, ErrConfigHeadMismatch) {
				// the reader was served a head that is not the one the base names
				self.emitHeadAlarm(SidecarHeadAlarmFork, state.Pin(), state.Pin())
			}
			return nil, err
		}
		if read == nil {
			return nil, fmt.Errorf("%w: the reader answered none", ErrConfigHeadUnavailable)
		}
		head = read
	}
	if err := self.checkHead(state, head); err != nil {
		if stored {
			_ = self.args.Store.Remove(name)
		}
		self.emitHeadAlarm(SidecarHeadAlarmFork, state.Pin(), state.Pin())
		return nil, err
	}
	if !stored {
		if err := self.records.write(name, forwarderEncodeHead(head.Files())); err != nil {
			return nil, err
		}
		if err := self.records.trimHeads(self.settings.HeadCacheCount); err != nil {
			self.log.Warningf("[forward]%s older heads were not dropped: %v", self.args.NetworkId, err)
		}
	}
	return head, nil
}

// Whether head is the one the judged state's base rows came from, as far as a rows-only reader checks (4.2.5's step
// 3): the anchored genesis, the rows' settings equal to its ServiceSettings, and the rows' has_document equal to
// whether it holds a policy.
func (self *Forwarder) checkHead(state *ConfigState, head *ConfigHead) error {
	_, signedGenesis := head.Genesis()
	if chain := bridge.GenesisChain(signedGenesis); !bytes.Equal(chain[:], self.args.Pending.GetGenesisSha256()) {
		return fmt.Errorf("%w: the head holds another genesis than the anchor's", ErrConfigHeadMismatch)
	}
	settings, _, err := head.ServiceSettings()
	if err != nil {
		return fmt.Errorf("%w: the head's ServiceSettings: %w", ErrConfigHeadMismatch, err)
	}
	if !proto.Equal(state.Settings(), ConfigProjectionSettings(settings)) {
		return fmt.Errorf("%w: the rows' settings are not the head's", ErrConfigHeadMismatch)
	}
	acl, err := state.Acl()
	if err != nil {
		return err
	}
	if acl.HasDocument() != (head.File(ConfigHeadPolicyPath) != nil) {
		return fmt.Errorf("%w: the rows' has_document is not the head's", ErrConfigHeadMismatch)
	}
	return nil
}

// Counts a compile that did not finish, and says to try it again.
func (self *Forwarder) compileFailed(through uint64, err error) forwarderCompileOutcome {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.compileErrors += 1
	}()
	if self.ctx.Err() == nil {
		self.log.Warningf("[forward]%s the compile at %d did not run: %v", self.args.NetworkId, through, err)
	}
	return forwarderCompileRetry
}

// Raises each alarm a compile's state found that the last one did not.
func (self *Forwarder) raiseCompileAlarms(alarms []BridgeAlarm) {
	for _, alarm := range alarms {
		if !slices.Contains(self.raisedCompileAlarms, alarm) {
			self.emitAlarm(alarm)
		}
	}
	for _, raised := range self.raisedCompileAlarms {
		if !slices.ContainsFunc(alarms, func(alarm BridgeAlarm) bool { return alarm.Reason == raised.Reason }) {
			self.clearAlarm(raised.Reason)
		}
	}
	self.raisedCompileAlarms = slices.Clone(alarms)
}

// After a compile the sink took: drops the entries before the judged state's retention point, the rows of every base
// before its newest, which later stored bases still name theirs, and nothing a later compile restores from.
func (self *Forwarder) trimStore(state *ConfigState, baseHeader *bridge.ProjectionHeader) {
	if baseHeader == nil || state.Base() == nil {
		return
	}
	if point := state.RetentionPoint(); 0 < point {
		if err := self.records.dropEntriesBefore(point); err != nil {
			self.log.Warningf("[forward]%s entries before %d were not dropped: %v", self.args.NetworkId, point, err)
		}
	}
	if err := self.records.keepRows([][]byte{state.Base().GetRowsSha256()}); err != nil {
		self.log.Warningf("[forward]%s older rows were not dropped: %v", self.args.NetworkId, err)
	}
}

// A binding a compile waited for, with the identity key its judged state admits for the sidecar.
type forwarderBindingWant struct {
	sidecarId   Id
	identityKey []byte
}

// The Forwarder's store as the binding cache writes to it: a SidecarStore with no directories.
type forwarderBindingStore struct {
	ForwarderStore
}

// None: the binding cache keeps one file.
func (self forwarderBindingStore) Directory(name string, class string) (SidecarStore, error) {
	return nil, fmt.Errorf("%w: a forwarding store has no directories", ErrSidecarStoreName)
}

// Fetches the bindings a compile waited for, each verified under the identity key its judged state admitted, keeps
// them, and says whether anything changed, which wants one more compile. Off the compile's memory.
func (self *Forwarder) fetchBindings(wants []forwarderBindingWant) bool {
	now := self.clock.Now()
	changed := self.bindings.Expire(now)
	if self.args.Binding != nil {
		for _, want := range wants[:min(len(wants), self.settings.BindingFetchMaxCount)] {
			if self.ctx.Err() != nil {
				break
			}
			binding, err := func() (*BridgeBinding, error) {
				ctx, cancel := context.WithTimeout(self.ctx, self.settings.FetchTimeout)
				defer cancel()
				signedBinding, err := self.args.Binding(ctx, want.sidecarId)
				if err != nil {
					return nil, err
				}
				return VerifyBridgeBinding(signedBinding, self.args.NetworkId, want.sidecarId, want.identityKey)
			}()
			if err != nil {
				if self.log.V(1).Enabled() {
					self.log.Infof("[forward]%s no binding for %s: %v", self.args.NetworkId, want.sidecarId, err)
				}
				continue
			}
			changed = self.bindings.Record(binding, now) || changed
		}
	}
	if changed {
		if err := self.bindings.Save(forwarderBindingStore{ForwarderStore: self.args.Store}); err != nil {
			self.log.Warningf("[forward]%s the binding cache was not kept: %v", self.args.NetworkId, err)
		}
	}
	return changed
}
