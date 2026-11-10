// ConfigClient (TEAM-M2-10): one network's follower of the authorization log on a device, the one place a device reads,
// verifies and keeps §7.9's log. It reads GET /network/config/projection?after=<its pin> at each start, on each team
// hint (MembershipChanged, ApprovalRequested, AuthorityHeadChanged, whose version is a log position) and hourly, the
// pass that recovers a lost hint, and applies what it reads to its ConfigLog as a full reader: every base's config head
// checked through ConfigHeadReader, and a reader that starts at a base, first or after it fell behind api's retention
// point, starts there by the base's verdicts and anchor (DESIGN-DETAILS 5.2.4's StartAtBase), never below a pin it held.
//
// It neither signs nor posts (C-01): CORE-M2-02's acts do, and read back what landed through State and WaitFor. After
// each applied entry it calls GkmClient.AuthAdvanced and every AddEntryCallback once, in log order, with the entry's
// verdict, so CORE-M2-03's alarms and ACL's AclFollower need no second follower. A fork stops the log: the client
// raises head_alarm with both pins and reports it to HeadStopState, which stops sealing in shared groups while
// rotations, Removes and revocations go on (§6.4). A base whose rows do not compile from its head is such a fork, so a
// rows mismatch installs nothing. A reader that cannot fetch an entry it has proof of, a hint naming a position api does
// not serve, treats itself as withheld.
//
// What it keeps across restarts is config_client_store.go's, in §5.9's authlog/.
//
// Every leg, the sidecar_http page Worker's included: no connect type. Safe for concurrent use; one goroutine follows.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The client follows no log: closed, or never started at a genesis this device trusts.
	ErrConfigClientClosed = errors.New("config client closed")
	// The genesis api serves is not the one this device trusts (an invite's or a bundle's hash, CORE-M2-06's anchor).
	ErrConfigClientGenesis = errors.New("config client: another genesis")
	// api serves less than this device holds proof of: a hint's position, or a pin it held, is past what api serves.
	ErrConfigClientWithheld = errors.New("config client: withheld")
)

// What GET /network/config/projection?after= answers (§7.9's read row; plan-TEAM-genesis-custody #3).
type ConfigProjection struct {
	// The Signed Genesis, verbatim, when the read starts at 0.
	SignedGenesis []byte
	// The entries after the position asked, verbatim and in position order, from api's retention point when that
	// position is before it; at most a page.
	Entries [][]byte
	// The rows of each base among Entries, verbatim.
	Rows [][]byte
	// The store's newest entry, nil before base 1.
	Tip *bridge.AuthPin
	// More entries follow the last one.
	More bool
}

// Where a ConfigClient reads the log: SidecarApi.GetConfigProjection, or a test's fake.
type ConfigProjectionReader interface {
	ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error)
}

// Reads the config head a base names (§7.9's BASE row): the config repo's file-mode main ref at configVersion, whose
// chain value C_v is configHeadSha256, verified on that ref's chain from C_0 through config writers' pushes (§11.8).
// ErrConfigHeadUnavailable when it cannot be read now, which withholds the base; any other error is a head that is not
// the one named, which forks the base.
type ConfigHeadReader interface {
	ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error)
}

// Tunables of a ConfigClient.
type ConfigClientSettings struct {
	// How often the client follows with no hint: hourly (§7.9's follow row), the pass that recovers a lost team hint.
	FollowInterval time.Duration
	// How long one follow may run before it gives up until the next hint or interval: 60 s, past a page of 1,024
	// entries and a base's 4 MiB of rows on a slow link.
	FollowTimeout time.Duration
	// The wait after a failed follow, doubling on each failure up to FollowInterval: 10 s.
	RetryInterval time.Duration
	// The most pages one follow reads before the next pass takes over: 64, some 65,000 entries, past the 4,096 a base
	// may leave unfolded.
	MaxPagesPerFollow int
	// §7.9's retain row: the newest entries' verbatim bytes every sidecar keeps for HeadCheckProof, a base as its
	// header, which HeadCheckMaxProofByteCount bounds: 64 KiB.
	RetainedEntryByteCount int
	// Whether this device keeps every entry's verbatim bytes from the retention point, about two fold spans, and the
	// rows of its current and previous bases: member devices on §18.4's desktop and CLI hosts. False keeps the 64 KiB
	// and its pin, and a restart reads the rest from api, held to that pin.
	RetainFullTail bool
	// The log's own tunables; nil for DefaultConfigLogSettings.
	LogSettings *ConfigLogSettings
	// Where refusals, forks and failed reads are logged, ids only (I-13). Nil is the leg's default.
	Log Logger
}

// §7.9's values: hourly, a 60 s follow, 10 s retries, 64 pages, 64 KiB kept, and the phone's retention.
func DefaultConfigClientSettings() *ConfigClientSettings {
	return &ConfigClientSettings{
		FollowInterval:         time.Hour,
		FollowTimeout:          60 * time.Second,
		RetryInterval:          10 * time.Second,
		MaxPagesPerFollow:      64,
		RetainedEntryByteCount: 64 * 1024,
	}
}

// What a ConfigClient runs on.
type ConfigClientArgs struct {
	NetworkId Id
	// A_0 = SHA-256(Signed Genesis) this device trusts, from an invite's or a bundle's hash (plan-TEAM-genesis-custody
	// #4); the genesis api serves must hash to it.
	GenesisChain [sha256.Size]byte
	// GET /network/config/projection.
	Projection ConfigProjectionReader
	// Reads each base's config head. Nil holds every base withheld, so no state past base 0 installs without one.
	Heads ConfigHeadReader
	// §5.9's authlog/, where the log persists. Nil keeps nothing across restarts.
	Store SidecarStore
	// Its AuthAdvanced runs after each applied entry (KEYS). Nil for none.
	Gkm GkmClient
	// Raises head_alarm. Nil drops it.
	Emit SidecarEventFunction
	// HeadStopState.ReportFork, which stops sealing in shared groups (§6.4). Nil for none.
	ReportFork func(fork HeadFork)
	Clock      Clock
	Settings   *ConfigClientSettings
}

// One network's follower of the log.
type ConfigClient struct {
	args        *ConfigClientArgs
	settings    *ConfigClientSettings
	logSettings *ConfigLogSettings
	clock       Clock
	log         Logger

	ctx    context.Context
	cancel context.CancelFunc

	callbacks *CallbackList[SidecarAuthorityEntryFunction]
	// a hint or a CatchUp asks for a follow now
	wake chan struct{}
	// serializes follows: the log has one applying goroutine at a time
	followLock sync.Mutex

	configLog atomic.Pointer[ConfigLog]
	// the newest applied position, which WaitFor watches
	position *MonitorValue[uint64]

	stateLock sync.Mutex
	// the newest pin this device held, persisted: no restart lands below it
	floor *bridge.AuthPin
	// the newest position a team hint named
	hinted uint64
	// set once api serves less than this device holds proof of
	withheldSince time.Time
	// the heads this device verified, by config_head_sha256, with the settings each held: a restart from authlog/
	// trusts what it verified before rather than reading the head again
	verifiedHeads map[[sha256.Size]byte]*configVerifiedHead
	// Signed RecoveryVetoes this device holds off the log (HoldVeto), newest last
	heldVetoes [][]byte
	// where a reader that started at a base began, which entry callbacks fire after
	startBase uint64
	// this device's config writer for the network, nil for none
	writer atomic.Pointer[ConfigWriter]
}

// This device's config writer for the network, nil while none runs: what an act saving a config head goes through.
func (self *ConfigClient) Writer() *ConfigWriter {
	return self.writer.Load()
}

// A config head this device verified at a base.
type configVerifiedHead struct {
	configVersion uint64
	settings      *protocol.ServiceSettings
}

// A client following args.NetworkId's log, started: it restores what authlog/ kept and follows at once, then on each
// hint and every FollowInterval, until ctx ends or Close.
func NewConfigClient(ctx context.Context, args *ConfigClientArgs) (*ConfigClient, error) {
	if args == nil || args.Projection == nil {
		return nil, errors.New("config client: no projection reader")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultConfigClientSettings()
	}
	logSettings := settings.LogSettings
	if logSettings == nil {
		logSettings = DefaultConfigLogSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &ConfigClient{
		args:          args,
		settings:      settings,
		logSettings:   logSettings,
		clock:         clock,
		log:           loggerOrDefault(settings.Log),
		ctx:           cancelCtx,
		cancel:        cancel,
		callbacks:     NewCallbackList[SidecarAuthorityEntryFunction](),
		wake:          make(chan struct{}, 1),
		position:      NewMonitorValue[uint64](0),
		verifiedHeads: map[[sha256.Size]byte]*configVerifiedHead{},
	}
	if err := self.restoreFromStore(); err != nil {
		// what authlog/ held does not restore: the first follow reads from api, held to the pin it kept
		self.log.Warningf("[config]%s the kept log does not restore: %v", args.NetworkId, err)
	}
	go self.run()
	return self, nil
}

// Stops following. Safe to call again.
func (self *ConfigClient) Close() {
	self.cancel()
}

// The network.
func (self *ConfigClient) NetworkId() Id {
	return self.args.NetworkId
}

// The log as this device verified it, nil before it trusts a genesis api served.
func (self *ConfigClient) Log() *ConfigLog {
	return self.configLog.Load()
}

// The newest verified S(n), nil before the first read. Safe for concurrent use, with no lock.
func (self *ConfigClient) State() *ConfigState {
	log := self.configLog.Load()
	if log == nil {
		return nil
	}
	return log.State()
}

// The newest verified (n, A_n), nil before the first read.
func (self *ConfigClient) Pin() *bridge.AuthPin {
	state := self.State()
	if state == nil {
		return nil
	}
	return state.Pin()
}

// The fork that stopped the log, nil while it follows.
func (self *ConfigClient) Fork() *ConfigForkError {
	log := self.configLog.Load()
	if log == nil {
		return nil
	}
	return log.Fork()
}

// When api began serving less than this device holds proof of, zero while it serves all of it.
func (self *ConfigClient) WithheldSince() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.withheldSince
}

// Waits until the log has applied position n, or ctx ends, or the client closes. A follow runs at once if n is past
// the newest hint, since whoever waits knows of an entry api holds (CORE-M2-02's act after its post).
func (self *ConfigClient) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	self.noteHint(n)
	for {
		position, changed := self.position.Get()
		if n <= position {
			return self.State(), nil
		}
		if fork := self.Fork(); fork != nil {
			return nil, fork
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-self.ctx.Done():
			return nil, ErrConfigClientClosed
		}
	}
}

// SidecarAuthorityCatchUp: one follow now, answering once it ran.
func (self *ConfigClient) CatchUp(ctx context.Context) error {
	followCtx, cancel := context.WithTimeout(ctx, self.settings.FollowTimeout)
	defer cancel()
	return self.follow(followCtx)
}

// A team hint (§6.8's push, topic team): its version is a log position, which a follow fetches through. A resync
// follows too. Never blocks.
func (self *ConfigClient) ReceiveNotice(notice PushNotice) {
	if notice.Topic != PushTopicTeam {
		return
	}
	if notice.Resync {
		self.requestFollow()
		return
	}
	self.noteHint(notice.Version)
}

// Records a position this device knows api holds and asks for a follow when it is past the pin.
func (self *ConfigClient) noteHint(n uint64) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.hinted = max(self.hinted, n)
	}()
	if self.position.Value() < n {
		self.requestFollow()
	}
}

// Asks the follower for a follow now, without blocking.
func (self *ConfigClient) requestFollow() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Calls callback with each entry applied from now on, in log order, on the follower's goroutine; the answer removes it.
func (self *ConfigClient) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	callbackId := self.callbacks.Add(callback)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.callbacks.Remove(callbackId)
		})
	}
}

// The follower: a follow at start, then on each wake and every FollowInterval, backing off after a failure.
func (self *ConfigClient) run() {
	retry := time.Duration(0)
	for {
		followCtx, cancel := context.WithTimeout(self.ctx, self.settings.FollowTimeout)
		err := self.follow(followCtx)
		cancel()
		if self.ctx.Err() != nil {
			return
		}
		wait := self.settings.FollowInterval
		if err != nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[config]%s follow: %v", self.args.NetworkId, err)
			}
			retry = min(max(2*retry, self.settings.RetryInterval), self.settings.FollowInterval)
			wait = retry
		} else {
			retry = 0
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-self.clock.After(wait):
		}
	}
}

// One follow: pages of entries after this device's pin until api has no more, each applied as §7.9's apply row says.
func (self *ConfigClient) follow(ctx context.Context) error {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	if fork := self.Fork(); fork != nil {
		return fork
	}
	for range max(self.settings.MaxPagesPerFollow, 1) {
		log := self.configLog.Load()
		after := uint64(0)
		if log != nil {
			after = log.Pin().GetVersion()
		}
		projection, err := self.args.Projection.ReadConfigProjection(ctx, after)
		if err != nil {
			return err
		}
		more, err := self.applyProjection(ctx, log, projection)
		if err != nil {
			return err
		}
		if !more {
			self.checkWithheld(projection)
			return nil
		}
	}
	return nil
}

// Whether api served all this device knows of: a hint or a held pin past api's tip is withheld (§7.9's retain row),
// which alarms once until api serves it.
func (self *ConfigClient) checkWithheld(projection *ConfigProjection) {
	position := self.position.Value()
	alarm := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		known := max(self.hinted, self.floor.GetVersion())
		if position < known {
			if self.withheldSince.IsZero() {
				self.withheldSince = self.clock.Now()
				alarm = true
			}
			return
		}
		self.withheldSince = time.Time{}
	}()
	if alarm {
		self.log.Warningf("[config]%s api serves through %d of what this device holds proof of", self.args.NetworkId, projection.Tip.GetVersion())
		local := self.Pin()
		self.emit(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmWithheld,
			Evidence: [2][]byte{configPinBytes(local), configPinBytes(projection.Tip)}})
	}
}

// Applies one page: the first one starts the log at genesis or at the newest base it holds; a page that starts past
// this log's next position, as one does once api's retention point passed this device's pin, starts the log again at
// that page's newest base, held to the pin; any other applies on. Answers whether api has more.
func (self *ConfigClient) applyProjection(ctx context.Context, log *ConfigLog, projection *ConfigProjection) (bool, error) {
	source := &configClientRowsSource{client: self, ctx: ctx, rows: map[[sha256.Size]byte][]byte{}}
	for _, rows := range projection.Rows {
		source.rows[sha256.Sum256(rows)] = rows
	}
	first := uint64(0)
	if 0 < len(projection.Entries) {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(projection.Entries[0], entry); err != nil {
			return false, fmt.Errorf("%w: %w", ErrConfigEntryMalformed, err)
		}
		first = entry.GetN()
	}

	if log == nil || (0 < first && log.Pin().GetVersion()+1 < first) {
		started, err := self.start(log, projection, source)
		if err != nil {
			return false, err
		}
		if started == nil {
			return false, nil
		}
		self.publish(started, nil, nil)
		err = self.save()
		self.position.Set(started.Pin().GetVersion())
		return projection.More, err
	}

	if len(projection.Entries) == 0 {
		return false, nil
	}
	before := log.State()
	verdicts, err := log.ApplyRun(projection.Entries, source)
	self.publish(log, before, verdicts)
	// kept before WaitFor hears of it, so whoever waited on a position finds it kept across a restart
	if saveErr := self.save(); saveErr != nil && err == nil {
		err = saveErr
	}
	self.position.Set(log.Pin().GetVersion())
	if err != nil {
		self.onApplyError(log, err)
		return false, err
	}
	return projection.More, nil
}

// A log built from a page: at S(0) of the genesis this device trusts and every entry from 1 on, or at the newest base
// the page holds, held to the pin this device held (restoreConfigLogAbove). Nil with no error when the page holds no
// entry and no log stands yet but S(0).
func (self *ConfigClient) start(log *ConfigLog, projection *ConfigProjection, source ConfigRowsSource) (*ConfigLog, error) {
	signedGenesis := projection.SignedGenesis
	if log != nil {
		signedGenesis = log.signedGenesis
	}
	if len(signedGenesis) == 0 {
		return nil, fmt.Errorf("%w: api served no genesis", ErrConfigClientGenesis)
	}
	if bridge.GenesisChain(signedGenesis) != self.args.GenesisChain {
		return nil, ErrConfigClientGenesis
	}
	floor := self.floorPin()
	if len(projection.Entries) == 0 {
		if log != nil {
			return nil, nil
		}
		started, err := NewConfigLog(self.logSettings, signedGenesis)
		if err != nil {
			return nil, err
		}
		if err := started.checkFloor(floor); err != nil {
			return nil, err
		}
		return started, nil
	}
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(projection.Entries[0], entry); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigEntryMalformed, err)
	}
	if entry.GetN() == 1 {
		started, err := NewConfigLog(self.logSettings, signedGenesis)
		if err != nil {
			return nil, err
		}
		if _, err := started.ApplyRun(projection.Entries, source); err != nil {
			self.onApplyError(started, err)
			return nil, err
		}
		if err := started.checkFloor(floor); err != nil {
			return nil, err
		}
		return started, nil
	}
	if log != nil {
		// fell behind api's retention point: the old pin is the floor, and the restart's anchor links it
		floor = log.Pin()
	}
	retained := &ConfigRetained{SignedGenesis: signedGenesis, Entries: projection.Entries, Rows: map[[sha256.Size]byte][]byte{}}
	started, err := restoreConfigLogAbove(self.logSettings, retained, source, floor)
	if err != nil {
		if errors.Is(err, ErrConfigFork) || errors.Is(err, ErrConfigRunRefused) || errors.Is(err, ErrConfigBelowPin) {
			self.log.Errorf("[config]%s a start at api's newest base refused: %v", self.args.NetworkId, err)
			local := configPinBytes(floor)
			self.emit(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork, Evidence: [2][]byte{local, nil}})
		}
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if base := started.State().Base(); base != nil {
			self.startBase = base.GetVersion()
		}
	}()
	return started, nil
}

// Installs log as the one this client follows, after it applied verdicts on before: each verdict's entry callbacks and
// KEYS's AuthAdvanced, in order. Its caller then keeps it and moves the position WaitFor watches.
func (self *ConfigClient) publish(log *ConfigLog, before *ConfigState, verdicts []ConfigVerdict) {
	self.configLog.Store(log)
	state := log.State()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.floor = state.Pin()
	}()
	previous := before
	for _, verdict := range verdicts {
		after, err := state.StateAt(verdict.Pin)
		if err != nil {
			after = state
		}
		if previous != nil {
			entry := self.authorityEntry(log, previous, after, verdict)
			for _, callback := range self.callbacks.Get() {
				callback(entry)
			}
		}
		if self.args.Gkm != nil {
			self.args.Gkm.AuthAdvanced(after)
		}
		previous = after
	}
	if len(verdicts) == 0 && self.args.Gkm != nil {
		self.args.Gkm.AuthAdvanced(state)
	}
}

// A fork or a refused run stops here: head_alarm with both pins, and the fork reported to HeadStopState.
func (self *ConfigClient) onApplyError(log *ConfigLog, err error) {
	fork := &ConfigForkError{}
	if !errors.As(err, &fork) {
		runError := &ConfigRunError{}
		if errors.As(err, &runError) && runError.HasLocalChain {
			self.emit(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork,
				Evidence: [2][]byte{configPinBytes(&bridge.AuthPin{Version: runError.N, Chain: runError.LocalChain[:]}),
					configPinBytes(&bridge.AuthPin{Version: runError.N, Chain: runError.RemoteChain[:]})}})
		}
		return
	}
	local := log.Pin()
	if fork.HasLocalChain {
		local = &bridge.AuthPin{Version: fork.N, Chain: bytes.Clone(fork.LocalChain[:])}
	}
	remote := &bridge.AuthPin{Version: fork.N, Chain: bytes.Clone(fork.RemoteChain[:])}
	localBytes, remoteBytes := configPinBytes(local), configPinBytes(remote)
	self.emit(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork, Evidence: [2][]byte{localBytes, remoteBytes}})
	if self.args.ReportFork != nil {
		self.args.ReportFork(HeadFork{Kind: HeadForkAuth, Local: localBytes, Remote: remoteBytes})
	}
}

// Raises an event, when the host takes them.
func (self *ConfigClient) emit(event SidecarEvent) {
	if self.args.Emit != nil {
		self.args.Emit(event)
	}
}

// A pin's deterministic bytes, as HeadCheck's evidence carries it; nil for nil.
func configPinBytes(pin *bridge.AuthPin) []byte {
	if pin == nil {
		return nil
	}
	pinBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(pin)
	if err != nil {
		return nil
	}
	return pinBytes
}

// The pin no start may land below, nil for none.
func (self *ConfigClient) floorPin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.floor == nil {
		return nil
	}
	return proto.Clone(self.floor).(*bridge.AuthPin)
}

// One applied entry as AddEntryCallback reports it: its verdict, its Signed and signers, what took effect there, the
// recovery windows it moved, the bindings its cascade voided, and the admissions and AdminSet after it.
func (self *ConfigClient) authorityEntry(log *ConfigLog, before *ConfigState, after *ConfigState, verdict ConfigVerdict) *SidecarAuthorityEntry {
	entry := &SidecarAuthorityEntry{Pin: proto.Clone(verdict.Pin).(*bridge.AuthPin), Kind: verdict.Kind, Applied: verdict.Accepted()}
	kept := log.keptEntry(verdict.Pin.GetVersion())
	if kept != nil {
		entry.TimeMs = kept.entry.GetTimeMs()
		switch kept.entry.GetKind() {
		case bridge.AuthEntryKindStatement:
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(kept.entry.GetBody(), signed); err == nil {
				entry.Signed = signed
				if kept.statement != nil {
					entry.Signers = append(entry.Signers, kept.statement.signers...)
				} else if signer, err := configSignerOf(signed); err == nil {
					entry.Signers = []ConfigSigner{signer}
				}
			}
			if statement := kept.statement; statement != nil && verdict.Accepted() {
				switch {
				case statement.completes != nil:
					entry.Effects = append(entry.Effects, configAuthorityEffect(statement.completes))
				case statement.proposed != nil:
				default:
					entry.Effects = append(entry.Effects, configAuthorityEffect(statement))
				}
			}
		case bridge.AuthEntryKindTick:
			for _, activation := range kept.activations {
				entry.Effects = append(entry.Effects, configAuthorityEffect(activation.statement))
			}
		}
	}
	entry.Windows = configMovedWindows(before, after)
	entry.VoidedBindings = configVoidedBindings(before, after)
	// what config_admissions bounds, as api counts it (config_workers.go)
	entry.AdmissionCount = after.AdmissionCount()
	for _, memberId := range after.MemberIds() {
		if configRoleInAdminSet(after.Member(memberId).GetRole()) {
			entry.AdminMemberIds = append(entry.AdminMemberIds, memberId)
		}
	}
	return entry
}

// A statement that took effect, as an entry's Effects names it.
func configAuthorityEffect(statement *configStatement) *SidecarAuthorityEffect {
	return &SidecarAuthorityEffect{
		Type:    statement.signedType,
		Body:    bytes.Clone(statement.bodyBytes),
		Signers: append([]ConfigSigner(nil), statement.signers...),
	}
}

// The recovery windows whose rows an entry changed: opened, moved by a recovery signature, or closed.
func configMovedWindows(before *ConfigState, after *ConfigState) []SidecarRecoveryWindow {
	windows := []SidecarRecoveryWindow{}
	for _, proposalId := range after.proposalIds() {
		proposal := after.proposals[proposalId]
		if !proposal.windowed() {
			continue
		}
		if previous := before.proposals[proposalId]; previous != nil && previous.closedAt == proposal.closedAt &&
			proto.Equal(previous.row, proposal.row) {
			continue
		}
		window, ok := after.RecoveryWindow(proposalId[:])
		if !ok {
			continue
		}
		state := SidecarRecoveryWindowPending
		switch {
		case window.Closed == ConfigProposalActivated:
			state = SidecarRecoveryWindowActivated
		case window.Closed == ConfigProposalVetoed:
			state = SidecarRecoveryWindowVetoed
		case window.ClosedAt != 0 || window.Expired:
			state = SidecarRecoveryWindowExpired
		}
		windows = append(windows, SidecarRecoveryWindow{
			ProposalId:     bytes.Clone(proposalId[:]),
			State:          state,
			Start:          window.Row.GetWindowEntry(),
			MemberId:       window.MemberId,
			SidecarId:      window.SidecarId,
			RecoverySigned: window.Row.GetWindowEntry() != 0,
		})
	}
	return windows
}

// The recovery bindings an entry's cascade voided: a member's newest binding no cascade voided before the entry and one
// voids after it (§7.9's cascade).
func configVoidedBindings(before *ConfigState, after *ConfigState) []SidecarVoidedBinding {
	voided := []SidecarVoidedBinding{}
	for _, memberId := range after.MemberIds() {
		bindings := after.Member(memberId).GetBindings()
		if len(bindings) == 0 {
			continue
		}
		newest := bindings[0]
		if after.CascadeVoids(newest.GetSigner(), newest.GetAt()) && !before.CascadeVoids(newest.GetSigner(), newest.GetAt()) {
			voided = append(voided, SidecarVoidedBinding{MemberId: memberId, KeySha256: bytes.Clone(newest.GetKeySha256()), Signer: bytes.Clone(newest.GetSigner())})
		}
	}
	return voided
}

// A rows source over one page's rows, whose head check reads the head the base names through ConfigHeadReader, or
// takes a head this device verified before.
type configClientRowsSource struct {
	client *ConfigClient
	ctx    context.Context
	rows   map[[sha256.Size]byte][]byte
}

// The page's rows, else what the log keeps.
func (self *configClientRowsSource) Rows(networkId Id, rowsSha256 []byte) ([]byte, error) {
	if len(rowsSha256) == sha256.Size {
		if rows, found := self.rows[[sha256.Size]byte(rowsSha256)]; found {
			return rows, nil
		}
	}
	return nil, fmt.Errorf("api served no rows at %x", rowsSha256)
}

// The base's head, read and checked (CheckConfigBase), and remembered as verified. A head this device verified before
// at the same version stands for a restart's anchor; every other check reads it.
func (self *configClientRowsSource) CheckHead(check *ConfigHeadCheck) (*ConfigHeadFacts, error) {
	headSha256 := check.Header.GetConfigHeadSha256()
	if len(headSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: a config_head_sha256 of %d bytes", ErrConfigHeadMismatch, len(headSha256))
	}
	if check.Previous == nil {
		if verified := self.client.verifiedHead(headSha256, check.Header.GetConfigVersion()); verified != nil {
			return &ConfigHeadFacts{Settings: verified.settings}, nil
		}
	}
	if self.client.args.Heads == nil {
		return nil, fmt.Errorf("%w: no config head reader", ErrConfigHeadUnavailable)
	}
	head, err := self.client.args.Heads.ReadConfigHead(self.ctx, check.Header.GetConfigVersion(), headSha256)
	if err != nil {
		return nil, err
	}
	facts, err := CheckConfigBase(head, check, check.CompileRows)
	if errors.Is(err, ErrConfigCompileUnavailable) {
		// no acl compile is registered (C-05): this reader cannot judge the base, which withholds it, never a fork
		return nil, fmt.Errorf("%w: %w", ErrConfigHeadUnavailable, err)
	}
	if err != nil {
		return nil, err
	}
	self.client.rememberHead(headSha256, check.Header.GetConfigVersion(), facts.Settings)
	return facts, nil
}

// A head this device verified at configVersion, nil for none.
func (self *ConfigClient) verifiedHead(headSha256 []byte, configVersion uint64) *configVerifiedHead {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	verified := self.verifiedHeads[[sha256.Size]byte(headSha256)]
	if verified == nil || verified.configVersion != configVersion {
		return nil
	}
	return verified
}

// Remembers a head this device verified, keeping only those its current and previous bases name once more land.
func (self *ConfigClient) rememberHead(headSha256 []byte, configVersion uint64, settings *protocol.ServiceSettings) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.verifiedHeads[[sha256.Size]byte(headSha256)] = &configVerifiedHead{configVersion: configVersion, settings: settings}
}

// HeadCheckAuthSource's ChainAt: A_version as the log keeps it, false before its retention point or past its pin.
func (self *ConfigClient) ChainAt(version uint64) ([]byte, bool) {
	state := self.State()
	if state == nil {
		return nil, false
	}
	chain, ok := state.chainAt(version)
	if !ok {
		return nil, false
	}
	return bytes.Clone(chain[:]), true
}

// HeadCheckAuthSource's Vetoes: the Signed RecoveryVetoes this device holds off the log, newest last, at most
// HeadCheckMaxVetoCount.
func (self *ConfigClient) Vetoes() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	vetoes := self.heldVetoes
	if HeadCheckMaxVetoCount < len(vetoes) {
		vetoes = vetoes[len(vetoes)-HeadCheckMaxVetoCount:]
	}
	copied := make([][]byte, 0, len(vetoes))
	for _, veto := range vetoes {
		copied = append(copied, bytes.Clone(veto))
	}
	return copied
}

// HeadCheckAuthSource's FetchAuth: a follow through through's position.
func (self *ConfigClient) FetchAuth(ctx context.Context, through *bridge.AuthPin) error {
	self.noteHint(through.GetVersion())
	return self.follow(ctx)
}

// HeadCheckAuthSource's HoldVeto: a peer's veto verified and held as §7.9's precedence row says (ConfigLog.HoldVeto).
func (self *ConfigClient) HoldVeto(ctx context.Context, signedVeto []byte) error {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	log := self.configLog.Load()
	if log == nil {
		return ErrConfigClientClosed
	}
	if err := log.HoldVeto(signedVeto); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heldVetoes = append(self.heldVetoes, bytes.Clone(signedVeto))
	return nil
}

// HeadCheckAuthSource's AuthProof: the entries after position after through this device's pin, verbatim, a base as its
// header, which every entry is, at most HeadCheckMaxProofByteCount (§6.5). ErrHeadCheckProofNotFound when the log
// keeps no entry from after+1 or the run passes the bound.
func (self *ConfigClient) AuthProof(after uint64) ([][]byte, error) {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	log := self.configLog.Load()
	if log == nil {
		return nil, ErrHeadCheckProofNotFound
	}
	state := log.State()
	entries := [][]byte{}
	byteCount := 0
	for n := after + 1; n <= state.n; n += 1 {
		kept := log.keptEntry(n)
		if kept == nil {
			return nil, ErrHeadCheckProofNotFound
		}
		byteCount += len(kept.entryBytes)
		if HeadCheckMaxProofByteCount < byteCount {
			return nil, ErrHeadCheckProofNotFound
		}
		entries = append(entries, bytes.Clone(kept.entryBytes))
	}
	return entries, nil
}

// HeadCheckAuthSource's VerifyAuthProof: the entries chain from this device's A_n, each at the next position, to
// through, and each statement's signature verifies under the signer this device's state names. It applies nothing.
// A base's rows and head, and a statement's rule at its own position, are not judged here: a proof shows the chain
// went on, and FetchAuth's follow judges every entry.
func (self *ConfigClient) VerifyAuthProof(ctx context.Context, entries [][]byte, through *bridge.AuthPin) error {
	state := self.State()
	if state == nil || len(entries) == 0 || through == nil {
		return ErrHeadCheckProofInvalid
	}
	chain := state.chain
	n := state.n
	for _, entryBytes := range entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return ErrHeadCheckProofInvalid
		}
		if entry.GetN() != n+1 || !bytes.Equal(entry.GetPrevChain(), chain[:]) || !bytes.Equal(entry.GetNetworkId(), state.networkId.Bytes()) {
			return ErrHeadCheckProofInvalid
		}
		next, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
		if err != nil {
			return ErrHeadCheckProofInvalid
		}
		if entry.GetKind() == bridge.AuthEntryKindStatement {
			signed := &bridge.Signed{}
			if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
				return ErrHeadCheckProofInvalid
			}
			purpose, ok := ConfigStatementPurpose(bridge.SignedType(signed.GetType()))
			if !ok {
				return ErrHeadCheckProofInvalid
			}
			if _, err := state.verifySigner(signed, purpose, bridge.SignedType(signed.GetType()), entry.GetTimeMs()); err != nil {
				return ErrHeadCheckProofInvalid
			}
		}
		chain, n = next, entry.GetN()
	}
	if n != through.GetVersion() || !bytes.Equal(chain[:], through.GetChain()) {
		return ErrHeadCheckProofInvalid
	}
	return nil
}

// GET /network/config/projection?after= (§7.9's read row; plan-TEAM-genesis-custody #3): the entries after a position,
// with their bases' rows and, from 0, the Signed Genesis. 503 while entry 1 exists without its genesis.
func (self *SidecarApi) GetConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	route := "GET /network/config/projection"
	query := url.Values{"after": []string{strconv.FormatUint(after, 10)}}
	reply := &sidecarConfigProjectionReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "config_projection",
		method:    "GET",
		url:       self.settings.ApiUrl + "/network/config/projection?" + query.Encode(),
		bearer:    true,
	}, nil, reply)
	if err != nil {
		return nil, err
	}
	projection := &ConfigProjection{SignedGenesis: reply.Genesis, Entries: reply.Entries, Rows: reply.Rows, More: reply.More}
	if reply.Tip != nil {
		if reply.Tip.N == 0 || len(reply.Tip.Chain) != sha256.Size {
			return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
		}
		projection.Tip = &bridge.AuthPin{Version: reply.Tip.N, Chain: reply.Tip.Chain}
	}
	return projection, nil
}

// ConfigProjectionReader over SidecarApi.
func (self *SidecarApi) ReadConfigProjection(ctx context.Context, after uint64) (*ConfigProjection, error) {
	return self.GetConfigProjection(ctx, after)
}

// GET /network/config/projection's answer (sidecartest/fake_api_config.go answers alike).
type sidecarConfigProjectionReply struct {
	Genesis []byte                 `json:"genesis,omitempty"`
	Entries [][]byte               `json:"entries"`
	Rows    [][]byte               `json:"rows"`
	Tip     *sidecarConfigPinReply `json:"tip,omitempty"`
	More    bool                   `json:"more"`
}
