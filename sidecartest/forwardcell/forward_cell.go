// DESIGN-DETAILS 4.4's forwarding compile on a real Forwarder, for T4's cells (BRIDGE-M8-03; 4.2.4, 4.2.5; §22.9;
// QD-620): a network of n devices in 4.2.4's mix (rows.go) at one base, and a sidecar.Forwarder for one of its
// devices, S, that follows it and compiles S's state as an app's VPN component does, so a cell samples the compile's
// transient heap and keeps the state it hands, beside whatever else the cell holds (sdk's link cell holds one link).
//
//	network   a Genesis device 0 signs; one BASE that device signs over the fixture's rows, past the ring with nothing
//	          unfolded after it, as api's retention point serves a rows-only reader; and a config head holding the
//	          Genesis and one fold through the base's, with no record, policy or ledger: I-10's no-document network,
//	          in which every device reaches S, an empty bridge ledger at the fold, and nothing a compile waits for, no
//	          key, generation or binding
//	host      S, device 1 by default, holds a forwarding Delegation in the mix; the Forwarder holds that Delegation's
//	          key and is anchored by a Pending naming it
//	run       Start builds the Forwarder over the caller's store (sdk's sealed store on disk, as a VPN component's, or
//	          one in memory), lets it follow, and holds its first compile at the admission rule's heap read; Compile
//	          releases it and returns once the Forwarder waits again, whatever the outcome: the state handed, the cap's
//	          refusal or a failure. Nothing is polled and nothing sleeps: the Forwarder's clock reports each wait
//	sample    the sink keeps the state it is handed, as device.Bridge keeps its state in force; a cell's Sample runs at
//	          that hand, where the compile holds the most, and at the head read, where the judged log is held
//
// What it is not: no posture verifies the hand (device.Bridge streams the rows again and adopts the state); no
// statement, generation or binding is judged, since the network is a base alone; F is not minted and api, gkm and evs
// are this file's. Every figure a cell takes from it is this host's, no surrogate's or device's (owner decision 100).
//
// It imports the root and the protocol packages alone, so sdk's T4 cells take it without sidecartest's servers (sdk's
// dependency_boundary_test.go).

package forwardcell

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a Network is built with.
type NetworkSettings struct {
	// The rows' mix: 4.2.4's from DefaultNetworkSettings.
	Rows *RowsSettings
	// S: the device whose forwarding role compiles. It must hold a forwarding Delegation in the mix.
	HostIndex int
	// The config version the base names.
	ConfigVersion uint64
	// The admin threshold the base carries.
	Threshold uint32
	// The device whose identity key signs the base: device 0, the Genesis's, a config writer. A test names a device of
	// another member to see the base refused.
	BaseSignerIndex int
}

// 4.2.4's mix, with device 1 as S.
func DefaultNetworkSettings() *NetworkSettings {
	return &NetworkSettings{
		Rows:          DefaultRowsSettings(),
		HostIndex:     1,
		ConfigVersion: 1,
		Threshold:     1,
	}
}

// One network at one base, which api serves and whose head evs serves (sidecar.ConfigProjectionReader and
// sidecar.ConfigHeadReader). Safe for concurrent use: nothing in it changes once built.
type Network struct {
	DeviceCount   int
	NetworkId     sidecar.Id
	ConfigRepoId  sidecar.Id
	HostSidecarId sidecar.Id

	settings      *NetworkSettings
	signedGenesis []byte
	baseEntry     []byte
	basePin       *bridge.AuthPin
	rows          []byte
	headFiles     map[string][]byte
	headSha256    []byte
	pending       *bridge.Pending
}

var _ sidecar.ConfigProjectionReader = (*Network)(nil)
var _ sidecar.ConfigHeadReader = (*Network)(nil)

// A Signed of body, of signedType, by device's identity key, as its bytes.
func signedBytes(device int, purpose string, signedType bridge.SignedType, body proto.Message) ([]byte, error) {
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.Signed{
		Body:      bodyBytes,
		SignerId:  SidecarId(device),
		Signature: ed25519.Sign(IdentityKey(device), bridge.SignedBytes(purpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// The network of deviceCount devices under settings, nil for DefaultNetworkSettings.
func NewNetwork(deviceCount int, settings *NetworkSettings) (*Network, error) {
	if settings == nil {
		settings = DefaultNetworkSettings()
	}
	copied := *settings
	settings = &copied
	if settings.Rows == nil {
		settings.Rows = DefaultRowsSettings()
	}
	if settings.HostIndex < 0 || deviceCount <= settings.HostIndex || !settings.Rows.HasForwarding(settings.HostIndex) {
		return nil, fmt.Errorf("device %d of %d holds no forwarding Delegation to host by", settings.HostIndex, deviceCount)
	}
	networkId, err := sidecar.IdFromBytes(Id("network", deviceCount))
	if err != nil {
		return nil, err
	}
	configRepoId, err := sidecar.IdFromBytes(Id("config repo", deviceCount))
	if err != nil {
		return nil, err
	}
	hostSidecarId, err := sidecar.IdFromBytes(SidecarId(settings.HostIndex))
	if err != nil {
		return nil, err
	}

	genesis := Genesis(networkId.Bytes(), configRepoId.Bytes(), settings.Rows.AdmittedTimeMs-1)
	signedGenesis, err := signedBytes(0, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_GENESIS, genesis)
	if err != nil {
		return nil, err
	}

	rows, err := Rows(deviceCount, settings.Rows)
	if err != nil {
		return nil, err
	}
	rowsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(rows)
	if err != nil {
		return nil, err
	}
	rowsSha256 := sha256.Sum256(rowsBytes)

	// the base: past the ring, folding everything before it, which a reader that starts there takes on its signer
	foldedThrough := settings.Rows.FoldedThrough(deviceCount)
	baseN := foldedThrough + 1
	prevChain := Digest("prev chain", deviceCount)
	headSha256 := Digest("config head", deviceCount)
	if settings.BaseSignerIndex < 0 || deviceCount <= settings.BaseSignerIndex {
		return nil, fmt.Errorf("no device %d of %d to sign the base", settings.BaseSignerIndex, deviceCount)
	}
	signedHeader, err := signedBytes(settings.BaseSignerIndex, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, &bridge.ProjectionHeader{
		NetworkId:        networkId.Bytes(),
		Version:          baseN,
		PrevChain:        prevChain,
		FoldedThrough:    foldedThrough,
		ConfigVersion:    settings.ConfigVersion,
		ConfigHeadSha256: headSha256,
		RowsSha256:       rowsSha256[:],
		RowsByteCount:    uint32(len(rowsBytes)),
		Threshold:        settings.Threshold,
	})
	if err != nil {
		return nil, err
	}
	entry := &bridge.AuthEntry{
		NetworkId: networkId.Bytes(),
		N:         baseN,
		PrevChain: prevChain,
		Kind:      bridge.AuthEntryKindBase,
		TimeMs:    settings.Rows.LastAdmittedTimeMs(deviceCount) + 1,
		Body:      signedHeader,
	}
	baseEntry, err := proto.MarshalOptions{Deterministic: true}.Marshal(entry)
	if err != nil {
		return nil, err
	}
	chain, err := bridge.AuthChainDigest(entry.GetN(), entry.GetPrevChain(), entry.GetKind(), entry.GetTimeMs(), entry.GetBody())
	if err != nil {
		return nil, err
	}

	// the head: the Genesis and one fold through the base's, which holds no record and no ledger, so the head is an
	// empty bridge ledger at the base's fold
	foldBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ConfigFold{After: 0, FoldedThrough: foldedThrough})
	if err != nil {
		return nil, err
	}
	headFiles := map[string][]byte{
		sidecar.ConfigHeadGenesisPath: signedGenesis,
		sidecar.ConfigFoldPath(1):     foldBytes,
	}

	genesisChain := bridge.GenesisChain(signedGenesis)
	return &Network{
		DeviceCount:   deviceCount,
		NetworkId:     networkId,
		ConfigRepoId:  configRepoId,
		HostSidecarId: hostSidecarId,
		settings:      settings,
		signedGenesis: signedGenesis,
		baseEntry:     baseEntry,
		basePin:       &bridge.AuthPin{Version: baseN, Chain: chain[:]},
		rows:          rowsBytes,
		headFiles:     headFiles,
		headSha256:    headSha256,
		pending: &bridge.Pending{
			NetworkId:           networkId.Bytes(),
			GenesisSha256:       genesisChain[:],
			SidecarId:           hostSidecarId.Bytes(),
			IdentityPublicKey:   IdentityKey(settings.HostIndex).Public().(ed25519.PublicKey),
			ForwardDelegationId: DelegationId(settings.HostIndex),
		},
	}, nil
}

// The base's rows, in bytes.
func (self *Network) RowsByteCount() int64 {
	return int64(len(self.rows))
}

// The head's files, in bytes.
func (self *Network) HeadByteCount() int64 {
	byteCount := int64(0)
	for _, file := range self.headFiles {
		byteCount += int64(len(file))
	}
	return byteCount
}

// The base entry, in bytes: what a store holding the network holds of its log.
func (self *Network) TailByteCount() int64 {
	return int64(len(self.baseEntry))
}

// The anchor S's hand-off carries.
func (self *Network) Pending() *bridge.Pending {
	return proto.Clone(self.pending).(*bridge.Pending)
}

// The base's pin.
func (self *Network) BasePin() *bridge.AuthPin {
	return proto.Clone(self.basePin).(*bridge.AuthPin)
}

// From api's retention point, the base: the genesis from 0, then the base and its rows; past it, nothing.
func (self *Network) ReadConfigProjection(ctx context.Context, after uint64) (*sidecar.ConfigProjection, error) {
	projection := &sidecar.ConfigProjection{Tip: self.BasePin()}
	if after == 0 {
		projection.SignedGenesis = bytes.Clone(self.signedGenesis)
	}
	if after < self.basePin.GetVersion() {
		projection.Entries = [][]byte{bytes.Clone(self.baseEntry)}
		projection.Rows = [][]byte{bytes.Clone(self.rows)}
	}
	return projection, nil
}

// The head the base names, and no other.
func (self *Network) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	if configVersion != self.settings.ConfigVersion || !bytes.Equal(configHeadSha256, self.headSha256) {
		return nil, fmt.Errorf("%w: the network names head %d alone", sidecar.ErrConfigHeadUnavailable, self.settings.ConfigVersion)
	}
	return sidecar.NewConfigHead(self.headFiles)
}

// S's forwarding key set, as the component's key store holds it after a hand-off: the Delegation and its key. Its
// reader key's DelegationWraps are never read, since the network seals nothing.
type hostKeys struct {
	delegationId [sha256.Size]byte
	key          ed25519.PrivateKey
}

var _ sidecar.ForwarderKeys = (*hostKeys)(nil)

func (self *hostKeys) Delegation() ([sha256.Size]byte, ed25519.PublicKey, bool) {
	return self.delegationId, self.key.Public().(ed25519.PublicKey), true
}

func (self *hostKeys) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(self.key, message), nil
}

func (self *hostKeys) ReaderKeys() ([]sidecar.ForwarderReaderKey, error) {
	return nil, nil
}

// The device role as the Forwarder sees it: it keeps what it is handed and samples there. Safe for concurrent use.
type recordingSink struct {
	sample func()
	// whether the hand reads the live heap after a collection
	liveAtHand bool

	stateLock sync.Mutex
	state     sidecar.BridgeSinkState
	pin       *bridge.AuthPin
	held      *bridge.BridgeState
	handed    int
	// the live heap at the first hand, when liveAtHand
	handLiveByteCount int64
}

// The heap's live objects once the collector has run: HeapAlloc after two collections, so what a finalizer or a
// sweep left behind the first is gone.
func liveHeap() int64 {
	runtime.GC()
	runtime.GC()
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return int64(stats.HeapAlloc)
}

var _ sidecar.ForwarderSink = (*recordingSink)(nil)

func (self *recordingSink) SetPending(pending *bridge.Pending) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == sidecar.BridgeSinkLegacy {
		self.state = sidecar.BridgeSinkPending
	}
	return nil
}

func (self *recordingSink) SetState(state *bridge.BridgeState, log *sidecar.BridgeStateLog) error {
	if self.sample != nil {
		self.sample()
	}
	live := int64(0)
	if self.liveAtHand {
		live = liveHeap()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.handed == 0 {
		self.handLiveByteCount = live
	}
	if self.pin != nil && state.GetAuth().GetVersion() < self.pin.GetVersion() {
		return nil
	}
	self.state = sidecar.BridgeSinkEnforcing
	self.pin = proto.Clone(state.GetAuth()).(*bridge.AuthPin)
	self.held = state
	self.handed += 1
	return nil
}

// A base alone has no entries past it.
func (self *recordingSink) ApplyDeltas(log *sidecar.BridgeStateLog) error {
	return nil
}

func (self *recordingSink) SetFork(fork bool) error {
	return nil
}

func (self *recordingSink) Decision() sidecar.BridgeSinkDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	decision := sidecar.BridgeSinkDecision{State: self.state}
	if self.pin != nil {
		decision.Pin = proto.Clone(self.pin).(*bridge.AuthPin)
		decision.StatePin = proto.Clone(self.pin).(*bridge.AuthPin)
	}
	return decision
}

// The state handed last, how many were and the live heap at the first hand: nil and 0 before one.
func (self *recordingSink) handedState() (*bridge.BridgeState, int, int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.held, self.handed, self.handLiveByteCount
}

// Real time, reporting each wait the Forwarder's loop starts: its loop waits only between pieces of work, so a wait
// after a compile was let run is that compile ended, whatever its outcome. Safe for concurrent use.
type waitingClock struct {
	sidecar.RealClock

	stateLock sync.Mutex
	waits     uint64
	waited    chan struct{}
}

func newWaitingClock() *waitingClock {
	return &waitingClock{waited: make(chan struct{})}
}

func (self *waitingClock) After(timeout time.Duration) <-chan time.Time {
	self.stateLock.Lock()
	self.waits += 1
	close(self.waited)
	self.waited = make(chan struct{})
	self.stateLock.Unlock()
	return self.RealClock.After(timeout)
}

// The waits so far, and what closes at the next.
func (self *waitingClock) snapshot() (uint64, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waits, self.waited
}

// Holds the first compile at its admission rule's heap read until it is let run. Safe for concurrent use.
type compileGate struct {
	heapInUse func() int64

	stateLock   sync.Mutex
	held        bool
	arrived     chan struct{}
	released    chan struct{}
	releaseOnce sync.Once
}

// Lets the held compile run, once.
func (self *compileGate) release() {
	self.releaseOnce.Do(func() {
		close(self.released)
	})
}

// The heap in use the admission rule reads, after the first read waited to be let run.
func (self *compileGate) pass(ctx context.Context) int64 {
	self.stateLock.Lock()
	first := !self.held
	self.held = true
	self.stateLock.Unlock()
	if first {
		close(self.arrived)
		select {
		case <-self.released:
		case <-ctx.Done():
		}
	}
	if self.heapInUse == nil {
		return 0
	}
	return self.heapInUse()
}

// The Forwarder's records in memory: a SidecarStore's calls. Safe for concurrent use.
type memoryStore struct {
	stateLock sync.Mutex
	records   map[string][]byte
}

var _ sidecar.ForwarderStore = (*memoryStore)(nil)

func (self *memoryStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	record, ok := self.records[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", sidecar.ErrSidecarStoreAbsent, name)
	}
	return io.NopCloser(bytes.NewReader(record)), nil
}

func (self *memoryStore) Create(name string) (sidecar.SidecarStoreWriter, error) {
	return &memoryStoreWriter{store: self, name: name}, nil
}

func (self *memoryStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.records, name)
	return nil
}

func (self *memoryStore) List(prefix string) ([]sidecar.SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []sidecar.SidecarStoreEntry{}
	for name, record := range self.records {
		if strings.HasPrefix(name, prefix) {
			entries = append(entries, sidecar.SidecarStoreEntry{Name: name, ByteCount: int64(len(record))})
		}
	}
	slices.SortFunc(entries, func(a sidecar.SidecarStoreEntry, b sidecar.SidecarStoreEntry) int {
		return strings.Compare(a.Name, b.Name)
	})
	return entries, nil
}

// One record being written, swapped in whole at Commit.
type memoryStoreWriter struct {
	store  *memoryStore
	name   string
	buffer bytes.Buffer
	done   bool
}

func (self *memoryStoreWriter) Write(data []byte) (int, error) {
	if self.done {
		return 0, errors.New("the record was committed or closed")
	}
	return self.buffer.Write(data)
}

func (self *memoryStoreWriter) Commit() error {
	if self.done {
		return errors.New("the record was committed or closed")
	}
	self.done = true
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	self.store.records[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *memoryStoreWriter) Close() error {
	self.done = true
	return nil
}

// What a Run is built over.
type RunArgs struct {
	// The Forwarder's records, empty of the network: nil keeps them in memory. sdk's cells pass the VPN component's
	// sealed store on disk, where the rows wait between compiles.
	Store sidecar.ForwarderStore
	// The Forwarder's settings: nil for the Apple extensions' (QD-620's 10 MiB cap and 30 MiB ceiling). A Run sets
	// no compile delay or interval, so the first compile follows the first follow at once.
	Settings *sidecar.ForwarderSettings
	// The process's heap in use as the admission rule reads it: nil reads 0, since a test process's heap is no
	// tunnel's and the ceiling would judge the test's own allocations. A cell holds the compile's peak to its
	// profile instead.
	HeapInUse func() int64
	// Called where the compile holds the most: at the head read, with the judged log held, and at the hand, with the
	// state built. A cell's Sample.
	Sample func()
	// Collects garbage before the compile is let run and again at its hand, and reports the heap the compile holds
	// live there (CompileResult.HandLiveByteCount): what 4.2.4's estimate models, beside a cell's sampled peak, which
	// counts garbage the collector had not yet freed. It moves the collector, so a cell takes it from a run of its own.
	LiveAtHand bool
	// The Forwarder's log: nil for none.
	Log sidecar.Logger
}

// A Forwarder for S over the network, its first compile held at its admission until Compile lets it run.
type Run struct {
	network  *Network
	settings *sidecar.ForwarderSettings
	sink     *recordingSink
	gate     *compileGate
	clock    *waitingClock

	stateLock sync.Mutex
	forwarder *sidecar.Forwarder
	compiled  bool
}

// The outcome of a Run's compile.
type CompileResult struct {
	DeviceCount int
	// The admission rule's terms, in bytes, and what it counts for them against the settings' cap.
	RowsByteCount     int64
	HeadByteCount     int64
	TailByteCount     int64
	EstimateByteCount int64
	// The admission rule's answer at the compile.
	Admission sidecar.ForwarderCompileAdmission
	// The state handed, nil when none was, and its encoded size.
	State          *bridge.BridgeState
	StateByteCount int64
	// Under RunArgs.LiveAtHand, the live heap at the hand over the live heap before the compile was let run, 0
	// otherwise.
	HandLiveByteCount int64
	// The Forwarder's counts and standing alarms after the compile.
	CompileCount        uint64
	CompileErrorCount   uint64
	CompileRefusedCount uint64
	Alarms              []string
	Duration            time.Duration
}

// A network whose head names the head reader it is served by.
type networkHeads struct {
	network *Network
	sample  func()
}

func (self networkHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	if self.sample != nil {
		self.sample()
	}
	return self.network.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

// Starts S's Forwarder over the network under args, and returns once it has followed the network and its first
// compile waits at its admission. ctx ends the Run; Close ends it sooner.
func (self *Network) Start(ctx context.Context, args *RunArgs) (*Run, error) {
	if args == nil {
		args = &RunArgs{}
	}
	settings := sidecar.DefaultForwarderSettings(sidecar.ForwarderHostApple)
	if args.Settings != nil {
		copied := *args.Settings
		settings = &copied
	}
	settings.CompileDelay = 0
	settings.CompileMinInterval = 0
	store := args.Store
	if store == nil {
		store = &memoryStore{records: map[string][]byte{}}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	run := &Run{
		network:  self,
		settings: settings,
		sink:     &recordingSink{sample: args.Sample, liveAtHand: args.LiveAtHand, state: sidecar.BridgeSinkLegacy},
		gate:     &compileGate{heapInUse: args.HeapInUse, arrived: make(chan struct{}), released: make(chan struct{})},
		clock:    newWaitingClock(),
	}
	forwarder, err := sidecar.NewForwarder(ctx, &sidecar.ForwarderArgs{
		NetworkId:    self.NetworkId,
		SidecarId:    self.HostSidecarId,
		Pending:      self.Pending(),
		ConfigRepoId: self.ConfigRepoId,
		Projection:   self,
		Heads:        networkHeads{network: self, sample: args.Sample},
		Store:        store,
		Keys: &hostKeys{
			delegationId: [sha256.Size]byte(DelegationId(self.settings.HostIndex)),
			key:          ForwardKey(self.settings.HostIndex),
		},
		Sink: run.sink,
		HeapInUse: func() int64 {
			return run.gate.pass(ctx)
		},
		Clock:    run.clock,
		Log:      log,
		Settings: settings,
	})
	if err != nil {
		return nil, err
	}
	run.forwarder = forwarder
	// the Forwarder's loop waits only once it has nothing to do: a wait before the compile arrives is a follow that
	// led to none
	_, waited := run.clock.snapshot()
	select {
	case <-run.gate.arrived:
		return run, nil
	case <-waited:
		status := forwarder.Status()
		run.Close()
		return nil, fmt.Errorf("the Forwarder followed and wanted no compile: status %+v", status)
	case <-ctx.Done():
		run.Close()
		return nil, fmt.Errorf("the Forwarder's first compile never reached its admission: %w", ctx.Err())
	}
}

// Lets the held compile run and returns its outcome once the Forwarder waits again. Once a Run.
func (self *Run) Compile(ctx context.Context) (*CompileResult, error) {
	self.stateLock.Lock()
	if self.compiled {
		self.stateLock.Unlock()
		return nil, errors.New("a Run compiles once")
	}
	self.compiled = true
	self.stateLock.Unlock()

	beforeByteCount := int64(0)
	if self.sink.liveAtHand {
		beforeByteCount = liveHeap()
	}
	waits, waited := self.clock.snapshot()
	started := time.Now()
	self.gate.release()
	for {
		select {
		case <-waited:
		case <-ctx.Done():
			return nil, fmt.Errorf("the compile did not end: %w; status %+v", ctx.Err(), self.forwarder.Status())
		}
		var now uint64
		now, waited = self.clock.snapshot()
		if waits < now {
			break
		}
	}
	duration := time.Since(started)

	network := self.network
	result := &CompileResult{
		DeviceCount:   network.DeviceCount,
		RowsByteCount: network.RowsByteCount(),
		HeadByteCount: network.HeadByteCount(),
		TailByteCount: network.TailByteCount(),
		Duration:      duration,
	}
	result.EstimateByteCount = self.settings.CompileEstimate(sidecar.ForwarderCompileSize{
		RowsByteCount: result.RowsByteCount,
		HeadByteCount: result.HeadByteCount,
		TailByteCount: result.TailByteCount,
	})
	status := self.forwarder.Status()
	result.Admission = status.Admission
	result.CompileCount = status.CompileCount
	result.CompileErrorCount = status.CompileErrorCount
	result.CompileRefusedCount = status.CompileRefusedCount
	for _, alarm := range status.Alarms {
		result.Alarms = append(result.Alarms, string(alarm.Reason))
	}
	if state, handed, handLiveByteCount := self.sink.handedState(); 0 < handed {
		if self.sink.liveAtHand {
			result.HandLiveByteCount = max(0, handLiveByteCount-beforeByteCount)
		}
		result.State = state
		stateBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(state)
		if err != nil {
			return nil, err
		}
		result.StateByteCount = int64(len(stateBytes))
	}
	return result, nil
}

// The Forwarder, for its status and signer.
func (self *Run) Forwarder() *sidecar.Forwarder {
	return self.forwarder
}

// Ends the Forwarder, letting a compile still held run first so its loop can end; what it handed stays with the
// result.
func (self *Run) Close() {
	self.gate.release()
	self.forwarder.Close()
}
