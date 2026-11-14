// The Forwarder (BRIDGE-M8-05; DESIGN-DETAILS 4.2.4, 4.2.5, 12.7; owner decision 197; QD-620, QD-621, QD-641): a VPN
// component's forwarding role for one network, which follows the authorization log and compiles its bridge state while
// no sidecar role runs. It is tier 2 of 4.2.1's two tiers. Tier 1, the posture behind ForwarderSink, verifies what it is
// handed and applies every revocation it can check as a denial at once; the Forwarder fetches the log into its sealed
// store, hands each page to the sink, and when a page held anything a denial does not cover runs a transient compile:
// the rows-only ConfigLog as the judge, the config's generations opened by DelegationWrap under the forwarding reader
// key, the head the base names, CompileBridgeState for its sidecar, and the state handed to the sink with the log run
// that vouches for it. It signs no statement and holds no identity key.
//
// One goroutine, run, owns every call into the sink and the store:
//
//	follow    at start, on a hint above the newest stored entry, each FollowInterval and at a witness
//	          (bridge_forward_follow.go)
//	compile   wanted by the follow, coalesced for CompileDelay, never within CompileMinInterval of the last, one at a
//	          time; a hint during a compile is followed after it and wants at most one more (bridge_forward_compile.go)
//	alarms    the sink's decision names the next time its posture raises an alarm, and the loop reads the decision
//	          then
//
// Between compiles nothing of the network stays in memory but the pin, the timers, the settings, the last compile's
// link targets and the binding cache: rows, entries, heads and generation keys are records in the store.
//
// A compile runs only when CompileAdmission passes. The estimate of a compile's memory is CompileEstimateRowsFactor
// times the rows' bytes, since a row decodes into a struct and a separate allocation for each id, key and hash it
// holds, CompileEstimateHeadFactor times the head's bytes, the newest base's tail bytes, CompileEstimateStateFactor
// times the last compiled state's size (12.7, stricter than QD-620's rule) and CompileEstimateOverheadByteCount. Past
// CompileMemoryMaxByteCount the compile never runs on this device (compile_over_budget); under it, with the process's
// heap in use the estimate must fit under CompileHeapCeilingByteCount, or the compile is deferred and retried
// (compile_deferred). Either way the last verified state stays in force and nothing goes pending (QD-621).
//
// Logs and alarms name opaque ids and positions, never a prefix, an address, a name or a key (I-13). On every leg,
// with no connect import: an app's VPN component links this file (DESIGN-DETAILS 4.2.3).
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The Forwarder is closed, or was built over nothing to follow.
var ErrForwarderClosed = errors.New("forwarder closed")

// Where a forwarding role runs, which sets its memory bounds (DESIGN-DETAILS 4.2.5's settings).
type ForwarderHostClass string

const (
	// An Apple network extension: the tunnel's 32 MiB soft limit bounds it.
	ForwarderHostApple ForwarderHostClass = "apple"
	// An Android VPN service.
	ForwarderHostAndroid ForwarderHostClass = "android"
	// A desktop service: Windows, Linux, macOS outside an extension.
	ForwarderHostDesktop ForwarderHostClass = "desktop"
)

// The bridge_alarm reasons a forwarding role raises (DESIGN-DETAILS 4.2.5; QD-621).
const (
	// A compile's estimate is past CompileMemoryMaxByteCount: it never runs on this device.
	ForwarderAlarmCompileOverBudget = "compile_over_budget"
	// A compile the heap ceiling has deferred for CompileDeferredAlarmTimeout.
	ForwarderAlarmCompileDeferred = "compile_deferred"
	// A generation's key the forwarding reader key has no wrap for yet.
	ForwarderAlarmConfigKeyWaiting = "config_key_waiting"
	// The forwarding client's credential lapsed.
	ForwarderAlarmForwardClientLapsed = "forward_client_lapsed"
	// A narrowing entry the posture cannot check has waited past its timeout (the posture's PostureAlarmCompileOverdue).
	ForwarderAlarmNarrowingOverdue = "narrowing_overdue"
)

// Tunables of a forwarding role.
type ForwarderSettings struct {
	// How long a compile waits for further hints to coalesce: 2 s.
	CompileDelay time.Duration
	// The least time between one compile's start and the next: 10 s.
	CompileMinInterval time.Duration
	// How long a deferred or failed compile waits before it tries again: 30 s, doubling to CompileRetryMaxInterval,
	// 10 min.
	CompileRetryInterval    time.Duration
	CompileRetryMaxInterval time.Duration
	// How long the heap ceiling may defer a compile before compile_deferred is raised: 10 min.
	CompileDeferredAlarmTimeout time.Duration
	// The most a compile's estimated memory may be: 10 MiB in an Apple extension, 16 MiB on Android, 64 MiB on a
	// desktop service. Non-positive refuses every compile.
	CompileMemoryMaxByteCount int64
	// The most the process's heap in use plus a compile's estimate may be: 30 MiB in an Apple extension, under the
	// tunnel's 32 MiB soft limit; 0 for no ceiling.
	CompileHeapCeilingByteCount int64
	// The estimate's terms (the file's comment): 5, 2, 2 and 1 MiB.
	CompileEstimateRowsFactor        int64
	CompileEstimateHeadFactor        int64
	CompileEstimateStateFactor       int64
	CompileEstimateOverheadByteCount int64
	// How many entries a compile applies at a time after its base: 256.
	CompileApplyRunCount int
	// How often the role follows the log with no hint: 1 h.
	FollowInterval time.Duration
	// How many pages one follow reads before it yields: 64.
	FollowPageMaxCount int
	// How often config_key_waiting is raised while a generation's key is missing: 10 min.
	KeyWaitAlarmInterval time.Duration
	// How many opened heads stay cached on storage: 2.
	HeadCacheCount int
	// Whether a compile returns its memory to the OS when it ends (debug.FreeOSMemory): the mobile classes.
	FreeMemoryAfterCompile bool
	// The longest one follow runs, and the wait after a failed one, doubling to FollowInterval: 60 s and 10 s.
	FollowTimeout       time.Duration
	FollowRetryInterval time.Duration
	// The longest one read of gkm, of a head or of a binding runs inside a compile: 30 s.
	FetchTimeout time.Duration
	// How long a client id stays among a subject's after it stopped being current, the most kept a subject, and the
	// most bindings fetched after one compile: 7 days (QD-161), 16 and 64.
	BindingRetainTimeout time.Duration
	BindingMaxCount      int
	BindingFetchMaxCount int
	// The judge's, the ledger's, the compile's and gkm's own settings. Nil is each one's defaults. The judge's
	// BridgeBodyJudge is the Forwarder's, over the generations its store holds, whatever this names.
	ConfigLog *ConfigLogSettings
	Ledger    *BridgeLedgerSettings
	Compile   *BridgeCompileSettings
	Gkm       *GkmSettings
}

// The settings for a host class; an unknown class takes the Apple extension's, the tightest.
func DefaultForwarderSettings(hostClass ForwarderHostClass) *ForwarderSettings {
	settings := &ForwarderSettings{
		CompileDelay:                     2 * time.Second,
		CompileMinInterval:               10 * time.Second,
		CompileRetryInterval:             30 * time.Second,
		CompileRetryMaxInterval:          10 * time.Minute,
		CompileDeferredAlarmTimeout:      10 * time.Minute,
		CompileMemoryMaxByteCount:        10 * 1024 * 1024,
		CompileHeapCeilingByteCount:      30 * 1024 * 1024,
		CompileEstimateRowsFactor:        5,
		CompileEstimateHeadFactor:        2,
		CompileEstimateStateFactor:       2,
		CompileEstimateOverheadByteCount: 1024 * 1024,
		CompileApplyRunCount:             256,
		FollowInterval:                   time.Hour,
		FollowPageMaxCount:               64,
		KeyWaitAlarmInterval:             10 * time.Minute,
		HeadCacheCount:                   2,
		FreeMemoryAfterCompile:           true,
		FollowTimeout:                    60 * time.Second,
		FollowRetryInterval:              10 * time.Second,
		FetchTimeout:                     30 * time.Second,
		BindingRetainTimeout:             7 * 24 * time.Hour,
		BindingMaxCount:                  16,
		BindingFetchMaxCount:             64,
	}
	switch hostClass {
	case ForwarderHostAndroid:
		settings.CompileMemoryMaxByteCount = 16 * 1024 * 1024
		settings.CompileHeapCeilingByteCount = 0
	case ForwarderHostDesktop:
		settings.CompileMemoryMaxByteCount = 64 * 1024 * 1024
		settings.CompileHeapCeilingByteCount = 0
		settings.FreeMemoryAfterCompile = false
	}
	return settings
}

// Refuses settings a forwarding role cannot run by.
func (self *ForwarderSettings) Validate() error {
	switch {
	case self.CompileDelay < 0 || self.CompileMinInterval < 0:
		return fmt.Errorf("%w: a forwarder's compile delay or interval is negative", errInvalidSettings)
	case self.CompileRetryInterval <= 0 || self.CompileRetryMaxInterval < self.CompileRetryInterval:
		return fmt.Errorf("%w: a forwarder's compile retry interval", errInvalidSettings)
	case self.CompileEstimateRowsFactor < 1 || self.CompileEstimateHeadFactor < 1 || self.CompileEstimateStateFactor < 0 || self.CompileEstimateOverheadByteCount < 0:
		return fmt.Errorf("%w: a forwarder's compile estimate", errInvalidSettings)
	case self.CompileHeapCeilingByteCount < 0:
		return fmt.Errorf("%w: a forwarder's heap ceiling is negative", errInvalidSettings)
	case self.CompileApplyRunCount <= 0 || self.FollowPageMaxCount <= 0 || self.HeadCacheCount <= 0:
		return fmt.Errorf("%w: a forwarder's run, page or cache count", errInvalidSettings)
	case self.FollowInterval <= 0 || self.KeyWaitAlarmInterval <= 0 || self.CompileDeferredAlarmTimeout <= 0:
		return fmt.Errorf("%w: a forwarder's follow or alarm interval", errInvalidSettings)
	case self.FollowTimeout <= 0 || self.FollowRetryInterval <= 0 || self.FetchTimeout <= 0:
		return fmt.Errorf("%w: a forwarder's follow or fetch timeout", errInvalidSettings)
	case self.BindingRetainTimeout <= 0 || self.BindingMaxCount <= 0 || self.BindingFetchMaxCount < 0:
		return fmt.Errorf("%w: a forwarder's binding bounds", errInvalidSettings)
	}
	return nil
}

// What a compile would read, in bytes, as the store holds it.
type ForwarderCompileSize struct {
	// The rows-only log's rows at its newest base.
	RowsByteCount int64
	// The head the compile reads.
	HeadByteCount int64
	// The entries after the newest base.
	TailByteCount int64
	// The last compiled state, 0 before the first.
	StateByteCount int64
}

// What the admission rule decides for one compile.
type ForwarderCompileAdmission int

const (
	// The compile may run now.
	ForwarderCompileAdmitted ForwarderCompileAdmission = iota + 1
	// The heap ceiling defers it: retried at CompileRetryInterval, compile_deferred after CompileDeferredAlarmTimeout.
	ForwarderCompileDeferred
	// Its estimate is past the cap: it never runs on this device, compile_over_budget.
	ForwarderCompileOverBudget
)

// A compile's estimated memory (the file's comment). A negative size, or a sum past int64, is the largest estimate, so
// a size nothing could hold is refused.
func (self *ForwarderSettings) CompileEstimate(size ForwarderCompileSize) int64 {
	const most = int64(1<<63 - 1)
	estimate := self.CompileEstimateOverheadByteCount
	for _, term := range [][2]int64{
		{self.CompileEstimateRowsFactor, size.RowsByteCount},
		{self.CompileEstimateHeadFactor, size.HeadByteCount},
		{1, size.TailByteCount},
		{self.CompileEstimateStateFactor, size.StateByteCount},
	} {
		factor, byteCount := term[0], term[1]
		if byteCount < 0 || factor < 0 || estimate < 0 {
			return most
		}
		if factor != 0 && (most-estimate)/factor < byteCount {
			return most
		}
		estimate += factor * byteCount
	}
	return estimate
}

// The admission rule for one compile, with the process's heap in use now: over budget past the cap whatever the
// heap, deferred where the heap and the estimate together pass the ceiling, else admitted.
func (self *ForwarderSettings) CompileAdmission(size ForwarderCompileSize, heapInUseByteCount int64) ForwarderCompileAdmission {
	estimate := self.CompileEstimate(size)
	if self.CompileMemoryMaxByteCount < estimate {
		return ForwarderCompileOverBudget
	}
	if 0 < self.CompileHeapCeilingByteCount && (heapInUseByteCount < 0 || self.CompileHeapCeilingByteCount-estimate < heapInUseByteCount) {
		return ForwarderCompileDeferred
	}
	return ForwarderCompileAdmitted
}

// How long a compile waits before its retryCount-th retry, from 0: CompileRetryInterval doubling to
// CompileRetryMaxInterval.
func (self *ForwarderSettings) CompileRetryTimeout(retryCount int) time.Duration {
	timeout := self.CompileRetryInterval
	for range max(retryCount, 0) {
		if self.CompileRetryMaxInterval <= timeout {
			break
		}
		timeout *= 2
	}
	return min(timeout, self.CompileRetryMaxInterval)
}

// What the sink's posture has in force, as its producer reads it.
type BridgeSinkState int

const (
	// No Pending yet: today's behavior.
	BridgeSinkLegacy BridgeSinkState = iota + 1
	// Anchored and denying every private destination and exit, with no verified state, or forked.
	BridgeSinkPending
	// A verified state in force.
	BridgeSinkEnforcing
)

// A narrowing entry the sink's posture could not check and no compile has judged within its timeout (DESIGN-DETAILS
// 4.2.5; QD-621, QD-696): a report, which nothing enforces.
type BridgeSinkOverdue struct {
	// The oldest waiting entry's position, or at an entry's own alarm that entry's.
	N uint64
	// How long it has waited.
	Age time.Duration
	// Whether the Decision call that answered this raised the posture's alarm for it, so its reader raises
	// bridge_alarm narrowing_overdue once.
	Raised bool
}

// What the sink holds, which its producer's catch-up, follows and compiles read.
type BridgeSinkDecision struct {
	State BridgeSinkState
	// The newest verified pin the sink holds: its state's, or past it the newest entry it applied. Nil before one.
	Pin *bridge.AuthPin
	// The pin of the state in force, nil before one.
	StatePin *bridge.AuthPin
	// Whether the sink holds a fork the sidecar role reported.
	Fork bool
	// Whether the sink's last ApplyDeltas took an entry it did not apply as a denial, an opening, a neutral or a
	// waiting one, which only a compile can judge. A sink whose producer judges every entry itself leaves it false.
	CompileWanted bool
	// How many narrowing entries above the state's pin wait for a compile.
	WaitingCount int
	// When the sink's posture next raises an alarm if no state has judged what waits by then, zero for never: its
	// producer reads Decision again at that time.
	NextAlarmAt time.Time
	// Set while a waiting entry is past its timeout.
	Overdue *BridgeSinkOverdue
}

// A run of the authorization log, device.PostureLog's shape at the root, which never links device/ (§4.4).
type BridgeStateLog struct {
	// AuthEntry bytes, verbatim, at consecutive positions, oldest first.
	Entries [][]byte
	// Streams the ProjectionRows a base among Entries names. Nil when no base is among them.
	OpenRows func(rowsSha256 []byte) (io.ReadCloser, error)
}

// What device.Bridge is to the Forwarder, through sdk (DESIGN-DETAILS 4.2.5): the posture's five calls. The Forwarder
// calls it from one goroutine. Decision is where the posture raises a narrowing entry's alarm, so the Forwarder reads
// it at each NextAlarmAt.
type ForwarderSink interface {
	// legacy -> pending, with the anchor a hand-off carried.
	SetPending(pending *bridge.Pending) error
	// A compiled state, with the log run from its newest base through its pin. A state below the one in force is
	// dropped, which is no error.
	SetState(state *bridge.BridgeState, log *BridgeStateLog) error
	// The entries after the sink's pin, which it verifies and applies as denials where it can.
	ApplyDeltas(log *BridgeStateLog) error
	// The app's sidecar role, a full reader, found a base that does not compile from its head, or cleared it.
	SetFork(fork bool) error
	Decision() BridgeSinkDecision
}

// One network's forwarding records, sealed, in the VPN component's own container (DESIGN-DETAILS 4.2.2's store):
// SidecarStore's calls without its directories, so a SidecarStore is one. A name is a relative path with / between
// segments, and the Forwarder owns the layout under it (bridge_forward_follow.go). Open answers ErrSidecarStoreAbsent,
// bare or wrapped, only when nothing is stored under the name. Safe for concurrent use.
type ForwarderStore interface {
	Open(name string) (io.ReadCloser, error)
	// Starts replacing name; nothing shows until Commit, so a kill leaves the old record or the new one.
	Create(name string) (SidecarStoreWriter, error)
	// Absent is not an error.
	Remove(name string) error
	// Each record whose name starts with prefix, sorted by name.
	List(prefix string) ([]SidecarStoreEntry, error)
}

// One reader key of the component's: the X-Wing private key a forwarding Delegation's DelegationWraps are sealed to.
type ForwarderReaderKey struct {
	// The forwarding Delegation that names the key's public half.
	DelegationId [sha256.Size]byte
	PrivateKey   hpke.PrivateKey
}

// The component's forwarding key sets as the Forwarder uses them (DESIGN-DETAILS 4.2.2's key store, 4.2.6's slots). The
// private halves stay behind it: nothing here crosses to the sidecar role (KeysStayPut). Safe for concurrent use.
type ForwarderKeys interface {
	// The current slot's forwarding Delegation and the Ed25519 public key it names; false while no key set is
	// current, which signs nothing.
	Delegation() (delegationId [sha256.Size]byte, publicKey ed25519.PublicKey, ok bool)
	// Signs message with the current slot's forwarding private key.
	Sign(message []byte) ([]byte, error)
	// The reader keys handed off so far, the current slot's first and then the next slot's, which a newer Delegation
	// names before it is promoted (4.2.6's C7 to C8). None before the first hand-off.
	ReaderKeys() ([]ForwarderReaderKey, error)
}

// What the Forwarder reads of gkm, with the forwarding client's token: *GkmApi is one.
type ForwarderGkm interface {
	// The Signed GenRotates after a generation, in order.
	Generations(ctx context.Context, repoId Id, groupId Id, since uint64) (*protocol.GkmGenerationsReply, error)
	// A recipient's deliveries of one generation.
	Wraps(ctx context.Context, repoId Id, groupId Id, generation uint64, query *GkmWrapsQuery) (*protocol.GkmWrapsReply, error)
}

// What a Forwarder is built over.
type ForwarderArgs struct {
	NetworkId Id
	// S: the sidecar whose forwarding role this is, which every state is compiled for.
	SidecarId Id
	// The anchor a hand-off carried (4.2.6's C7): the sink is set pending with it while it is legacy, and a genesis
	// api serves must hash to its genesis_sha256. Required.
	Pending *bridge.Pending
	// The config repo and its group at gkm, from the hand-off.
	ConfigRepoId  Id
	ConfigGroupId Id
	// GET /network/config/projection with the forwarding client's token. Required.
	Projection ConfigProjectionReader
	// Reads the config head a base names, with the keys RepoKeyAt answers. Nil reads none: a network past its first
	// base then never compiles, and the sink stays as its posture has it.
	Heads ConfigHeadReader
	// Nil opens no generation, so every sealed body stays pending.
	Gkm ForwarderGkm
	// GET /sidecar/identity/<sidecar_id>'s current binding as api signed it, which the Forwarder verifies under the
	// identity key its judged state admits. Nil fetches none, so every link waits.
	Binding func(ctx context.Context, sidecarId Id) ([]byte, error)
	// Whether the forwarding client's credential has lapsed (4.2.6's lapsed): read when a follow fails. Nil never.
	ClientLapsed func() bool
	Store        ForwarderStore
	Keys         ForwarderKeys
	Sink         ForwarderSink
	// The zones the names answer under (§12.9), and the labels the zone publishes, which no client name shadows.
	NameZones      []string
	PublishedNames func() []string
	// The process's heap in use, for the admission rule. Nil reads the runtime's.
	HeapInUse func() int64
	// Raises bridge_alarm and head_alarm. Nil drops them.
	Emit     SidecarEventFunction
	Clock    Clock
	Log      Logger
	Settings *ForwarderSettings
}

// What a status reads of the Forwarder.
type ForwarderStatus struct {
	// The sink's decision as the Forwarder last read it.
	Decision BridgeSinkDecision
	// The newest entry in the store, nil before one.
	Tip *bridge.AuthPin
	// The newest compile the sink took: its pin, its digest, and its sidecar's forwarding Delegation live at that
	// state, which a key set is promoted by (4.2.6's C8). Nil and zero before one.
	CompiledPin         *bridge.AuthPin
	Digest              [sha256.Size]byte
	ForwardDelegationId []byte
	// What the newest compile waited for, and the alarms standing now.
	Waits  []BridgeCompileWait
	Alarms []BridgeAlarm
	// The newest compile's admission, zero before one, and the generations the store holds a key of.
	Admission       ForwarderCompileAdmission
	GenerationCount int
	// Follows and compiles since the Forwarder started: compiles handed to the sink, compiles that failed, and
	// compiles the admission rule refused or deferred.
	FollowCount         uint64
	CompileCount        uint64
	CompileErrorCount   uint64
	CompileRefusedCount uint64
}

// A hint as the loop reads it: each one moves seq, position is the highest named, and zeroSeq the seq of the last
// that named none.
type forwarderHint struct {
	seq      uint64
	position uint64
	zeroSeq  uint64
}

// How long a generation's key has been missing.
type forwarderKeyWait struct {
	since     time.Time
	alarmedAt time.Time
}

// The Forwarder (the file's comment).
type Forwarder struct {
	args     *ForwarderArgs
	settings *ForwarderSettings
	clock    Clock
	log      Logger

	ctx    context.Context
	cancel context.CancelFunc
	// closed when run returns
	done chan struct{}

	// work a caller hands the loop: a witness
	requests chan func()
	hint     *MonitorValue[forwarderHint]
	records  *forwarderRecords
	bindings *BridgeBindingCache
	lateAsks *GkmLateAsks

	stateLock sync.Mutex
	// what run owns, read by Status, LinkTargets and RepoKeyAt under stateLock
	decision       BridgeSinkDecision
	tip            *bridge.AuthPin
	compiled       *forwarderCompiled
	waits          []BridgeCompileWait
	alarms         []BridgeAlarm
	admission      ForwarderCompileAdmission
	generations    int
	followCount    uint64
	compileCount   uint64
	compileErrors  uint64
	compileRefused uint64

	// owned by run alone
	hintSeen          uint64
	followWanted      bool
	followAt          time.Time
	followRetryCount  int
	compileWanted     bool
	compileWantedAt   time.Time
	compileLastAt     time.Time
	compileRetryAt    time.Time
	compileRetryCount int
	// when the heap ceiling first deferred the compile now wanted, zero while none is deferred
	deferredSince time.Time
	keyWaits      map[uint64]*forwarderKeyWait
	// the generations the last compile waited for beside its unopened bodies
	wantedGenerations []uint64
	// the sink's next alarm time not yet read at
	sinkAlarmAt    time.Time
	bindingsLoaded bool
	// the alarms the last compile's state raised, so a repeat is not raised again
	raisedCompileAlarms []BridgeAlarm
}

// A Forwarder over args, its goroutine started, following at once. The network, the sidecar, the anchor, the
// projection reader, the store, the keys and the sink are required.
func NewForwarder(ctx context.Context, args *ForwarderArgs) (*Forwarder, error) {
	if args == nil || args.NetworkId == (Id{}) || args.SidecarId == (Id{}) || args.Pending == nil || args.Projection == nil ||
		args.Store == nil || args.Keys == nil || args.Sink == nil {
		return nil, fmt.Errorf("%w: a forwarder needs its network, sidecar, anchor, projection, store, keys and sink", errInvalidSettings)
	}
	if !slices.Equal(args.Pending.GetNetworkId(), args.NetworkId.Bytes()) || len(args.Pending.GetGenesisSha256()) != sha256.Size {
		return nil, fmt.Errorf("%w: a forwarder's anchor names another network or no genesis", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultForwarderSettings(ForwarderHostApple)
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Forwarder{
		args:     args,
		settings: settings,
		clock:    clockOrReal(args.Clock),
		log:      loggerOrDefault(args.Log),
		ctx:      cancelCtx,
		cancel:   cancel,
		done:     make(chan struct{}),
		requests: make(chan func()),
		hint:     NewMonitorValue(forwarderHint{}),
		records:  &forwarderRecords{store: args.Store},
		bindings: NewBridgeBindingCache(settings.BindingRetainTimeout, settings.BindingMaxCount),
		lateAsks: NewGkmLateAsks(settings.Gkm),
		keyWaits: map[uint64]*forwarderKeyWait{},
	}
	go self.run()
	return self, nil
}

// A team hint: the log holds an entry at position, 0 for one that names none. Never blocks.
func (self *Forwarder) ReceiveHint(position uint64) {
	self.hint.Update(func(hint forwarderHint) forwarderHint {
		hint.seq += 1
		hint.position = max(hint.position, position)
		if position == 0 {
			hint.zeroSeq = hint.seq
		}
		return hint
	})
}

// The app's sidecar role, a full reader, witnessed pin, and found a fork or none (DESIGN-DETAILS 4.2.5's Witness): the
// Forwarder follows up to it, raises head_alarm where the pin is off its chain or api serves less, and sets the
// sink's fork, which holds it pending with no compile until a witness with fork false. Returns once the loop has
// applied it, which waits behind a compile in flight.
func (self *Forwarder) Witness(pin *bridge.AuthPin, fork bool) error {
	return self.onRun(func() {
		self.witness(pin, fork)
	})
}

// What the Forwarder holds, for a status.
func (self *Forwarder) Status() ForwarderStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := ForwarderStatus{
		Decision:            self.decision,
		Tip:                 self.tip,
		Waits:               slices.Clone(self.waits),
		Alarms:              slices.Clone(self.alarms),
		Admission:           self.admission,
		GenerationCount:     self.generations,
		FollowCount:         self.followCount,
		CompileCount:        self.compileCount,
		CompileErrorCount:   self.compileErrors,
		CompileRefusedCount: self.compileRefused,
	}
	if self.compiled != nil {
		status.CompiledPin = &bridge.AuthPin{Version: self.compiled.PinVersion, Chain: slices.Clone(self.compiled.PinChain)}
		copy(status.Digest[:], self.compiled.Digest)
		status.ForwardDelegationId = slices.Clone(self.compiled.ForwardDelegationId)
	}
	return status
}

// The sidecars the state in force links to, and false while none the Forwarder compiled is in force: what its
// signer signs for (ForwardingSignerArgs.LinkTargets).
func (self *Forwarder) LinkTargets() ([]Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.compiledInForceWithLock() {
		return nil, false
	}
	return slices.Clone(self.compiled.LinkTargets), true
}

// Whether the newest compile the sink took is the state it has in force, as the Forwarder last read its decision.
func (self *Forwarder) compiledInForceWithLock() bool {
	statePin := self.decision.StatePin
	return self.compiled != nil && self.decision.State == BridgeSinkEnforcing && !self.decision.Fork &&
		statePin.GetVersion() == self.compiled.PinVersion && slices.Equal(statePin.GetChain(), self.compiled.PinChain)
}

// Stops the Forwarder and waits for its goroutine. The sink keeps what it has in force.
func (self *Forwarder) Close() {
	self.cancel()
	<-self.done
}

// Runs work on the loop's goroutine and waits for it.
func (self *Forwarder) onRun(work func()) error {
	ran := make(chan struct{})
	select {
	case self.requests <- func() {
		defer close(ran)
		work()
	}:
	case <-self.ctx.Done():
		return ErrForwarderClosed
	}
	select {
	case <-ran:
		return nil
	case <-self.done:
		return ErrForwarderClosed
	}
}

// The loop that owns every call into the sink and the store (the file's comment).
func (self *Forwarder) run() {
	defer close(self.done)
	self.start()
	for {
		hint, hintChanged := self.hint.Get()
		if hint.seq != self.hintSeen {
			if self.hintSeen < hint.zeroSeq || self.tipVersion() < hint.position {
				self.followWanted = true
			}
			self.hintSeen = hint.seq
		}
		if self.ctx.Err() != nil {
			return
		}
		now := self.clock.Now()
		if self.followWanted || !self.followAt.After(now) {
			self.followWanted = false
			self.followNow()
			continue
		}
		wake := self.followAt
		if self.compileWanted {
			due := self.compileDueAt()
			if !due.After(now) {
				self.compileNow()
				continue
			}
			wake = earlierTime(wake, due)
		}
		if !self.sinkAlarmAt.IsZero() {
			if !self.sinkAlarmAt.After(now) {
				// where the posture raises its alarm (4.2.5); a time it answers again that has passed is not read at twice
				self.sinkAlarmAt = time.Time{}
				if decision := self.readDecision(); !decision.NextAlarmAt.After(now) {
					self.sinkAlarmAt = time.Time{}
				}
				continue
			}
			wake = earlierTime(wake, self.sinkAlarmAt)
		}
		select {
		case <-self.ctx.Done():
			return
		case work := <-self.requests:
			work()
		case <-hintChanged:
		case <-self.clock.After(wake.Sub(now)):
		}
	}
}

// When the wanted compile may start: CompileDelay after it was wanted, CompileMinInterval after the last one started,
// and no sooner than a retry's wait.
func (self *Forwarder) compileDueAt() time.Time {
	due := self.compileWantedAt.Add(self.settings.CompileDelay)
	due = laterTime(due, self.compileLastAt.Add(self.settings.CompileMinInterval))
	return laterTime(due, self.compileRetryAt)
}

// The later of two times.
func laterTime(a time.Time, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// The earlier of two times.
func earlierTime(a time.Time, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// Before the first follow: the sink anchored while it is legacy, and the last compile the store records, which a
// restart signs by once the sink shows its state in force.
func (self *Forwarder) start() {
	if decision := self.readDecision(); decision.State == BridgeSinkLegacy {
		testHookBarrier("bridge_forward.pending.before", self.args.NetworkId.String())
		if err := self.args.Sink.SetPending(self.args.Pending); err != nil {
			self.log.Warningf("[forward]%s the device role refused its anchor: %v", self.args.NetworkId, err)
		}
		self.readDecision()
	}
	compiled, err := self.records.compiled()
	if err != nil {
		self.log.Warningf("[forward]%s the last compile's record did not read: %v", self.args.NetworkId, err)
	}
	tip, err := self.records.tip()
	if err != nil {
		self.log.Warningf("[forward]%s the stored log did not read: %v", self.args.NetworkId, err)
	}
	generations, err := self.records.generations()
	if err != nil {
		self.log.Warningf("[forward]%s the stored generations did not list: %v", self.args.NetworkId, err)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.compiled = compiled
		self.tip = tip
		self.generations = len(generations)
	}()
	self.followWanted = true
	self.followAt = self.clock.Now().Add(self.settings.FollowInterval)
	if decision := self.readDecision(); decision.State == BridgeSinkEnforcing && !self.compiledInForce() {
		// a state in force with no record of its compile, as a kill between the two leaves: compiled again, so the
		// signer has a state to sign by
		self.wantCompile()
	}
}

// compiledInForceWithLock, taking the lock.
func (self *Forwarder) compiledInForce() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.compiledInForceWithLock()
}

// The newest stored entry's position, 0 for none.
func (self *Forwarder) tipVersion() uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tip.GetVersion()
}

// Reads the sink's decision, keeps it for Status and the signer, and raises what it reports: every read of the
// decision goes through here, since a read is where the posture raises a narrowing entry's alarm. On run's goroutine.
func (self *Forwarder) readDecision() BridgeSinkDecision {
	decision := self.args.Sink.Decision()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.decision = decision
	}()
	self.sinkAlarmAt = decision.NextAlarmAt
	if overdue := decision.Overdue; overdue != nil && overdue.Raised {
		self.emitAlarm(BridgeAlarm{
			Reason: SidecarBridgeAlarm(ForwarderAlarmNarrowingOverdue),
			N:      overdue.N,
			Detail: fmt.Sprintf("a narrowing entry has waited %s for a compile", overdue.Age),
		})
	}
	if decision.Overdue == nil {
		self.clearAlarm(SidecarBridgeAlarm(ForwarderAlarmNarrowingOverdue))
	}
	return decision
}

// Marks a compile wanted, coalescing with one already wanted. On run's goroutine.
func (self *Forwarder) wantCompile() {
	if !self.compileWanted {
		self.compileWanted = true
		self.compileWantedAt = self.clock.Now()
	}
}

// Raises one bridge_alarm, and holds it standing for Status until cleared.
func (self *Forwarder) emitAlarm(alarm BridgeAlarm) {
	self.log.Warningf("[forward]%s %s at %d: %s", self.args.NetworkId, alarm.Reason, alarm.N, alarm.Detail)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.alarms = slices.DeleteFunc(self.alarms, func(standing BridgeAlarm) bool { return standing.Reason == alarm.Reason })
		self.alarms = append(self.alarms, alarm)
	}()
	if self.args.Emit == nil {
		return
	}
	event := SidecarEvent{Kind: SidecarEventBridgeAlarm, BridgeAlarm: alarm.Reason}
	if alarm.SidecarId != (Id{}) {
		sidecarId := alarm.SidecarId
		event.SidecarId = &sidecarId
	}
	self.args.Emit(event)
}

// Raises alarm unless one of its reason stands already.
func (self *Forwarder) raiseAlarm(alarm BridgeAlarm) {
	if !self.alarmStanding(alarm.Reason) {
		self.emitAlarm(alarm)
	}
}

// Whether an alarm of the reason stands.
func (self *Forwarder) alarmStanding(reason SidecarBridgeAlarm) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.ContainsFunc(self.alarms, func(standing BridgeAlarm) bool { return standing.Reason == reason })
}

// The condition behind an alarm ended.
func (self *Forwarder) clearAlarm(reason SidecarBridgeAlarm) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.alarms = slices.DeleteFunc(self.alarms, func(standing BridgeAlarm) bool { return standing.Reason == reason })
}

// Raises head_alarm with this device's pin and the other, as §6.5 encodes them.
func (self *Forwarder) emitHeadAlarm(kind SidecarHeadAlarm, local *bridge.AuthPin, remote *bridge.AuthPin) {
	self.log.Errorf("[forward]%s head_alarm %s: this device at %d, the other at %d", self.args.NetworkId, kind, local.GetVersion(), remote.GetVersion())
	if self.args.Emit == nil {
		return
	}
	event := SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: kind}
	event.Evidence[0], _ = forwarderMarshal(local)
	event.Evidence[1], _ = forwarderMarshal(remote)
	self.args.Emit(event)
}

// The process's heap in use: the host's reading, or the runtime's.
func (self *Forwarder) heapInUse() int64 {
	if self.args.HeapInUse != nil {
		return self.args.HeapInUse()
	}
	stats := &runtime.MemStats{}
	runtime.ReadMemStats(stats)
	return int64(min(stats.HeapInuse, uint64(1<<63-1)))
}

// What the Forwarder holds, for a log line: never a prefix, an address, a name or a key.
func (self *Forwarder) String() string {
	status := self.Status()
	return fmt.Sprintf("forwarder{network %s, tip %d, compiled %d, %d compiles}", self.args.NetworkId, status.Tip.GetVersion(), status.CompiledPin.GetVersion(), status.CompileCount)
}
