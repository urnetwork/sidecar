// ConfigWriter (TEAM-M2-09): a config writer's side of §7.9's log, on an AdminSet member's member device that is not
// read_only. It saves config heads to the config repo's file-mode main ref and publishes the base that names each, as
// DESIGN-DETAILS 5.2.4's WriterPublishBase says:
//
//	fold     folded_through is the previous base's, or the tip when folding, and always the tip once the tail would
//	         pass 4,096 entries; a fold saves a head holding the entries in (the previous fold, the tip] as records,
//	         BASE entries included
//	compile  rows = compile(head, L(folded_through)), L the previous base's rows when the fold did not move, else this
//	         device's state at folded_through, the open proposals and the replay ring with it
//	verdicts tail_verdicts carries this device's own verdict at every tail position, which it held as a reader
//	shrinks  shrunk_repo_ids the repos whose key holders the base's own change shrinks, from the tip's state and the
//	         one the base gives, at this device's clock, computed again at every re-sign (QD-746)
//	publish  POST /network/config/projection {Signed ProjectionHeader, rows, config_pushes}; on 409 the device catches
//	         up and re-signs at the new tip, keeping its fold and its compile while folded_through stays within 1,024
//	         of the tip and no other base landed, so a stream of statements never starves it; a base that landed
//	         meanwhile replans from its rows, so no stale compile is signed
//
// The fold loop (run) folds once the oldest unfolded statement or tick is 1,024 positions behind the tip or 24 h old,
// at once at a start after being offline, after a random delay of up to 10 min that another base cancels. A config
// head with no base, saved by a writer that never published, shows as pending, and after 10 min this writer publishes
// its base, as any config writer may.
//
// SaveHead is the path every other change to the config repo goes through: SOCK's K_sock file and §17's bridge files
// edit the head, which saves with the fold where it is and lands as a base.
//
// A head that holds no bridge block, an older network's or one bootstrapped before the bridge shipped, gets the
// network's first from this writer's next head, whatever saves it, and a block whose signer no longer stands is signed
// again there, through BridgeBlock, whichever head and bases carried it since (§17.4's first block row; QD-1205).
// SaveBridgeBlock saves a head for that alone, as a revocation's own flow does on the device that made it, so the
// re-sign comes at once even where no other save follows, as in ur daemon, whose one writer saves only what a person
// confirmed (ConfigClient.ConfirmedWriter).
//
// It signs heads, bases and that block only; statements are CORE's acts (C-01). The clock, the delay's randomness and
// the block's draw come through ConfigWriterSettings, so a test steers all three. Every leg, no connect type. Safe for
// concurrent use; one publish runs at a time.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// This device writes no config head at the newest state: not a config writer, an ephemeral sidecar, or a log
	// that stopped at a fork.
	ErrConfigWriterNotWriter = errors.New("config writer: not a config writer here")
	// The config repo's ref moved since the head was read: read it again and save on top.
	ErrConfigHeadConflict = errors.New("config head conflict")
	// The base did not land within ConfigWriterSettings.PublishAttemptCount re-signs: the tip kept moving, or api kept
	// finding other shrinks at its time than this device's clock gave (QD-746).
	ErrConfigWriterGaveUp = errors.New("config writer: the tip kept moving")
	// A base would keep both the newest base's fold and its head: it says nothing new, so none is published.
	ErrConfigWriterNothing = errors.New("config writer: nothing new to publish")
)

// A head push signed and not yet sent: what a base names and carries before its head lands (plan-TEAM-api-config-head-
// reach #2, #4).
type ConfigHeadPush struct {
	// A native writer holds the sealed request, including any parts and receipts, until commit.
	deliver func(ctx context.Context, networkId Id, repoId Id) error
	Head    *ConfigHead
	// The ref's version after the push, and its chain value C_v, which a base names as config_head_sha256.
	Version uint64
	Chain   [sha256.Size]byte
	// The Signed EvsPush, which a base's config_pushes carries.
	SignedPush []byte
	// The push's one-part payload, which the commit posts beside SignedPush: EvsClient's config kind fills it
	// (evs_config_push.go); nil for a ref that keeps its own.
	Payload []byte
}

// A confirmed edit compares the signed parent with the exact head it previewed.
func (self *ConfigHeadPush) extends(version uint64, chain [sha256.Size]byte) bool {
	signed, statement := &bridge.Signed{}, &protocol.EvsPush{}
	return self != nil && self.Version == version+1 && proto.Unmarshal(self.SignedPush, signed) == nil &&
		signed.GetType() == uint32(bridge.SignedType_SIGNED_EVS_PUSH) && proto.Unmarshal(signed.GetBody(), statement) == nil &&
		statement.GetBaseVersion() == version && bytes.Equal(statement.GetBaseChain(), chain[:])
}

// The current verified main-ref head, including a pending head that no base names yet.
type ConfigHeadTipReader interface {
	// A nil head at version 0 before the first push.
	CurrentConfigHead(ctx context.Context) (*ConfigHead, uint64, [sha256.Size]byte, error)
}

// A verified config ref position. A native EVS reader also reports whether the host that
// answered its fresh read enforces the signed exact-head flag.
type ConfigHeadTip struct {
	Head              *ConfigHead
	Version           uint64
	Chain             [sha256.Size]byte
	SupportsExactHead bool
}

// A host can supply an exact ref only for explicitly confirmed ACL edits. The ordinary
// follower keeps its existing head reader and never runs its periodic writer on this ref.
type ConfirmedAclConfigRefProvider interface {
	ConfirmedAclConfigRef() ConfigHeadRef
}

// The config repo's file-mode main ref as a writer saves heads to it (§11.8).
type ConfigHeadRef interface {
	ConfigHeadTipReader
	// Signs, and does not send, the push that makes head the ref's version after version: its Signed EvsPush and the
	// chain value it gives.
	PrepareConfigHead(ctx context.Context, head *ConfigHead, version uint64) (*ConfigHeadPush, error)
	// Sends a prepared push: ErrConfigHeadConflict when the ref moved since. A push already applied is success.
	CommitConfigHead(ctx context.Context, push *ConfigHeadPush) error
	// The Signed EvsPush of each version in (after, through], oldest first, which a base adding them carries.
	ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error)
}

// One base as POST /network/config/projection takes it.
type ConfigBasePublish struct {
	SignedHeader []byte
	Rows         []byte
	// The Signed Genesis, base 1's alone (plan-TEAM-genesis-custody #2).
	Genesis []byte
	// The Signed EvsPush of each config version the base adds (plan-TEAM-api-config-head-reach).
	ConfigPushes [][]byte
}

// Where a config writer publishes bases: SidecarApi.PostConfigProjection, or a test's fake api. ErrConfigTipMoved for
// api's 409, after which the writer re-signs; an ErrConfigRefused for its 403.
type ConfigBasePublisher interface {
	PublishConfigBase(ctx context.Context, base *ConfigBasePublish) (*bridge.AuthPin, error)
}

// Signs a record or base by this device's identity key: Sidecar.Sign with no agent.
type ConfigSignFunction func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error)

// Tunables of a ConfigWriter. §7.9's 4,096-entry tail cap is a protocol constant, not these.
type ConfigWriterSettings struct {
	// §7.9's fold row: fold once the oldest unfolded statement or tick is this many positions behind the tip, 1,024,
	// or this old, 24 h.
	FoldEntryCount int
	FoldAge        time.Duration
	// The most a due fold waits before publishing, a random fraction of it, so two writers rarely race: 10 min.
	// Another base landing meanwhile cancels it. Non-positive publishes at once.
	FoldDelayMax time.Duration
	// A head saved with no base past this long is published by this writer (§7.9's state row): 10 min.
	PendingHeadTimeout time.Duration
	// How often the loop looks again with nothing landing: 1 min, so a pending head and a fold due by age are seen
	// within it.
	CheckInterval time.Duration
	// How many times a publish re-signs after api's 409 before it gives up until the next pass: 16.
	PublishAttemptCount int
	// How long one publish may take: 60 s.
	PublishTimeout time.Duration
	// How many times SaveBridgeBlock tries: 4. A try after another writer's head landed at the ref first reads the head
	// that landed, so one that leaves the block nothing to do ends it. Non-positive tries once.
	BridgeBlockAttemptCount int
	// How long SaveBridgeBlock waits before trying again after an answer that refuses nothing (a 429 or 503 from gkm or
	// evs) or gkm's wait: 2 s, the time a gate takes to load the revocation its hint names. Non-positive tries again at
	// once.
	BridgeBlockRetryWait time.Duration
	// The fold delay's randomness, a fraction in [0, 1). Nil is crypto/rand.
	Random func() float64
	// The first bridge block's draw (ConfigWriterArgs.BridgeBlock). Nil is crypto/rand's reader.
	BridgeBlockRandom io.Reader
	// The clock; nil is real time.
	Clock Clock
	// Ids only (I-13). Nil is the leg's default.
	Log Logger
}

// §7.9's values.
func DefaultConfigWriterSettings() *ConfigWriterSettings {
	return &ConfigWriterSettings{
		FoldEntryCount:          1024,
		FoldAge:                 24 * time.Hour,
		FoldDelayMax:            10 * time.Minute,
		PendingHeadTimeout:      10 * time.Minute,
		CheckInterval:           time.Minute,
		PublishAttemptCount:     16,
		PublishTimeout:          60 * time.Second,
		BridgeBlockAttemptCount: 4,
		BridgeBlockRetryWait:    2 * time.Second,
	}
}

// The bridge ledger's fold a writer's plan calls (FoldBridgeLedger, DESIGN-DETAILS 12.2.3): the ledger files of a head
// folded through foldedThrough from previous, the head being extended, and state, the writer's tip, with entryTimeMs
// answering the entries the fold holds. It answers the fold reached, which a body the writer could not open can hold
// below the one asked. BridgeBodyJudge.Fold is one.
type ConfigBridgeFold func(previous *ConfigHead, state *ConfigState, foldedThrough uint64, entryTimeMs func(n uint64) (int64, bool)) (*BridgeLedgerFold, error)

// The network's bridge block on a head a writer's plan is about to save (§17.4's first block row; QD-1205): head with
// the network's first block drawn with random where it holds none, or with the block every reader of state's newest
// base holds signed again where head carries its record and that record's signer no longer stands, each signed by sign
// and only where readers at state take sign's block; head itself otherwise. WithBridgeBlock is one.
type ConfigBridgeBlock func(state *ConfigState, head *ConfigHead, sign ConfigSignFunction, random io.Reader) (*ConfigHead, error)

// What a ConfigWriter runs on.
type ConfigWriterArgs struct {
	// This device, which signs heads and bases.
	SidecarId Id
	Sign      ConfigSignFunction
	// The verified state the writer stands on, which it catches up after a 409.
	Client    *ConfigClient
	Heads     ConfigHeadRef
	Publisher ConfigBasePublisher
	Settings  *ConfigWriterSettings
	// The bridge ledger's fold. Nil folds no bridge statement: a fold stops below the first one, or keeps the previous
	// fold where §7.9's fold rule does not allow that, so no head this writer saves misses its ledger.
	BridgeFold ConfigBridgeFold
	// The bridge block this writer's next head draws where a head holds none, or signs again where its signer no longer
	// stands, which the follower's writers take (WithBridgeBlock). Nil does neither: no writer runs on the ios_extension
	// legs, which link no block draw, and a network's block then waits for a writer that has one.
	BridgeBlock ConfigBridgeBlock
}

// One device's config writer.
type ConfigWriter struct {
	args     *ConfigWriterArgs
	settings *ConfigWriterSettings
	clock    Clock
	log      Logger
	random   func() float64

	ctx    context.Context
	cancel context.CancelFunc

	// one publish at a time
	publishLock sync.Mutex
	// a base landing, which cancels a fold's delay
	baseLanded chan struct{}
	// an entry landing, which may make a fold due
	entryLanded    chan struct{}
	removeCallback func()

	stateLock sync.Mutex
	// the newest head the store held with no base naming it, and since when this writer saw it
	pendingVersion uint64
	pendingSince   time.Time
}

// A writer on args, its fold loop started; a device that is no config writer runs it idle until it becomes one.
func NewConfigWriter(ctx context.Context, args *ConfigWriterArgs) (*ConfigWriter, error) {
	if args == nil || args.Client == nil || args.Heads == nil || args.Publisher == nil || args.Sign == nil {
		return nil, errors.New("config writer: missing args")
	}
	self := newConfigWriter(ctx, args)
	self.removeCallback = args.Client.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		if entry.Kind == bridge.AuthEntryKindBase {
			configSignal(self.baseLanded)
		}
		configSignal(self.entryLanded)
	})
	args.Client.writer.Store(self)
	go self.run()
	return self, nil
}

// A writer with no fold loop, for a confirmed ACL save, BootstrapNetwork and tests.
func newConfigWriter(ctx context.Context, args *ConfigWriterArgs) *ConfigWriter {
	settings := args.Settings
	if settings == nil {
		settings = DefaultConfigWriterSettings()
	}
	clock := settings.Clock
	if clock == nil {
		clock = RealClock{}
	}
	random := settings.Random
	if random == nil {
		random = configCryptoFraction
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	return &ConfigWriter{
		args:        args,
		settings:    settings,
		clock:       clock,
		log:         loggerOrDefault(settings.Log),
		random:      random,
		ctx:         cancelCtx,
		cancel:      cancel,
		baseLanded:  make(chan struct{}, 1),
		entryLanded: make(chan struct{}, 1),
	}
}

// Stops the fold loop. Safe to call again.
func (self *ConfigWriter) Close() {
	self.cancel()
	if self.removeCallback != nil {
		self.removeCallback()
	}
	self.args.Client.writer.CompareAndSwap(self, nil)
}

// A fraction in [0, 1) from crypto/rand.
func configCryptoFraction() float64 {
	var data [8]byte
	if _, err := cryptorand.Read(data[:]); err != nil {
		return 0
	}
	return float64(binary.BigEndian.Uint64(data[:])>>11) / float64(uint64(1)<<53)
}

// Signals a buffered channel without blocking.
func configSignal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}

// Saves a head edit makes from the current one, the fold where it is, and publishes its base: the path SOCK's K_sock
// file, §17's bridge files and every other config file a writer changes take. Answers the base's pin.
func (self *ConfigWriter) SaveHead(ctx context.Context, edit func(head *ConfigHead) (*ConfigHead, error)) (*bridge.AuthPin, error) {
	return self.publish(ctx, false, edit, nil)
}

// Publishes a base at the tip: folding through it when fold is set or the tail would pass the cap, else keeping the
// previous base's fold, over the store's current head, a pending one included. Answers the base's pin.
func (self *ConfigWriter) PublishBase(ctx context.Context, fold bool) (*bridge.AuthPin, error) {
	return self.publish(ctx, fold, nil, nil)
}

// Saves a head only for the network's bridge block, and publishes its base: its first drawn where the head holds none,
// or the block every reader holds signed again where its signer no longer stands (ConfigWriterArgs.BridgeBlock;
// QD-1205), as a revocation this device made needs at once (Sidecar.saveBridgeBlockAfter). Nil, with nothing saved,
// where the block needs neither, so it publishes no fold of its own, and where no BridgeBlock is installed. Up to
// BridgeBlockAttemptCount tries, each bounded by PublishTimeout: another writer's head landing at the ref first is read
// and planned on again at once, and an answer that refuses nothing, gkm's or evs's 429 or 503, or gkm's wait for a
// covering generation or for the log, is tried again after BridgeBlockRetryWait, since right after a revocation their
// gates may not have loaded it yet, which its hint brings. Answers the base's pin.
func (self *ConfigWriter) SaveBridgeBlock(ctx context.Context) (*bridge.AuthPin, error) {
	var last error
	for range max(self.settings.BridgeBlockAttemptCount, 1) {
		pin, err := func() (*bridge.AuthPin, error) {
			attemptCtx, cancel := context.WithTimeout(ctx, self.settings.PublishTimeout)
			defer cancel()
			return self.publishRequest(attemptCtx, &configWriterRequest{blockOnly: true})
		}()
		var transient interface{ RefusesNothing() bool }
		switch {
		case err == nil:
			return pin, nil
		case errors.Is(err, ErrConfigWriterNothing):
			return nil, nil
		case errors.Is(err, ErrConfigHeadConflict):
			last = err
			if err := self.args.Client.CatchUp(ctx); err != nil {
				return nil, err
			}
		case errors.As(err, &transient) && transient.RefusesNothing(), errors.Is(err, ErrGkmWait), errors.Is(err, ErrGkmAuthAhead):
			last = err
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-self.clock.After(self.settings.BridgeBlockRetryWait):
			}
		default:
			return nil, err
		}
	}
	return nil, last
}

// What one publish holds across re-signs: its fold, the head it names and the pushes that reach it, and the rows.
type configWriterPlan struct {
	// the base the plan stands on
	previousN     uint64
	foldedThrough uint64
	configVersion uint64
	headChain     [sha256.Size]byte
	pushes        [][]byte
	rows          []byte
	threshold     uint32
}

// What one publish asks of its plans.
type configWriterRequest struct {
	// fold through the tip, where the fold rule does not already
	fold bool
	// the change the first plan makes to the head, nil for none; a later plan re-reads the head it saved
	edit func(head *ConfigHead) (*ConfigHead, error)
	// the head a confirmed save previewed, which the plan must stand on; nil for whichever is current
	expected *ConfigHeadTip
	// the first plan saves a head only where the bridge block step changes it (SaveBridgeBlock), answering
	// ErrConfigWriterNothing otherwise, whatever the fold would do
	blockOnly bool
}

// One publish (DESIGN-DETAILS 5.2.4's WriterPublishBase), re-signing at each new tip up to PublishAttemptCount times.
func (self *ConfigWriter) publish(ctx context.Context, fold bool, edit func(head *ConfigHead) (*ConfigHead, error), expected *ConfigHeadTip) (*bridge.AuthPin, error) {
	return self.publishRequest(ctx, &configWriterRequest{fold: fold, edit: edit, expected: expected})
}

// The publish request asks for.
func (self *ConfigWriter) publishRequest(ctx context.Context, request *configWriterRequest) (*bridge.AuthPin, error) {
	self.publishLock.Lock()
	defer self.publishLock.Unlock()
	var plan *configWriterPlan
	for range max(self.settings.PublishAttemptCount, 1) {
		var err error
		plan, err = self.plan(ctx, plan, request)
		if err != nil {
			return nil, err
		}
		// the head the first plan saved holds its edit and its block
		request = &configWriterRequest{fold: request.fold, expected: request.expected}
		signedHeader, err := self.signBase(plan)
		if err != nil {
			return nil, err
		}
		pin, err := self.args.Publisher.PublishConfigBase(ctx, &ConfigBasePublish{SignedHeader: signedHeader, Rows: plan.rows, ConfigPushes: plan.pushes})
		if err == nil {
			if self.log.V(1).Enabled() {
				self.log.Infof("[config]%s published a base at %d folding through %d", self.args.Client.NetworkId(), pin.GetVersion(), plan.foldedThrough)
			}
			if _, err := self.args.Client.WaitFor(ctx, pin.GetVersion()); err != nil {
				return pin, err
			}
			return pin, nil
		}
		if !errors.Is(err, ErrConfigTipMoved) {
			return nil, err
		}
		// the tip moved: catch up and re-sign at the new tip
		if err := self.args.Client.CatchUp(ctx); err != nil {
			return nil, err
		}
	}
	return nil, ErrConfigWriterGaveUp
}

// The plan for a base at the client's tip. A plan from the attempt before is kept, its fold and compile, while no
// other base landed and its fold stays within FoldEntryCount of the tip; else the fold, the head and the rows are
// planned anew from the newest base.
func (self *ConfigWriter) plan(ctx context.Context, previous *configWriterPlan, request *configWriterRequest) (*configWriterPlan, error) {
	fold, edit, expected := request.fold, request.edit, request.expected
	state := self.args.Client.State()
	if state == nil {
		return nil, ErrConfigWriterNotWriter
	}
	if err := CheckConfigHeadWriter(state, self.args.SidecarId); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfigWriterNotWriter, err)
	}
	base := state.Base()
	if base == nil {
		return nil, fmt.Errorf("%w: no base yet, which BootstrapNetwork publishes", ErrConfigWriterNotWriter)
	}
	if previous != nil && previous.previousN == base.GetVersion() && state.n-previous.foldedThrough <= uint64(max(self.settings.FoldEntryCount, 1)) &&
		state.n-previous.foldedThrough <= configTailMax {
		return previous, nil
	}

	head, version, chain, err := self.args.Heads.CurrentConfigHead(ctx)
	if err != nil {
		return nil, err
	}
	if head == nil || version < base.GetConfigVersion() {
		return nil, fmt.Errorf("%w: the config repo holds version %d, below the newest base's %d", ErrConfigHeadConflict, version, base.GetConfigVersion())
	}
	if expected != nil {
		requiredVersion, requiredChain := expected.Version, expected.Chain
		if previous != nil {
			// The approved push already landed. Re-sign only for its result.
			requiredVersion, requiredChain = previous.configVersion, previous.headChain
		}
		if version != requiredVersion || chain != requiredChain {
			return nil, fmt.Errorf("%w: the confirmed config head moved", ErrConfigHeadConflict)
		}
	}

	// the fold and the records it adds, read under the client's follow lock: the log's kept entries are its follower's.
	// A bridge statement unfolded at the tip folds through it, so a filing stays unfolded across a base only when it
	// lands between this head's writing and the base's acceptance (DESIGN-DETAILS 12.2.3's writer rule)
	foldedThrough := base.GetFoldedThrough()
	if fold || configTailMax < state.n-foldedThrough || state.Bridge().Len() != 0 {
		foldedThrough = state.n
	}
	foldedThrough = max(foldedThrough, head.FoldedThrough())
	var records []ConfigFoldRecord
	var compileRows *ConfigCompileRows
	var ledgerFold *BridgeLedgerFold
	err = func() error {
		self.args.Client.followLock.Lock()
		defer self.args.Client.followLock.Unlock()
		log := self.args.Client.configLog.Load()
		if log == nil || log.State().n != state.n {
			return ErrConfigTipMoved
		}
		if fork := log.Fork(); fork != nil {
			return fmt.Errorf("%w: %w", ErrConfigWriterNotWriter, fork)
		}
		// the ledger at the fold, which can stop it below a body this writer could not open
		if head.FoldedThrough() < foldedThrough {
			var err error
			if ledgerFold, err = self.bridgeFold(head, state, foldedThrough, log.EntryTimeMs); err != nil {
				return err
			}
			foldedThrough = ledgerFold.FoldedThrough
		}
		known := false
		records, known = log.foldedRecords(head.FoldedThrough()+1, foldedThrough)
		if !known {
			return fmt.Errorf("the entries through %d are not all kept", foldedThrough)
		}
		var err error
		compileRows, err = log.foldRows(state, &bridge.ProjectionHeader{FoldedThrough: foldedThrough})
		return err
	}()
	if err != nil {
		return nil, err
	}

	// the head: the current one with the edit, the network's bridge block where it holds none or its signer no longer
	// stands, the bridge ledger and the fold, saved when any changes it
	next := head
	if edit != nil {
		if next, err = edit(next); err != nil {
			return nil, err
		}
	}
	if self.args.BridgeBlock != nil {
		edited := next
		if next, err = self.args.BridgeBlock(state, next, self.args.Sign, self.settings.BridgeBlockRandom); err != nil {
			return nil, err
		}
		if request.blockOnly && configHeadsEqual(next, edited) {
			// the block needs no head: the save asked for one only for it
			return nil, ErrConfigWriterNothing
		}
	} else if request.blockOnly {
		return nil, ErrConfigWriterNothing
	}
	if ledgerFold != nil {
		if next, err = ledgerFold.Apply(next); err != nil {
			return nil, err
		}
	}
	if next, err = next.WithFold(records, foldedThrough); err != nil {
		return nil, err
	}
	if !configHeadsEqual(next, head) {
		if previous != nil && expected != nil {
			return nil, fmt.Errorf("%w: publication now requires a further config head edit", ErrConfigHeadConflict)
		}
		push, err := self.args.Heads.PrepareConfigHead(ctx, next, version)
		if err != nil {
			return nil, err
		}
		// Prepare may read the ref again. Even at the same version a restored or forked
		// ref must never substitute another chain for the one whose files the edit saw.
		if expected != nil && !push.extends(version, chain) {
			return nil, fmt.Errorf("%w: the prepared push does not extend the selected version and chain", ErrConfigHeadConflict)
		}
		if err := self.args.Heads.CommitConfigHead(ctx, push); err != nil {
			return nil, err
		}
		version, chain = push.Version, push.Chain
	}
	if foldedThrough == base.GetFoldedThrough() && version == base.GetConfigVersion() {
		return nil, ErrConfigWriterNothing
	}
	pushes, err := self.args.Heads.ConfigHeadPushes(ctx, base.GetConfigVersion(), version)
	if err != nil {
		return nil, err
	}
	rows, err := CompileProjectionRows(next, compileRows)
	if err != nil {
		return nil, err
	}
	return &configWriterPlan{
		previousN:     base.GetVersion(),
		foldedThrough: foldedThrough,
		configVersion: version,
		headChain:     chain,
		pushes:        pushes,
		rows:          rows,
		threshold:     state.threshold,
	}, nil
}

// The bridge ledger's fold through foldedThrough over the head being extended, by args.BridgeFold. With none, the fold
// stops below the first bridge statement it would take, or stays at the head's where §7.9's fold rule does not allow
// that, and the head's ledger stands: a writer that cannot write the ledger never folds a statement into a head
// without it. A fold stopped below a body still waiting alarms config_key_waiting, and each body it froze void as
// unformed is logged config_key_void (DESIGN-DETAILS 12.2.3); both lines name the body's generation and its filer, on
// every plan, so an admin can revoke a filer that keeps the fold held (QD-774).
func (self *ConfigWriter) bridgeFold(head *ConfigHead, state *ConfigState, foldedThrough uint64, entryTimeMs func(n uint64) (int64, bool)) (*BridgeLedgerFold, error) {
	if self.args.BridgeFold != nil {
		fold, err := self.args.BridgeFold(head, state, foldedThrough, entryTimeMs)
		if err != nil {
			return nil, err
		}
		if stopped := fold.Stopped; stopped != nil {
			self.log.Warningf("[config]%s config_key_waiting: the fold stops at %d below the bridge body at %d, of generation %d, filed by %s", state.NetworkId(), fold.FoldedThrough, stopped.Statement.N, stopped.Generation, stopped.Statement.Signer)
		}
		for _, voided := range fold.Voided {
			self.log.Warningf("[config]%s config_key_void: the fold through %d freezes void the bridge body at %d, of generation %d above every generation gkm names, filed by %s", state.NetworkId(), fold.FoldedThrough, voided.Statement.N, voided.Generation, voided.Statement.Signer)
		}
		return fold, nil
	}
	reached := foldedThrough
	for _, statement := range state.Bridge().Statements() {
		if head.FoldedThrough() < statement.N && statement.N <= reached {
			reached = statement.N - 1
			break
		}
	}
	if base := state.Base(); reached != head.FoldedThrough() && (base == nil || reached < base.GetVersion()) {
		reached = head.FoldedThrough()
	}
	if reached < foldedThrough {
		self.log.Warningf("[config]%s no bridge fold is installed: the fold stops at %d", state.NetworkId(), reached)
	}
	files, err := bridgeLedgerRowsFiles(&bridgeLedgerHeadRows{head: head})
	if err != nil {
		return nil, err
	}
	return &BridgeLedgerFold{FoldedThrough: reached, Files: files}, nil
}

// Whether two heads hold the same files.
func configHeadsEqual(a *ConfigHead, b *ConfigHead) bool {
	aFiles, bFiles := a.Files(), b.Files()
	if len(aFiles) != len(bFiles) {
		return false
	}
	for path, data := range aFiles {
		if other, found := bFiles[path]; !found || !bytes.Equal(other, data) {
			return false
		}
	}
	return true
}

// The plan's Signed ProjectionHeader at the client's tip: version tip+1, prev_chain A_tip, the tail's verdicts as this
// device holds them, and the repos the base's own change shrinks at this device's clock.
func (self *ConfigWriter) signBase(plan *configWriterPlan) ([]byte, error) {
	var header *bridge.ProjectionHeader
	err := func() error {
		self.args.Client.followLock.Lock()
		defer self.args.Client.followLock.Unlock()
		log := self.args.Client.configLog.Load()
		if log == nil {
			return ErrConfigClientClosed
		}
		state := log.State()
		verdicts := []uint8{}
		for k := plan.foldedThrough + 1; k <= state.n; k += 1 {
			kept := log.keptEntry(k)
			if kept == nil || !kept.verdictHeld {
				return fmt.Errorf("no verdict held at %d for the tail", k)
			}
			verdicts = append(verdicts, kept.verdict.tailBits())
		}
		rowsSha256 := sha256.Sum256(plan.rows)
		header = &bridge.ProjectionHeader{
			NetworkId:        state.networkId.Bytes(),
			Version:          state.n + 1,
			PrevChain:        bytes.Clone(state.chain[:]),
			FoldedThrough:    plan.foldedThrough,
			ConfigVersion:    plan.configVersion,
			ConfigHeadSha256: bytes.Clone(plan.headChain[:]),
			RowsSha256:       rowsSha256[:],
			RowsByteCount:    uint32(len(plan.rows)),
			Threshold:        plan.threshold,
			TailVerdicts:     configEncodeTailVerdicts(verdicts),
		}
		// the repos the base's own change shrinks, from this tip and the state the base gives, at this device's clock:
		// api stamps the entry's time and answers 409 when its own differ, and this re-signs (QD-746)
		shrunkRepoIds, err := log.BaseShrunkRepoIds(header, plan.rows, self.clock.Now().UnixMilli())
		if err != nil {
			return fmt.Errorf("the base's own shrinks: %w", err)
		}
		header.ShrunkRepoIds = shrunkRepoIds
		return nil
	}()
	if err != nil {
		return nil, err
	}
	return self.signRecord(bridge.SignedType_SIGNED_PROJECTION_HEADER, header)
}

// A record signed by this device's identity key, as Signed's bytes.
func (self *ConfigWriter) signRecord(signedType bridge.SignedType, body proto.Message) ([]byte, error) {
	return configSignRecord(self.args.Sign, signedType, body)
}

// body signed under its type's purpose by sign, as Signed's bytes.
func configSignRecord(sign ConfigSignFunction, signedType bridge.SignedType, body proto.Message) ([]byte, error) {
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	purpose, ok := ConfigStatementPurpose(signedType)
	if !ok {
		return nil, fmt.Errorf("no purpose for %s", signedType)
	}
	signed, err := sign(purpose, signedType, bodyBytes)
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// The fold loop: a fold due now waits its random delay, which another base cancels, then publishes; a pending head
// past its timeout gets its base; otherwise the loop waits for an entry, a base or CheckInterval.
func (self *ConfigWriter) run() {
	for {
		wait := self.settings.CheckInterval
		if due, untilDue := self.foldDue(); due {
			delay := time.Duration(self.random() * float64(self.settings.FoldDelayMax))
			select {
			case <-self.ctx.Done():
				return
			case <-self.baseLanded:
				// another writer's base: look again, the fold most likely done
				continue
			case <-self.clock.After(delay):
			}
			if due, _ := self.foldDue(); due {
				self.publishWithTimeout(true)
			}
			continue
		} else if 0 < untilDue && untilDue < wait {
			wait = untilDue
		}
		if self.pendingDue() {
			self.publishWithTimeout(false)
			continue
		}
		select {
		case <-self.ctx.Done():
			return
		case <-self.entryLanded:
		case <-self.clock.After(wait):
		}
	}
}

// One publish bounded by PublishTimeout, its failure logged for the next pass.
func (self *ConfigWriter) publishWithTimeout(fold bool) {
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.PublishTimeout)
	defer cancel()
	if _, err := self.PublishBase(ctx, fold); err != nil && self.ctx.Err() == nil {
		self.log.Warningf("[config]%s a base did not land: %v", self.args.Client.NetworkId(), err)
	}
}

// Whether a fold is due at the client's state (§7.9's fold row): the oldest statement or tick past the newest base's
// folded_through is FoldEntryCount positions behind the tip, or FoldAge old by this device's clock. Not due, how long
// until age makes it due, zero for never.
func (self *ConfigWriter) foldDue() (bool, time.Duration) {
	state := self.args.Client.State()
	if state == nil || state.Base() == nil || CheckConfigHeadWriter(state, self.args.SidecarId) != nil {
		return false, 0
	}
	foldedThrough := state.Base().GetFoldedThrough()
	oldestN, oldestTimeMs := uint64(0), int64(0)
	func() {
		self.args.Client.followLock.Lock()
		defer self.args.Client.followLock.Unlock()
		log := self.args.Client.configLog.Load()
		if log == nil {
			return
		}
		for k := foldedThrough + 1; k <= log.State().n; k += 1 {
			kept := log.keptEntry(k)
			if kept != nil && kept.entry.GetKind() != bridge.AuthEntryKindBase {
				oldestN, oldestTimeMs = k, kept.entry.GetTimeMs()
				return
			}
		}
	}()
	if oldestN == 0 {
		return false, 0
	}
	if uint64(max(self.settings.FoldEntryCount, 1)) <= state.n-oldestN+1 {
		return true, 0
	}
	age := self.clock.Now().Sub(time.UnixMilli(oldestTimeMs))
	if self.settings.FoldAge <= age {
		return true, 0
	}
	return false, self.settings.FoldAge - age
}

// Whether a head the store holds with no base naming it has waited past PendingHeadTimeout (§7.9's state row).
func (self *ConfigWriter) pendingDue() bool {
	state := self.args.Client.State()
	if state == nil || state.Base() == nil || CheckConfigHeadWriter(state, self.args.SidecarId) != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.PublishTimeout)
	defer cancel()
	_, version, _, err := self.args.Heads.CurrentConfigHead(ctx)
	if err != nil {
		return false
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if version <= state.Base().GetConfigVersion() {
		self.pendingVersion, self.pendingSince = 0, time.Time{}
		return false
	}
	if self.pendingVersion != version {
		self.pendingVersion, self.pendingSince = version, now
		self.log.Warningf("[config]%s config head %d has no base yet", self.args.Client.NetworkId(), version)
		return false
	}
	return self.settings.PendingHeadTimeout <= now.Sub(self.pendingSince)
}

// The config head the store holds with no base naming it, and since when this writer saw it; 0 for none.
func (self *ConfigWriter) PendingHead() (uint64, time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pendingVersion, self.pendingSince
}

// POST /network/config/projection (§7.9's base row): a config writer's base with its rows, base 1's genesis and the
// pushes that walk to its head. Answers the entry's (n, A_n): a new entry, or for a retry of a base api holds, that
// entry. 409 is ErrConfigTipMoved, 403 an ErrConfigRefused; each is a *SidecarApiError too.
func (self *SidecarApi) PostConfigProjection(ctx context.Context, base *ConfigBasePublish) (*bridge.AuthPin, error) {
	route := "POST /network/config/projection"
	if base == nil || len(base.SignedHeader) == 0 || len(base.Rows) == 0 {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiArgs)
	}
	reply := &sidecarConfigPinReply{}
	err := self.sendJson(ctx, &sidecarApiRequest{
		route:     route,
		operation: "config_projection_publish",
		method:    "POST",
		url:       self.settings.ApiUrl + "/network/config/projection",
		bearer:    true,
	}, &sidecarConfigProjectionPublishWire{
		SignedHeader: base.SignedHeader,
		Rows:         base.Rows,
		Genesis:      base.Genesis,
		ConfigPushes: base.ConfigPushes,
	}, reply)
	if err != nil {
		apiError := &SidecarApiError{}
		if errors.As(err, &apiError) {
			switch apiError.Status {
			case http.StatusConflict:
				return nil, fmt.Errorf("%w: %w", ErrConfigTipMoved, err)
			case http.StatusForbidden:
				return nil, fmt.Errorf("%w: %w", ErrConfigRefused, err)
			}
		}
		return nil, err
	}
	if reply.N == 0 || len(reply.Chain) != sha256.Size {
		return nil, fmt.Errorf("sidecar api %s: %w", route, ErrSidecarApiReply)
	}
	return &bridge.AuthPin{Version: reply.N, Chain: reply.Chain}, nil
}

// ConfigBasePublisher over SidecarApi.
func (self *SidecarApi) PublishConfigBase(ctx context.Context, base *ConfigBasePublish) (*bridge.AuthPin, error) {
	return self.PostConfigProjection(ctx, base)
}

// POST /network/config/projection's body (sidecartest/fake_api_config.go reads alike).
type sidecarConfigProjectionPublishWire struct {
	SignedHeader []byte   `json:"signed_header"`
	Rows         []byte   `json:"rows"`
	Genesis      []byte   `json:"genesis,omitempty"`
	ConfigPushes [][]byte `json:"config_pushes,omitempty"`
}
