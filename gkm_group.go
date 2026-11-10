// gkm's client side of the groups one sidecar holds (KEYS-M2-20, KEYS-M2-21; DESIGN-DETAILS 6.2.4): one manager per
// repo's group, each flow single-flight, over what the device keeps of a repo in keychain.ur under gkm's namespace
// (§5.9, 6.2.2's names):
//
//	<repo_id>/gen/<g>    RK_g with gen/<g>'s Signed GenRotate bytes, which a re-form copies byte for byte
//	                     (plan-KEYS-reform-ladder rule 2), and whether this device holds g as poisoned
//	<repo_id>/draft      a rotation's RK' and its Signed GenRotate, written before anything is staged
//	<repo_id>/pins       the group, the newest epoch adopted with its epoch_authenticator and header, and the
//	                     newest generation held with its C_g; they never fall (R8, I-16)
//	<repo_id>/pending    KF1's draft and the Welcomes this device committed and has not yet written
//
// A flow is a method that runs to its end or to an error, and every transition it makes is fenced by the object it
// writes at gkm, each an If-None-Match create, and by the member checks (gkm_verify_*.go) at this device's own
// state. A kill at any point resumes from the keychain: nothing here keeps a flow's progress in memory alone.
//
// GkmGroupClient is GkmClient's real implementation: RotateRepo (KEYS-M2-20), CreateGroup and AuthAdvanced
// (KEYS-M2-21), CurrentRepoKey, RepoKey, EnsureWritable, DropKey and ForgetRepo (KEYS-M2-22, gkm_access.go), and
// the group sync, pins and HeadCheck heads (KEYS-M2-23, gkm_sync.go and gkm_pins.go).
//
// Locks: a manager's flowLock is held across a whole flow and its I/O, so it is never taken under stateLock, which
// guards only the newest state and the manager table. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the group flows call at gkm: GkmApi's methods, so a test fakes them.
type GkmGroupApi interface {
	CreateGroup(ctx context.Context, repoId Id, request *protocol.GkmGroupCreateRequest) error
	Forms(ctx context.Context, repoId Id) (*protocol.GkmFormsReply, error)
	Epochs(ctx context.Context, repoId Id, groupId Id, after uint64) (*protocol.GkmEpochsReply, error)
	CommitEpoch(ctx context.Context, repoId Id, groupId Id, epoch uint64, request *protocol.GkmEpochRequest) error
	Generations(ctx context.Context, repoId Id, groupId Id, since uint64) (*protocol.GkmGenerationsReply, error)
	ClaimGeneration(ctx context.Context, repoId Id, groupId Id, generation uint64, rotate *bridge.Signed) error
	Wraps(ctx context.Context, repoId Id, groupId Id, generation uint64, query *GkmWrapsQuery) (*protocol.GkmWrapsReply, error)
	UploadWraps(ctx context.Context, repoId Id, groupId Id, generation uint64, commitment []byte, batch *protocol.GkmWrapBatch) (*protocol.GkmWrapBatchReply, error)
	UploadRecoveryWraps(ctx context.Context, repoId Id, groupId Id, generation uint64, commitment []byte, batch *protocol.GkmRecoveryWrapBatch) (*protocol.GkmWrapBatchReply, error)
	ReaderKey(ctx context.Context, sidecarId Id) (*bridge.Signed, error)
	ReaderKeys(ctx context.Context, sidecarIds []Id) ([]*bridge.Signed, error)
	ClaimKeyPackage(ctx context.Context, repoId Id, groupId Id, target Id) (*protocol.GkmKeyPackageClaimReply, error)
	GroupInfo(ctx context.Context, repoId Id, groupId Id, want *uint64) (*protocol.GkmGroupInfoObject, error)
	UploadGroupInfo(ctx context.Context, repoId Id, groupId Id, object *protocol.GkmGroupInfoObject) error
	UploadWelcome(ctx context.Context, repoId Id, groupId Id, epoch uint64, request *protocol.GkmWelcomeRequest) error
	Welcomes(ctx context.Context) ([]*protocol.GkmWelcomeEntry, error)
	DropKeys(ctx context.Context, repoId Id, since uint64) (*protocol.GkmGenerationsReply, error)
}

var _ GkmGroupApi = (*GkmApi)(nil)

// The kinds of alarm a flow raises (§10.9), as GkmAlarm.Kind names them.
const (
	// A commit, rotation or delivery a member check refused: never adopted, never encrypted to.
	GkmAlarmRefused = "refused"
	// A pin off this device's chain, or a pin that would fall: §5.4's head_alarm (fork).
	GkmAlarmHead = "head_alarm"
	// An owner-bound repo's unconsented device waits for approval (§8.5).
	GkmAlarmApprovalPending = "approval_pending"
	// A delivery's path holds bytes this rotation did not write.
	GkmAlarmWrapConflict = "wrap_conflict"
)

// One alarm of a flow: opaque ids and positions only (I-13).
type GkmAlarm struct {
	Kind    string
	RepoId  Id
	GroupId Id
	Epoch   uint64
	// The generation the alarm poisons or names, 0 for none.
	Generation uint64
	// The committer, signer or waiting device the alarm names.
	SidecarId Id
	Reason    GkmRefusalReason
	Detail    string
}

// The X-Wing key a member's current RecoveryBind publishes, with the hash of the binding's Ed25519 key, which names
// the binding in a RecoveryWrap's path (§10.6, §10.8).
type GkmRecoveryKey struct {
	XwingPublicKey   []byte
	BindingKeySha256 []byte
}

// What a GkmGroupClient takes.
type GkmGroupClientArgs struct {
	SidecarId Id
	NetworkId Id
	Api       GkmGroupApi
	// Signs with the identity key: GenRotates, deliveries and GroupForms.
	Sign GkmSignFunction
	// The network's keychain.ur under gkm's namespace (§5.9).
	Secrets SidecarSecrets
	// This sidecar's MLS engine. Nil for a sidecar that holds no leaf, an agent: it commits nothing and rotates by
	// wraps.
	Mls MlsEngine
	// The private key of a ReaderKey this sidecar signed, by its key's digest: GkmUpkeep.ReaderPrivateKey. Nil opens
	// no delivery.
	ReaderPrivateKey func(keySha256 []byte) (hpke.PrivateKey, error)
	// The digest of this sidecar's current ReaderKey, which a late ask wants a delivery to. Nil asks for none.
	ReaderKeySha256 func() []byte
	// A member's current RecoveryBind key, from the config repo's sealed RecoveryBindBody, which TEAM's ConfigClient
	// opens (§7.9). Nil, or an answer of none for a member that holds a recovery identity, refuses the rotation
	// rather than leave that member without its RecoveryWrap (D-KEYS-18).
	RecoveryKey func(memberId Id) (*GkmRecoveryKey, error)
	// Whether a device a restored binding admitted is anchored (§10.8): until it is, no committer adds it. Nil
	// reads every device as anchored, since only §7.9's restored row parks one.
	Anchored func(sidecarId Id) bool
	// The repos this sidecar reads at its newest state, the list its token scopes come from: where a Welcome's
	// group is looked for. Nil joins only groups of repos this device already holds.
	ReaderRepoIds func() []Id
	// Each alarm a flow raises (§10.9): refused, head_alarm, approval_pending. It must not block. Nil drops them.
	Alarm func(alarm *GkmAlarm)
	// HeadStopState.SealAllowed: whether new content may be sealed in a group now, which EnsureWritable asks only
	// after its commits and rotations, since the witness stop never holds a Remove, a rotation or a revocation
	// (owner decision 129). Nil allows.
	SealAllowed func(groupId Id) error
	// HeadStopState.ReportFork: a pin this client refuses stops sealing there as a fork HeadCheck finds does
	// (§6.4). It must not block. Nil reports none.
	ReportFork func(fork HeadFork)
	// Whether this process holds the network's state: §18.8's Web Lock in a page Worker, §5.8's flock elsewhere.
	// One that does not loads no MLS state and runs no flow. Nil holds it.
	HoldsState func() bool
	// A uniform draw in [0, max), for the jittered waits. Nil draws from crypto/rand.
	Jitter func(max time.Duration) time.Duration
	// nil takes the defaults.
	Settings *GkmSettings
	// nil is real time.
	Clock Clock
	Log   Logger
}

// One sidecar's group flows. See the file header.
type GkmGroupClient struct {
	args     *GkmGroupClientArgs
	settings *GkmSettings
	clock    Clock
	log      Logger
	lateAsks *GkmLateAsks

	stateLock sync.Mutex
	// the newest verified state the log applier gave
	state          GkmAuthView
	repoIdManagers map[Id]*gkmGroupManager
	// the hint work running now, by kind and repo
	hintWorkKeys map[string]bool
	// what HeadCheck and the acks read from memory: each held repo's pins and its tree's leaves (gkm_pins.go)
	repoIdHeads map[Id]*gkmRepoHead
	// when a late ask for a GroupInfo or a waiting leaf's want last went, by repo (H2)
	repoIdWantAskedAt map[Id]time.Time
	// when this device last joined a group through its last-resort KeyPackage, read from the keychain at first use
	lastResortJoinedAt     time.Time
	lastResortJoinedLoaded bool
	// what the flows' yields measured (gkm_yield.go)
	yieldStats GkmYieldStats
}

var _ GkmClient = (*GkmGroupClient)(nil)

// A client with no state yet: every flow refuses with ErrGkmUnavailable until the first AuthAdvanced.
func NewGkmGroupClient(args *GkmGroupClientArgs) (*GkmGroupClient, error) {
	if args == nil || args.Api == nil || args.Sign == nil || args.Secrets == nil || args.SidecarId == (Id{}) {
		return nil, fmt.Errorf("%w: gkm's group client needs its sidecar, api, signer and keychain", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultGkmSettings()
	}
	return &GkmGroupClient{
		args:              args,
		settings:          settings,
		clock:             clockOrReal(args.Clock),
		log:               loggerOrDefault(args.Log),
		lateAsks:          NewGkmLateAsks(settings),
		repoIdManagers:    map[Id]*gkmGroupManager{},
		hintWorkKeys:      map[string]bool{},
		repoIdHeads:       map[Id]*gkmRepoHead{},
		repoIdWantAskedAt: map[Id]time.Time{},
	}, nil
}

// §7.9's applier, after each entry it applies. It never blocks, and a state at or below one already given changes
// nothing (I-16). The flows a new state makes due, a commit of pending changes and a rotation, run when their
// driver calls RunPending: at a pending hint, at EnsureWritable (KEYS-M2-22) and at the hint intake's resync.
func (self *GkmGroupClient) AuthAdvanced(state GkmAuthView) {
	if state == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state != nil && state.Pin().GetVersion() <= self.state.Pin().GetVersion() {
		return
	}
	self.state = state
}

// The newest verified state, or ErrGkmUnavailable before the first, and in a process that does not hold the
// network's state, where no flow runs.
func (self *GkmGroupClient) currentState() (GkmAuthView, error) {
	if !self.holdsState() {
		return nil, fmt.Errorf("%w: this process does not hold the network's state", ErrGkmUnavailable)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == nil {
		return nil, fmt.Errorf("%w: no verified state yet", ErrGkmUnavailable)
	}
	return self.state, nil
}

// The repo's manager, made at first use.
func (self *GkmGroupClient) manager(repoId Id) *gkmGroupManager {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	manager, ok := self.repoIdManagers[repoId]
	if !ok {
		manager = &gkmGroupManager{client: self, repoId: repoId}
		self.repoIdManagers[repoId] = manager
	}
	return manager
}

// Raises an alarm, if anything listens.
func (self *GkmGroupClient) alarm(alarm *GkmAlarm) {
	if self.log.V(1).Enabled() {
		self.log.Infof("[gkm]alarm %s reason=%s epoch=%d generation=%d", alarm.Kind, alarm.Reason, alarm.Epoch, alarm.Generation)
	}
	if self.args.Alarm != nil {
		self.args.Alarm(alarm)
	}
}

// A uniform draw in [0, max).
func (self *GkmGroupClient) jitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	if self.args.Jitter != nil {
		return self.args.Jitter(max)
	}
	drawn, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(drawn.Int64())
}

// Waits out a delay on the client's clock, or ctx.
func (self *GkmGroupClient) wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-self.clock.After(delay):
		return nil
	}
}

// One repo's group as this sidecar drives it. One flow runs at a time.
type gkmGroupManager struct {
	client *GkmGroupClient
	repoId Id
	// held across a flow and its I/O; never taken under the client's stateLock
	flowLock sync.Mutex
}

// The keychain records' version byte.
const gkmRecordVersion = 1

// The flags of a generation record.
const (
	gkmGenerationRecordPoisoned = 1 << 0
	gkmGenerationRecordHasKey   = 1 << 1
)

// The keychain name of one of a repo's records.
func gkmRepoRecordName(repoId Id, rest string) string {
	return gkmPathId(repoId) + "/" + rest
}

// <repo_id>/gen/<g>.
func gkmGenerationRecordName(repoId Id, generation uint64) string {
	return gkmRepoRecordName(repoId, "gen/"+gkmPathGeneration(generation))
}

// One generation as this device holds it: gen/<g>'s verified statement, RK_g where it could open it, and whether a
// check poisoned it.
type gkmHeldGeneration struct {
	generation *GkmGeneration
	// nil for a poisoned generation this device never opened
	key      *EvsRepoKey
	poisoned bool
}

// A Signed GenRotate read back from this device's own sealed keychain, which verified it under its signer's
// admitted key before it stored it: held to its format, its signature not checked again.
func gkmStoredGeneration(signedBytes []byte) (*GkmGeneration, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: a stored GenRotate: %w", ErrGkmMalformed, err)
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, fmt.Errorf("%w: a stored GenRotate names no signer", ErrGkmMalformed)
	}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil {
		return nil, fmt.Errorf("%w: a stored GenRotate: %w", ErrGkmMalformed, err)
	}
	if err := checkGkmGenRotate(rotate); err != nil {
		return nil, err
	}
	return &GkmGeneration{Signed: signed, SignerId: signerId, Rotate: rotate}, nil
}

// A Signed statement's stored bytes.
func gkmSignedBytes(signed *bridge.Signed) ([]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGkmMalformed, err)
	}
	return encoded, nil
}

// version | flags | u32 length | Signed GenRotate | RK_g where held.
func (self *gkmHeldGeneration) encode() ([]byte, error) {
	signedBytes, err := gkmSignedBytes(self.generation.Signed)
	if err != nil {
		return nil, err
	}
	flags := byte(0)
	if self.poisoned {
		flags |= gkmGenerationRecordPoisoned
	}
	if self.key != nil {
		flags |= gkmGenerationRecordHasKey
	}
	encoded := []byte{gkmRecordVersion, flags}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(signedBytes)))
	encoded = append(encoded, signedBytes...)
	if self.key != nil {
		encoded = append(encoded, self.key.repoKey...)
	}
	return encoded, nil
}

// A generation record's fields.
func decodeGkmHeldGeneration(encoded []byte) (*gkmHeldGeneration, error) {
	malformed := fmt.Errorf("%w: a generation record", ErrGkmMalformed)
	if len(encoded) < 6 || encoded[0] != gkmRecordVersion {
		return nil, malformed
	}
	flags := encoded[1]
	signedByteCount := int(binary.BigEndian.Uint32(encoded[2:6]))
	rest := encoded[6:]
	if len(rest) < signedByteCount {
		return nil, malformed
	}
	generation, err := gkmStoredGeneration(rest[:signedByteCount])
	if err != nil {
		return nil, err
	}
	held := &gkmHeldGeneration{generation: generation, poisoned: flags&gkmGenerationRecordPoisoned != 0}
	rest = rest[signedByteCount:]
	if flags&gkmGenerationRecordHasKey != 0 {
		if len(rest) != gkmRepoKeyByteCount {
			return nil, malformed
		}
		key, err := OpenEvsRepoKey(generation, rest)
		if err != nil {
			return nil, err
		}
		held.key = key
	} else if len(rest) != 0 {
		return nil, malformed
	}
	return held, nil
}

// A stored record, or ErrGkmKeyMissing for none.
func (self *GkmGroupClient) getRecord(name string) ([]byte, error) {
	encoded, err := self.args.Secrets.Get(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, fmt.Errorf("%w: no record %s", ErrGkmKeyMissing, name[len(name)-min(len(name), 8):])
	}
	return encoded, err
}

// Generation g of a repo as held, or ErrGkmKeyMissing.
func (self *GkmGroupClient) heldGeneration(repoId Id, generation uint64) (*gkmHeldGeneration, error) {
	encoded, err := self.getRecord(gkmGenerationRecordName(repoId, generation))
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return decodeGkmHeldGeneration(encoded)
}

// The newest generation of a repo this device holds a record of, or ErrGkmKeyMissing for none.
func (self *GkmGroupClient) newestHeldGeneration(repoId Id) (*gkmHeldGeneration, error) {
	names, err := self.args.Secrets.List(gkmRepoRecordName(repoId, "gen/"))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: no generation of the repo is held", ErrGkmKeyMissing)
	}
	// 20-digit names sort as numbers
	encoded, err := self.getRecord(names[len(names)-1])
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return decodeGkmHeldGeneration(encoded)
}

// Keeps a generation. A record already there at g with another commitment is a fork and is never replaced; one with
// the same commitment gains the key or the poison this one carries, and loses neither.
func (self *GkmGroupClient) putHeldGeneration(repoId Id, held *gkmHeldGeneration) error {
	rotate := held.generation.Rotate
	existing, err := self.heldGeneration(repoId, rotate.GetGeneration())
	switch {
	case err == nil:
		if !bytes.Equal(existing.generation.Rotate.GetCommitment(), rotate.GetCommitment()) {
			self.alarm(&GkmAlarm{Kind: GkmAlarmHead, RepoId: repoId, Generation: rotate.GetGeneration(), Reason: GkmRefusalFork, Detail: "a second commitment at a generation this device holds"})
			return fmt.Errorf("%w: generation %d holds another commitment", ErrGkmAuthOffChain, rotate.GetGeneration())
		}
		if held.key == nil {
			held.key = existing.key
		}
		held.poisoned = held.poisoned || existing.poisoned
	case errors.Is(err, ErrGkmKeyMissing):
	default:
		return err
	}
	encoded, err := held.encode()
	if err != nil {
		return err
	}
	defer clear(encoded)
	return self.args.Secrets.Put(gkmGenerationRecordName(repoId, rotate.GetGeneration()), encoded)
}

// A repo's pins (R8, 6.2.6): its group, the newest epoch this device adopted with its epoch_authenticator and its
// header, and the newest generation it holds with its commitment. KEYS-M2-23 compares them with HeadCheck's.
type gkmRepoPins struct {
	groupId Id
	// 0 with no authenticator: this device is no leaf, or has adopted none
	epoch              uint64
	epochAuthenticator []byte
	// the adopted epoch's GkmCommitHeader, encoded: the floor of the next commit's pin and generation (R2)
	epochHeader []byte
	generation  uint64
	commitment  []byte
}

// version | group_id | u64 epoch | u16 length | authenticator | u16 length | header | u64 generation | u16 length |
// commitment.
func (self *gkmRepoPins) encode() []byte {
	encoded := []byte{gkmRecordVersion}
	encoded = append(encoded, self.groupId.Bytes()...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.epoch)
	for _, field := range [][]byte{self.epochAuthenticator, self.epochHeader} {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(field)))
		encoded = append(encoded, field...)
	}
	encoded = binary.BigEndian.AppendUint64(encoded, self.generation)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(self.commitment)))
	return append(encoded, self.commitment...)
}

// A pins record's fields.
func decodeGkmRepoPins(encoded []byte) (*gkmRepoPins, error) {
	malformed := fmt.Errorf("%w: a pins record", ErrGkmMalformed)
	remaining := encoded
	failed := false
	take := func(byteCount int) []byte {
		if failed || len(remaining) < byteCount {
			failed = true
			return nil
		}
		taken := remaining[:byteCount]
		remaining = remaining[byteCount:]
		return taken
	}
	takeUint64 := func() uint64 {
		taken := take(8)
		if taken == nil {
			return 0
		}
		return binary.BigEndian.Uint64(taken)
	}
	takeField := func() []byte {
		length := take(2)
		if length == nil {
			return nil
		}
		return bytes.Clone(take(int(binary.BigEndian.Uint16(length))))
	}
	if version := take(1); version == nil || version[0] != gkmRecordVersion {
		return nil, malformed
	}
	pins := &gkmRepoPins{}
	groupIdBytes := take(gkmIdByteCount)
	if groupIdBytes == nil {
		return nil, malformed
	}
	groupId, err := IdFromBytes(groupIdBytes)
	if err != nil {
		return nil, malformed
	}
	pins.groupId = groupId
	pins.epoch = takeUint64()
	pins.epochAuthenticator = takeField()
	pins.epochHeader = takeField()
	pins.generation = takeUint64()
	pins.commitment = takeField()
	if failed || len(remaining) != 0 {
		return nil, malformed
	}
	return pins, nil
}

// A repo's pins, or ErrGkmKeyMissing for a repo this device holds no group of.
func (self *GkmGroupClient) repoPins(repoId Id) (*gkmRepoPins, error) {
	encoded, err := self.getRecord(gkmRepoRecordName(repoId, "pins"))
	if err != nil {
		return nil, err
	}
	return decodeGkmRepoPins(encoded)
}

// Moves a repo's pins forward by edit, which sees the stored pins or, for a repo with none, a zero value. A pin
// that would fall, or a group that would change, is a fork alarm and nothing is written (R8): a re-formed group's
// new id is taken only along a verified GroupForm chain, by movePinsToReform (gkm_reform.go).
func (self *GkmGroupClient) advancePins(repoId Id, edit func(pins *gkmRepoPins)) error {
	stored, err := self.repoPins(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		stored = &gkmRepoPins{}
	} else if err != nil {
		return err
	}
	next := *stored
	edit(&next)
	fell := next.epoch < stored.epoch || next.generation < stored.generation ||
		stored.groupId != (Id{}) && next.groupId != stored.groupId ||
		next.epoch == stored.epoch && 0 < len(stored.epochAuthenticator) && !bytes.Equal(next.epochAuthenticator, stored.epochAuthenticator) ||
		next.generation == stored.generation && 0 < len(stored.commitment) && !bytes.Equal(next.commitment, stored.commitment)
	if fell {
		self.alarm(&GkmAlarm{Kind: GkmAlarmHead, RepoId: repoId, GroupId: stored.groupId, Epoch: next.epoch, Generation: next.generation, Reason: GkmRefusalFork, Detail: "a pin that would fall or fork"})
		return fmt.Errorf("%w: a pin that would fall or fork", ErrGkmAuthOffChain)
	}
	if err := self.args.Secrets.Put(gkmRepoRecordName(repoId, "pins"), next.encode()); err != nil {
		return err
	}
	self.pinsMoved(repoId, stored, &next)
	return nil
}

// The group's MLS state as this sidecar last adopted it, or ErrMlsGroupUnknown for a sidecar that holds no leaf.
func (self *GkmGroupClient) loadGroup(groupId Id) (MlsGroup, error) {
	if self.args.Mls == nil {
		return nil, ErrMlsGroupUnknown
	}
	if !self.holdsState() {
		return nil, fmt.Errorf("%w: this process does not hold the network's state", ErrGkmUnavailable)
	}
	return self.args.Mls.LoadGroup(groupId)
}

// gen/<g> of a group, fetched and verified under the identity keys the state admits; ErrGkmKeyMissing when gkm
// holds none.
func (self *GkmGroupClient) fetchGeneration(ctx context.Context, state GkmAuthView, repoId Id, groupId Id, generation uint64) (*GkmGeneration, error) {
	if generation == 0 {
		return nil, fmt.Errorf("%w: generation 0", ErrGkmKeyMissing)
	}
	reply, err := self.args.Api.Generations(ctx, repoId, groupId, generation-1)
	if err != nil {
		return nil, err
	}
	if len(reply.GetGenerations()) == 0 {
		return nil, fmt.Errorf("%w: gkm holds no gen/%d", ErrGkmKeyMissing, generation)
	}
	signedBytes, err := gkmSignedBytes(reply.GetGenerations()[0])
	if err != nil {
		return nil, err
	}
	// a re-formed group's ladder names its old group (gkm_reform.go)
	return self.parseServedGeneration(ctx, state, repoId, groupId, generation, signedBytes)
}

// A Welcome this device's commit owes its joiners: written to the keychain before the commit is uploaded, so a kill
// between the epoch's 200 and the Welcome's write loses nothing once this device returns.
type gkmOwedWelcome struct {
	epoch uint64
	// SHA-256 of the commit's MLSMessage: the Welcome is owed only if this commit holds the epoch
	commitSha256 []byte
	// the GkmWelcomeRequest, encoded
	request []byte
}

// A repo's pending-change record: KF1's draft until the group stands with its deliveries, and the Welcomes owed.
type gkmPendingRecord struct {
	create       *gkmCreateDraft
	owedWelcomes []*gkmOwedWelcome
}

// version | u32 length | [group_id | RK_1 | request] | u16 count | { u64 epoch | commit hash | u32 length | request }.
func (self *gkmPendingRecord) encode() []byte {
	encoded := []byte{gkmRecordVersion}
	create := []byte{}
	if self.create != nil {
		create = append(create, self.create.groupId.Bytes()...)
		create = append(create, self.create.repoKey...)
		create = append(create, self.create.request...)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(create)))
	encoded = append(encoded, create...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(self.owedWelcomes)))
	for _, owed := range self.owedWelcomes {
		encoded = binary.BigEndian.AppendUint64(encoded, owed.epoch)
		encoded = append(encoded, owed.commitSha256...)
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(owed.request)))
		encoded = append(encoded, owed.request...)
	}
	return encoded
}

// A pending record's fields.
func decodeGkmPendingRecord(encoded []byte) (*gkmPendingRecord, error) {
	malformed := fmt.Errorf("%w: a pending record", ErrGkmMalformed)
	remaining := encoded
	failed := false
	take := func(byteCount int) []byte {
		if failed || byteCount < 0 || len(remaining) < byteCount {
			failed = true
			return nil
		}
		taken := remaining[:byteCount]
		remaining = remaining[byteCount:]
		return taken
	}
	takeUint := func(byteCount int) uint64 {
		taken := take(byteCount)
		if taken == nil {
			return 0
		}
		padded := make([]byte, 8)
		copy(padded[8-byteCount:], taken)
		return binary.BigEndian.Uint64(padded)
	}
	if version := take(1); version == nil || version[0] != gkmRecordVersion {
		return nil, malformed
	}
	record := &gkmPendingRecord{}
	if create := take(int(takeUint(4))); 0 < len(create) {
		if len(create) <= gkmIdByteCount+gkmRepoKeyByteCount {
			return nil, malformed
		}
		groupId, err := IdFromBytes(create[:gkmIdByteCount])
		if err != nil {
			return nil, malformed
		}
		record.create = &gkmCreateDraft{
			groupId: groupId,
			repoKey: bytes.Clone(create[gkmIdByteCount : gkmIdByteCount+gkmRepoKeyByteCount]),
			request: bytes.Clone(create[gkmIdByteCount+gkmRepoKeyByteCount:]),
		}
	}
	for count := takeUint(2); 0 < count && !failed; count -= 1 {
		owed := &gkmOwedWelcome{epoch: takeUint(8)}
		owed.commitSha256 = bytes.Clone(take(gkmDigestByteCount))
		owed.request = bytes.Clone(take(int(takeUint(4))))
		record.owedWelcomes = append(record.owedWelcomes, owed)
	}
	if failed || len(remaining) != 0 {
		return nil, malformed
	}
	return record, nil
}

// The repo's pending record, empty for none.
func (self *gkmGroupManager) pendingRecord() (*gkmPendingRecord, error) {
	encoded, err := self.client.getRecord(gkmRepoRecordName(self.repoId, "pending"))
	if errors.Is(err, ErrGkmKeyMissing) {
		return &gkmPendingRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	return decodeGkmPendingRecord(encoded)
}

// Keeps the repo's pending record, or removes it once it holds nothing.
func (self *gkmGroupManager) putPendingRecord(record *gkmPendingRecord) error {
	name := gkmRepoRecordName(self.repoId, "pending")
	if record.create == nil && len(record.owedWelcomes) == 0 {
		return self.client.args.Secrets.Delete(name)
	}
	encoded := record.encode()
	defer clear(encoded)
	return self.client.args.Secrets.Put(name, encoded)
}

// Records the Welcome a commit to epoch will owe, before the commit is uploaded.
func (self *gkmGroupManager) oweWelcome(epoch uint64, commit []byte, request *protocol.GkmWelcomeRequest) error {
	requestBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return err
	}
	record, err := self.pendingRecord()
	if err != nil {
		return err
	}
	commitSha256 := sha256.Sum256(commit)
	record.owedWelcomes = slices.DeleteFunc(record.owedWelcomes, func(owed *gkmOwedWelcome) bool { return owed.epoch == epoch })
	record.owedWelcomes = append(record.owedWelcomes, &gkmOwedWelcome{epoch: epoch, commitSha256: commitSha256[:], request: requestBytes})
	return self.putPendingRecord(record)
}

// Drops the Welcome owed for epoch: its commit lost the epoch, or its Welcome stands.
func (self *gkmGroupManager) dropOwedWelcome(epoch uint64) error {
	record, err := self.pendingRecord()
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(record.owedWelcomes), func(owed *gkmOwedWelcome) bool { return owed.epoch == epoch })
	if len(kept) == len(record.owedWelcomes) {
		return nil
	}
	record.owedWelcomes = kept
	return self.putPendingRecord(record)
}

// 6.2.4's welcome step, and its resumption after a kill: each Welcome this device owes is written, with its
// pointers, if its own commit holds the epoch; one whose commit lost the epoch, or never landed, is dropped, since a
// staged commit that dies is made again. gkm writes welcome/<n> and each pointer If-None-Match, equal bytes
// answering success, so a repeat finishes what a crash left.
func (self *gkmGroupManager) writeOwedWelcomes(ctx context.Context, groupId Id) error {
	client := self.client
	record, err := self.pendingRecord()
	if err != nil {
		return err
	}
	for _, owed := range slices.Clone(record.owedWelcomes) {
		standing, err := client.args.Api.Epochs(ctx, self.repoId, groupId, owed.epoch-1)
		if err != nil {
			return err
		}
		mine := false
		if entries := standing.GetEpochs(); 0 < len(entries) && entries[0].GetEpoch() == owed.epoch {
			commitSha256 := sha256.Sum256(entries[0].GetObject().GetCommit())
			mine = bytes.Equal(commitSha256[:], owed.commitSha256)
		}
		if mine {
			request := &protocol.GkmWelcomeRequest{}
			if err := proto.Unmarshal(owed.request, request); err != nil {
				return fmt.Errorf("%w: an owed Welcome", ErrGkmMalformed)
			}
			if err := client.args.Api.UploadWelcome(ctx, self.repoId, groupId, owed.epoch, request); err != nil && !IsGkmStatus(err, http.StatusConflict) {
				// a 409 is a Welcome that already stands for the epoch, which only this uploader wrote
				return err
			}
		}
		if err := self.dropOwedWelcome(owed.epoch); err != nil {
			return err
		}
	}
	return nil
}

// The repo among those this sidecar reads whose newest GroupForm names groupId, which a Welcome's pointer does not
// say. What gkm answers here binds nothing: a wrong repo fails at the GenWrap, whose KEK and gen/<g> name the repo.
func (self *GkmGroupClient) repoOfGroup(ctx context.Context, groupId Id) (Id, bool, error) {
	repoIds, err := self.heldRepoIds()
	if err != nil {
		return Id{}, false, err
	}
	for _, repoId := range repoIds {
		if pins, err := self.repoPins(repoId); err == nil && pins.groupId == groupId {
			return repoId, true, nil
		}
	}
	if self.args.ReaderRepoIds == nil {
		return Id{}, false, nil
	}
	for _, repoId := range self.args.ReaderRepoIds() {
		forms, err := self.args.Api.Forms(ctx, repoId)
		if err != nil {
			if _, refused := GkmErrorOf(err); refused {
				continue
			}
			return Id{}, false, err
		}
		if signedForms := forms.GetForms(); 0 < len(signedForms) {
			form := &protocol.GroupForm{}
			if err := proto.Unmarshal(signedForms[len(signedForms)-1].GetBody(), form); err == nil && bytes.Equal(form.GetGroupId(), groupId.Bytes()) {
				return repoId, true, nil
			}
		}
	}
	return Id{}, false, nil
}

// KF2's joiner (the welcome hint's work, and each resync's): takes each Welcome gkm holds for this sidecar. Of the
// pointers for one group it takes the one with the highest epoch above the newest it reached and skips the rest: a
// lower one names a leaf a later Remove took out, or an epoch at or below its pin (I-16). Returns the repos joined.
func (self *GkmGroupClient) JoinWelcomes(ctx context.Context) ([]Id, error) {
	if self.args.Mls == nil {
		return nil, nil
	}
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	entries, err := self.args.Api.Welcomes(ctx)
	if err != nil {
		return nil, err
	}
	groupIdEntries := map[Id]*protocol.GkmWelcomeEntry{}
	groupIds := []Id{}
	for _, entry := range entries {
		groupId, err := IdFromBytes(entry.GetPointer().GetGroupId())
		if err != nil {
			continue
		}
		best, ok := groupIdEntries[groupId]
		if !ok {
			groupIds = append(groupIds, groupId)
		}
		if !ok || best.GetPointer().GetEpoch() < entry.GetPointer().GetEpoch() {
			groupIdEntries[groupId] = entry
		}
	}
	joinedRepoIds := []Id{}
	errs := []error{}
	for _, groupId := range groupIds {
		repoId, found, err := self.repoOfGroup(ctx, groupId)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !found {
			continue
		}
		manager := self.manager(repoId)
		joined, err := func() (bool, error) {
			manager.flowLock.Lock()
			defer manager.flowLock.Unlock()
			return manager.joinInFlow(ctx, state, groupId, groupIdEntries[groupId])
		}()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if joined {
			joinedRepoIds = append(joinedRepoIds, repoId)
		}
	}
	return joinedRepoIds, errors.Join(errs...)
}

// One Welcome join (§10.6's two phases): the Welcome gives the epoch's exporter and so KEK_n; GenWrap_n gives
// RK_g, accepted only against gen/<g>'s C_g, the generation itself judged by the rotation checks; K_groupinfo of
// the generation the epoch names opens the sealed GroupInfo; and only then does the engine verify the GroupInfo's
// signature and tree against the Welcome. Nothing the Welcome or gkm says is trusted before those pass.
func (self *gkmGroupManager) joinInFlow(ctx context.Context, state GkmAuthView, groupId Id, entry *protocol.GkmWelcomeEntry) (bool, error) {
	client := self.client
	epoch := entry.GetPointer().GetEpoch()
	if pins, err := client.repoPins(self.repoId); err == nil {
		if pins.groupId != groupId {
			// another group of the repo: a re-form's, followed first along a form chain this device verifies
			// (gkm_reform.go), so a Welcome taken before a sync joins; any other group is no join
			adopted, err := self.adoptReformInFlow(ctx, state)
			if errors.Is(err, ErrGkmWait) || err == nil && !adopted {
				return false, nil
			}
			if err != nil {
				return false, err
			}
			if pins, err = client.repoPins(self.repoId); err != nil {
				return false, err
			}
			if pins.groupId != groupId {
				return false, nil
			}
		}
		if epoch <= pins.epoch {
			// an epoch at or below the one reached is no join
			return false, nil
		}
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return false, err
	}
	pendingJoin, err := client.args.Mls.JoinWelcome(entry.GetWelcome())
	if err != nil {
		return false, err
	}
	if pendingJoin.GroupId() != groupId || pendingJoin.Epoch() != epoch {
		return false, fmt.Errorf("%w: a Welcome that is not its pointer's", ErrGkmAuthentication)
	}
	standing, err := client.args.Api.Epochs(ctx, self.repoId, groupId, epoch-1)
	if err != nil {
		return false, err
	}
	if len(standing.GetEpochs()) == 0 || standing.GetEpochs()[0].GetEpoch() != epoch {
		return false, fmt.Errorf("%w: gkm holds no epoch %d for a Welcome", ErrGkmKeyMissing, epoch)
	}
	object := standing.GetEpochs()[0].GetObject()
	// the commit's header as its clear framing shows it; gkm's copy where the commit is no member's
	headerBytes := []byte{}
	if parsed, err := ParseMlsHeader(object.GetCommit()); err == nil {
		headerBytes = parsed.AuthenticatedData
	} else {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(object.GetHeader())
		if err == nil {
			headerBytes = encoded
		}
	}
	header := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(headerBytes, header); err != nil || header.GetGeneration() == 0 {
		return false, fmt.Errorf("%w: epoch %d names no generation to join with", ErrGkmKeyMissing, epoch)
	}
	held, err := self.judgedGeneration(ctx, state, groupId, header.GetGeneration())
	if err != nil {
		return false, err
	}
	if held.poisoned {
		return false, fmt.Errorf("%w: epoch %d carries a poisoned generation", ErrGkmCommitRefused, epoch)
	}
	kek, err := MlsKek(pendingJoin, self.repoId)
	if err != nil {
		return false, err
	}
	key, err := OpenGkmGenWrap(held.generation, groupId, epoch, kek, object.GetGenWrap())
	clear(kek)
	if err != nil {
		return false, err
	}
	sealedGroupInfo, groupInfoGeneration := object.GetSealedGroupInfo(), object.GetGroupInfoGeneration()
	if len(sealedGroupInfo) == 0 {
		// above 16 leaves the GroupInfo rides group-info, asked for by epoch
		groupInfoObject, err := client.args.Api.GroupInfo(ctx, self.repoId, groupId, &epoch)
		if err != nil {
			return false, err
		}
		if groupInfoObject.GetEpoch() != epoch || len(groupInfoObject.GetSealedGroupInfo()) == 0 {
			return false, fmt.Errorf("%w: no GroupInfo of epoch %d yet", ErrGkmKeyMissing, epoch)
		}
		sealedGroupInfo, groupInfoGeneration = groupInfoObject.GetSealedGroupInfo(), groupInfoObject.GetGeneration()
	}
	groupInfoKey := key
	if groupInfoGeneration != header.GetGeneration() {
		other, err := client.heldGeneration(self.repoId, groupInfoGeneration)
		if err != nil {
			return false, err
		}
		if other.key == nil {
			return false, fmt.Errorf("%w: generation %d, which seals the GroupInfo", ErrGkmKeyMissing, groupInfoGeneration)
		}
		groupInfoKey = other.key
	}
	groupInfo, err := OpenGkmGroupInfo(groupInfoKey, groupId, epoch, sealedGroupInfo)
	if err != nil {
		return false, err
	}
	group, err := pendingJoin.Complete(groupInfo)
	if err != nil {
		return false, err
	}
	if err := client.putHeldGeneration(self.repoId, &gkmHeldGeneration{generation: held.generation, key: key}); err != nil {
		return false, err
	}
	epochAuthenticator := group.EpochAuthenticator()
	err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
		pins.groupId = groupId
		pins.epoch = epoch
		pins.epochAuthenticator = epochAuthenticator
		pins.epochHeader = headerBytes
		if pins.generation < header.GetGeneration() {
			pins.generation = header.GetGeneration()
			pins.commitment = key.Commitment()
		}
	})
	if err != nil {
		return false, err
	}
	// the ladder below the generation the epoch carried (KF2). A failure leaves the join standing: the next read of
	// an older generation walks again
	self.walkLadderForLater(ctx, state, groupId)
	if lastResort, ok := pendingJoin.(MlsLastResortJoin); ok && lastResort.LastResort() {
		// its leaf's HPKE key is every other Welcome's that package serves: a path at once, and a new package
		if err := self.noteLastResortJoin(); err != nil {
			return false, err
		}
	}
	return true, nil
}

// The granting device's first wrap (KF2's wrapped row): one LATE delivery of the newest generation to an agent, or
// in the config and directory groups to a wrapped member device, at once, under the late delivery's checks.
func (self *GkmGroupClient) DeliverFirstWrap(ctx context.Context, repoId Id, sidecarId Id) error {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.deliverLateInFlow(ctx, "s:"+hex.EncodeToString(sidecarId.Bytes()))
}

// The repo this device holds whose group is groupId.
func (self *GkmGroupClient) heldRepoOfGroup(groupId Id) (Id, bool) {
	repoIds, err := self.heldRepoIds()
	if err != nil {
		return Id{}, false
	}
	for _, repoId := range repoIds {
		if pins, err := self.repoPins(repoId); err == nil && pins.groupId == groupId {
			return repoId, true
		}
	}
	return Id{}, false
}

// Takes gkm's hints (§10.14): pending runs the engine, the granting device at once and every other writer after
// PendingCommitDelay plus jitter; welcome joins; wrap-pending answers with a late delivery after its own wait; and
// each resync runs all three for every repo held, so a lost hint costs at most the resync interval. A hint is only
// a wake: whatever it names is refetched and verified. commit catches up or resyncs (KF5, gkm_sync.go), and a
// resync also runs each repo's due self-update and its drop key's renewal. Each wake's work runs on its own
// goroutine until ctx ends,
// one at a time per repo and kind, so a wait never holds the intake and a repeated hint piles nothing up.
func (self *GkmGroupClient) AttachHints(ctx context.Context, hints *GkmHints) {
	if hints == nil {
		return
	}
	pending := func(repoId Id) {
		self.hintWork(ctx, "pending", repoId, func() {
			changes, granting, err := self.Pending(ctx, repoId)
			if err != nil || changes.Empty() {
				// nothing this device sees to do; what gkm holds past its epoch is still processed
				granting = true
			}
			if self.wait(ctx, self.PendingCommitWait(granting)) != nil {
				return
			}
			self.logFlowError("pending", self.RunPending(ctx, repoId))
		})
	}
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_PENDING, func(ctx context.Context, wake *GkmHintWake) {
		if wake.GroupId == nil {
			return
		}
		if repoId, ok := self.heldRepoOfGroup(*wake.GroupId); ok {
			pending(repoId)
		}
	})
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_WELCOME, func(ctx context.Context, wake *GkmHintWake) {
		joinedRepoIds, err := self.JoinWelcomes(ctx)
		self.logFlowError("welcome", err)
		self.selfUpdateJoined(ctx, joinedRepoIds)
	})
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_COMMIT, func(ctx context.Context, wake *GkmHintWake) {
		if wake.GroupId == nil {
			return
		}
		if repoId, ok := self.heldRepoOfGroup(*wake.GroupId); ok {
			self.hintWork(ctx, "commit", repoId, func() {
				self.logFlowError("commit", self.SyncRepo(ctx, repoId))
			})
		}
	})
	hints.SetHandler(protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, func(ctx context.Context, wake *GkmHintWake) {
		if wake.GroupId == nil {
			return
		}
		repoId, ok := self.heldRepoOfGroup(*wake.GroupId)
		if !ok {
			return
		}
		if wake.Recipient == "" {
			// a waiting leaf's want, or a resync's (H2): the Remove it waits on, and the GroupInfo above 16 leaves
			self.hintWork(ctx, "want", repoId, func() {
				self.logFlowError("want", self.AnswerWant(ctx, repoId))
			})
			return
		}
		recipient := wake.Recipient
		self.hintWork(ctx, "wrap-pending:"+recipient, repoId, func() {
			self.logFlowError("wrap-pending", self.DeliverLate(ctx, repoId, recipient))
		})
	})
	hints.AddResync(func(ctx context.Context) {
		self.logFlowError("heads", self.LoadHeads())
		joinedRepoIds, err := self.JoinWelcomes(ctx)
		self.logFlowError("welcome", err)
		self.selfUpdateJoined(ctx, joinedRepoIds)
		repoIds, err := self.heldRepoIds()
		if err != nil {
			return
		}
		for _, repoId := range repoIds {
			// catch-up or resync first, then the changes this device may commit, its self-update and a drop key's
			// renewal, one repo's work at a time
			self.hintWork(ctx, "sync", repoId, func() {
				self.logFlowError("sync", self.SyncRepo(ctx, repoId))
				self.logFlowError("self-update", self.RunSelfUpdate(ctx, repoId))
				self.logFlowError("drop key renewal", self.RenewDropKey(ctx, repoId))
			})
			pending(repoId)
		}
	})
}

// Runs work on its own goroutine unless the same kind of work for the repo is already running.
func (self *GkmGroupClient) hintWork(ctx context.Context, kind string, repoId Id, work func()) {
	key := kind + ":" + gkmPathId(repoId)
	running := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		running = self.hintWorkKeys[key]
		self.hintWorkKeys[key] = true
	}()
	if running {
		return
	}
	go func() {
		defer func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.hintWorkKeys, key)
		}()
		if ctx.Err() == nil {
			work()
		}
	}()
}

// Logs what a hint's flow ended with. A wait is the expected end of a flow whose turn has not come.
func (self *GkmGroupClient) logFlowError(flow string, err error) {
	if err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm]%s: %v", flow, err)
	}
}
