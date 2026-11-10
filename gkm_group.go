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
// GkmGroupClient is GkmClient's real implementation as far as these tasks reach: RotateRepo (KEYS-M2-20),
// CreateGroup and AuthAdvanced (KEYS-M2-21). CurrentRepoKey, RepoKey, EnsureWritable, DropKey and ForgetRepo are
// KEYS-M2-22's key access, and until it lands they refuse with ErrGkmUnavailable, so nothing reads this client as
// serving keys it does not yet serve.
//
// Locks: a manager's flowLock is held across a whole flow and its I/O, so it is never taken under stateLock, which
// guards only the newest state and the manager table. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
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
	UploadWelcome(ctx context.Context, repoId Id, groupId Id, epoch uint64, request *protocol.GkmWelcomeRequest) error
	Welcomes(ctx context.Context) ([]*protocol.GkmWelcomeEntry, error)
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
	// Each alarm a flow raises (§10.9): refused, head_alarm, approval_pending. It must not block. Nil drops them.
	Alarm func(alarm *GkmAlarm)
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
}

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
		args:           args,
		settings:       settings,
		clock:          clockOrReal(args.Clock),
		log:            loggerOrDefault(args.Log),
		lateAsks:       NewGkmLateAsks(settings),
		repoIdManagers: map[Id]*gkmGroupManager{},
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

// The newest verified state, or ErrGkmUnavailable before the first.
func (self *GkmGroupClient) currentState() (GkmAuthView, error) {
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

// KEYS-M2-22's key access, which this client does not serve yet: refused, never defaulted.
func (self *GkmGroupClient) CurrentRepoKey(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, fmt.Errorf("%w: key access lands with KEYS-M2-22", ErrGkmUnavailable)
}

// Refused until KEYS-M2-22.
func (self *GkmGroupClient) RepoKey(ctx context.Context, repoId Id, generation uint64) (*EvsRepoKey, error) {
	return nil, fmt.Errorf("%w: key access lands with KEYS-M2-22", ErrGkmUnavailable)
}

// Refused until KEYS-M2-22, whose step 2 runs RunPending and step 3 the rotation here.
func (self *GkmGroupClient) EnsureWritable(ctx context.Context, repoId Id) (*EvsRepoKey, error) {
	return nil, fmt.Errorf("%w: key access lands with KEYS-M2-22", ErrGkmUnavailable)
}

// Refused until KEYS-M2-22.
func (self *GkmGroupClient) DropKey(ctx context.Context, repoId Id) (*GkmDropKey, error) {
	return nil, fmt.Errorf("%w: key access lands with KEYS-M2-22", ErrGkmUnavailable)
}

// Refused until KEYS-M2-22: a shred must not read as done here.
func (self *GkmGroupClient) ForgetRepo(ctx context.Context, repoId Id) error {
	return fmt.Errorf("%w: key access lands with KEYS-M2-22", ErrGkmUnavailable)
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
// new id is taken only along a verified GroupForm chain, which KEYS-M2-25 builds.
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
	return self.args.Secrets.Put(gkmRepoRecordName(repoId, "pins"), next.encode())
}

// The group's MLS state as this sidecar last adopted it, or ErrMlsGroupUnknown for a sidecar that holds no leaf.
func (self *GkmGroupClient) loadGroup(groupId Id) (MlsGroup, error) {
	if self.args.Mls == nil {
		return nil, ErrMlsGroupUnknown
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
	return ParseGenRotate(signedBytes, groupId, generation, GkmIdentityKeys(state))
}
