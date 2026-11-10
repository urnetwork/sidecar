// Recovery by a member's recovery code, gkm's side (KEYS-M2-24; D-KEYS-9, FI-12, I-15; §10.8's Recovery block,
// §7.9's anchor and restored rows, DESIGN-DETAILS 6.2.4's Recovery): what CORE-M2-06 composes, in §5.6's order,
// for a device a recovery key admitted, and what `ur keychain recovery-rotate` runs after a rebind.
//
//	fetch     under recovery:<member_id> while unadmitted, GET recovery/<member_id>/wraps: of what gkm serves, the
//	          newest wrap per group whose b8 names this code's binding is kept in the keychain. Nothing else of gkm
//	          is read before admission, and a wrap opens only against gen/<g>'s C_g, all 32 bytes of which its AAD
//	          holds, so it is opened once the device is admitted and gen/<g> reaches it (question
//	          keys-m2-24-recovery-wrap-opens-before-admission)
//	anchor    once admitted, before any commit, wrap, sealed write or further statement: the config group's RK_g,
//	          opened from its RecoveryWrap against gen/<g>'s C_g, or under a binding a void restored from the late
//	          ReaderWrap a config writer gives the device, goes to §7.9's anchor check, which is CORE-M2-06's
//	          (CONTRACTS.md). A failed check raises head_alarm (fork), drops what was opened and stops recovery in
//	          this keychain for good; a check that could not run changes nothing. Nothing below runs before it passes
//	open      every other group's RecoveryWrap is opened the same way, its generation judged by the rotation checks,
//	          kept, and its ladder walked
//	self-join by external commit, the config group if this device is leaf-entitled there and every group it writes,
//	          from the newest epoch's sealed GroupInfo under the generation it names: with the newest generation and
//	          its GenWrap when every other leaf is a key holder at this device's state (an ordinary resync's shape),
//	          else at generation 0 with no GenWrap, the lost devices' leaves staying (R4's exception), its GroupInfo
//	          sealed under the newest generation this device holds. Above 16 leaves it waits for a leaf to write the
//	          GroupInfo, and asks (H2). The other groups it joins through KF2, once upkeep uploads its KeyPackages
//	then      the pending engine: as a leaf this device's next commit removes every dropped leaf (R3), which no
//	          commit of its own may skip, and a REMOVE rotation follows where the newest generation does not cover;
//	          so no generation after the lost devices' revocation is wrapped into a tree that holds them. Revoking
//	          them is §5.6's, in any order with the self-join
//	restored  a binding a void restored takes no RecoveryWrap: the device uploads its ReaderKey and no KeyPackage
//	          (upkeep's AwaitingAnchor), anchors on the late ReaderWrap, and only then self-joins the config group
//	rebind    after a RecoveryRebind: each group's newest generation is wrapped to the new binding at its own b8
//	          path, the retired binding's wraps are deleted only once every new one stands, and then a REQUEST
//	          rotation is run in the groups this device may rotate; a compromise rebind asks REMOVE, which Rotate
//	          takes from the shrink the rebind is in the log (§7.9). Its record is kept in the keychain from before
//	          the first wrap, so a kill between any two steps resumes and finishes
//
// The keychain holds, under gkm's namespace: recovery/wraps (the kept wraps), recovery/phase (anchored or stopped)
// and recovery/rebind (a rebind under way). DESIGN-DETAILS 6.7 names <repo_id>/pending for the recovery phase; the
// anchor is the network's and not a repo's, and a self-join's progress is the group's own state (the pins and the
// engine's leaf), so no repo's record carries one.
//
// Calls testHookSecret through OpenGkmRecoveryWrap and the ladder's own functions at every key opened.

package sidecar

import (
	"bytes"
	"context"
	"crypto/hpke"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// §7.9's anchor check failed: what an anchor callback wraps to say the config head does not chain to a genesis
	// this code's binding signed, as against a check that could not run.
	ErrGkmRecoveryAnchor = errors.New("gkm: the recovery anchor failed")
	// A failed anchor stopped recovery in this keychain: it acts no further (§7.9).
	ErrGkmRecoveryStopped = errors.New("gkm: recovery stopped at a failed anchor")
	// A recovery step was asked for before the anchor passed.
	ErrGkmRecoveryNotAnchored = errors.New("gkm: recovery has not anchored")
)

// The keychain names of recovery's records.
const (
	gkmRecoveryWrapsRecord  = "recovery/wraps"
	gkmRecoveryPhaseRecord  = "recovery/phase"
	gkmRecoveryRebindRecord = "recovery/rebind"
)

// The phases recovery/phase holds.
const (
	gkmRecoveryPhaseAnchored = 1
	gkmRecoveryPhaseStopped  = 2
)

// The phases recovery/rebind holds.
const (
	// the new binding's wraps are being written; the retired binding's stand
	gkmRebindPhaseWrapping = 1
	// every new wrap stands and the retired binding's are deleted; the rotations remain
	gkmRebindPhaseRotating = 2
)

// What recovery calls at gkm beside the group flows: GkmApi's methods, so a test fakes them.
type GkmRecoveryApi interface {
	RecoveryWraps(ctx context.Context, memberId Id, recoveryScope bool) (*protocol.GkmRecoveryWrapsReply, error)
	UploadRecoveryWrap(ctx context.Context, repoId Id, memberId Id, wrap *protocol.GkmRecoveryWrap) error
	DeleteRecoveryWraps(ctx context.Context, memberId Id, bindingPrefix []byte) error
	EpochsFromStart(ctx context.Context, repoId Id, groupId Id) (*protocol.GkmEpochsReply, error)
}

var _ GkmRecoveryApi = (*GkmApi)(nil)

// The binding a recovery code derives (§5.9; RecoveryKeys), as recovery reads it.
type GkmRecoveryBinding struct {
	MemberId Id
	// RecoveryKeys.XwingPrivateKey.
	PrivateKey hpke.PrivateKey
	// RecoveryKeys.KeySha256, SHA-256 of the binding's Ed25519 key: b8 is its first 8 bytes.
	KeySha256 []byte
}

// What a recovering device's steps read.
type GkmRecoverArgs struct {
	Binding *GkmRecoveryBinding
	// The network's config repo, whose group's key the anchor reads.
	ConfigRepoId Id
	// §7.9's restored row: the binding takes no wrap, so the anchor reads the config group's late ReaderWrap.
	Restored bool
	// §7.9's anchor on the config group's RK_g, CORE-M2-06's: it opens the config head its newest verified base
	// names and holds its genesis to the binding's genesis_sig. An error wrapping ErrGkmRecoveryAnchor says the check
	// failed; any other says it could not run. Nil refuses, since nothing may run ahead of the anchor.
	Anchor func(ctx context.Context, key *EvsRepoKey) error
}

// What one pass of RunRecovery left a repo at.
type GkmRecoveryRepo struct {
	RepoId Id
	// The newest generation this device holds a key of, 0 for none yet.
	Generation uint64
	// Whether this device holds a leaf of the repo's group now.
	Leaf bool
	// Whether this pass self-joined, and whether at generation 0, the lost devices' leaves staying.
	SelfJoined     bool
	GenerationZero bool
	// What this repo waits on, nil for nothing: a GroupInfo above 16 leaves, a KF2 Add, a key, a state.
	Waiting error
}

// The recovery client's routes, or ErrGkmUnavailable for an api that serves none.
func (self *GkmGroupClient) recoveryApi() (GkmRecoveryApi, error) {
	api, ok := self.args.Api.(GkmRecoveryApi)
	if !ok {
		return nil, fmt.Errorf("%w: this api serves no recovery route", ErrGkmUnavailable)
	}
	return api, nil
}

// A binding held to its shape.
func checkGkmRecoveryBinding(binding *GkmRecoveryBinding) error {
	if binding == nil || binding.MemberId == (Id{}) || binding.PrivateKey == nil || len(binding.KeySha256) != gkmDigestByteCount {
		return fmt.Errorf("%w: a recovery binding needs its member, its X-Wing key and its key's digest", ErrGkmMalformed)
	}
	return nil
}

// Of what gkm served, the newest wrap per group whose b8 names the binding, each held to its shape, sorted by group.
func gkmNewestRecoveryWraps(wraps []*protocol.GkmRecoveryWrap, bindingKeySha256 []byte) []*protocol.GkmRecoveryWrap {
	groupIdWraps := map[Id]*protocol.GkmRecoveryWrap{}
	for _, wrap := range wraps {
		groupId, err := IdFromBytes(wrap.GetGroupId())
		if err != nil || wrap.GetGeneration() == 0 || len(wrap.GetCommitmentPrefix()) != gkmDigestPrefixByteCount ||
			len(wrap.GetCiphertext()) != gkmHpkeWrapByteCount ||
			!bytes.Equal(wrap.GetBindingPrefix(), bindingKeySha256[:gkmDigestPrefixByteCount]) {
			continue
		}
		if newest, ok := groupIdWraps[groupId]; !ok || newest.GetGeneration() < wrap.GetGeneration() {
			groupIdWraps[groupId] = wrap
		}
	}
	newest := make([]*protocol.GkmRecoveryWrap, 0, len(groupIdWraps))
	for _, wrap := range groupIdWraps {
		newest = append(newest, wrap)
	}
	slices.SortFunc(newest, func(a *protocol.GkmRecoveryWrap, b *protocol.GkmRecoveryWrap) int {
		return bytes.Compare(a.GetGroupId(), b.GetGroupId())
	})
	return newest
}

// The fetch row: the member's recovery wraps as gkm serves them, under recovery:<member_id> while the device is
// unadmitted, the newest per group of this binding kept in the keychain. Returns how many it keeps. It reads no
// state and touches nothing else of gkm, so it runs before admission.
func (self *GkmGroupClient) FetchRecoveryWraps(ctx context.Context, binding *GkmRecoveryBinding, admitted bool) (int, error) {
	if err := checkGkmRecoveryBinding(binding); err != nil {
		return 0, err
	}
	api, err := self.recoveryApi()
	if err != nil {
		return 0, err
	}
	reply, err := api.RecoveryWraps(ctx, binding.MemberId, !admitted)
	if err != nil {
		return 0, err
	}
	kept := &protocol.GkmRecoveryWrapsReply{Wraps: gkmNewestRecoveryWraps(reply.GetWraps(), binding.KeySha256)}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(kept)
	if err != nil {
		return 0, err
	}
	if err := self.args.Secrets.Put(gkmRecoveryWrapsRecord, encoded); err != nil {
		return 0, err
	}
	return len(kept.GetWraps()), nil
}

// The wraps the keychain keeps for a binding, none for a keychain that fetched none.
func (self *GkmGroupClient) keptRecoveryWraps(binding *GkmRecoveryBinding) ([]*protocol.GkmRecoveryWrap, error) {
	encoded, err := self.getRecord(gkmRecoveryWrapsRecord)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kept := &protocol.GkmRecoveryWrapsReply{}
	if err := proto.Unmarshal(encoded, kept); err != nil {
		return nil, fmt.Errorf("%w: the kept recovery wraps", ErrGkmMalformed)
	}
	return gkmNewestRecoveryWraps(kept.GetWraps(), binding.KeySha256), nil
}

// The recovery phase the keychain holds, 0 for none.
func (self *GkmGroupClient) recoveryPhase() (int, error) {
	encoded, err := self.getRecord(gkmRecoveryPhaseRecord)
	if errors.Is(err, ErrGkmKeyMissing) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if len(encoded) != 2 || encoded[0] != gkmRecordVersion {
		return 0, fmt.Errorf("%w: a recovery phase record", ErrGkmMalformed)
	}
	return int(encoded[1]), nil
}

// Whether this keychain's recovery passed its anchor: what upkeep's AwaitingAnchor and CORE's order read.
func (self *GkmGroupClient) RecoveryAnchored() (bool, error) {
	phase, err := self.recoveryPhase()
	return phase == gkmRecoveryPhaseAnchored, err
}

// The state a recovery step runs at: this device admitted by a recovery key and standing. ErrGkmWait until then.
func (self *GkmGroupClient) recoveryState() (GkmAuthView, error) {
	state, err := self.currentState()
	if err != nil {
		return nil, err
	}
	row := state.SidecarRow(self.args.SidecarId)
	if !gkmRowStanding(row) || !gkmRecoveryAdmitted(state, row) {
		return nil, fmt.Errorf("%w: this device is not admitted by a recovery key at this state", ErrGkmWait)
	}
	return state, nil
}

// The group gkm's newest GroupForm names for the repo, which binds nothing by itself: a generation's statement
// names the repo and is held to its signer, and a GroupInfo's tree is verified before anything is built on it.
func (self *gkmGroupManager) formedGroupId(ctx context.Context) (Id, error) {
	if pins, err := self.client.repoPins(self.repoId); err == nil {
		return pins.groupId, nil
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return Id{}, err
	}
	forms, err := self.client.args.Api.Forms(ctx, self.repoId)
	if err != nil {
		return Id{}, err
	}
	signedForms := forms.GetForms()
	if len(signedForms) == 0 {
		return Id{}, fmt.Errorf("%w: gkm holds no group for the repo", ErrGkmKeyMissing)
	}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(signedForms[len(signedForms)-1].GetBody(), form); err != nil {
		return Id{}, fmt.Errorf("%w: a GroupForm", ErrGkmReplyInvalid)
	}
	groupId, err := IdFromBytes(form.GetGroupId())
	if err != nil || !bytes.Equal(form.GetRepoId(), self.repoId.Bytes()) {
		return Id{}, fmt.Errorf("%w: a GroupForm of another repo", ErrGkmReplyInvalid)
	}
	return groupId, nil
}

// One generation as its RecoveryWrap opens it: gen/<g> fetched and verified under its signer's admitted key, the
// wrap's c8 held to its commitment, RK_g accepted only against C_g, and the statement judged by the rotation checks
// on its parent. Nothing is kept here. ErrGkmKeyMissing for a wrap of a claim gkm does not hold.
func (self *gkmGroupManager) openRecoveryWrapInFlow(ctx context.Context, state GkmAuthView, binding *GkmRecoveryBinding, groupId Id, wrap *protocol.GkmRecoveryWrap) (*gkmHeldGeneration, error) {
	client := self.client
	generationNumber := wrap.GetGeneration()
	generation, err := client.fetchGeneration(ctx, state, self.repoId, groupId, generationNumber)
	if err != nil {
		return nil, err
	}
	rotate := generation.Rotate
	if !bytes.Equal(rotate.GetRepoId(), self.repoId.Bytes()) {
		return nil, fmt.Errorf("%w: gen/%d names another repo", ErrGkmAuthentication, generationNumber)
	}
	if !bytes.Equal(rotate.GetCommitment()[:gkmDigestPrefixByteCount], wrap.GetCommitmentPrefix()) {
		// a staged wrap of a lost claim: gkm passes these over, so one served here is not this generation's
		return nil, fmt.Errorf("%w: a recovery wrap of another claim of generation %d", ErrGkmKeyMissing, generationNumber)
	}
	key, err := OpenGkmRecoveryWrap(wrap.GetCiphertext(), generation, &GkmRecoveryArgs{
		MemberId: binding.MemberId, GroupId: Id(rotate.GetGroupId()), BindingKeySha256: binding.KeySha256,
	}, binding.PrivateKey)
	if err != nil {
		return nil, err
	}
	checkArgs := &GkmRotationCheckArgs{RepoId: self.repoId, Generation: generation, DropKeyLifetime: client.settings.DropKeyLifetime, Now: client.clock.Now()}
	if 1 < generationNumber {
		if parent, err := client.heldGeneration(self.repoId, generationNumber-1); err == nil {
			checkArgs.Parent = parent.generation
			checkArgs.ParentPoisoned = parent.poisoned
		} else if errors.Is(err, ErrGkmKeyMissing) {
			checkArgs.Parent, err = client.fetchGeneration(ctx, state, self.repoId, groupId, generationNumber-1)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	verdict, err := CheckRotation(state, checkArgs)
	if err != nil {
		return nil, err
	}
	held := &gkmHeldGeneration{generation: generation, key: key, poisoned: verdict.Refused}
	if verdict.Refused {
		client.alarm(&GkmAlarm{
			Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: groupId, Generation: generationNumber,
			SidecarId: generation.SignerId, Reason: verdict.Reason, Detail: verdict.Detail,
		})
	}
	return held, nil
}

// Keeps a generation a RecoveryWrap opened, moves the generation pin where its checks passed, and walks the ladder
// below it.
func (self *gkmGroupManager) keepRecoveredInFlow(ctx context.Context, state GkmAuthView, groupId Id, held *gkmHeldGeneration) error {
	client := self.client
	if err := client.putHeldGeneration(self.repoId, held); err != nil {
		return err
	}
	rotate := held.generation.Rotate
	err := client.advancePins(self.repoId, func(pins *gkmRepoPins) {
		pins.groupId = groupId
		if !held.poisoned && pins.generation < rotate.GetGeneration() {
			pins.generation = rotate.GetGeneration()
			pins.commitment = bytes.Clone(rotate.GetCommitment())
		}
	})
	if err != nil {
		return err
	}
	self.walkLadderForLater(ctx, state, groupId)
	return nil
}

// The wrap among wraps of groupId, nil for none.
func gkmRecoveryWrapOf(wraps []*protocol.GkmRecoveryWrap, groupId Id) *protocol.GkmRecoveryWrap {
	for _, wrap := range wraps {
		if bytes.Equal(wrap.GetGroupId(), groupId.Bytes()) {
			return wrap
		}
	}
	return nil
}

// Every record the keychain holds of a repo this device has no leaf of, dropped: what a failed anchor leaves
// nothing of.
func (self *GkmGroupClient) dropRepoRecords(repoId Id) error {
	names, err := self.args.Secrets.List(gkmRepoRecordName(repoId, ""))
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := self.args.Secrets.Delete(name); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoIdHeads, repoId)
	return nil
}

// The anchor row. See the file header. Nil once the anchor has passed, now or before; ErrGkmRecoveryStopped, with
// head_alarm (fork) raised, when the check failed, now or before; ErrGkmWait while this device is not admitted, or
// under a restored binding while no ReaderWrap has reached it; the check's own error when it could not run.
func (self *GkmGroupClient) AnchorRecovery(ctx context.Context, args *GkmRecoverArgs) error {
	if args == nil || args.ConfigRepoId == (Id{}) {
		return fmt.Errorf("%w: recovery needs its binding and the config repo", ErrGkmMalformed)
	}
	if err := checkGkmRecoveryBinding(args.Binding); err != nil {
		return err
	}
	manager := self.manager(args.ConfigRepoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	phase, err := self.recoveryPhase()
	if err != nil {
		return err
	}
	switch phase {
	case gkmRecoveryPhaseAnchored:
		return nil
	case gkmRecoveryPhaseStopped:
		return ErrGkmRecoveryStopped
	}
	if args.Anchor == nil {
		// nothing may run ahead of the anchor, so a host with no check recovers nothing
		return fmt.Errorf("%w: no anchor check is installed", ErrGkmUnavailable)
	}
	state, err := self.recoveryState()
	if err != nil {
		return err
	}
	if state.Repo(args.ConfigRepoId) == nil {
		return fmt.Errorf("%w: repo %s", ErrGkmNoRepo, args.ConfigRepoId)
	}

	// the config group's RK_g
	var held *gkmHeldGeneration
	var groupId Id
	if args.Restored {
		// the late ReaderWrap a config writer gives such a device, or one a later rotation staged to it: taken as
		// any first wrap, under the rotation and delivery checks, and kept only if the anchor passes
		if err := manager.takeGenerationsInFlow(ctx, state); err != nil {
			if errors.Is(err, ErrGkmKeyMissing) {
				return fmt.Errorf("%w: no ReaderWrap of the config group reached this device yet: %w", ErrGkmWait, err)
			}
			return err
		}
		held, err = self.newestOpenedGeneration(args.ConfigRepoId)
		if errors.Is(err, ErrGkmKeyMissing) {
			return fmt.Errorf("%w: no ReaderWrap of the config group reached this device yet", ErrGkmWait)
		}
		if err != nil {
			return err
		}
		pins, err := self.repoPins(args.ConfigRepoId)
		if err != nil {
			return err
		}
		groupId = pins.groupId
	} else {
		groupId, err = manager.formedGroupId(ctx)
		if err != nil {
			return err
		}
		// as a device of the member now: gkm may hold a newer wrap than the fetch before admission kept, and with
		// gkm unreachable the kept one serves
		if _, err := self.FetchRecoveryWraps(ctx, args.Binding, true); err != nil && !gkmUnreachable(ctx, err) {
			return err
		}
		wraps, err := self.keptRecoveryWraps(args.Binding)
		if err != nil {
			return err
		}
		wrap := gkmRecoveryWrapOf(wraps, groupId)
		if wrap == nil {
			return fmt.Errorf("%w: gkm serves no recovery wrap of the config group for this binding", ErrGkmKeyMissing)
		}
		held, err = manager.openRecoveryWrapInFlow(ctx, state, args.Binding, groupId, wrap)
		if err != nil {
			return err
		}
	}

	stop := func(detail string, cause error) error {
		self.alarm(&GkmAlarm{
			Kind: GkmAlarmHead, RepoId: args.ConfigRepoId, GroupId: groupId, Generation: held.generation.Rotate.GetGeneration(),
			SidecarId: self.args.SidecarId, Reason: GkmRefusalFork, Detail: detail,
		})
		if err := self.dropRepoRecords(args.ConfigRepoId); err != nil {
			return err
		}
		if err := self.args.Secrets.Put(gkmRecoveryPhaseRecord, []byte{gkmRecordVersion, gkmRecoveryPhaseStopped}); err != nil {
			return err
		}
		return fmt.Errorf("%w: %w", ErrGkmRecoveryStopped, cause)
	}
	if held.key == nil || held.poisoned {
		// a wrap whose statement fails its checks proves nothing of the log it rests on
		return stop("the config group's recovery key rests on a generation that fails its checks", ErrGkmRecoveryAnchor)
	}
	if err := args.Anchor(ctx, held.key); err != nil {
		if errors.Is(err, ErrGkmRecoveryAnchor) {
			return stop("the config head does not chain to a genesis this binding signed", err)
		}
		return err
	}
	if !args.Restored {
		if err := manager.keepRecoveredInFlow(ctx, state, groupId, held); err != nil {
			return err
		}
	}
	return self.args.Secrets.Put(gkmRecoveryPhaseRecord, []byte{gkmRecordVersion, gkmRecoveryPhaseAnchored})
}

// The open, self-join and then rows, for the config repo and every repo this device reads, each pass doing what is
// due: a repo's newer RecoveryWrap is opened, a group this device should hold a leaf of and does not is self-joined,
// and the pending engine runs where it holds one. It is run again as the log moves, at each revocation of a lost
// device among them, until no repo waits. ErrGkmRecoveryNotAnchored before the anchor passed and
// ErrGkmRecoveryStopped after it failed.
func (self *GkmGroupClient) RunRecovery(ctx context.Context, args *GkmRecoverArgs) ([]*GkmRecoveryRepo, error) {
	if args == nil || args.ConfigRepoId == (Id{}) {
		return nil, fmt.Errorf("%w: recovery needs its binding and the config repo", ErrGkmMalformed)
	}
	if err := checkGkmRecoveryBinding(args.Binding); err != nil {
		return nil, err
	}
	phase, err := self.recoveryPhase()
	if err != nil {
		return nil, err
	}
	switch phase {
	case gkmRecoveryPhaseAnchored:
	case gkmRecoveryPhaseStopped:
		return nil, ErrGkmRecoveryStopped
	default:
		return nil, ErrGkmRecoveryNotAnchored
	}
	if _, err := self.recoveryState(); err != nil {
		return nil, err
	}
	var wraps []*protocol.GkmRecoveryWrap
	if !args.Restored {
		// as a device of the member now: a rotation since the last fetch left a newer wrap
		if _, err := self.FetchRecoveryWraps(ctx, args.Binding, true); err != nil && !gkmUnreachable(ctx, err) {
			return nil, err
		}
		if wraps, err = self.keptRecoveryWraps(args.Binding); err != nil {
			return nil, err
		}
	}
	repoIds := []Id{args.ConfigRepoId}
	if self.args.ReaderRepoIds != nil {
		for _, repoId := range self.args.ReaderRepoIds() {
			if !slices.Contains(repoIds, repoId) {
				repoIds = append(repoIds, repoId)
			}
		}
	}
	held, err := self.heldRepoIds()
	if err != nil {
		return nil, err
	}
	for _, repoId := range held {
		if !slices.Contains(repoIds, repoId) {
			repoIds = append(repoIds, repoId)
		}
	}
	progress := make([]*GkmRecoveryRepo, 0, len(repoIds))
	yield := self.newYield()
	for _, repoId := range repoIds {
		yield.step()
		manager := self.manager(repoId)
		manager.flowLock.Lock()
		repo, err := manager.recoverInFlow(ctx, args, wraps)
		manager.flowLock.Unlock()
		if err != nil {
			return progress, err
		}
		progress = append(progress, repo)
	}
	return progress, nil
}

// Whether an error of one repo's recovery step leaves that repo waiting without failing the pass: a key, a state,
// a GroupInfo, another leaf's commit, or gkm itself.
func gkmRecoveryWaits(ctx context.Context, err error) bool {
	return gkmLeafWaits(err) || errors.Is(err, ErrGkmAuthAhead) || errors.Is(err, ErrGkmNotWriter) || errors.Is(err, ErrGkmNoRepo) ||
		gkmUnreachable(ctx, err)
}

// One repo's pass of RunRecovery.
func (self *gkmGroupManager) recoverInFlow(ctx context.Context, args *GkmRecoverArgs, wraps []*protocol.GkmRecoveryWrap) (*GkmRecoveryRepo, error) {
	client := self.client
	progress := &GkmRecoveryRepo{RepoId: self.repoId}
	state, err := client.recoveryState()
	if err != nil {
		return nil, err
	}
	finish := func(waiting error) (*GkmRecoveryRepo, error) {
		if waiting != nil && !gkmRecoveryWaits(ctx, waiting) {
			return nil, waiting
		}
		progress.Waiting = waiting
		if top, err := client.newestOpenedGeneration(self.repoId); err == nil {
			progress.Generation = top.generation.Rotate.GetGeneration()
		}
		if pins, err := client.repoPins(self.repoId); err == nil {
			if _, err := client.loadGroup(pins.groupId); err == nil {
				progress.Leaf = true
			}
		}
		return progress, nil
	}
	repo := state.Repo(self.repoId)
	if repo == nil {
		return finish(fmt.Errorf("%w: repo %s", ErrGkmNoRepo, self.repoId))
	}

	// open: the repo's RecoveryWrap where it is newer than what this device opened, else what gkm holds past it
	groupId, err := self.formedGroupId(ctx)
	if err != nil {
		return finish(err)
	}
	opened := uint64(0)
	if top, err := client.newestOpenedGeneration(self.repoId); err == nil {
		opened = top.generation.Rotate.GetGeneration()
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return nil, err
	}
	if wrap := gkmRecoveryWrapOf(wraps, groupId); wrap != nil && opened < wrap.GetGeneration() {
		held, err := self.openRecoveryWrapInFlow(ctx, state, args.Binding, groupId, wrap)
		if err != nil {
			return finish(err)
		}
		if err := self.keepRecoveredInFlow(ctx, state, groupId, held); err != nil {
			return nil, err
		}
	} else if err := self.takeGenerationsInFlow(ctx, state); err != nil {
		return finish(err)
	}

	// self-join: the config group if leaf-entitled, every group this device writes; the others by KF2
	sidecarId := client.args.SidecarId
	row := state.SidecarRow(sidecarId)
	now := client.clock.Now()
	wantsLeaf := client.args.Mls != nil && gkmRowMemberDevice(row) && gkmWrites(state, self.repoId, sidecarId)
	if gkmGroupLeafRanked(repo) {
		wantsLeaf = client.args.Mls != nil && gkmRowMemberDevice(row) && GkmLeafEntitled(state, self.repoId, sidecarId, now)
	}
	if !wantsLeaf {
		return finish(nil)
	}
	if _, err := client.loadGroup(groupId); err != nil {
		if !errors.Is(err, ErrMlsGroupUnknown) && !errors.Is(err, ErrMlsNotMember) {
			return nil, err
		}
		joined, generationZero, err := self.selfJoinInFlow(ctx, state)
		if err != nil {
			return finish(err)
		}
		progress.SelfJoined, progress.GenerationZero = joined, generationZero
		if !joined {
			return finish(nil)
		}
	}

	// then: this leaf's next commit removes every dropped leaf, and the rotation past them follows
	if err := self.syncEpochsInFlow(ctx, state); err != nil {
		return finish(err)
	}
	return finish(self.runPendingInFlow(ctx))
}

// §10.8's self-join of this repo's group by external commit. joined is false, with no error, for a device the
// state does not seat. See the file header for the generation it carries.
func (self *gkmGroupManager) selfJoinInFlow(ctx context.Context, state GkmAuthView) (joined bool, generationZero bool, err error) {
	client := self.client
	reader, ok := client.args.Mls.(MlsGroupInfoReader)
	if !ok {
		return false, false, fmt.Errorf("%w: this engine reads no GroupInfo to join from", ErrGkmUnavailable)
	}
	api, err := client.recoveryApi()
	if err != nil {
		return false, false, err
	}
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return false, false, err
	}
	now := client.clock.Now()
	sidecarId := client.args.SidecarId
	holders, err := KeyHolders(state, self.repoId, now)
	if err != nil {
		return false, false, err
	}
	if !holders.Contains(GkmHolderLeaf, sidecarId.Bytes()) {
		return false, false, nil
	}

	// the newest epoch and its sealed GroupInfo; a group no commit has moved stands at epoch 0
	newest, groupInfoObject, err := self.newestEpochInFlow(ctx, pins)
	if err != nil {
		return false, false, err
	}
	if newest == nil {
		reply, err := api.EpochsFromStart(ctx, self.repoId, pins.groupId)
		if err != nil {
			return false, false, err
		}
		if entries := reply.GetEpochs(); 0 < len(entries) {
			newest = entries[len(entries)-1]
		}
	}
	if newest == nil || newest.GetObject() == nil {
		return false, false, fmt.Errorf("%w: gkm holds no epoch to join from", ErrGkmWait)
	}
	epoch := newest.GetEpoch()
	object := newest.GetObject()
	sealedGroupInfo, groupInfoGeneration := object.GetSealedGroupInfo(), object.GetGroupInfoGeneration()
	if len(sealedGroupInfo) == 0 {
		// above 16 leaves a self-join waits for one leaf online to write the current GroupInfo
		if groupInfoObject.GetEpoch() != epoch || len(groupInfoObject.GetSealedGroupInfo()) == 0 {
			client.askWant(ctx, self.repoId, pins.groupId, epoch)
			return false, false, fmt.Errorf("%w: no GroupInfo of epoch %d yet", ErrGkmWait, epoch)
		}
		sealedGroupInfo, groupInfoGeneration = groupInfoObject.GetSealedGroupInfo(), groupInfoObject.GetGeneration()
	}
	groupInfoHeld, err := client.heldGeneration(self.repoId, groupInfoGeneration)
	if err != nil {
		return false, false, err
	}
	if groupInfoHeld.key == nil {
		return false, false, fmt.Errorf("%w: generation %d, which seals the GroupInfo", ErrGkmKeyMissing, groupInfoGeneration)
	}
	groupInfo, err := OpenGkmGroupInfo(groupInfoHeld.key, pins.groupId, epoch, sealedGroupInfo)
	if err != nil {
		return false, false, err
	}
	groupId, groupInfoEpoch, roster, err := reader.GroupInfoRoster(groupInfo)
	if err != nil {
		return false, false, err
	}
	if groupId != pins.groupId || groupInfoEpoch != epoch {
		return false, false, fmt.Errorf("%w: a GroupInfo of another group or epoch", ErrGkmAuthentication)
	}

	// R1, R2: the newest generation, opened and judged, at a state at or past the epoch's pin and its own
	previousHeader, err := gkmEpochObjectHeader(object)
	if err != nil {
		return false, false, err
	}
	top, headerBytes, err := self.commitHeader(state, previousHeader)
	if err != nil {
		return false, false, err
	}

	// R3 and R4's exception: with a leaf that is no key holder at this state standing, generation 0 and no GenWrap
	base := &gkmExternalBase{groupId: groupId, epoch: epoch, roster: roster, self: MlsMember{SidecarId: sidecarId}}
	args := &MlsCommitArgs{Path: true, AuthenticatedData: headerBytes}
	keptLeafCount := 0
	for _, member := range roster {
		if member.SidecarId == sidecarId {
			base.self = member
			args.Removes = []uint32{member.LeafIndex}
			continue
		}
		keptLeafCount += 1
		if !holders.Contains(GkmHolderLeaf, member.SidecarId.Bytes()) {
			generationZero = true
		}
	}
	if min(max(client.settings.SeatCount, 0), GkmSeatCount) <= keptLeafCount {
		// no free seat: it waits keyless, or reads by wraps (§8.12)
		return false, false, nil
	}
	if generationZero {
		args.AuthenticatedData, err = proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmCommitHeader{Auth: state.Pin()})
		if err != nil {
			return false, false, err
		}
	}
	staged, err := client.args.Mls.JoinExternal(groupInfo, args)
	if err != nil {
		return false, false, err
	}
	outcome, err := self.uploadCommitInFlow(ctx, state, base, staged, previousHeader, top, nil)
	if err != nil {
		return false, false, err
	}
	if outcome != gkmCommitAdopted {
		// another's commit took the epoch: the next pass starts over from the newer one
		return false, false, fmt.Errorf("%w: the self-join lost its epoch", ErrGkmWait)
	}
	// an external join is a fresh path
	return true, generationZero, client.notePathCommitted(self.repoId)
}

// What a rebind's steps read.
type GkmRecoveryRebindArgs struct {
	MemberId Id
	// The new binding, as the config publishes it once the RecoveryBind or RecoveryRebind has landed.
	New *GkmRecoveryKey
	// SHA-256 of the retired binding's Ed25519 key, whose wraps go once every new one stands. Empty for a member's
	// first binding, which retires none.
	RetiredKeySha256 []byte
	// RecoveryRebind{reason: compromise}: the rotation is cause REMOVE.
	Compromise bool
}

// version | phase | flags | member_id | new binding's digest | u16 length | new X-Wing key | u16 length | retired
// digest.
func (self *GkmRecoveryRebindArgs) encode(phase int) []byte {
	flags := byte(0)
	if self.Compromise {
		flags = 1
	}
	encoded := []byte{gkmRecordVersion, byte(phase), flags}
	encoded = append(encoded, self.MemberId.Bytes()...)
	encoded = append(encoded, self.New.BindingKeySha256...)
	for _, field := range [][]byte{self.New.XwingPublicKey, self.RetiredKeySha256} {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(field)))
		encoded = append(encoded, field...)
	}
	return encoded
}

// A rebind record's fields.
func decodeGkmRecoveryRebind(encoded []byte) (*GkmRecoveryRebindArgs, int, error) {
	malformed := fmt.Errorf("%w: a rebind record", ErrGkmMalformed)
	headByteCount := 3 + gkmIdByteCount + gkmDigestByteCount
	if len(encoded) < headByteCount || encoded[0] != gkmRecordVersion {
		return nil, 0, malformed
	}
	memberId, err := IdFromBytes(encoded[3 : 3+gkmIdByteCount])
	if err != nil {
		return nil, 0, malformed
	}
	args := &GkmRecoveryRebindArgs{
		MemberId:   memberId,
		Compromise: encoded[2]&1 != 0,
		New:        &GkmRecoveryKey{BindingKeySha256: bytes.Clone(encoded[3+gkmIdByteCount : headByteCount])},
	}
	remaining := encoded[headByteCount:]
	fields := [][]byte{nil, nil}
	for index := range fields {
		if len(remaining) < 2 || len(remaining) < 2+int(binary.BigEndian.Uint16(remaining)) {
			return nil, 0, malformed
		}
		length := int(binary.BigEndian.Uint16(remaining))
		fields[index] = bytes.Clone(remaining[2 : 2+length])
		remaining = remaining[2+length:]
	}
	if len(remaining) != 0 {
		return nil, 0, malformed
	}
	args.New.XwingPublicKey, args.RetiredKeySha256 = fields[0], fields[1]
	return args, int(encoded[1]), nil
}

// A rebind held to its shape.
func checkGkmRecoveryRebind(args *GkmRecoveryRebindArgs) error {
	if args == nil || args.MemberId == (Id{}) || args.New == nil || len(args.New.XwingPublicKey) != gkmXWingPublicKeyByteCount ||
		len(args.New.BindingKeySha256) != gkmDigestByteCount {
		return fmt.Errorf("%w: a rebind needs its member and the new binding's keys", ErrGkmMalformed)
	}
	if len(args.RetiredKeySha256) != 0 && (len(args.RetiredKeySha256) != gkmDigestByteCount || bytes.Equal(args.RetiredKeySha256, args.New.BindingKeySha256)) {
		return fmt.Errorf("%w: a rebind's retired binding", ErrGkmMalformed)
	}
	return nil
}

// The rebind row, by a device of the member once its RecoveryBind or RecoveryRebind has landed. See the file
// header. A rebind another call left unfinished is finished first if it is this one, and refused otherwise.
// ErrGkmWait while the new binding has not reached this state, ErrGkmKeyMissing while this device holds no key of
// a group's newest generation, in which case nothing is deleted.
func (self *GkmGroupClient) RebindRecovery(ctx context.Context, args *GkmRecoveryRebindArgs) error {
	if err := checkGkmRecoveryRebind(args); err != nil {
		return err
	}
	phase := gkmRebindPhaseWrapping
	stored, storedPhase, err := self.storedRecoveryRebind()
	if err != nil {
		return err
	}
	if stored != nil {
		if !bytes.Equal(stored.encode(0), args.encode(0)) {
			return fmt.Errorf("%w: another rebind is unfinished", ErrGkmWait)
		}
		phase = storedPhase
	} else if err := self.args.Secrets.Put(gkmRecoveryRebindRecord, args.encode(phase)); err != nil {
		// kept before the first wrap, so a kill resumes
		return err
	}
	return self.rebindRecovery(ctx, args, phase)
}

// Finishes a rebind a kill cut short. resumed is false for a keychain that holds none.
func (self *GkmGroupClient) ResumeRecoveryRebind(ctx context.Context) (resumed bool, err error) {
	stored, phase, err := self.storedRecoveryRebind()
	if err != nil || stored == nil {
		return false, err
	}
	return true, self.rebindRecovery(ctx, stored, phase)
}

// The keychain's rebind record, nil for none.
func (self *GkmGroupClient) storedRecoveryRebind() (*GkmRecoveryRebindArgs, int, error) {
	encoded, err := self.getRecord(gkmRecoveryRebindRecord)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return decodeGkmRecoveryRebind(encoded)
}

// The rebind's steps from phase.
func (self *GkmGroupClient) rebindRecovery(ctx context.Context, args *GkmRecoveryRebindArgs, phase int) error {
	api, err := self.recoveryApi()
	if err != nil {
		return err
	}
	state, err := self.currentState()
	if err != nil {
		return err
	}
	row := state.SidecarRow(self.args.SidecarId)
	if !gkmRowStanding(row) || gkmRowReadOnly(row) || !bytes.Equal(row.GetMemberId(), args.MemberId.Bytes()) {
		return fmt.Errorf("%w: a rebind's wraps are its member's own device's", ErrGkmNotWriter)
	}
	member := state.Member(args.MemberId)
	if member == nil || !bytes.Equal(member.GetRecoveryKeySha256(), args.New.BindingKeySha256) {
		return fmt.Errorf("%w: the new binding has not reached this state", ErrGkmWait)
	}

	// the member's groups: every repo this device reads or holds in which the member holds a recovery identity
	repoIds, err := self.heldRepoIds()
	if err != nil {
		return err
	}
	if self.args.ReaderRepoIds != nil {
		for _, repoId := range self.args.ReaderRepoIds() {
			if !slices.Contains(repoIds, repoId) {
				repoIds = append(repoIds, repoId)
			}
		}
	}
	now := self.clock.Now()
	memberRepoIds := []Id{}
	for _, repoId := range repoIds {
		if state.Repo(repoId) == nil {
			continue
		}
		holders, err := KeyHolders(state, repoId, now)
		if err != nil {
			return err
		}
		if holders.Contains(GkmHolderRecovery, args.MemberId.Bytes()) {
			memberRepoIds = append(memberRepoIds, repoId)
		}
	}

	if phase == gkmRebindPhaseWrapping {
		yield := self.newYield()
		for _, repoId := range memberRepoIds {
			yield.step()
			manager := self.manager(repoId)
			manager.flowLock.Lock()
			err := manager.rewrapRecoveryInFlow(ctx, state, api, args)
			manager.flowLock.Unlock()
			if err != nil {
				// the retired binding's wraps stand until every new one does
				return err
			}
		}
		if 0 < len(args.RetiredKeySha256) {
			if err := api.DeleteRecoveryWraps(ctx, args.MemberId, args.RetiredKeySha256[:gkmDigestPrefixByteCount]); err != nil {
				return err
			}
		}
		phase = gkmRebindPhaseRotating
		if err := self.args.Secrets.Put(gkmRecoveryRebindRecord, args.encode(phase)); err != nil {
			return err
		}
	}

	// a `request` rotation in the member's groups, `remove` for a compromise, where this device may rotate; in the
	// others a writer's next write rotates once the log's shrink closes the gate, which a compromise rebind does
	cause := GkmCauseRequest
	if args.Compromise {
		cause = GkmCauseRemove
	}
	waits := []error{}
	for _, repoId := range memberRepoIds {
		manager := self.manager(repoId)
		manager.flowLock.Lock()
		rotated, err := manager.rebindRotateInFlow(ctx, args, cause)
		manager.flowLock.Unlock()
		switch {
		case err == nil && rotated, errors.Is(err, ErrGkmNotWriter):
		case err == nil:
		case gkmLeafWaits(err) || errors.Is(err, ErrGkmAuthAhead) || gkmUnreachable(ctx, err):
			waits = append(waits, err)
		default:
			return err
		}
	}
	if 0 < len(waits) {
		return fmt.Errorf("%w: %d of the rebind's rotations wait: %w", ErrGkmWait, len(waits), waits[0])
	}
	return self.args.Secrets.Delete(gkmRecoveryRebindRecord)
}

// One group's newest generation wrapped to the new binding at its own b8 path. A wrap that already stands there is
// an earlier try's: only the member's own device writes that path.
func (self *gkmGroupManager) rewrapRecoveryInFlow(ctx context.Context, state GkmAuthView, api GkmRecoveryApi, args *GkmRecoveryRebindArgs) error {
	client := self.client
	for sendCount := 0; sendCount < 2; sendCount += 1 {
		if err := self.takeGenerationsInFlow(ctx, state); err != nil {
			return err
		}
		pins, err := client.repoPins(self.repoId)
		if err != nil {
			return err
		}
		top, err := client.newestHeldGeneration(self.repoId)
		if err != nil {
			return err
		}
		rotate := top.generation.Rotate
		if top.key == nil {
			return fmt.Errorf("%w: no delivery of generation %d reached this device yet", ErrGkmKeyMissing, rotate.GetGeneration())
		}
		ciphertext, err := SealGkmRecoveryWrap(top.key, &GkmRecoveryArgs{
			MemberId: args.MemberId, GroupId: Id(rotate.GetGroupId()), RecoveryPublicKey: args.New.XwingPublicKey, BindingKeySha256: args.New.BindingKeySha256,
		})
		if err != nil {
			return err
		}
		err = api.UploadRecoveryWrap(ctx, self.repoId, args.MemberId, &protocol.GkmRecoveryWrap{
			GroupId:          pins.groupId.Bytes(),
			Generation:       rotate.GetGeneration(),
			CommitmentPrefix: bytes.Clone(rotate.GetCommitment()[:gkmDigestPrefixByteCount]),
			BindingPrefix:    bytes.Clone(args.New.BindingKeySha256[:gkmDigestPrefixByteCount]),
			Ciphertext:       ciphertext,
		})
		switch {
		case err == nil, IsGkmStatus(err, http.StatusPreconditionFailed):
			return nil
		case IsGkmStatus(err, http.StatusConflict):
			// a rotation landed since the refresh: the newer generation is wrapped instead
			continue
		default:
			return err
		}
	}
	return fmt.Errorf("%w: the group's newest generation moved under the re-wrap", ErrGkmWait)
}

// The rebind's rotation of one group, unless a generation claimed since the new binding landed already carries
// its RecoveryWrap. rotated is false for a group that needs none.
func (self *gkmGroupManager) rebindRotateInFlow(ctx context.Context, args *GkmRecoveryRebindArgs, cause GkmCause) (rotated bool, err error) {
	client := self.client
	state, err := client.currentState()
	if err != nil {
		return false, err
	}
	if err := self.takeGenerationsInFlow(ctx, state); err != nil {
		return false, err
	}
	top, err := client.newestHeldGeneration(self.repoId)
	if err != nil {
		return false, err
	}
	member := state.Member(args.MemberId)
	for _, binding := range member.GetBindings() {
		if bytes.Equal(binding.GetKeySha256(), args.New.BindingKeySha256) && binding.GetAt() <= top.generation.Rotate.GetAuth().GetVersion() && !top.poisoned {
			// its rotator computed its wraps at a state that held the new binding
			return false, nil
		}
	}
	if _, err := self.rotateInFlow(ctx, cause); err != nil {
		return false, err
	}
	return true, nil
}
