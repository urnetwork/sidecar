// The real MlsEngine: §10.4's subset over mls_group.go's state machine and mls_state.go's files, one per sidecar
// and network. sidecartest/mlssuite holds it to the same behavior as sidecartest.FakeMls, so what was built on
// the fake keeps working here.
//
// Leaves it makes carry credential 0xF552 under a fresh signature key, signed by the sidecar's identity key, which
// every path commit rotates (§10.4: rotated by self-update), and every leaf it takes in passes CheckCredential,
// KEYS-M2-19's admission and pins, after the credential's own checks. With no CheckCredential it refuses every
// leaf but its own, so it can create a group and update its own leaf, and adds and joins nothing.
//
// What the engine holds lives on disk, never in it: LoadGroup reads one group's state, tree included, for its
// caller to drive, and the engine keeps of each group only the epoch it holds and the newest it reached (§18.4's
// budgets). A commit this sidecar stages is written as a draft before Commit returns, so a crash between staging,
// gkm's answer and adoption loses nothing: after a restart, Process of the commit gkm holds at the next epoch
// returns the draft when its bytes are the draft's, which Adopt then adopts, and any other commit there is
// processed as received, the draft dropped when it is adopted (KEYS-M2-09).
//
// No join, a Welcome's or an external commit's, takes a group to an epoch at or below the newest this engine
// reached of it, held or since left, and a one-time KeyPackage's private keys are dropped before the group it
// joins is written, so a Welcome under it joins once even across a crash (RFC 9420 §16.8; I-16). A member's own
// handshake generation is reserved on disk before it seals, so no key of the secret tree seals twice.
//
// The engine is safe for concurrent use. A group, a pending join and a staged commit have one owner each, and the
// engine serializes every write: transitionLock is held across one transition's checks and its writes to the
// engine's own store, and never while waiting on anything else.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Tunes an engine.
type MlsSettings struct {
	// How long a leaf this sidecar makes stays valid, its KeyPackage's lifetime and its credential's not_after:
	// 90 days (§10.6's KeyPackages; QD-057). The tree refuses a longer one.
	LeafLifetime time.Duration
	// How far before now a new leaf's lifetime starts, so a committer whose clock runs behind can still add it:
	// gkm's 10 minutes of skew (§10.6).
	LeafClockSkew time.Duration
}

// The defaults every engine runs on outside tests.
func DefaultMlsSettings() *MlsSettings {
	return &MlsSettings{
		LeafLifetime:  90 * 24 * time.Hour,
		LeafClockSkew: 10 * time.Minute,
	}
}

// What NewMlsEngine builds one sidecar's engine from.
type MlsEngineArgs struct {
	SidecarId         Id
	IdentityPublicKey ed25519.PublicKey
	// SHA-256 of the SidecarAdmit admitting this sidecar, or of the Genesis for a network's first device, which
	// every credential it signs names (§10.4).
	AdmissionSha256 []byte
	// Signs with the identity key, for credentials (purpose mls-credential).
	Sign GkmSignFunction
	// The network's store. The engine keeps its files under gkm/ (mls_state.go).
	Store SidecarStore
	// Judges each leaf another sidecar brings, past the credential's own checks. Nil refuses every one.
	CheckCredential MlsCredentialCheck
	// Nil is real time.
	Clock    Clock
	Settings *MlsSettings
}

// One sidecar's real MLS engine.
func NewMlsEngine(args *MlsEngineArgs) (MlsEngine, error) {
	return newMlsEngine(args, mlsSuite, defaultMlsGroupSettings())
}

// The engine on suite and groupSettings, which tests vary.
func newMlsEngine(args *MlsEngineArgs, suite *mlsCipherSuite, groupSettings *mlsGroupSettings) (*mlsEngine, error) {
	if args == nil || args.Sign == nil || len(args.IdentityPublicKey) != ed25519.PublicKeySize || len(args.AdmissionSha256) != gkmDigestByteCount {
		return nil, fmt.Errorf("mls: an engine needs its identity key, its admission's hash and a signer")
	}
	store, err := newMlsStateStore(args.Store)
	if err != nil {
		return nil, err
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMlsSettings()
	}
	if settings.LeafLifetime <= 0 || groupSettings.Tree.MaximumLeafLifetime < settings.LeafLifetime {
		return nil, fmt.Errorf("mls: a leaf lifetime of %s", settings.LeafLifetime)
	}
	return &mlsEngine{
		suite:               suite,
		groupSettings:       groupSettings,
		settings:            settings,
		sidecarId:           args.SidecarId,
		identityPublicKey:   ed25519.PublicKey(bytes.Clone(args.IdentityPublicKey)),
		admissionSha256:     bytes.Clone(args.AdmissionSha256),
		sign:                args.Sign,
		clock:               clockOrReal(args.Clock),
		credentialValidator: mlsUrCredentialValidator(args.CheckCredential),
		store:               store,
		groupIdHeads:        map[Id]*mlsGroupHead{},
	}, nil
}

// What the engine keeps of one group: the epoch it holds, if any, and the newest it reached.
type mlsGroupHead struct {
	held               bool
	epoch              uint64
	epochAuthenticator []byte
	reached            uint64
	reachedAny         bool
}

// One sidecar's engine over its store.
type mlsEngine struct {
	suite               *mlsCipherSuite
	groupSettings       *mlsGroupSettings
	settings            *MlsSettings
	sidecarId           Id
	identityPublicKey   ed25519.PublicKey
	admissionSha256     []byte
	sign                GkmSignFunction
	clock               Clock
	credentialValidator mlsCredentialValidator
	store               *mlsStateStore

	transitionLock sync.Mutex
	// loaded on first use from the group's files
	groupIdHeads map[Id]*mlsGroupHead
}

// A group's head, loaded from its files the first time.
func (self *mlsEngine) headWithLock(groupId Id) (*mlsGroupHead, error) {
	if head, ok := self.groupIdHeads[groupId]; ok {
		return head, nil
	}
	head := &mlsGroupHead{}
	reached, reachedAny, err := self.store.reached(groupId)
	if err != nil {
		return nil, err
	}
	head.reached, head.reachedAny = reached, reachedAny
	state, err := self.store.state(groupId, self.suite, self.groupSettings, self.credentialValidator)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return nil, err
	default:
		head.held = true
		head.epoch = state.epoch()
		head.epochAuthenticator = bytes.Clone(state.epochAuthenticator)
		state.erase()
	}
	self.groupIdHeads[groupId] = head
	return head, nil
}

// Whether the engine holds exactly this epoch of a group.
func (self *mlsEngine) heldWithLock(groupId Id, epoch uint64, epochAuthenticator []byte) (bool, error) {
	head, err := self.headWithLock(groupId)
	if err != nil {
		return false, err
	}
	return head.held && head.epoch == epoch && bytes.Equal(head.epochAuthenticator, epochAuthenticator), nil
}

// ErrMlsGroupUnknown unless the engine holds exactly state's epoch.
func (self *mlsEngine) checkHeld(state *mlsGroupState) error {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	return self.checkHeldWithLock(state)
}

// checkHeld, with transitionLock held.
func (self *mlsEngine) checkHeldWithLock(state *mlsGroupState) error {
	held, err := self.heldWithLock(Id(state.groupId()), state.epoch(), state.epochAuthenticator)
	if err != nil {
		return err
	}
	if !held {
		return fmt.Errorf("%w: epoch %d is no longer held", ErrMlsGroupUnknown, state.epoch())
	}
	return nil
}

// Makes state the group's, recording the epoch reached first so a crash between the two writes never lets a
// later join go back, and dropping any draft or used generation of the epoch it leaves.
func (self *mlsEngine) adoptStateWithLock(state *mlsGroupState) error {
	groupId := Id(state.groupId())
	head, err := self.headWithLock(groupId)
	if err != nil {
		return err
	}
	if !head.reachedAny || head.reached < state.epoch() {
		if err := self.store.putReached(groupId, state.epoch()); err != nil {
			return err
		}
		head.reached, head.reachedAny = state.epoch(), true
	}
	if err := self.store.putState(groupId, state); err != nil {
		return err
	}
	head.held = true
	head.epoch = state.epoch()
	head.epochAuthenticator = bytes.Clone(state.epochAuthenticator)
	if err := self.store.removeDraft(groupId); err != nil {
		return err
	}
	return nil
}

// A fresh signature key and the credential naming it, signed by the identity key (§10.4), its not_after the
// signing time plus a leaf's lifetime (QD-057).
func (self *mlsEngine) newLeafIdentity() (*mlsLeafIdentity, error) {
	signatureKey, err := self.suite.generateSignatureKey("signature_priv")
	if err != nil {
		return nil, err
	}
	credential, err := SignUrMlsCredential(&UrMlsCredentialArgs{
		SidecarId:             self.sidecarId,
		IdentityPublicKey:     self.identityPublicKey,
		MlsSignaturePublicKey: signatureKey.Public().(ed25519.PublicKey),
		NotAfter:              self.clock.Now().Add(self.settings.LeafLifetime),
		AdmissionSha256:       self.admissionSha256,
	}, self.sign)
	if err != nil {
		return nil, err
	}
	return &mlsLeafIdentity{
		signatureKey: signatureKey,
		credential:   mlsCredential{credentialType: mlsCredentialTypeUrSidecar, urMlsCredential: credential},
	}, nil
}

// A new leaf's lifetime, from a little before now.
func (self *mlsEngine) leafLifetime() mlsLifetime {
	return newMlsLifetime(self.clock.Now(), self.settings.LeafClockSkew, self.settings.LeafLifetime)
}

// A KeyPackage for a new leaf identity, its private keys kept on disk until a Welcome under it joins or, for the
// last-resort one, for its life.
func (self *mlsEngine) CreateKeyPackage(lastResort bool) (*MlsKeyPackage, error) {
	identity, err := self.newLeafIdentity()
	if err != nil {
		return nil, err
	}
	held, err := newMlsHeldKeyPackage(self.suite, identity, self.leafLifetime(), lastResort)
	if err != nil {
		return nil, err
	}
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	if err := self.store.putKeyPackage(held); err != nil {
		return nil, err
	}
	return &MlsKeyPackage{Encoded: bytes.Clone(held.encoded), Ref: bytes.Clone(held.ref), LastResort: lastResort}, nil
}

// A new group, refused for a group this engine holds or ever reached.
func (self *mlsEngine) CreateGroup(groupId Id, urGroup *MlsUrGroup) (MlsGroup, error) {
	extensions, err := mlsSubsetGroupExtensions(urGroup)
	if err != nil {
		return nil, err
	}
	identity, err := self.newLeafIdentity()
	if err != nil {
		return nil, err
	}
	state, err := newMlsGroup(self.suite, self.groupSettings, self.credentialValidator, groupId.Bytes(), extensions, identity, self.leafLifetime())
	if err != nil {
		return nil, err
	}
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	head, err := self.headWithLock(groupId)
	if err != nil {
		return nil, err
	}
	if head.held || head.reachedAny {
		return nil, fmt.Errorf("%w: group %s exists here", errMlsInvalid, groupId)
	}
	if err := self.adoptStateWithLock(state); err != nil {
		return nil, err
	}
	return &mlsRealGroup{engine: self, state: state}, nil
}

// The first phase under the first of this sidecar's KeyPackages the Welcome names.
func (self *mlsEngine) JoinWelcome(welcome []byte) (MlsPendingJoin, error) {
	decoded := &mlsWelcome{}
	if err := mlsUnmarshalMessageOf(welcome, mlsWireFormatWelcome, decoded); err != nil {
		return nil, err
	}
	for _, ref := range decoded.newMembers() {
		held, err := func() (*mlsHeldKeyPackage, error) {
			self.transitionLock.Lock()
			defer self.transitionLock.Unlock()
			return self.store.keyPackage(self.suite, ref)
		}()
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return nil, err
		}
		opened, err := openMlsWelcome(self.suite, decoded, held)
		if err != nil {
			return nil, err
		}
		if _, err := mlsCheckSubsetGroupExtensions(opened.groupInfo.groupContext.extensions); err != nil {
			opened.erase()
			return nil, err
		}
		return &mlsRealPendingJoin{engine: self, opened: opened}, nil
	}
	return nil, fmt.Errorf("%w: %w", ErrMlsNotMember, errMlsWelcomeNotOurs)
}

// An external commit from a full GroupInfo whose tree and signature hold, under a new leaf identity.
func (self *mlsEngine) JoinExternal(groupInfo []byte, args *MlsCommitArgs) (MlsStagedCommit, error) {
	if args == nil || len(args.Adds) != 0 || !args.Path {
		return nil, fmt.Errorf("%w: an external commit adds no one and carries a path", errMlsInvalid)
	}
	decoded := &mlsGroupInfo{}
	if err := mlsUnmarshalMessageOf(groupInfo, mlsWireFormatGroupInfo, decoded); err != nil {
		return nil, err
	}
	tree, err := decoded.checkTree(self.suite, self.groupSettings.Tree, self.credentialValidator)
	if err != nil {
		return nil, err
	}
	identity, err := self.newLeafIdentity()
	if err != nil {
		return nil, err
	}
	removes := []mlsLeafIndex{}
	for _, removed := range args.Removes {
		removes = append(removes, mlsLeafIndex(removed))
	}
	staged, err := mlsStageExternalCommit(self.suite, self.groupSettings, self.credentialValidator, decoded, tree, identity, removes, args.AuthenticatedData)
	if err != nil {
		return nil, err
	}
	return &mlsRealStagedCommit{engine: self, staged: staged, own: true}, nil
}

// The held state of a group, read from disk, its handshake generation resumed past what it used.
func (self *mlsEngine) LoadGroup(groupId Id) (MlsGroup, error) {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	head, err := self.headWithLock(groupId)
	if err != nil {
		return nil, err
	}
	if !head.held {
		return nil, ErrMlsGroupUnknown
	}
	state, err := self.store.state(groupId, self.suite, self.groupSettings, self.credentialValidator)
	if err != nil {
		return nil, err
	}
	if state.epoch() != head.epoch {
		return nil, fmt.Errorf("%w: a state of epoch %d where %d is held", errMlsStateFormat, state.epoch(), head.epoch)
	}
	if state.handshakeGeneration, err = self.store.sent(groupId, state.epoch()); err != nil {
		return nil, err
	}
	return &mlsRealGroup{engine: self, state: state}, nil
}

// Reserves the next handshake generation of state's epoch on disk, before it seals.
func (self *mlsEngine) reserveGeneration(state *mlsGroupState) (uint32, error) {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	if err := self.checkHeldWithLock(state); err != nil {
		return 0, err
	}
	groupId := Id(state.groupId())
	generation, err := self.store.sent(groupId, state.epoch())
	if err != nil {
		return 0, err
	}
	generation = max(generation, state.handshakeGeneration)
	if err := self.store.putSent(groupId, state.epoch(), generation+1); err != nil {
		return 0, err
	}
	return generation, nil
}

// One group at the epoch this engine adopted.
type mlsRealGroup struct {
	engine *mlsEngine
	state  *mlsGroupState
}

// While the epoch is held.
func (self *mlsRealGroup) Exporter(label string, context []byte, length int) ([]byte, error) {
	if err := self.engine.checkHeld(self.state); err != nil {
		return nil, err
	}
	return self.state.exportSecret(label, context, length)
}

// The group's id.
func (self *mlsRealGroup) GroupId() Id {
	return Id(self.state.groupId())
}

// The epoch this state is at.
func (self *mlsRealGroup) Epoch() uint64 {
	return self.state.epoch()
}

// A copy.
func (self *mlsRealGroup) EpochAuthenticator() []byte {
	return bytes.Clone(self.state.epochAuthenticator)
}

// This sidecar's leaf.
func (self *mlsRealGroup) Self() MlsMember {
	member, _ := mlsMemberOf(self.state.ownLeaf(), self.state.tree.leafNode(self.state.ownLeaf()))
	return member
}

// Every leaf of the epoch.
func (self *mlsRealGroup) Roster() []MlsMember {
	roster, _ := self.state.roster()
	return roster
}

// The full GroupInfo, while the epoch is held.
func (self *mlsRealGroup) GroupInfo() ([]byte, error) {
	if err := self.engine.checkHeld(self.state); err != nil {
		return nil, err
	}
	return self.state.encodedGroupInfo()
}

// Stages this sidecar's commit, refusing what the subset refuses before anything seals.
func (self *mlsRealGroup) Commit(args *MlsCommitArgs) (MlsStagedCommit, error) {
	engine := self.engine
	if err := engine.checkHeld(self.state); err != nil {
		return nil, err
	}
	if args == nil {
		return nil, fmt.Errorf("%w: an empty commit", errMlsInvalid)
	}
	input := &mlsCommitInput{path: args.Path, authenticatedData: args.AuthenticatedData, now: engine.clock.Now()}
	for _, encoded := range args.Adds {
		keyPackage := &mlsKeyPackage{}
		if err := mlsUnmarshalMessageOf(encoded, mlsWireFormatKeyPackage, keyPackage); err != nil {
			return nil, err
		}
		input.adds = append(input.adds, keyPackage)
	}
	for _, removed := range args.Removes {
		input.removes = append(input.removes, mlsLeafIndex(removed))
	}
	if len(input.adds) == 0 && len(input.removes) == 0 && !input.path {
		return nil, fmt.Errorf("%w: an empty commit", errMlsInvalid)
	}
	if 0 < len(input.removes) && !input.path {
		return nil, fmt.Errorf("%w: a Remove carries a path (§10.4)", errMlsInvalid)
	}
	return self.stage(input)
}

// Stages input as this sidecar's commit: a new leaf identity for a path, a handshake generation reserved on disk,
// and the draft written before it returns. Commit's arguments carry no GroupContextExtensions, which v0's flows
// never commit (§10.9 gives them to a repo admin's leaf); input may.
func (self *mlsRealGroup) stage(input *mlsCommitInput) (MlsStagedCommit, error) {
	engine := self.engine
	if input.path {
		identity, err := engine.newLeafIdentity()
		if err != nil {
			return nil, err
		}
		input.pathIdentity = identity
	}
	generation, err := engine.reserveGeneration(self.state)
	if err != nil {
		return nil, err
	}
	input.generation = generation
	staged, err := self.state.stageCommit(input)
	if err != nil {
		return nil, err
	}
	if err := engine.putDraft(self.state, staged); err != nil {
		staged.next.erase()
		return nil, err
	}
	return &mlsRealStagedCommit{engine: engine, base: self.state, staged: staged, own: true}, nil
}

// Stages another's commit, or returns this sidecar's own draft when message is its commit.
func (self *mlsRealGroup) Process(message []byte) (MlsStagedCommit, error) {
	engine := self.engine
	if err := engine.checkHeld(self.state); err != nil {
		return nil, err
	}
	if draft := engine.matchingDraft(self.state, message); draft != nil {
		return &mlsRealStagedCommit{engine: engine, base: self.state, staged: draft, own: true}, nil
	}
	staged, err := self.state.processCommit(message)
	if err != nil {
		return nil, err
	}
	return &mlsRealStagedCommit{engine: engine, base: self.state, staged: staged}, nil
}

// Writes this member's staged commit as the group's draft, while its base epoch is still held.
func (self *mlsEngine) putDraft(base *mlsGroupState, staged *mlsStagedState) error {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	if err := self.checkHeldWithLock(base); err != nil {
		return err
	}
	return self.store.putDraft(Id(base.groupId()), staged)
}

// The draft on base's epoch whose commit is message, nil for none: a commit staged here before a crash, which gkm
// took. A draft that does not read is left for the commit to be processed as received.
func (self *mlsEngine) matchingDraft(base *mlsGroupState, message []byte) *mlsStagedState {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	draft, err := self.store.draft(Id(base.groupId()), self.suite, self.groupSettings, self.credentialValidator)
	if err != nil {
		return nil
	}
	if draft.baseEpoch != base.epoch() || !bytes.Equal(draft.baseEpochAuthenticator, base.epochAuthenticator) || !bytes.Equal(draft.message, message) {
		draft.next.erase()
		return nil
	}
	return draft
}

// Adopts a staged commit: base's epoch must still be held, but for this sidecar's own external commit, which joins
// above the newest epoch reached. A commit that removes this member drops the group, all but the epoch reached.
func (self *mlsEngine) adopt(base *mlsGroupState, staged *mlsStagedState, own bool) (MlsGroup, error) {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	var groupId Id
	if staged.next != nil {
		groupId = Id(staged.next.groupId())
	} else {
		groupId = Id(base.groupId())
	}
	if staged.external && own {
		head, err := self.headWithLock(groupId)
		if err != nil {
			return nil, err
		}
		if head.reachedAny && staged.next.epoch() <= head.reached {
			return nil, fmt.Errorf("%w: a join to epoch %d of a group this engine reached epoch %d of", errMlsInvalid, staged.next.epoch(), head.reached)
		}
	} else if err := self.checkHeldWithLock(base); err != nil {
		return nil, err
	}
	if staged.removesSelf {
		head, err := self.headWithLock(groupId)
		if err != nil {
			return nil, err
		}
		epoch := staged.baseEpoch + 1
		if !head.reachedAny || head.reached < epoch {
			if err := self.store.putReached(groupId, epoch); err != nil {
				return nil, err
			}
			head.reached, head.reachedAny = epoch, true
		}
		if err := self.store.removeState(groupId); err != nil {
			return nil, err
		}
		head.held = false
		head.epochAuthenticator = nil
		if base != nil {
			base.erase()
		}
		return nil, ErrMlsNotMember
	}
	if err := self.adoptStateWithLock(staged.next); err != nil {
		return nil, err
	}
	if base != nil {
		base.erase()
	}
	return &mlsRealGroup{engine: self, state: staged.next}, nil
}

// Drops this member's draft when it is staged's.
func (self *mlsEngine) discardDraft(base *mlsGroupState, staged *mlsStagedState) {
	self.transitionLock.Lock()
	defer self.transitionLock.Unlock()
	groupId := Id(base.groupId())
	draft, err := self.store.draft(groupId, self.suite, self.groupSettings, self.credentialValidator)
	if err != nil {
		return
	}
	defer draft.next.erase()
	if bytes.Equal(draft.message, staged.message) {
		self.store.removeDraft(groupId)
	}
}

// A commit staged on this engine's epoch, its own or one received.
type mlsRealStagedCommit struct {
	engine *mlsEngine
	// The state it is staged on, nil for an external join of this sidecar's.
	base   *mlsGroupState
	staged *mlsStagedState
	// made by this engine, so it holds its Welcome and its draft
	own       bool
	discarded bool
}

// The next epoch's: ErrMlsNotMember when the commit removes this sidecar.
func (self *mlsRealStagedCommit) Exporter(label string, context []byte, length int) ([]byte, error) {
	if self.staged.next == nil || self.discarded {
		return nil, ErrMlsNotMember
	}
	return self.staged.next.exportSecret(label, context, length)
}

// A copy of the commit's MLSMessage.
func (self *mlsRealStagedCommit) Message() []byte {
	return bytes.Clone(self.staged.message)
}

// The epoch the commit makes.
func (self *mlsRealStagedCommit) Epoch() uint64 {
	return self.staged.baseEpoch + 1
}

// The next epoch's, nil when the commit removes this sidecar.
func (self *mlsRealStagedCommit) EpochAuthenticator() []byte {
	if self.staged.next == nil {
		return nil
	}
	return bytes.Clone(self.staged.next.epochAuthenticator)
}

// Its committer's leaf.
func (self *mlsRealStagedCommit) Committer() MlsMember {
	member, _ := mlsMemberOf(self.staged.committer, self.staged.committerLeaf)
	return member
}

// The leaves it adds.
func (self *mlsRealStagedCommit) Added() []MlsMember {
	if self.staged.next == nil {
		return []MlsMember{}
	}
	added, _ := self.staged.addedMembers()
	return added
}

// The leaves it removes.
func (self *mlsRealStagedCommit) Removed() []MlsMember {
	removed, _ := self.staged.removedMembers()
	return removed
}

// A copy of what it authenticated in the clear.
func (self *mlsRealStagedCommit) AuthenticatedData() []byte {
	return bytes.Clone(self.staged.authenticatedData)
}

// This sidecar's own commit's Welcome.
func (self *mlsRealStagedCommit) Welcome() []byte {
	if !self.own || self.staged.welcome == nil {
		return nil
	}
	return bytes.Clone(self.staged.welcome)
}

// The next epoch's full GroupInfo.
func (self *mlsRealStagedCommit) GroupInfo() ([]byte, error) {
	if self.staged.next == nil || self.discarded {
		return nil, ErrMlsNotMember
	}
	return self.staged.next.encodedGroupInfo()
}

// Adopts it, unless discarded.
func (self *mlsRealStagedCommit) Adopt() (MlsGroup, error) {
	if self.discarded {
		return nil, fmt.Errorf("%w: a discarded commit", ErrMlsGroupUnknown)
	}
	return self.engine.adopt(self.base, self.staged, self.own)
}

// Drops it and, for this sidecar's own, its draft.
func (self *mlsRealStagedCommit) Discard() {
	if self.discarded {
		return
	}
	self.discarded = true
	if self.own && self.base != nil {
		self.engine.discardDraft(self.base, self.staged)
	}
	if self.staged.next != nil {
		self.staged.next.erase()
	}
}

// A Welcome opened, its epoch's exporter reachable, and its group not yet joined.
type mlsRealPendingJoin struct {
	engine *mlsEngine
	opened *mlsOpenedWelcome
}

// The joined epoch's, before anything the Welcome says is trusted.
func (self *mlsRealPendingJoin) Exporter(label string, context []byte, length int) ([]byte, error) {
	return self.opened.exportSecret(label, context, length)
}

// The group the Welcome names.
func (self *mlsRealPendingJoin) GroupId() Id {
	return Id(self.opened.groupInfo.groupContext.groupId)
}

// The epoch it joins.
func (self *mlsRealPendingJoin) Epoch() uint64 {
	return self.opened.groupInfo.groupContext.epoch
}

// The second phase, then the join written: refused above an epoch reached or a one-time KeyPackage used.
func (self *mlsRealPendingJoin) Complete(groupInfo []byte) (MlsGroup, error) {
	engine := self.engine
	full := &mlsGroupInfo{}
	if err := mlsUnmarshalMessageOf(groupInfo, mlsWireFormatGroupInfo, full); err != nil {
		return nil, err
	}
	tree, err := full.ratchetTree(engine.suite, engine.groupSettings.Tree)
	if err != nil {
		return nil, err
	}
	state, err := self.opened.complete(tree, full, engine.groupSettings, engine.credentialValidator)
	if err != nil {
		return nil, err
	}
	if err := mlsCheckUniqueSidecars(state.tree); err != nil {
		state.erase()
		return nil, err
	}
	held := self.opened.held

	engine.transitionLock.Lock()
	defer engine.transitionLock.Unlock()
	groupId := Id(state.groupId())
	head, err := engine.headWithLock(groupId)
	if err != nil {
		state.erase()
		return nil, err
	}
	if head.reachedAny && state.epoch() <= head.reached {
		state.erase()
		return nil, fmt.Errorf("%w: a join to epoch %d of a group this engine reached epoch %d of", errMlsInvalid, state.epoch(), head.reached)
	}
	if !held.lastResort {
		// one Welcome joins under a one-time KeyPackage: its keys go before the group is written, so a crash
		// between the two loses the join rather than allowing a second
		if _, err := engine.store.keyPackage(engine.suite, held.ref); err != nil {
			state.erase()
			if errors.Is(err, ErrSidecarStoreAbsent) {
				return nil, fmt.Errorf("%w: a Welcome under a one-time KeyPackage already used", ErrMlsNotMember)
			}
			return nil, err
		}
		if err := engine.store.removeKeyPackage(held.ref); err != nil {
			state.erase()
			return nil, err
		}
	}
	if err := engine.store.removeState(groupId); err != nil {
		state.erase()
		return nil, err
	}
	if err := engine.adoptStateWithLock(state); err != nil {
		state.erase()
		return nil, err
	}
	self.opened.erase()
	return &mlsRealGroup{engine: engine, state: state}, nil
}
