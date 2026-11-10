// Code-only recovery (CORE-M2-06; R-CORE-16, D-CORE-5, I-1, I-4, I-16, FS-16; §5.6's genesis row, §7.9's Recovery,
// C-03): a member's new device holding nothing but the member's recovery code, its 12 words typed on /dev/tty or in an
// app's UI, admits itself by the code's key and checks, before it acts at all, that the network that admitted it is the
// one the code was bound in. The order is §5.6's and §7.9's, and this file owns it:
//
//	before    after ur login the device holds an unadmitted client of its member M, the user its token names. It
//	          reads the log (its ConfigClient follows, as every device's does), fetches M's recovery wraps under
//	          recovery:<member_id> (KEYS-M2-24's FetchRecoveryWraps, which keeps them and opens none yet), and signs
//	          one statement by the code's Ed25519 key: a plain SidecarAdmit of itself, or an AuthorityProposal of it,
//	          whichever the verified state takes now, by the log's own judge (SidecarStatementJudge), never a table
//	          kept here (C-01): plain outside the AdminSet with self_admit on; a proposal with it off, inside the
//	          AdminSet, in a personal network and under a binding a void restored. It keeps the statement in
//	          keychain.ur's pending records before it posts it, the same bytes until its not_after, and its own record
//	          beside it: the member, the code's key hash, the statement's id and whether it is a proposal, which with
//	          the identity key and sidecar_id that enrollment kept is what §7.9's restart row names. A restart resumes
//	          from it and never files a second admission
//	pending   a proposal waits on one admission signer's cosign or on Recovery's 72 h window and its veto. The device
//	          polls the log as before; the code is asked for again once the admission has landed, since no device
//	          keeps a code or the keys it derives (§5.9), and RecoverWithCode erases them before it answers
//	anchor    once admitted, before any commit, wrap, sealed write or further statement: KEYS-M2-24's AnchorRecovery
//	          opens the config group's RK_g, from M's RecoveryWrap against gen/<g>'s C_g or, under a binding a void
//	          restored, from the late ReaderWrap a config writer gives the device, and hands it to this file's check
//	          (checkRecoveryCodeAnchor). The config head the newest verified base names, read under that key and the
//	          ladder below it, must hold the genesis the verified log starts from and records chaining from it to the
//	          entries the log holds (CheckConfigBase's anchor, DESIGN-DETAILS 5.2.4's StartAtBase), and M's binding of
//	          this code on that chain must carry a genesis_sig that verifies, under the Ed25519 key the code derives,
//	          over this network and SHA-256 of that genesis. A C_g match alone proves nothing, since gkm sees every C_g
//	          and a forged log can admit any real rotator; genesis_sig is the one input only the code makes. A failed
//	          check raises head_alarm (fork, with that base's AuthPin), keeps the record stopped, and the device acts
//	          no further, now or after a restart; a check that could not run changes nothing
//	restored  under a binding a void restored, §7.9's restored row in the same frame: pending, it signs only its
//	          AuthorityProposal; activated, its ReaderKey goes up and no KeyPackage (RecoveryAwaitingAnchor, upkeep's
//	          AwaitingAnchor, and Sign's gate below), so no Add precedes the anchor; it waits for the late ReaderWrap
//	          and anchors on that wrap's RK_g
//	after     KEYS-M2-24's RunRecovery: the other RecoveryWraps opened, the self-join where the device is entitled to a
//	          leaf, reads by wraps where it is not; then the caller offers `ur keychain recovery-rotate`, since the
//	          code was typed into this device
//
// The gate is Sign's (checkRecoveryAnchorSign): while a recovery's anchor has not passed, the identity key signs only
// this device's ReaderKey and its own sign-out, so no component commits, wraps, seals or files ahead of the check
// whatever it asks; once the check failed, only the sign-out.
//
// What a host installs beside the authority: KEYS-M2-24's GkmGroupClient and a reader of the config head under a
// recovery's key (InstallRecovery), and an authority that also judges statements and shows the anchor its log
// (SidecarStatementJudge, SidecarRecoveryLogView, which ConfigAuthority answers below from ConfigLog's own Check and
// kept entries). With any of these missing nothing is signed.
//
// No code, word or private key of the code's is written anywhere, and each is erased once used; testHookSecret sees
// them where keys_recovery.go derives them. On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The keychain record of the core's namespace keeping a code-only recovery's progress: §5.9's "a pending recovery
// proposal's or admission's id (§7.9)".
const sidecarRecoveryRecordName = "recovery"

// The record's format version.
const sidecarRecoveryRecordVersion = 1

var (
	// The code's binding is not its member's binding in effect: another member's code, a code a rebind retired, or
	// a member the verified log holds no binding of. Nothing was signed.
	ErrSidecarRecoveryUnbound = errors.New("this recovery code is not the member's recovery code in effect")
	// A recovery by another code is under way on this device: finish it with that code, or sign out.
	ErrSidecarRecoveryOtherCode = errors.New("a recovery by another code is under way on this device")
	// The device is admitted by other than its own recovery: it needs no code to join, and recovery-rotate sets a new
	// one.
	ErrSidecarRecoveryAdmitted = errors.New("this device is admitted already, by other than its recovery code")
	// The anchor failed (§7.9's anchor): the network this device was admitted into is not the one the code was bound in,
	// or not as its log says. head_alarm was raised and the device acts no further.
	ErrSidecarRecoveryStopped = errors.New("recovery stopped: the network's config does not chain to the genesis this code signed")
	// What recovery runs on is not installed: the verified log's judge or anchor view, gkm's recovery client or the
	// head reader. Nothing was signed.
	ErrSidecarRecoveryUnavailable = errors.New("recovery cannot run on this host yet")
	// The verified state takes no admission by this code now, neither plainly nor as a proposal. Nothing was posted.
	ErrSidecarRecoveryRefused = errors.New("the log takes no admission of this device by this recovery code now")
	// A recovery's anchor has not passed, or failed: the identity key signs only the ReaderKey and the sign-out.
	ErrSidecarRecoveryUnanchored = errors.New("this device recovers by code and acts only once its recovery anchor passes")
)

// Where a code-only recovery stands.
type SidecarRecoveryPhase string

const (
	// Its admission is filed: a plain one whose post has not landed, or a proposal its cosign or window holds.
	SidecarRecoveryPending SidecarRecoveryPhase = "pending"
	// Admitted, and the anchor has not passed: it waits for the config group's key, or its check could not run.
	SidecarRecoveryAdmitted SidecarRecoveryPhase = "admitted"
	// The anchor passed, and the device acts as any device of its member.
	SidecarRecoveryAnchored SidecarRecoveryPhase = "anchored"
	// The anchor failed, and the device acts no further.
	SidecarRecoveryStopped SidecarRecoveryPhase = "stopped"
)

// What a code-only recovery did, and where it stands: ids and positions, never a key.
type SidecarRecovery struct {
	Phase SidecarRecoveryPhase
	// The member whose code it is.
	MemberId Id
	// The statement this device filed: its plain SidecarAdmit's id, or its AuthorityProposal's proposal_id (§7.9),
	// the id cosigns and vetoes name.
	StatementId []byte
	// Whether it went as an AuthorityProposal, and the kind the log fixed for it, unspecified while the log shows none.
	Proposal     bool
	ProposalKind bridge.ProposalKind
	// Under a binding a void restored (§7.9's restored row).
	Restored bool
	// Where this call's post landed, nil when it made none or its answer was lost: a lost one goes again with the
	// same bytes (PostPendingStatements).
	Entry *bridge.AuthPin
	// A windowed proposal's earliest activation: 72 h after the entry of its newest recovery-key signature (§7.9's
	// activation row). Zero for one no window holds, which an admission signer's cosign completes, and for an
	// admission that is not a proposal.
	ActivatesAfter time.Time
	// What it waits on, for the person, empty for nothing.
	Waiting string
	// Each repo KEYS-M2-24's pass left, once anchored.
	Repos []*GkmRecoveryRepo
	// Anchored: the code was typed into this device, so the caller offers `ur keychain recovery-rotate`.
	OfferRotate bool
}

// What a code-only recovery runs at gkm: KEYS-M2-24's GkmGroupClient, whose functions hold their own order inside
// and refuse before admission and before the anchor (gkm_recovery.go).
type SidecarRecoveryGroups interface {
	FetchRecoveryWraps(ctx context.Context, binding *GkmRecoveryBinding, admitted bool) (int, error)
	AnchorRecovery(ctx context.Context, args *GkmRecoverArgs) error
	RunRecovery(ctx context.Context, args *GkmRecoverArgs) ([]*GkmRecoveryRepo, error)
}

var _ SidecarRecoveryGroups = (*GkmGroupClient)(nil)

// Reads the config head a base names under the config group's key a recovery opened, which nothing has kept yet,
// so the head is read under that key alone and the ladder below it (§7.9's anchor): the config repo's file-mode main
// ref at configVersion, whose chain value C_v is configHeadSha256, on that ref's chain from C_0. Answers the head and
// the key of each generation the ladder reaches from key, nil for one it does not. As ConfigHeadReader:
// ErrConfigHeadUnavailable when it cannot be read now, and any other error a head that is not the one named, or that
// does not open under key, which fails the anchor.
type SidecarRecoveryHeads interface {
	ReadRecoveryHead(ctx context.Context, key *EvsRepoKey, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, func(generation uint64) *EvsRepoKey, error)
}

// What a host installs for code-only recovery (InstallRecovery).
type SidecarRecoveryArgs struct {
	Groups SidecarRecoveryGroups
	Heads  SidecarRecoveryHeads
}

// An authority that also judges a statement as api would at its tip now, keeping nothing: ConfigLog.Check, §7.9's
// statement row. nil takes effect; an error is the verifier's refusal. Optional beside SidecarAuthority: without it a
// code-only recovery signs nothing, since which of §7.9's Recovery rows holds is the verifier's to say.
type SidecarStatementJudge interface {
	JudgeStatement(signedBytes []byte) error
}

// What §7.9's recovery anchor reads of the verified log, a copy.
type SidecarRecoveryLog struct {
	NetworkId Id
	// The genesis's config_repo_id, whose group's key the anchor runs on.
	ConfigRepoId Id
	// A_0 = SHA-256(Signed Genesis) of the genesis the log starts from.
	GenesisChain [sha256.Size]byte
	// The newest verified base, and its (n, A_n).
	Base    *bridge.ProjectionHeader
	BasePin *bridge.AuthPin
	// The first position the log holds an entry at, and that entry's prev_chain, A_{HeldFrom-1}.
	HeldFrom      uint64
	HeldPrevChain [sha256.Size]byte
	// Every entry the log holds, from HeldFrom to its tip, as a head's records carry them.
	Held []ConfigFoldRecord
}

// An authority that also shows the anchor its verified log. Optional beside SidecarAuthority: without it no anchor
// runs, so a code-only recovery signs nothing.
type SidecarRecoveryLogView interface {
	RecoveryLog() (*SidecarRecoveryLog, error)
}

// The keychain record: public values only.
type sidecarRecoveryRecord struct {
	Version  int `json:"version"`
	MemberId Id  `json:"member_id"`
	// SHA-256 of the code's Ed25519 public key: MemberRow.recovery_key_sha256's form.
	KeySha256   []byte               `json:"key_sha256"`
	StatementId []byte               `json:"statement_id"`
	Proposal    bool                 `json:"proposal,omitempty"`
	Restored    bool                 `json:"restored,omitempty"`
	Phase       SidecarRecoveryPhase `json:"phase"`
}

// A Sidecar's recovery seams, under their own lock.
type sidecarRecoveries struct {
	// one recovery at a time, held across its requests, so never stateLock
	flowLock sync.Mutex

	stateLock sync.Mutex
	args      *SidecarRecoveryArgs
}

// A secret no reply carries.
func (self *RecoveryCode) daemonSecret() {}

// A secret no reply carries.
func (self *RecoveryKeys) daemonSecret() {}

// Installs what a code-only recovery runs on beside the authority, replacing any before; the answer removes it, if it
// is still the installed one.
func (self *Sidecar) InstallRecovery(args *SidecarRecoveryArgs) func() {
	func() {
		self.recoveries.stateLock.Lock()
		defer self.recoveries.stateLock.Unlock()
		self.recoveries.args = args
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.recoveries.stateLock.Lock()
			defer self.recoveries.stateLock.Unlock()
			if self.recoveries.args == args {
				self.recoveries.args = nil
			}
		})
	}
}

// The installed seams, nil for none or for one missing a part.
func (self *Sidecar) recoveryArgs() *SidecarRecoveryArgs {
	self.recoveries.stateLock.Lock()
	defer self.recoveries.stateLock.Unlock()
	if self.recoveries.args == nil || self.recoveries.args.Groups == nil || self.recoveries.args.Heads == nil {
		return nil
	}
	return self.recoveries.args
}

// The record in secrets, nil for none.
func loadSidecarRecoveryRecord(secrets SidecarSecrets) (*sidecarRecoveryRecord, error) {
	encoded, err := secrets.Get(sidecarRecoveryRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record := &sidecarRecoveryRecord{}
	if err := json.Unmarshal(encoded, record); err != nil || record.Version != sidecarRecoveryRecordVersion {
		return nil, fmt.Errorf("%w: the recovery record", ErrSidecarStoreFailed)
	}
	switch record.Phase {
	case SidecarRecoveryPending, SidecarRecoveryAnchored, SidecarRecoveryStopped:
	default:
		return nil, fmt.Errorf("%w: the recovery record's phase", ErrSidecarStoreFailed)
	}
	return record, nil
}

// Keeps the record in secrets.
func persistSidecarRecoveryRecord(secrets SidecarSecrets, record *sidecarRecoveryRecord) error {
	record.Version = sidecarRecoveryRecordVersion
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return secrets.Put(sidecarRecoveryRecordName, encoded)
}

// The user a client token names, read unverified: §7.9's M, whose binding in effect the verified state must hold the
// code's key as, so a wrong claim admits nothing.
func sidecarJwtUserId(byJwt string) (Id, bool) {
	parse := parseSidecarJwt(byJwt)
	if !parse.ok {
		return Id{}, false
	}
	userId, err := ParseId(parse.stringClaim("user_id"))
	if err != nil || userId == (Id{}) {
		return Id{}, false
	}
	return userId, true
}

// Sign's gate while this device recovers by code (§7.9's anchor). Before the anchor passes the identity key signs only
// this device's ReaderKey, which §7.9's restored row uploads ahead of it, and its own sign-out, which only narrows;
// once the anchor failed, only the sign-out. nil on a device that recovers by no code. A record that does not read
// refuses.
func (self *Sidecar) checkRecoveryAnchorSign(secrets SidecarSecrets, signedType bridge.SignedType, body []byte) error {
	record, err := loadSidecarRecoveryRecord(secrets)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if record == nil || record.Phase == SidecarRecoveryAnchored {
		return nil
	}
	switch signedType {
	case bridge.SignedType_SIGNED_READER_KEY:
		if record.Phase != SidecarRecoveryStopped {
			return nil
		}
	case bridge.SignedType_SIGNED_SIDECAR_REVOKE:
		revoke := &bridge.SidecarRevoke{}
		identity := self.currentIdentity()
		if proto.Unmarshal(body, revoke) == nil && identity != nil && bytes.Equal(revoke.GetSidecarId(), identity.SidecarId.Bytes()) &&
			revoke.GetReason() == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED {
			return nil
		}
	}
	return fmt.Errorf("%w: type %#x", ErrSidecarRecoveryUnanchored, int32(signedType))
}

// Whether this device recovers by code and its anchor has not passed: what upkeep's GkmUpkeepRole.AwaitingAnchor
// reads, so its ReaderKey goes up and its KeyPackages wait (§7.9's restored row), and what a component asks before it
// commits, wraps, seals or files. Sign refuses those meanwhile whatever a component asks. True for a record that does
// not read, false on a device that recovers by no code.
func (self *Sidecar) RecoveryAwaitingAnchor() bool {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return false
	}
	record, err := loadSidecarRecoveryRecord(secrets)
	if err != nil {
		return true
	}
	return record != nil && record.Phase != SidecarRecoveryAnchored
}

// Where this device's code-only recovery stands, from what it keeps and the verified state, nil for none.
func (self *Sidecar) Recovery() (*SidecarRecovery, error) {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	record, err := loadSidecarRecoveryRecord(secrets)
	if err != nil || record == nil {
		return nil, err
	}
	return self.recoveryResult(record, self.authority()), nil
}

// The result a record and the verified state give.
func (self *Sidecar) recoveryResult(record *sidecarRecoveryRecord, authority SidecarAuthority) *SidecarRecovery {
	result := &SidecarRecovery{
		Phase:       record.Phase,
		MemberId:    record.MemberId,
		StatementId: bytes.Clone(record.StatementId),
		Proposal:    record.Proposal,
		Restored:    record.Restored,
	}
	if record.Phase == SidecarRecoveryPending && self.Admitted() {
		result.Phase = SidecarRecoveryAdmitted
	}
	if result.Phase != SidecarRecoveryPending {
		return result
	}
	result.Waiting = "the admission is filed and not yet landed"
	if !record.Proposal {
		return result
	}
	proposals, ok := authority.(SidecarAuthorityProposals)
	if !ok {
		return result
	}
	row := proposals.PendingProposal(record.StatementId)
	if row == nil {
		return result
	}
	result.ProposalKind = bridge.ProposalKind(row.GetKind())
	switch result.ProposalKind {
	case bridge.ProposalKind_PROPOSAL_KIND_RECOVERY_SCOPED:
		result.Waiting = "the admission waits for one admin's cosign: ur approve on an admin's device"
	case bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY, bridge.ProposalKind_PROPOSAL_KIND_RESTORED:
		result.ActivatesAfter = time.UnixMilli(row.GetWindowTimeMs() + configRecoveryWindowMs)
		result.Waiting = "the admission waits out the recovery window, in which an admin may veto it"
		if result.ProposalKind == bridge.ProposalKind_PROPOSAL_KIND_AUTHORITY {
			result.Waiting += ", and for its cosigns where the network needs more than one admin"
		}
	}
	return result
}

// A statement header for a recovery's statement: this network, the verified pin, a fresh nonce and a not_after
// StatementTimeout on, at most §7.9's 7 days.
func (self *Sidecar) recoveryStatementHeader(networkId Id, at *bridge.AuthPin, random io.Reader) (*bridge.StatementHeader, error) {
	nonce := make([]byte, configNonceByteCount)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, fmt.Errorf("no randomness for a nonce: %w", err)
	}
	timeout := min(self.settings.statementTimeout(), time.Duration(configStatementMaxLifetimeMs)*time.Millisecond)
	return &bridge.StatementHeader{
		NetworkId:  networkId.Bytes(),
		At:         &bridge.AuthPin{Version: at.GetVersion(), Chain: bytes.Clone(at.GetChain())},
		Nonce:      nonce,
		NotAfterMs: self.clock.Now().Add(timeout).UnixMilli(),
	}, nil
}

// A recovery key's statement as a pending record keeps it: its Signed bytes, its not_after and its id.
func recoveryPendingStatement(signed *bridge.Signed, notAfterMs int64) (*sidecarPendingStatement, []byte, error) {
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		return nil, nil, err
	}
	statementId := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType(signed.GetType()), signed.GetBody())
	return &sidecarPendingStatement{signed: signedBytes, notAfterMs: notAfterMs}, statementId[:], nil
}

// The recovery's one statement, signed by the code's key: a plain SidecarAdmit of this device where the verified state
// takes it now, else an AuthorityProposal of it (§7.9's Recovery table), as the log's judge says. Answers the pending
// record, its id and whether it is a proposal; ErrSidecarRecoveryRefused, with both refusals, when the log takes
// neither.
func (self *Sidecar) recoveryStatement(identity *SidecarIdentity, memberId Id, keys *RecoveryKeys, pin *bridge.AuthPin, judge SidecarStatementJudge) (*sidecarPendingStatement, []byte, bool, error) {
	header, err := self.recoveryStatementHeader(identity.NetworkId, pin, rand.Reader)
	if err != nil {
		return nil, nil, false, err
	}
	admitBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.SidecarAdmit{
		Header:            header,
		NetworkId:         identity.NetworkId.Bytes(),
		SidecarId:         identity.SidecarId.Bytes(),
		IdentityPublicKey: bytes.Clone(identity.IdentityPublicKey),
		IdentityAlg:       configIdentityAlgEd25519,
		MemberId:          memberId.Bytes(),
	})
	if err != nil {
		return nil, nil, false, err
	}
	plain, err := keys.Sign(memberId, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admitBytes)
	if err != nil {
		return nil, nil, false, err
	}
	pending, statementId, err := recoveryPendingStatement(plain, header.GetNotAfterMs())
	if err != nil {
		return nil, nil, false, err
	}
	plainErr := judge.JudgeStatement(pending.signed)
	if plainErr == nil {
		return pending, statementId, false, nil
	}

	proposalHeader, err := self.recoveryStatementHeader(identity.NetworkId, pin, rand.Reader)
	if err != nil {
		return nil, nil, false, err
	}
	proposalBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.AuthorityProposal{
		Header:        proposalHeader,
		StatementType: uint32(bridge.SignedType_SIGNED_SIDECAR_ADMIT),
		Statement:     admitBytes,
	})
	if err != nil {
		return nil, nil, false, err
	}
	proposal, err := keys.Sign(memberId, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, proposalBytes)
	if err != nil {
		return nil, nil, false, err
	}
	pending, statementId, err = recoveryPendingStatement(proposal, proposalHeader.GetNotAfterMs())
	if err != nil {
		return nil, nil, false, err
	}
	proposalErr := judge.JudgeStatement(pending.signed)
	if proposalErr == nil {
		return pending, statementId, true, nil
	}
	return nil, nil, false, fmt.Errorf("%w: plainly: %w; as a proposal: %w", ErrSidecarRecoveryRefused, plainErr, proposalErr)
}

// Brings the authority up to what api serves now, where it can say, so a plain admission that just landed shows.
func recoveryCatchUp(ctx context.Context, authority SidecarAuthority) {
	if catchUp, ok := authority.(interface {
		CatchUp(ctx context.Context) error
	}); ok {
		catchUp.CatchUp(ctx)
	}
}

// Recovers this device by its member's recovery code, in §5.6's and §7.9's order (see the file header): it files the
// device's admission by the code's key once, and on each later call, once admitted, runs the anchor and then
// KEYS-M2-24's pass. The code is erased whatever the outcome, and the keys it derives before this answers. origin must
// be the person's confirmation, on /dev/tty or in an app's UI (D-CORE-13); a recovery key's statements carry no
// presence countersignature. Answers where the recovery stands. Refusals: ErrSidecarActMode, ErrSidecarNoIdentity,
// ErrSidecarActNoAuthority, ErrSidecarRecoveryUnavailable, ErrSidecarRecoveryOtherCode, ErrSidecarRecoveryUnbound,
// ErrSidecarRecoveryAdmitted, ErrSidecarRecoveryRefused and ErrSidecarActRefused, each with nothing signed or kept;
// ErrSidecarRecoveryStopped once the anchor failed; and, from an anchor or a pass that could not run, its error, with
// the result.
func (self *Sidecar) RecoverWithCode(ctx context.Context, code *RecoveryCode, origin SidecarActOrigin) (*SidecarRecovery, error) {
	if code == nil {
		return nil, fmt.Errorf("%w: no recovery code", ErrSidecarApiArgs)
	}
	if origin != SidecarActConfirmed {
		code.Erase()
		return nil, ErrSidecarActMode
	}
	self.recoveries.flowLock.Lock()
	defer self.recoveries.flowLock.Unlock()
	identity := self.currentIdentity()
	secrets := self.currentCoreSecrets()
	if identity == nil || secrets == nil {
		code.Erase()
		return nil, ErrSidecarNoIdentity
	}
	keys, err := code.Keys()
	if err != nil {
		return nil, err
	}
	defer keys.Erase()
	keySha256 := keys.KeySha256()

	record, err := loadSidecarRecoveryRecord(secrets)
	if err != nil {
		return nil, err
	}
	if record != nil {
		if !bytes.Equal(record.KeySha256, keySha256) {
			return nil, ErrSidecarRecoveryOtherCode
		}
		if record.Phase == SidecarRecoveryStopped {
			return self.recoveryResult(record, self.authority()), ErrSidecarRecoveryStopped
		}
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	recoveryArgs := self.recoveryArgs()
	judge, judges := authority.(SidecarStatementJudge)
	view, views := authority.(SidecarRecoveryLogView)
	if recoveryArgs == nil || !judges || !views {
		return nil, ErrSidecarRecoveryUnavailable
	}

	var entry *bridge.AuthPin
	if record == nil {
		record, entry, err = self.fileRecovery(ctx, identity, secrets, keys, authority, judge, recoveryArgs)
		if err != nil {
			return nil, err
		}
	} else if record.Phase == SidecarRecoveryPending {
		// a post a kill or a lost answer left goes again, the same bytes
		if err := self.PostPendingStatements(ctx); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[identity]a recovery's pending statement did not post: %s", err)
		}
		recoveryCatchUp(ctx, authority)
	}
	// every answer from here names where this call's post landed
	resultOf := func() *SidecarRecovery {
		result := self.recoveryResult(record, authority)
		result.Entry = entry
		return result
	}
	if record.Phase == SidecarRecoveryPending && !self.Admitted() {
		return resultOf(), nil
	}

	gkmBinding := &GkmRecoveryBinding{MemberId: record.MemberId, KeySha256: keySha256}
	if gkmBinding.PrivateKey, err = keys.XwingPrivateKey(); err != nil {
		return nil, err
	}
	log, err := view.RecoveryLog()
	if err != nil {
		return resultOf(), err
	}
	// the base whose head the check reads, which a failed check's alarm names
	var anchorBasePin *bridge.AuthPin
	gkmArgs := &GkmRecoverArgs{
		Binding:      gkmBinding,
		ConfigRepoId: log.ConfigRepoId,
		Restored:     record.Restored,
		Anchor: func(ctx context.Context, key *EvsRepoKey) error {
			log, err := view.RecoveryLog()
			if err != nil {
				return err
			}
			anchorBasePin = log.BasePin
			head, keyAt, err := recoveryArgs.Heads.ReadRecoveryHead(ctx, key, log.Base.GetConfigVersion(), log.Base.GetConfigHeadSha256())
			if err != nil {
				if errors.Is(err, ErrConfigHeadUnavailable) || ctx.Err() != nil {
					return err
				}
				return fmt.Errorf("%w: the config head the newest base names is not one this key opens: %w", ErrGkmRecoveryAnchor, err)
			}
			return checkRecoveryCodeAnchor(&recoveryCodeAnchorArgs{
				log:              log,
				head:             head,
				keyAt:            keyAt,
				networkId:        identity.NetworkId,
				memberId:         record.MemberId,
				ed25519PublicKey: keys.Ed25519PublicKey(),
			})
		},
	}
	if record.Phase != SidecarRecoveryAnchored {
		testHookBarrier("identity.recover.anchor.before", identity.SidecarId.String())
		err := recoveryArgs.Groups.AnchorRecovery(ctx, gkmArgs)
		testHookBarrier("identity.recover.anchor.after", identity.SidecarId.String())
		switch {
		case err == nil:
			record.Phase = SidecarRecoveryAnchored
			if err := persistSidecarRecoveryRecord(secrets, record); err != nil {
				return nil, err
			}
		case errors.Is(err, ErrGkmRecoveryStopped):
			record.Phase = SidecarRecoveryStopped
			if persistErr := persistSidecarRecoveryRecord(secrets, record); persistErr != nil {
				self.log.Warningf("[identity]a failed recovery anchor was not kept as stopped: %s", persistErr)
			}
			if anchorBasePin == nil {
				anchorBasePin = log.BasePin
			}
			self.log.Errorf("[identity]the recovery anchor failed: the network's config does not chain to the genesis this code signed")
			self.emitEvent(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork, Evidence: [2][]byte{configPinBytes(anchorBasePin), nil}})
			return resultOf(), fmt.Errorf("%w: %w", ErrSidecarRecoveryStopped, err)
		case errors.Is(err, ErrGkmWait):
			result := resultOf()
			result.Waiting = "admitted; waiting for the config group's key"
			if record.Restored {
				result.Waiting = "admitted; waiting for a config writer's ReaderWrap"
			}
			return result, nil
		default:
			// the check could not run: nothing is decided
			return resultOf(), err
		}
	}

	repos, err := recoveryArgs.Groups.RunRecovery(ctx, gkmArgs)
	result := resultOf()
	result.Repos = repos
	result.OfferRotate = true
	return result, err
}

// The before row: the member, its binding in effect held to the code, the wraps fetched, the statement judged,
// signed, kept with the record and posted. A refusal keeps nothing. Answers the record and where the post landed, nil
// for a lost answer, which stays pending.
func (self *Sidecar) fileRecovery(ctx context.Context, identity *SidecarIdentity, secrets SidecarSecrets, keys *RecoveryKeys, authority SidecarAuthority,
	judge SidecarStatementJudge, recoveryArgs *SidecarRecoveryArgs) (*sidecarRecoveryRecord, *bridge.AuthPin, error) {
	if self.Admitted() {
		return nil, nil, ErrSidecarRecoveryAdmitted
	}
	byJwt, err := loadSidecarByJwt(secrets)
	if err != nil {
		return nil, nil, err
	}
	memberId, ok := sidecarJwtUserId(byJwt)
	if !ok {
		return nil, nil, fmt.Errorf("%w: the client token names no member", ErrSidecarRecoveryUnbound)
	}
	keySha256 := keys.KeySha256()
	binding := authority.CurrentBinding(memberId)
	if binding == nil || !bytes.Equal(binding.GetKeySha256(), keySha256) {
		return nil, nil, ErrSidecarRecoveryUnbound
	}
	restored := false
	if restores, ok := authority.(SidecarRecoveryAuthority); ok {
		restored = restores.BindingRestored(memberId)
	}
	pin := authority.Pin()
	if pin == nil {
		return nil, nil, ErrSidecarActNoAuthority
	}

	if !restored {
		// M's wraps while unadmitted, under recovery:<member_id>: kept, and opened only once the device is admitted
		// (KEYS-M2-24's fetch row); a failure here leaves the anchor's own fetch
		privateKey, err := keys.XwingPrivateKey()
		if err != nil {
			return nil, nil, err
		}
		binding := &GkmRecoveryBinding{MemberId: memberId, PrivateKey: privateKey, KeySha256: keySha256}
		if _, err := recoveryArgs.Groups.FetchRecoveryWraps(ctx, binding, false); err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[identity]the member's recovery wraps were not fetched before admission: %s", err)
		}
	}

	pending, statementId, proposal, err := self.recoveryStatement(identity, memberId, keys, pin, judge)
	if err != nil {
		return nil, nil, err
	}
	record := &sidecarRecoveryRecord{
		MemberId:    memberId,
		KeySha256:   keySha256,
		StatementId: statementId,
		Proposal:    proposal,
		Restored:    restored,
		Phase:       SidecarRecoveryPending,
	}
	// the record and the statement are kept before the post, so a kill resumes on the same bytes
	testHookBarrier("identity.recover.file.before", identity.SidecarId.String())
	if err := persistSidecarRecoveryRecord(secrets, record); err != nil {
		return nil, nil, err
	}
	if err := self.keepPendingStatement(pending); err != nil {
		secrets.Delete(sidecarRecoveryRecordName)
		return nil, nil, err
	}
	testHookBarrier("identity.recover.file.after", identity.SidecarId.String())
	entry, err := self.postPendingStatement(ctx, pending)
	if errors.Is(err, ErrSidecarActRefused) {
		// api refused it at the tip: nothing was filed, and the record goes with the statement
		if deleteErr := secrets.Delete(sidecarRecoveryRecordName); deleteErr != nil {
			return nil, nil, deleteErr
		}
		return nil, nil, err
	}
	if err != nil {
		// the answer was lost: the statement stays pending, and its post goes again with the same bytes
		if self.log.V(1).Enabled() {
			self.log.Infof("[identity]a recovery's admission is signed and its post goes again: %s", err)
		}
		entry = nil
	}
	recoveryCatchUp(ctx, authority)
	return record, entry, nil
}

// What §7.9's recovery anchor checks.
type recoveryCodeAnchorArgs struct {
	log *SidecarRecoveryLog
	// the head the newest base names, read under the config group's key the recovery opened
	head *ConfigHead
	// the key of each generation the ladder reaches from that key, nil for one it does not
	keyAt     func(generation uint64) *EvsRepoKey
	networkId Id
	memberId  Id
	// the Ed25519 public key the code derives
	ed25519PublicKey []byte
}

// The config keys a recovery's ladder reaches, as a binding's sealed body opens under them.
type recoveryAnchorKeys struct {
	keyAt func(generation uint64) *EvsRepoKey
}

// A binding's body is only opened here, never sealed.
func (self *recoveryAnchorKeys) CurrentConfigKey(ctx context.Context) (*EvsRepoKey, error) {
	return nil, fmt.Errorf("%w: a recovery anchor seals nothing", ErrGkmKeyMissing)
}

// The key of a generation the ladder reaches, nil for one it does not.
func (self *recoveryAnchorKeys) ConfigKeyAt(generation uint64) *EvsRepoKey {
	if self.keyAt == nil {
		return nil
	}
	return self.keyAt(generation)
}

// The binding a record carries, as a RecoveryBind or RecoveryRebind of memberId to keySha256, on its own or as the
// statement of an AuthorityProposal, as an AdminSet member's binding goes where k > 1 (§7.9's several row): its type
// and statement bytes, false for any other record.
func recoveryBindingOfRecord(kind uint32, body []byte, memberId Id, keySha256 []byte) (bridge.SignedType, []byte, bool) {
	if kind != bridge.AuthEntryKindStatement {
		return 0, nil, false
	}
	signed := &bridge.Signed{}
	if proto.Unmarshal(body, signed) != nil {
		return 0, nil, false
	}
	signedType := bridge.SignedType(signed.GetType())
	statementBytes := signed.GetBody()
	if signedType == bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL {
		proposal := &protocol.AuthorityProposal{}
		if proto.Unmarshal(statementBytes, proposal) != nil {
			return 0, nil, false
		}
		signedType, statementBytes = bridge.SignedType(proposal.GetStatementType()), proposal.GetStatement()
	}
	var boundMemberId []byte
	var boundKeySha256 []byte
	switch signedType {
	case bridge.SignedType_SIGNED_RECOVERY_BIND:
		bind := &protocol.RecoveryBind{}
		if proto.Unmarshal(statementBytes, bind) != nil {
			return 0, nil, false
		}
		boundMemberId, boundKeySha256 = bind.GetMemberId(), bind.GetEd25519PublicKeySha256()
	case bridge.SignedType_SIGNED_RECOVERY_REBIND:
		rebind := &protocol.RecoveryRebind{}
		if proto.Unmarshal(statementBytes, rebind) != nil {
			return 0, nil, false
		}
		boundMemberId, boundKeySha256 = rebind.GetMemberId(), rebind.GetEd25519PublicKeySha256()
	default:
		return 0, nil, false
	}
	if !bytes.Equal(boundMemberId, memberId.Bytes()) || !bytes.Equal(boundKeySha256, keySha256) {
		return 0, nil, false
	}
	return signedType, statementBytes, true
}

// §7.9's recovery anchor, §5.6's genesis row steps 2 and 3, on the head the config group's key opened. nil when the
// head is the verified log's and the code's binding on its chain carries a genesis_sig, under the code's Ed25519 key,
// over this network and SHA-256 of the head's genesis; an error wrapping ErrGkmRecoveryAnchor when either fails, which
// stops recovery for good; any other error when the check could not run.
func checkRecoveryCodeAnchor(args *recoveryCodeAnchorArgs) error {
	failed := func(why string, cause error) error {
		if cause == nil {
			return fmt.Errorf("%w: %s", ErrGkmRecoveryAnchor, why)
		}
		return fmt.Errorf("%w: %s: %w", ErrGkmRecoveryAnchor, why, cause)
	}
	log := args.log
	if log == nil || log.Base == nil || log.BasePin == nil {
		return errors.New("recovery anchor: the verified log stands at no base")
	}
	if args.head == nil {
		return errors.New("recovery anchor: no config head was read")
	}
	foldedThrough := log.Base.GetFoldedThrough()
	if foldedThrough+1 < log.HeldFrom {
		// the head's records end before the first entry the log holds, so no chain links them
		return fmt.Errorf("recovery anchor: the log holds no entry at or before %d, where the head's records end", foldedThrough+1)
	}

	// 2 the head is the verified log's: the genesis the log starts from, and records chaining from it to the entries
	// the log holds
	folded := []ConfigFoldRecord{}
	tail := []ConfigFoldRecord{}
	for _, record := range log.Held {
		if record.N <= foldedThrough {
			folded = append(folded, record)
		} else {
			tail = append(tail, record)
		}
	}
	check := &ConfigHeadCheck{
		Header:         log.Base,
		Folded:         folded,
		FoldedKnown:    true,
		GenesisChain:   log.GenesisChain,
		FoldedFrom:     log.HeldFrom,
		FirstPrevChain: log.HeldPrevChain,
	}
	if _, err := CheckConfigBase(args.head, check, nil); err != nil {
		return failed("the config head is not the verified log's", err)
	}
	genesis, signedGenesis := args.head.Genesis()
	if !bytes.Equal(genesis.GetNetworkId(), args.networkId.Bytes()) {
		return failed("the genesis is another network's", nil)
	}
	genesisSha256 := sha256.Sum256(signedGenesis)

	// 3 the code's binding on that chain, the newest record of it, and its genesis_sig over that genesis
	headRecords, err := args.head.RecordsIn(0, foldedThrough)
	if err != nil {
		return failed("the config head's records", err)
	}
	keySha256 := RecoveryKeySha256(args.ed25519PublicKey)
	var bindingType bridge.SignedType
	var bindingBytes []byte
	found := false
	for _, record := range headRecords {
		if signedType, statementBytes, ok := recoveryBindingOfRecord(record.GetKind(), record.GetBody(), args.memberId, keySha256); ok {
			bindingType, bindingBytes, found = signedType, statementBytes, true
		}
	}
	for _, record := range tail {
		if signedType, statementBytes, ok := recoveryBindingOfRecord(record.Kind, record.Body, args.memberId, keySha256); ok {
			bindingType, bindingBytes, found = signedType, statementBytes, true
		}
	}
	if !found {
		return failed("no record on the verified chain binds this code to its member", nil)
	}
	_, _, body, err := openRecoveryBindBody(bindingType, bindingBytes, &recoveryAnchorKeys{keyAt: args.keyAt}, args.networkId, nil)
	switch {
	case errors.Is(err, ErrConfigSealGenerationMissing):
		return fmt.Errorf("recovery anchor: %w", err)
	case err != nil:
		return failed("the binding's sealed body does not open to this code's keys", err)
	}
	if !bytes.Equal(body.GetEd25519PublicKey(), args.ed25519PublicKey) {
		return failed("the binding's body names another Ed25519 key", nil)
	}
	if err := VerifyRecoveryGenesisSig(args.ed25519PublicKey, args.networkId, genesisSha256[:], body.GetGenesisSig()); err != nil {
		return failed("the binding's genesis_sig does not sign this genesis", err)
	}
	return nil
}

// The verifier's judgment of a statement at its tip now, keeping nothing (SidecarStatementJudge).
func (self *ConfigAuthority) JudgeStatement(signedBytes []byte) error {
	self.client.followLock.Lock()
	defer self.client.followLock.Unlock()
	log := self.client.configLog.Load()
	if log == nil {
		return ErrConfigClientClosed
	}
	return configJudgeStatement(log, signedBytes, self.client.clock.Now())
}

// What §7.9's recovery anchor reads of the verified log (SidecarRecoveryLogView).
func (self *ConfigAuthority) RecoveryLog() (*SidecarRecoveryLog, error) {
	self.client.followLock.Lock()
	defer self.client.followLock.Unlock()
	log := self.client.configLog.Load()
	if log == nil {
		return nil, ErrConfigClientClosed
	}
	return configRecoveryLog(log)
}

// ConfigLog.Check of a statement sequenced now, or at the log's newest time when now is behind it: its refusal, nil
// for one that takes effect.
func configJudgeStatement(log *ConfigLog, signedBytes []byte, now time.Time) error {
	timeMs := max(now.UnixMilli(), log.State().TimeMs())
	return log.Check(signedBytes, timeMs).Refusal
}

// The anchor's view of a log: its genesis, newest base and every entry it keeps, as records. For the log's applying
// goroutine, or under the lock that serializes it, as Retained is.
func configRecoveryLog(log *ConfigLog) (*SidecarRecoveryLog, error) {
	state := log.State()
	if state.base == nil {
		return nil, errors.New("recovery anchor: the log stands at no base")
	}
	if len(log.kept) == 0 {
		return nil, errors.New("recovery anchor: the log keeps no entry")
	}
	configRepoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil, fmt.Errorf("recovery anchor: the genesis's config_repo_id: %w", err)
	}
	held, ok := log.foldedRecords(log.keptFrom, state.n)
	if !ok {
		return nil, errors.New("recovery anchor: the log does not keep every entry from its retention point")
	}
	prevChain := log.kept[0].entry.GetPrevChain()
	if len(prevChain) != sha256.Size {
		return nil, errors.New("recovery anchor: the first kept entry's prev_chain")
	}
	return &SidecarRecoveryLog{
		NetworkId:     log.networkId,
		ConfigRepoId:  configRepoId,
		GenesisChain:  bridge.GenesisChain(log.signedGenesis),
		Base:          proto.Clone(state.base.header).(*bridge.ProjectionHeader),
		BasePin:       &bridge.AuthPin{Version: state.base.n, Chain: bytes.Clone(state.base.chain[:])},
		HeldFrom:      log.keptFrom,
		HeldPrevChain: [sha256.Size]byte(prevChain),
		Held:          held,
	}, nil
}
