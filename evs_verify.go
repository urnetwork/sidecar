// The verifying reader (§11.8's Readers verify, §11.9's reader row, D-TRUST-1): what a device checks of what evs
// serves before it shows anything, against a malicious server that may lie about everything it stores (I-4).
//
// A head read gives the head summary and the Signed EvsPush of every version after the request's pin. The reader
// checks each statement as received, never a re-marshal: its shape (format 1's, a format-2 construct refused as
// FORMAT_UNSUPPORTED and never read as a fork), its repo and ref, its signature by the identity key its signer's
// admission gives, and §11.8's refs table, each judged at the statement's own authorization pin, which must lie on
// the reader's chain (§7.9); then the chain C from the pin through every statement to the head's C_v (§11.6), so no
// version is skipped, reordered or replaced. Only then does it pin (ref, v, C_v), durably, before the read is shown.
//
// A head below the pin is refused and raises head_alarm's fork with both RefHeads as evidence, unless a verified
// EvsReseed covers it (§11.13, §19.10), which lowers the pin and is kept as a loss. A head at the pin's version with
// another chain is the same fork.
//
// Catching up costs at most EvsSettings.CatchUpByteCount of statements (§11.9's budget): past it the reader re-pins
// at the head and marks the gap, raising evs_gap, so what a never-read path or any path read after the gap holds is
// evs's word until the next HeadCheck (§2.8, Q-EVS-6), and the code claims nothing more.
//
// A reader's config state is TEAM's: GkmAuthView's At, IdentityKey, RepoWriters and Repo, from EvsClientArgs.Config.
// With none, nothing verifies, and every read refuses.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose a Signed EvsReseed is signed under (§6.11).
const evsReseedPurpose = "evs-reseed"

var (
	// A statement whose signer, signature or ref rules fail the reader's state: it never counts toward a head.
	ErrEvsStatementRefused = errors.New("evs: statement refused")
	// The chain from the pin through the statements does not reach the head's C_v, or the statements skip a
	// version: evs served a history no writer signed.
	ErrEvsChainBroken = errors.New("evs: chain broken")
	// A head below the pin, or at it with another chain, and no verified EvsReseed covering it.
	ErrEvsHeadForked = errors.New("evs: head does not extend the pin")
	// What a path's reply claims does not verify against its statements.
	ErrEvsEntryRefused = errors.New("evs: entry refused")
	// A version off §11.7's rule: a write not at its base + 1, a creation not at max(b, m) + 1.
	ErrEvsVersionRule = errors.New("evs: version off the rule")
)

// The verifying reader of one EvsClient.
type EvsVerifier struct {
	client *EvsClient
}

// The verifier of client's reads.
func newEvsVerifier(client *EvsClient) *EvsVerifier {
	return &EvsVerifier{client: client}
}

// One statement as the walk verified it: its parse, its version and C at that version.
type EvsVerifiedStatement struct {
	Version   uint64
	Statement *EvsStatement
	Chain     [sha256.Size]byte
}

// A head as a read reply gives it, before any check.
type EvsHeadRead struct {
	RepoId Id
	RefId  Id
	Head   *protocol.EvsHeadSummary
	// The version the request read from, its pin_version, and C there: the ref pin's, an older read record's
	// pin, or 0 and C_0 for a first read.
	FromVersion uint64
	FromChain   [sha256.Size]byte
	// The statements after FromVersion, as received.
	Statements []*protocol.EvsReadStatement
	// The reply's behind: the first version it could not serve from the window, 0 when none.
	Behind uint64
}

// A head the reader verified, ready to pin.
type EvsVerifiedHead struct {
	RepoId  Id
	RefId   Id
	Head    *protocol.EvsHeadSummary
	Version uint64
	Chain   [sha256.Size]byte
	// Every statement from FromVersion + 1 to Version, verified, in order: empty after a re-pin past the budget.
	Statements []*EvsVerifiedStatement
	// The version the statements start after.
	FromVersion uint64
	// The read re-pinned at the head past the catch-up budget: the versions before it are evs's word.
	Gap bool
}

// The statement at version, false when the walk does not hold it.
func (self *EvsVerifiedHead) StatementAt(version uint64) (*EvsVerifiedStatement, bool) {
	if version <= self.FromVersion || self.FromVersion+uint64(len(self.Statements)) < version {
		return nil, false
	}
	return self.Statements[version-self.FromVersion-1], true
}

// The newest verified config state, or ErrEvsNoConfig.
func (self *EvsVerifier) config() (GkmAuthView, error) {
	if self.client.args.Config == nil {
		return nil, ErrEvsNoConfig
	}
	state := self.client.args.Config()
	if state == nil {
		return nil, ErrEvsNoConfig
	}
	return state, nil
}

// The kinds whose refs are record-class streams (§11.12's kinds table): every kind but general and config.
func EvsRepoKindRecordClass(kind protocol.RepoKind) bool {
	return kind != protocol.RepoKind_REPO_KIND_GENERAL && kind != protocol.RepoKind_REPO_KIND_CONFIG
}

// Whether sidecarId is one of the repo's admins in state: its access log's RepoAdmins, and for the config repo its
// writers.
func evsRepoAdmin(state GkmAuthView, repo *protocol.AclRepo, sidecarId Id) bool {
	for _, admin := range repo.GetAdmins() {
		if bytes.Equal(admin.GetSidecarId(), sidecarId.Bytes()) {
			return true
		}
	}
	return false
}

// Parses and checks one statement as received for repoId and refId: format 1's shape, its signature by the identity
// key its signer's admission gives at the statement's own auth pin, and §11.8's refs table at that state. A format-2
// construct answers ErrEvsFormatUnsupported, which is never a fork and never tampering (EVS1-M2-39).
func (self *EvsVerifier) VerifyStatement(statementBytes []byte, repoId Id, refId Id) (*EvsStatement, error) {
	statement, err := ParseEvsStatement(statementBytes)
	if err != nil {
		return nil, err
	}
	push := statement.Push
	if !bytes.Equal(push.GetRepoId(), repoId.Bytes()) || !bytes.Equal(push.GetRefId(), refId.Bytes()) {
		return nil, fmt.Errorf("%w: a statement of another repo or ref", ErrEvsStatementRefused)
	}
	newest, err := self.config()
	if err != nil {
		return nil, err
	}
	state, err := newest.At(push.GetAuth())
	if err != nil {
		return nil, fmt.Errorf("%w: its authorization pin: %w", ErrEvsStatementRefused, err)
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: its signer", ErrEvsStatementRefused)
	}
	identityKey := state.IdentityKey(signerId)
	if len(identityKey) == 0 {
		return nil, fmt.Errorf("%w: a signer the state never admitted", ErrEvsStatementRefused)
	}
	if err := statement.Verify(identityKey); err != nil {
		return nil, fmt.Errorf("%w: its signature: %w", ErrEvsStatementRefused, err)
	}
	if err := evsCheckRefRules(state, statement, repoId, refId, signerId); err != nil {
		return nil, err
	}
	return statement, nil
}

// §11.8's refs table at the statement's state: who may write each ref kind, and who may FORCE, DELETE, BASE, CONSUME
// and ERASE there. Record-class owned refs, deposit refs and the erasure ref take only creations from their writers.
func evsCheckRefRules(state GkmAuthView, statement *EvsStatement, repoId Id, refId Id, signerId Id) error {
	push := statement.Push
	repo := state.Repo(repoId)
	if repo == nil {
		return fmt.Errorf("%w: a repo the state does not hold", ErrEvsStatementRefused)
	}
	flags := push.GetFlags()
	has := func(flag protocol.EvsPushFlag) bool { return flags&uint32(flag) != 0 }
	writer := slices.Contains(state.RepoWriters(repoId), signerId)
	admin := evsRepoAdmin(state, repo, signerId)
	createsOnly := func() error {
		for _, change := range statement.Changes {
			if change.Change.GetBaseEntryVersion() != 0 || len(change.Change.GetEntrySha256()) == 0 {
				return fmt.Errorf("%w: a creates-only ref changed or removed a path", ErrEvsStatementRefused)
			}
		}
		if has(protocol.EvsPushFlag_EVS_PUSH_FORCE) || has(protocol.EvsPushFlag_EVS_PUSH_DELETE) {
			return fmt.Errorf("%w: FORCE or DELETE on a creates-only ref", ErrEvsStatementRefused)
		}
		return nil
	}
	ownerId, ownerErr := IdFromBytes(push.GetOwnerSidecarId())
	switch protocol.EvsRefKind(push.GetRefKind()) {
	case protocol.EvsRefKind_EVS_REF_SHARED:
		if !writer {
			return fmt.Errorf("%w: a shared ref's writer the state does not list", ErrEvsStatementRefused)
		}
		if (has(protocol.EvsPushFlag_EVS_PUSH_FORCE) || has(protocol.EvsPushFlag_EVS_PUSH_DELETE)) && !admin {
			return fmt.Errorf("%w: FORCE or DELETE on a shared ref by a non-admin", ErrEvsStatementRefused)
		}
	case protocol.EvsRefKind_EVS_REF_OWNED:
		if ownerErr != nil || ownerId != signerId {
			// a record-class stream takes its BASE and an erasure's CLOSURE from a repo admin (§11.8, §11.12)
			adminPush := has(protocol.EvsPushFlag_EVS_PUSH_BASE) || has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE)
			if ownerErr == nil && adminPush && admin && EvsRepoKindRecordClass(repo.GetKind()) {
				return nil
			}
			return fmt.Errorf("%w: an owned ref signed by another sidecar", ErrEvsStatementRefused)
		}
		if !writer {
			return fmt.Errorf("%w: an owned ref's sidecar no longer writes the repo", ErrEvsStatementRefused)
		}
		if EvsRepoKindRecordClass(repo.GetKind()) {
			if has(protocol.EvsPushFlag_EVS_PUSH_ERASE) || has(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) {
				return nil
			}
			return createsOnly()
		}
	case protocol.EvsRefKind_EVS_REF_DEPOSIT:
		if ownerErr != nil || EvsDepositRefId(repoId, ownerId) != refId {
			return fmt.Errorf("%w: a deposit ref not its depositor's", ErrEvsStatementRefused)
		}
		if has(protocol.EvsPushFlag_EVS_PUSH_CONSUME) {
			if !writer {
				return fmt.Errorf("%w: a CONSUME by a sidecar that does not write the repo", ErrEvsStatementRefused)
			}
			for _, change := range statement.Changes {
				if len(change.Change.GetEntrySha256()) != 0 {
					return fmt.Errorf("%w: a CONSUME that writes", ErrEvsStatementRefused)
				}
			}
			return nil
		}
		if ownerId != signerId {
			return fmt.Errorf("%w: a deposit signed by another sidecar", ErrEvsStatementRefused)
		}
		return createsOnly()
	case protocol.EvsRefKind_EVS_REF_ERASURE:
		if EvsErasureRefId(repoId) != refId {
			return fmt.Errorf("%w: an erasure ref at another id", ErrEvsStatementRefused)
		}
		if !admin {
			return fmt.Errorf("%w: an erasure push by a non-admin", ErrEvsStatementRefused)
		}
		return createsOnly()
	default:
		return fmt.Errorf("%w: ref kind %d", ErrEvsStatementRefused, push.GetRefKind())
	}
	return nil
}

// Checks a head read: the pin rule, then every statement after FromVersion and the chain they make to the head. A
// reply that is behind, and statements that stop short of the head, page GET .../log from the last version held,
// within the catch-up budget; past it, the head is taken as evs's word and the result marked Gap.
func (self *EvsVerifier) VerifyHead(ctx context.Context, read *EvsHeadRead) (*EvsVerifiedHead, error) {
	head := read.Head
	if head == nil {
		return nil, fmt.Errorf("%w: a read with no head", ErrEvsReplyInvalid)
	}
	if !bytes.Equal(head.GetRefId(), read.RefId.Bytes()) {
		return nil, fmt.Errorf("%w: a head of another ref", ErrEvsReplyInvalid)
	}
	headChain, err := EvsChainFromBytes(head.GetChain())
	if err != nil {
		return nil, fmt.Errorf("%w: the head's chain", ErrEvsReplyInvalid)
	}
	if err := self.checkPin(read.RepoId, read.RefId, head.GetVersion(), headChain); err != nil {
		return nil, err
	}
	verified := &EvsVerifiedHead{
		RepoId:      read.RepoId,
		RefId:       read.RefId,
		Head:        head,
		Version:     head.GetVersion(),
		Chain:       headChain,
		FromVersion: read.FromVersion,
	}
	if head.GetVersion() < read.FromVersion {
		return nil, fmt.Errorf("%w: a head below the version read from", ErrEvsHeadForked)
	}
	statements := read.Statements
	byteCount := int64(0)
	for _, statement := range statements {
		byteCount += int64(len(statement.GetStatement()))
	}
	if read.Behind != 0 || read.FromVersion+uint64(len(statements)) < head.GetVersion() {
		// the window does not reach back to the pin: page the log from the pin, as far as the budget goes
		paged, gap, err := self.pageLog(ctx, read, byteCount)
		if err != nil {
			return nil, err
		}
		if gap {
			return self.gapHead(verified, read)
		}
		statements = paged
	}
	if byteCount > self.client.settings.CatchUpByteCount {
		return self.gapHead(verified, read)
	}
	walked, err := self.walk(read.RepoId, read.RefId, read.FromVersion, read.FromChain, statements, head.GetVersion())
	if err != nil {
		return nil, err
	}
	if 0 < len(walked) && walked[len(walked)-1].Chain != headChain {
		return nil, fmt.Errorf("%w: the statements do not chain to the head", ErrEvsChainBroken)
	}
	if len(walked) == 0 && read.FromChain != headChain {
		return nil, fmt.Errorf("%w: a head at the pin's version with another chain", ErrEvsHeadForked)
	}
	if err := self.checkPinOnWalk(read.RepoId, read.RefId, walked); err != nil {
		return nil, err
	}
	verified.Statements = walked
	return verified, nil
}

// A head re-pinned past the catch-up budget (§11.9's budget row): its version and chain are evs's word, and the
// statements the reply carried, contiguous up to the head, are each checked alone, signature and ref rules, so a
// path's entry still answers to a writer's statement and the window's later changes still count against it. Their
// chain to the head is not checked, since C before the first of them is not known here.
func (self *EvsVerifier) gapHead(verified *EvsVerifiedHead, read *EvsHeadRead) (*EvsVerifiedHead, error) {
	verified.Gap = true
	verified.Statements = nil
	verified.FromVersion = verified.Version
	carried := []*protocol.EvsReadStatement{}
	for _, statement := range read.Statements {
		if read.FromVersion < statement.GetVersion() && statement.GetVersion() <= verified.Version {
			carried = append(carried, statement)
		}
	}
	if len(carried) == 0 || carried[len(carried)-1].GetVersion() != verified.Version {
		return verified, nil
	}
	first := carried[0].GetVersion()
	for i, statement := range carried {
		if statement.GetVersion() != first+uint64(i) {
			return nil, fmt.Errorf("%w: the window's statements skip a version", ErrEvsChainBroken)
		}
		parsed, err := self.VerifyStatement(statement.GetStatement(), read.RepoId, read.RefId)
		if err != nil {
			return nil, err
		}
		verified.Statements = append(verified.Statements, &EvsVerifiedStatement{Version: statement.GetVersion(), Statement: parsed})
	}
	verified.FromVersion = first - 1
	return verified, nil
}

// A ref's statements from fromVersion + 1 to throughVersion, read from GET .../log and each verified, chained from
// fromChain, as a replaying reader walks them: what §16.8's stream chains and §7.9's config replay call. The caller
// compares the last statement's Chain with the C it expects at throughVersion, and pins as it decides.
func (self *EvsVerifier) Walk(ctx context.Context, repoId Id, refId Id, fromVersion uint64, fromChain [sha256.Size]byte, throughVersion uint64) ([]*EvsVerifiedStatement, error) {
	if throughVersion <= fromVersion {
		return nil, nil
	}
	statements, err := self.client.readLog(ctx, repoId, refId, fromVersion+1, throughVersion)
	if err != nil {
		return nil, err
	}
	return self.walk(repoId, refId, fromVersion, fromChain, statements, throughVersion)
}

// The statements from fromVersion + 1 to throughVersion, each verified, chained from fromChain, in order.
func (self *EvsVerifier) walk(repoId Id, refId Id, fromVersion uint64, fromChain [sha256.Size]byte, statements []*protocol.EvsReadStatement, throughVersion uint64) ([]*EvsVerifiedStatement, error) {
	walked := []*EvsVerifiedStatement{}
	chain := fromChain
	expected := fromVersion + 1
	for _, read := range statements {
		if read.GetVersion() < expected {
			// one the caller already held, as a page overlapping the window gives
			continue
		}
		if read.GetVersion() != expected || throughVersion < read.GetVersion() {
			return nil, fmt.Errorf("%w: a statement at version %d where %d was due", ErrEvsChainBroken, read.GetVersion(), expected)
		}
		statement, err := self.VerifyStatement(read.GetStatement(), repoId, refId)
		if err != nil {
			// a format-2 construct, no config, and a pin this device's state is behind or no longer retains prove
			// nothing against the signer: only a failed signature, shape or rule alarms
			quiet := errors.Is(err, ErrEvsFormatUnsupported) || errors.Is(err, ErrEvsNoConfig) ||
				errors.Is(err, ErrGkmAuthAhead) || errors.Is(err, ErrGkmAuthNotRetained)
			if !quiet {
				self.client.alarm(repoId, refId, SidecarEvsAlarmTamper, "", evsSignerOf(read.GetStatement()))
			}
			return nil, err
		}
		pushId, _ := IdFromBytes(statement.Push.GetPushId())
		chain = EvsChainNext(chain, pushId, statement.Sha256)
		walked = append(walked, &EvsVerifiedStatement{Version: expected, Statement: statement, Chain: chain})
		expected += 1
	}
	if expected <= throughVersion {
		return nil, fmt.Errorf("%w: the statements stop at version %d, short of %d", ErrEvsChainBroken, expected-1, throughVersion)
	}
	if err := evsCheckWalkRules(walked, fromVersion, fromChain); err != nil {
		self.client.alarm(repoId, refId, SidecarEvsAlarmVersionRule, "", nil)
		return nil, err
	}
	return walked, nil
}

// The signer a statement's bytes name, for an alarm, nil when they do not parse.
func evsSignerOf(statementBytes []byte) *Id {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(statementBytes, signed); err != nil {
		return nil
	}
	push := &protocol.EvsPush{}
	if err := proto.Unmarshal(signed.GetBody(), push); err != nil {
		return nil
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil
	}
	return &signerId
}

// GET .../log?ref=&since= pages from the read's pin, at most the catch-up budget less what the read already carried,
// then the read's own statements past the last page. gap is true once the budget runs out first.
func (self *EvsVerifier) pageLog(ctx context.Context, read *EvsHeadRead, spentByteCount int64) ([]*protocol.EvsReadStatement, bool, error) {
	statements := []*protocol.EvsReadStatement{}
	since := read.FromVersion + 1
	for {
		reply := &protocol.EvsLogReply{}
		err := self.client.http.callMessage(ctx, &evsCall{
			route:  "GET /evs/v1/repos/{repo_id}/log",
			method: http.MethodGet,
			path: "/evs/v1/repos/" + evsUrlId(read.RepoId) + "/log?ref=" + evsUrlId(read.RefId) +
				"&since=" + strconv.FormatUint(since, 10),
			repoId: read.RepoId,
			role:   evsScopeRead,
			retry:  true,
		}, reply)
		if err != nil {
			return nil, false, err
		}
		for _, statement := range reply.GetStatements() {
			spentByteCount += int64(len(statement.GetStatement()))
			if self.client.settings.CatchUpByteCount < spentByteCount {
				return nil, true, nil
			}
			statements = append(statements, statement)
		}
		next := reply.GetNextVersion()
		if next == 0 || len(reply.GetStatements()) == 0 {
			break
		}
		if next <= since {
			return nil, false, fmt.Errorf("%w: a log page that does not move forward", ErrEvsReplyInvalid)
		}
		since = next
	}
	// the read's own statements carry on past the last page
	last := read.FromVersion + uint64(len(statements))
	for _, statement := range read.Statements {
		if last < statement.GetVersion() {
			statements = append(statements, statement)
			last = statement.GetVersion()
		}
	}
	return statements, false, nil
}

// The pin rule (I-16): a head below the ref's pin, or at it with another chain, is a fork, alarmed with both
// RefHeads, unless a verified reseed lowered the pin to exactly that head first.
func (self *EvsVerifier) checkPin(repoId Id, refId Id, version uint64, chain [sha256.Size]byte) error {
	pin, ok, err := self.client.pins.Pin(repoId, refId)
	if err != nil || !ok {
		return err
	}
	if version < pin.Version || (version == pin.Version && chain != pin.Chain) {
		self.alarmFork(repoId, refId, pin, version, chain)
		return ErrEvsHeadForked
	}
	return nil
}

// Checks that the walk passes through the pin: C at the pin's version equals the pin's chain.
func (self *EvsVerifier) checkPinOnWalk(repoId Id, refId Id, walked []*EvsVerifiedStatement) error {
	pin, ok, err := self.client.pins.Pin(repoId, refId)
	if err != nil || !ok {
		return err
	}
	for _, statement := range walked {
		if statement.Version == pin.Version && statement.Chain != pin.Chain {
			self.alarmFork(repoId, refId, pin, statement.Version, statement.Chain)
			return ErrEvsHeadForked
		}
	}
	return nil
}

// head_alarm's fork (plan-EVS1-evs-events): SidecarId nil, Evidence this device's RefHead and evs's.
func (self *EvsVerifier) alarmFork(repoId Id, refId Id, pin *EvsPin, version uint64, chain [sha256.Size]byte) {
	mine, _ := proto.Marshal(&protocol.RefHead{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Version: pin.Version, Chain: pin.Chain[:]})
	served, _ := proto.Marshal(&protocol.RefHead{RepoId: repoId.Bytes(), RefId: refId.Bytes(), Version: version, Chain: chain[:]})
	self.client.log.Warningf("[evs]a head of repo %s ref %s does not extend the pin", repoId, refId)
	self.client.emit(SidecarEvent{
		Kind:      SidecarEventHeadAlarm,
		RepoId:    &repoId,
		RefId:     &refId,
		HeadAlarm: SidecarHeadAlarmFork,
		Evidence:  [2][]byte{mine, served},
	})
}

// Pins a verified head durably, before anything it backs is shown: raised to its version and chain, its group from
// the head's generation pin, and, past the budget, the gap marked and evs_gap raised.
func (self *EvsVerifier) Pin(verified *EvsVerifiedHead) error {
	now := self.client.clock.Now()
	pin := &EvsPin{
		RepoId:   verified.RepoId,
		RefId:    verified.RefId,
		Version:  verified.Version,
		Chain:    verified.Chain,
		PinnedAt: now,
	}
	if groupId, err := IdFromBytes(verified.Head.GetGroupId()); err == nil {
		pin.GroupId = groupId
	}
	if verified.Gap {
		pin.VerifiedSince = now
	}
	if err := self.client.pins.Raise(pin); err != nil {
		if errors.Is(err, ErrEvsPinLower) || errors.Is(err, ErrEvsPinFork) {
			if held, ok, _ := self.client.pins.Pin(verified.RepoId, verified.RefId); ok {
				self.alarmFork(verified.RepoId, verified.RefId, held, verified.Version, verified.Chain)
			}
		}
		return err
	}
	if verified.Gap {
		repoId, refId := verified.RepoId, verified.RefId
		self.client.emit(SidecarEvent{Kind: SidecarEventEvsGap, RepoId: &repoId, RefId: &refId, VerifiedSince: now})
	}
	return nil
}

// Checks a Signed EvsReseed (§11.6, §19.10) for a head below the pin: by a repo admin at the reader's newest state,
// for this repo and ref, naming exactly the head served. A verified one lowers the pin to that head, kept as a loss,
// so the next read of it verifies from there.
func (self *EvsVerifier) AcceptReseed(signedBytes []byte, repoId Id, refId Id, head *protocol.EvsHeadSummary) error {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return fmt.Errorf("%w: a reseed that does not parse", ErrEvsStatementRefused)
	}
	reseed := &protocol.EvsReseed{}
	if err := proto.Unmarshal(signed.GetBody(), reseed); err != nil {
		return fmt.Errorf("%w: a reseed body that does not parse", ErrEvsStatementRefused)
	}
	if !bytes.Equal(reseed.GetRepoId(), repoId.Bytes()) || !bytes.Equal(reseed.GetRefId(), refId.Bytes()) ||
		reseed.GetVersion() != head.GetVersion() || !bytes.Equal(reseed.GetChain(), head.GetChain()) {
		return fmt.Errorf("%w: a reseed of another head", ErrEvsStatementRefused)
	}
	state, err := self.config()
	if err != nil {
		return err
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return fmt.Errorf("%w: a reseed's signer", ErrEvsStatementRefused)
	}
	repo := state.Repo(repoId)
	if repo == nil || !evsRepoAdmin(state, repo, signerId) {
		return fmt.Errorf("%w: a reseed by a non-admin", ErrEvsStatementRefused)
	}
	identityKey := state.IdentityKey(signerId)
	if err := bridge.VerifySigned(signed, evsReseedPurpose, bridge.SignedType_SIGNED_EVS_RESEED, bridge.SignedKeyAlgEd25519, identityKey); err != nil {
		return fmt.Errorf("%w: a reseed's signature: %w", ErrEvsStatementRefused, err)
	}
	chain, err := EvsChainFromBytes(head.GetChain())
	if err != nil {
		return err
	}
	pin := &EvsPin{RepoId: repoId, RefId: refId, Version: head.GetVersion(), Chain: chain, PinnedAt: self.client.clock.Now()}
	return self.client.pins.lowerByReseed(pin, reseed.GetIncidentId(), self.client.clock.Now())
}
