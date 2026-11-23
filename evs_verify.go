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
// A pin before what the reader's config retains, its previous base, is not judged and counts against no one
// (QD-1178, beside §10.9's judged row): bases land with every confirmed ACL save and each fold, so a path untouched for
// a day or two would otherwise read on no device. Such a statement is taken on its signature, which the key the oldest
// retained rows that admit its signer give must verify (VerifyStatement), and the chain does the rest: one at or below
// the ref's pin is what this device verified when it was new, and one above it, a new device's or a long-offline
// reader's, stands only on a walk whose chain reaches the head the reader verifies and pins. I-16 is unchanged: no pin
// falls, and the walk's authorization pins only rise (evsCheckWalkRules).
//
// A pin above the newest state the reader holds waits (QD-1202, as §10.9's judged row has it for gkm: one above my tip
// waits until I reach it, one I cannot reach being withheld): the device's log is behind a faster writer's, so the
// reader asks its log to reach the pin (EvsClientArgs.ConfigWait, ConfigClient.WaitForPin), within
// EvsSettings.AuthPinWaitTimeout and the read's ctx, then judges the statement at its own pin in the state it reached.
// Past the bound the statement is withheld, ErrConfigPinAhead under ErrEvsStatementRefused, which alarms nothing: a
// pin no state of the log reaches still refuses, and nothing is judged at a state it was not signed under. The config
// follower's own reads of the config repo (evs_config_head.go) never wait, since they run on the follow the wait
// would wait on (withholdingAhead).
//
// A head below the pin is refused and raises head_alarm's fork with both RefHeads as evidence, unless a verified
// EvsReseed covers it (§11.13, §19.10), which lowers the pin and is kept as a loss. A head at the pin's version with
// another chain is the same fork. The pin a head is judged against is the one its read asked at (EvsHeadRead.ask):
// another read of the same client may raise the pin while this one is in flight, and a head it passed is no fork. It
// stands as read where the pin store holds its chain at its version, and is a stale read, read again or answered
// ErrEvsReadStale, where it holds none; a walk that meets a chain the store holds with another one is still a fork,
// whichever read raised it (evs_pin_store.go's header).
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

// Format 2's verdicts on a version (evs_verify_format2.go).
var (
	// A version whose versioning §11.7's refused row does not allow where it sits: refused, with an alarm.
	ErrEvsVersioningRefused = fmt.Errorf("%w: versioning refused where it sits", ErrEvsEntryRefused)
	// A version a reader ignores, as if its path held none: versioning 2 outside an index root, or a version under an
	// index root or on ur/lfs that is none of its writer's.
	ErrEvsVersionIgnored = errors.New("evs: version ignored")
	// The content of a replaced versionless version, which nothing restores (§11.7's history row): no alarm.
	ErrEvsCollected = errors.New("evs: content collected")
	// A versionless file replaced each time ReadHead read it, EvsSettings.ReadReplacedRestartCount times over: a path
	// overwritten faster than it downloads (§11.7's reads row). No alarm.
	ErrEvsReplacedMidRead = errors.New("evs: replaced while it was read")
)

// A read whose head another read of this client raised the pin past while it was in flight, where nothing this device
// holds places that head on the pinned history: no fork, and no alarm. The read is read again, fresh, at most
// EvsSettings.ReadStaleRetryCount times before it answers this (evs_pin_store.go's header).
var ErrEvsReadStale = errors.New("evs: read stale")

// The two refs format 2 reserves by name (§11.7's git row, §11.11, §11.14).
var (
	EvsIndexRefName = []byte("ur/index")
	EvsLfsRefName   = []byte("ur/lfs")
)

// Which reserved ref a version sits on.
type EvsReservedRef int

const (
	// Any other ref.
	EvsReservedRefNone EvsReservedRef = iota
	// The repo's ur/index, whose every path is under the index root.
	EvsReservedRefIndex
	// The repo's ur/lfs, git-lfs's versionless store.
	EvsReservedRefLfs
)

// A repo's reserved ref ids, which K_ref gives at every generation.
type evsReservedRefIds struct {
	indexRefId Id
	lfsRefId   Id
}

// Format 2's reader as a client holds it once its composition installs it (EvsClient.EnableFormat2Reader,
// evs_verify_format2.go): the rules format 2 adds to a read, behind a seam so that a leg which reads format 1 alone,
// the network extensions', links none of them.
type evsFormat2Reader interface {
	// §11.7's rows over one version a statement wrote at names, where it sits: nil, a refusal, or
	// ErrEvsVersionIgnored, the last two after an alarm.
	verifyVersion(verifier *EvsVerifier, repoId Id, refId Id, statement *EvsStatement, names [][]byte, reserved EvsReservedRef, entry *protocol.EvsEntryVersion) error
	// A format-2 statement's own rules beside the refs table.
	checkRefRules(state GkmAuthView, statement *EvsStatement, repoId Id, signerId Id) error
	// Which reserved ref refId is in repo.
	reservedRef(ctx context.Context, repo *EvsRepo, refId Id) (EvsReservedRef, error)
	// What a versionless version's `collected` or missing content comes to after a fresh read of its path's newest
	// version: ErrEvsObjectMissing after an alarm, or ErrEvsCollected for a replaced one (evs_read_versionless.go).
	contentGone(ctx context.Context, repo *EvsRepo, result *evsReadResult, verified *EvsVerifiedPath) error
	// A path's reply in a drop's state, drop_pending or dropped: DESIGN-DETAILS 10.2.3's H0 to H7 and its verdict
	// (evs_drop_verify.go), the path verified as VerifyPath verifies a version asked for by number, with the drop's
	// state on it where the drop stands; errEvsDropBodyMissing where the reply left out a body this device lacks.
	verifyDropPath(ctx context.Context, verifier *EvsVerifier, head *EvsVerifiedHead, epochs *EvsPathEpochs, reply *protocol.EvsReadPathReply) (*EvsVerifiedPath, error)
	// The ref versions of the DROP bodies this device keeps for a ref, which a read names in held_drops.
	heldDrops(client *EvsClient, repoId Id, refId Id) []uint64
}

// The client's format-2 reader, nil for one that reads format 1 alone: a client whose composition installed none, as
// every client is made, or one its settings hold to format 1 (EvsSettings.MaxFormat). Such a client answers each
// format-2 construct FORMAT_UNSUPPORTED (D-EVS-39).
func (self *EvsClient) format2Reader() evsFormat2Reader {
	if self.settings.MaxFormat < 2 {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.format2Reads
}

// The verifying reader of one EvsClient.
type EvsVerifier struct {
	client *EvsClient
	// a statement pinned above the reader's state is withheld at once, never waited for (withholdingAhead)
	withholdAhead bool
}

// The verifier of client's reads.
func newEvsVerifier(client *EvsClient) *EvsVerifier {
	return &EvsVerifier{client: client}
}

// This verifier, withholding at once a statement pinned above the reader's state rather than waiting for its log to
// reach the pin: for the config follower's own reads of the config repo, a base's head (evs_config_head.go), which run
// on the follow, under its followLock, that the wait would wait on. A base's head holds no push pinned at or past the
// base, whose chain value covers that head, so its reader loses nothing by not waiting.
func (self *EvsVerifier) withholdingAhead() *EvsVerifier {
	return &EvsVerifier{client: self.client, withholdAhead: true}
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
	// The ref's pin as the read asked (EvsPinStore.ask), which the head is judged against; nil judges it against the
	// pin as it stands when the head is checked.
	ask *evsPinAsk
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
	// The pin VerifyHead judged the head against, and C at FromVersion: Pin raises a head with an ask as the pin store
	// judges it (EvsPinStore.raiseRead), and one built any other way, with none, as Raise does.
	ask       *evsPinAsk
	fromChain [sha256.Size]byte
	// A walk read a page at a time, which keeps no statement: C at each version after FromVersion it passed, in order,
	// where Statements is empty (evsWalkTrail), what its raise is judged by
	walkChains [][sha256.Size]byte
	// The walk starts at its reader's own verified state, a copy's, a mirror's, a mount's or a replay's, not at a pin
	// of this store's: a start above the pin that nothing the store holds places raises as Raise raises one
	ownStart bool
	// A page of the history, ending where its read stopped short of the head: below the pin it raises nothing and is
	// no regression (evs_pin_walk.go)
	page bool
	// Pin raised it, or found the pin past it and so raised nothing
	pinned bool
}

// C at version as the head's walk verified it, false where it holds none: its own, its walk's start's or a walked
// statement's.
func (self *EvsVerifiedHead) chainAt(version uint64) ([sha256.Size]byte, bool) {
	switch {
	case version == self.Version:
		return self.Chain, true
	case self.Gap:
		return [sha256.Size]byte{}, false
	case version == self.FromVersion:
		return self.fromChain, true
	}
	if statement, ok := self.StatementAt(version); ok {
		return statement.Chain, true
	}
	if self.FromVersion < version && version <= self.FromVersion+uint64(len(self.walkChains)) {
		return self.walkChains[version-self.FromVersion-1], true
	}
	return [sha256.Size]byte{}, false
}

// Each version the head's walk verified after FromVersion, and C there, in order: its statements', or a paged walk's
// chains.
func (self *EvsVerifiedHead) walked(yield func(version uint64, chain [sha256.Size]byte) bool) {
	for _, statement := range self.Statements {
		if !yield(statement.Version, statement.Chain) {
			return
		}
	}
	for i, chain := range self.walkChains {
		if !yield(self.FromVersion+uint64(i)+1, chain) {
			return
		}
	}
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

// Whether sidecarId is one of the repo's admins in state: its access log's RepoAdmins that stand, and for the config
// repo its writers.
func evsRepoAdmin(state GkmAuthView, repo *protocol.AclRepo, sidecarId Id) bool {
	for _, admin := range repo.GetAdmins() {
		if AclRepoAdminStands(admin) && bytes.Equal(admin.GetSidecarId(), sidecarId.Bytes()) {
			return true
		}
	}
	return false
}

// Parses and checks one statement as received for repoId and refId: format 1's shape, its signature by the identity
// key its signer's admission gives at the statement's own auth pin, and §11.8's refs table at that state. A format-2
// statement of format 2's shape that its signer's key signed is taken by a reader of format 2, under the refs table
// and format 2's own rules (evs_verify_format2.go; EVS2-M10-17), and answers ErrEvsFormatUnsupported to a reader of
// format 1 alone (EvsClient.format2Reader), which is never a fork and never tampering; one out of shape or unsigned
// refuses as a format-1 statement does (EVS1-M2-39).
//
// An auth pin before what the reader's config retains is not judged and counts against no one (QD-1178, as §10.9's
// judged row has it for gkm): the statement is taken on its signature alone, checked against the key the oldest
// retained rows that admit its signer give it (evsUnjudgedSignerKey), and refused where none admits the signer at its
// pin. Where it sits is the caller's, as for any statement: one at or below the ref's pin is what this device verified
// when it was new, the walk holding it to the pin's chain where it walks it, and one above the pin stands only on a
// walk whose chain reaches the head the reader verifies and pins. Only a pin off the chain, one ahead of every state
// the reader's log reaches in time, and a signature that does not verify refuse.
//
// An auth pin above the newest state waits for the reader's log to reach it, within EvsSettings.AuthPinWaitTimeout
// and ctx (QD-1202; awaitPin), and the statement is then judged at its own pin in the state reached; one still above
// it answers ErrConfigPinAhead as before. A verifier that withholds ahead (withholdingAhead) never waits.
func (self *EvsVerifier) VerifyStatement(ctx context.Context, statementBytes []byte, repoId Id, refId Id) (*EvsStatement, error) {
	statement, err := ParseEvsStatement(statementBytes)
	var unsupported error
	if errors.Is(err, ErrEvsFormatUnsupported) {
		// a format-2 statement is still held to format 2's shape and to its signer's key, so a malformed or unsigned
		// one refuses, and alarms, as any other does: only one a writer signed answers as needing format 2 (FS-72)
		unsupported = err
		statement, err = ParseEvsStatementFormat2(statementBytes)
	}
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
	if errors.Is(err, ErrGkmAuthAhead) {
		// this device's log is behind the signer's: the statement is judged at its own pin once the log reaches it,
		// and withheld as before where it does not in time
		newest = self.awaitPin(ctx, newest, push.GetAuth().GetVersion())
		state, err = newest.At(push.GetAuth())
	}
	switch {
	case errors.Is(err, ErrGkmAuthNotRetained):
		// two bases may have passed the pin while the log caught up: unjudged, as for any pin before the window
		return self.takeUnjudged(newest, statement, unsupported)
	case err != nil:
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
	if unsupported != nil {
		reader := self.client.format2Reader()
		if reader == nil {
			// format 2's ref rules are its readers' to judge
			return nil, unsupported
		}
		// a format-2 reader takes it: the refs table as for any statement, then format 2's own rules
		if err := reader.checkRefRules(state, statement, repoId, signerId); err != nil {
			return nil, err
		}
	}
	if err := evsCheckRefRules(state, statement, repoId, refId, signerId); err != nil {
		return nil, err
	}
	return statement, nil
}

// The newest state once the reader's log has reached position n, a statement's pin above newest (QD-1202): asked of
// EvsClientArgs.ConfigWait within EvsSettings.AuthPinWaitTimeout on the client's clock, and within ctx, then read
// again, for the caller to judge the statement in. Where this verifier withholds ahead, no wait is wired or the bound is
// not positive it waits for nothing; a wait that fails, times out or ends with ctx leaves whatever state then stands,
// whose At answers ErrConfigPinAhead as before. It holds no lock while it waits.
func (self *EvsVerifier) awaitPin(ctx context.Context, newest GkmAuthView, n uint64) GkmAuthView {
	wait := self.client.args.ConfigWait
	timeout := self.client.settings.AuthPinWaitTimeout
	if self.withholdAhead || wait == nil || timeout <= 0 {
		return newest
	}
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.client.clock.AfterFunc(timeout, cancel)
	defer stop()
	if err := wait(waitCtx, n); err != nil && self.client.log.V(1).Enabled() {
		self.client.log.Infof("[evs]the wait for the config log to reach a statement's pin %d: %v", n, err)
	}
	state, err := self.config()
	if err != nil {
		return newest
	}
	return state
}

// A statement whose auth pin newest no longer retains, taken unjudged (QD-1178; VerifyStatement's header): its
// signature checked against the key newest's oldest retained rows give its signer, with no refs table and no format-2
// rule, which judge at the pin's state. A format-2 statement still answers ErrEvsFormatUnsupported to a reader of
// format 1 alone, once its signature verifies.
func (self *EvsVerifier) takeUnjudged(newest GkmAuthView, statement *EvsStatement, unsupported error) (*EvsStatement, error) {
	push := statement.Push
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return nil, fmt.Errorf("%w: its signer", ErrEvsStatementRefused)
	}
	identityKey, err := evsUnjudgedSignerKey(newest, signerId, push.GetAuth())
	if err != nil {
		return nil, err
	}
	if err := statement.Verify(identityKey); err != nil {
		return nil, fmt.Errorf("%w: its signature: %w", ErrEvsStatementRefused, err)
	}
	if unsupported != nil && self.client.format2Reader() == nil {
		return nil, unsupported
	}
	return statement, nil
}

// A state that gives, for a pin before what it retains, the identity key its oldest retained rows that admit a signer
// give it: *ConfigState (config_state_at.go).
type evsRetainedSignerState interface {
	retainedIdentityKey(sidecarId Id, pin *bridge.AuthPin) ([]byte, error)
}

// The identity key that checks what signerId signed at pin, a pin newest no longer retains, which is not judged and
// counts against no one (QD-1178): the key newest's oldest retained rows that admit the signer give it, and a refusal
// where none admits it at pin, never admitted, admitted after it or revoked at or before it (ErrConfigSignerNotAdmitted
// under ErrEvsStatementRefused). A state that keeps no window, a stand-in's, answers from its own rows.
func evsUnjudgedSignerKey(newest GkmAuthView, signerId Id, pin *bridge.AuthPin) ([]byte, error) {
	var identityKey []byte
	var err error
	if retained, ok := newest.(evsRetainedSignerState); ok {
		identityKey, err = retained.retainedIdentityKey(signerId, pin)
	} else {
		identityKey, err = configSignerKeyAt(newest.SidecarRow(signerId), newest.IdentityKey(signerId), pin)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsStatementRefused, err)
	}
	return identityKey, nil
}

// evsUnjudgedSignerKey for a gate that takes a statement pinned before what its state retains as a reader does: evs's
// re-seed (evsservice/reseed.go), whose gate state is a *ConfigState, so the same rows give the same key and the same
// refusal on both sides.
func EvsUnjudgedSignerKey(newest GkmAuthView, signerId Id, pin *bridge.AuthPin) ([]byte, error) {
	return evsUnjudgedSignerKey(newest, signerId, pin)
}

// §11.8's refs table again over a verified statement's payload, as a replaying reader holds it: changes are the push's
// own, each with its entry version, and pathOf gives each change's path as the reader's replay holds it, nil for a path
// it holds none of. What VerifyStatement leaves a statement read alone to, a write on a base of a record-class stream,
// is judged here: a directory's add-only delta passes, and any other change is ErrEvsStatementRefused (QD-722). A
// statement whose auth pin the reader no longer retains is not judged here either (QD-1178): VerifyStatement took it on
// its signature.
func (self *EvsVerifier) VerifyPayloadRefRules(statement *EvsStatement, repoId Id, refId Id, changes []*EvsCheckedChange, pathOf func(change *EvsCheckedChange) *EvsCreatesOnlyPath) error {
	push := statement.Push
	newest, err := self.config()
	if err != nil {
		return err
	}
	state, err := newest.At(push.GetAuth())
	switch {
	case errors.Is(err, ErrGkmAuthNotRetained):
		return nil
	case err != nil:
		return fmt.Errorf("%w: its authorization pin: %w", ErrEvsStatementRefused, err)
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return fmt.Errorf("%w: its signer", ErrEvsStatementRefused)
	}
	return evsCheckRefRulesOver(state, statement, changes, pathOf, repoId, refId, signerId)
}

// §11.8's refs table at the statement's state over the statement read alone: who may write each ref kind, and who may
// FORCE, DELETE, BASE, CONSUME and ERASE there. Record-class owned refs, deposit refs and the erasure ref take only
// creations from their writers, a record-class stream also a directory's add-only delta (evs_creates_only.go), which
// a statement alone cannot tell from a file's write: the replaying reader that holds the payload judges that
// (VerifyPayloadRefRules).
func evsCheckRefRules(state GkmAuthView, statement *EvsStatement, repoId Id, refId Id, signerId Id) error {
	return evsCheckRefRulesOver(state, statement, statement.Changes, nil, repoId, refId, signerId)
}

// A state that names its network's genesis config writer, the Genesis's owner sidecar at S(0) (§7.9): *ConfigState.
type evsGenesisWriterState interface {
	Genesis() *bridge.Genesis
	IsConfigWriter(sidecarId Id) bool
}

// The refs table as evsCheckRefRules holds it, over changes: the statement's inline ones, or a push's payload's with
// their entry versions. pathOf gives a change's path as the caller's replay holds it, nil when it holds none, as nil
// pathOf does for every change.
func evsCheckRefRulesOver(state GkmAuthView, statement *EvsStatement, changes []*EvsCheckedChange, pathOf func(change *EvsCheckedChange) *EvsCreatesOnlyPath, repoId Id, refId Id, signerId Id) error {
	push := statement.Push
	repo := state.Repo(repoId)
	if repo == nil {
		return fmt.Errorf("%w: a repo the state does not hold", ErrEvsStatementRefused)
	}
	flags := push.GetFlags()
	has := func(flag protocol.EvsPushFlag) bool { return flags&uint32(flag) != 0 }
	writer := slices.Contains(state.RepoWriters(repoId), signerId)
	if genesis, ok := state.(evsGenesisWriterState); ok && !writer && push.GetAuth().GetVersion() == 0 &&
		bytes.Equal(genesis.Genesis().GetConfigRepoId(), repoId.Bytes()) {
		// the config repo's first push, pinned at the genesis (QD-081 #4): S(0) holds no rows, so its one config
		// writer, the Genesis's owner sidecar (§7.9), is no row's
		writer = genesis.IsConfigWriter(signerId)
	}
	admin := evsRepoAdmin(state, repo, signerId)
	createsOnly := func(deltas bool) error {
		for _, change := range changes {
			var path *EvsCreatesOnlyPath
			if pathOf != nil {
				path = pathOf(change)
			}
			if refusal := EvsCreatesOnlyRefusal(change, deltas, path); refusal != "" {
				return fmt.Errorf("%w: a creates-only ref's change: %s", ErrEvsStatementRefused, refusal)
			}
		}
		if has(protocol.EvsPushFlag_EVS_PUSH_FORCE) || has(protocol.EvsPushFlag_EVS_PUSH_DELETE) {
			return fmt.Errorf("%w: FORCE or DELETE on a creates-only ref", ErrEvsStatementRefused)
		}
		return nil
	}
	// a BASE re-lists a stream's live set by removals alone (plan-EVS1-v1-unspecified#6)
	baseRemovalsOnly := func() error {
		for _, change := range changes {
			if len(change.Change.GetEntrySha256()) != 0 {
				return fmt.Errorf("%w: a BASE that writes", ErrEvsStatementRefused)
			}
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
				if has(protocol.EvsPushFlag_EVS_PUSH_BASE) {
					return baseRemovalsOnly()
				}
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
			if has(protocol.EvsPushFlag_EVS_PUSH_BASE) && admin {
				// a stream's own writer that is a repo admin may BASE it too
				return baseRemovalsOnly()
			}
			// a stream's directories grow by add-only deltas (QD-722)
			return createsOnly(true)
		}
	case protocol.EvsRefKind_EVS_REF_DEPOSIT:
		if ownerErr != nil || EvsDepositRefId(repoId, ownerId) != refId {
			return fmt.Errorf("%w: a deposit ref not its depositor's", ErrEvsStatementRefused)
		}
		if has(protocol.EvsPushFlag_EVS_PUSH_CONSUME) {
			if !writer {
				return fmt.Errorf("%w: a CONSUME by a sidecar that does not write the repo", ErrEvsStatementRefused)
			}
			for _, change := range changes {
				if len(change.Change.GetEntrySha256()) != 0 {
					return fmt.Errorf("%w: a CONSUME that writes", ErrEvsStatementRefused)
				}
			}
			return nil
		}
		if ownerId != signerId {
			return fmt.Errorf("%w: a deposit signed by another sidecar", ErrEvsStatementRefused)
		}
		return createsOnly(false)
	case protocol.EvsRefKind_EVS_REF_ERASURE:
		if EvsErasureRefId(repoId) != refId {
			return fmt.Errorf("%w: an erasure ref at another id", ErrEvsStatementRefused)
		}
		if !admin {
			return fmt.Errorf("%w: an erasure push by a non-admin", ErrEvsStatementRefused)
		}
		return createsOnly(false)
	default:
		return fmt.Errorf("%w: ref kind %d", ErrEvsStatementRefused, push.GetRefKind())
	}
	return nil
}

// Checks a head read: the pin rule against the pin the read asked at, then every statement after FromVersion and the
// chain they make to the head, then the head against the pin as it stands now and the chains the pin store keeps. A
// reply that is behind, and statements that stop short of the head, page GET .../log from the last version held,
// within the catch-up budget; past it, the head is taken as evs's word and the result marked Gap. A head another read
// of this client passed while this one was in flight answers ErrEvsReadStale where the store cannot place it, so the
// caller reads again before it reads any path (see the file header).
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
	ask := read.ask
	if ask == nil {
		// a read that kept no ask: the pin as it stands now
		if ask, err = self.client.pins.ask(read.RepoId, read.RefId); err != nil {
			return nil, err
		}
	}
	if pin := ask.pin; pin != nil && (head.GetVersion() < pin.Version || (head.GetVersion() == pin.Version && headChain != pin.Chain)) {
		// the pin rule (I-16) at the pin the read asked at
		self.alarmFork(read.RepoId, read.RefId, pin, head.GetVersion(), headChain)
		return nil, ErrEvsHeadForked
	}
	verified := &EvsVerifiedHead{
		RepoId:      read.RepoId,
		RefId:       read.RefId,
		Head:        head,
		Version:     head.GetVersion(),
		Chain:       headChain,
		FromVersion: read.FromVersion,
		ask:         ask,
		fromChain:   read.FromChain,
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
			return self.judgeHead(self.gapHead(ctx, verified, read))
		}
		statements = paged
	}
	if byteCount > self.client.settings.CatchUpByteCount {
		return self.judgeHead(self.gapHead(ctx, verified, read))
	}
	walked, err := self.walk(ctx, read.RepoId, read.RefId, read.FromVersion, read.FromChain, statements, head.GetVersion())
	if err != nil {
		return nil, err
	}
	if 0 < len(walked) && walked[len(walked)-1].Chain != headChain {
		return nil, fmt.Errorf("%w: the statements do not chain to the head", ErrEvsChainBroken)
	}
	if len(walked) == 0 && read.FromChain != headChain {
		return nil, fmt.Errorf("%w: a head at the pin's version with another chain", ErrEvsHeadForked)
	}
	verified.Statements = walked
	return self.judgeHead(verified, nil)
}

// A verified head judged against the pin as it stands now, which another read of this client may have raised past
// the one this read asked at, and the chains the pin store keeps (EvsPinStore.standing): a version they hold with
// another chain is a fork, alarmed; a head they passed and cannot place is ErrEvsReadStale, with no alarm; else the
// head, which Pin judges again as it raises.
func (self *EvsVerifier) judgeHead(verified *EvsVerifiedHead, err error) (*EvsVerifiedHead, error) {
	if err != nil {
		return nil, err
	}
	standing, mine, err := self.client.pins.standing(verified)
	switch {
	case errors.Is(err, ErrEvsPinFork), errors.Is(err, ErrEvsPinLower):
		self.alarmHeadAgainst(verified, mine)
		return nil, ErrEvsHeadForked
	case err != nil:
		return nil, err
	case standing == evsPinStale:
		return nil, ErrEvsReadStale
	}
	return verified, nil
}

// head_alarm's fork over a verified head the pin store refused: this device's RefHead that it contradicts, and evs's,
// the head's own chain at that version where its walk holds one, else the head.
func (self *EvsVerifier) alarmHeadAgainst(verified *EvsVerifiedHead, mine *EvsPin) {
	if mine == nil {
		mine = &EvsPin{RepoId: verified.RepoId, RefId: verified.RefId}
	}
	version, chain := verified.Version, verified.Chain
	if served, ok := verified.chainAt(mine.Version); ok {
		version, chain = mine.Version, served
	}
	self.alarmFork(verified.RepoId, verified.RefId, mine, version, chain)
}

// A head re-pinned past the catch-up budget (§11.9's budget row): its version and chain are evs's word, and the
// statements the reply carried, contiguous up to the head, are each checked alone, signature and ref rules, so a
// path's entry still answers to a writer's statement and the window's later changes still count against it. Their
// chain to the head is not checked, since C before the first of them is not known here. One pinned before what the
// reader retains is checked on its signature alone (QD-1178), as evs's word the gap already is: a reply carrying none
// of them would be taken as the head alone.
func (self *EvsVerifier) gapHead(ctx context.Context, verified *EvsVerifiedHead, read *EvsHeadRead) (*EvsVerifiedHead, error) {
	verified.Gap = true
	verified.Statements = nil
	verified.FromVersion = verified.Version
	// C before the carried statements is not known here
	verified.fromChain = [sha256.Size]byte{}
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
		parsed, err := self.VerifyStatement(ctx, statement.GetStatement(), read.RepoId, read.RefId)
		if err != nil {
			return nil, err
		}
		if err := evsCheckExactHeadVersion(parsed.Push, statement.GetVersion()); err != nil {
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
	return self.walk(ctx, repoId, refId, fromVersion, fromChain, statements, throughVersion)
}

// The whole log of a verified head. Its signed statements must reach that head's chain.
func (self *EvsVerifier) walkToHead(ctx context.Context, head *EvsVerifiedHead) ([]*EvsVerifiedStatement, error) {
	start := EvsChainStart(head.RepoId, head.RefId)
	walked, err := self.Walk(ctx, head.RepoId, head.RefId, 0, start, head.Version)
	if err != nil {
		return nil, err
	}
	reached := start
	if len(walked) != 0 {
		reached = walked[len(walked)-1].Chain
	}
	if reached != head.Chain {
		return nil, fmt.Errorf("%w: the history does not chain to the head", ErrEvsChainBroken)
	}
	return walked, nil
}

// The statements from fromVersion + 1 to throughVersion, each verified, chained from fromChain, in order: one pinned
// above the reader's state waiting, within the bound and ctx, for the log to reach its pin (VerifyStatement).
func (self *EvsVerifier) walk(ctx context.Context, repoId Id, refId Id, fromVersion uint64, fromChain [sha256.Size]byte, statements []*protocol.EvsReadStatement, throughVersion uint64) ([]*EvsVerifiedStatement, error) {
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
		statement, err := self.VerifyStatement(ctx, read.GetStatement(), repoId, refId)
		if err != nil {
			// a format-2 construct, no config, and a pin this device's state is still behind once the wait ends prove
			// nothing against the signer: only a failed signature, shape or rule alarms, a signer no retained row admits
			// at a pin before the window among them; such a pin is otherwise taken unjudged (QD-1178) and refuses
			// nothing here
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
// the head's generation pin, and, past the budget, the gap marked and evs_gap raised. A head read at an ask, by
// VerifyHead or by a reader that walks its statements itself (evs_pin_walk.go), is judged again as it is raised,
// against the pin it was read at and the pin as it then stands (EvsPinStore.raiseRead): one another read raised the
// pin past stands with nothing raised where the store places it on the pinned history, and answers ErrEvsReadStale,
// with no alarm, where it cannot; a regression or a fork refuses with the alarm. A page of a history raises the pin to
// its end where that stands above it, and below the pin raises nothing.
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
	// the raise is the read's linearization point: another read of the client may raise the pin up to it
	barrierKey := verified.RepoId.String() + ":" + verified.RefId.String()
	testHookBarrier("evs.pin.raise.before", barrierKey)
	defer testHookBarrier("evs.pin.raise.after", barrierKey)
	if verified.ask != nil {
		standing, mine, err := self.client.pins.raiseRead(pin, verified)
		if err != nil {
			if errors.Is(err, ErrEvsPinLower) || errors.Is(err, ErrEvsPinFork) {
				self.alarmHeadAgainst(verified, mine)
				// a head that does not extend the pin, as VerifyHead names one, whether its check or its raise found it
				return fmt.Errorf("%w: %w", ErrEvsHeadForked, err)
			}
			return err
		}
		switch standing {
		case evsPinStale:
			return ErrEvsReadStale
		case evsPinPassed:
			// the pin stands past this head, on its history, or past a page of it: nothing to raise, no gap to mark,
			// though its statements may fill what the raise past it carried none of (evs_subscribe.go's marks row)
			verified.pinned = true
			self.client.subscriber.notePinned(verified)
			return nil
		}
	} else if err := self.client.pins.Raise(pin); err != nil {
		if errors.Is(err, ErrEvsPinLower) || errors.Is(err, ErrEvsPinFork) {
			if held, ok, _ := self.client.pins.Pin(verified.RepoId, verified.RefId); ok {
				self.alarmFork(verified.RepoId, verified.RefId, held, verified.Version, verified.Chain)
			}
		}
		return err
	}
	verified.pinned = true
	if verified.Gap {
		repoId, refId := verified.RepoId, verified.RefId
		self.client.emit(SidecarEvent{Kind: SidecarEventEvsGap, RepoId: &repoId, RefId: &refId, VerifiedSince: now})
	}
	// every statement past the pin raises its change to the ref's subscriptions, whichever call of the client verified
	// it (evs_subscribe.go's changes row)
	self.client.subscriber.notePinned(verified)
	return nil
}

// Checks a Signed EvsReseed (§11.6, §19.10) for a head below the pin: by a repo admin at the reader's newest state,
// for this repo and ref, naming exactly the head served. A verified one lowers the pin to that head, kept as a loss,
// so the next read of it verifies from there, and the ref's read records with it (QD-816; evs_pin_store.go): a path
// whose entry the incident lost reads its surviving version as part of the loss, and every other recorded path keeps
// its rollback check from that head, its floor at most the head's current epoch. What memory holds of the ref's head
// above it goes too (forgetRefHead).
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
	now := self.client.clock.Now()
	pin := &EvsPin{RepoId: repoId, RefId: refId, Version: head.GetVersion(), Chain: chain, PinnedAt: now}
	if err := self.client.pins.lowerByReseed(pin, reseed.GetIncidentId(), now, evsCurrentEpoch(head.GetPathEpoch())); err != nil {
		return err
	}
	self.client.forgetRefHead(repoId, refId, head.GetVersion())
	return nil
}
