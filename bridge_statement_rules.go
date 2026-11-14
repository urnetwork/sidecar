// §17.8's statements at body level: what a reader that holds the config's generations makes of the bridge statements
// the log took at id level (bridge_statement.go). A BridgeLedger starts from the config head's ledger rows, the verdicts
// a fold froze (bridge_ledger.go), and runs the rules no keyless verifier can over each unfolded statement in log order,
// each route and map by the verdict its judge reached where its entry landed:
//
//	pending   the body is sealed to a generation the reader lacks, or a route's or map's approval was not judged where
//	          it landed (Unopened, or no judge): the entry keeps its id-level effect, its id held and nothing active,
//	          and opens once RK_g arrives (plan-TEAM-sealed-field-format); a bodiless BridgeWithdraw never waits
//	void      the AEAD or the padding fails, which is the reader's alarm, the approval was Refused, or the body breaks
//	          its rule below: the id-level effect stands and the sealed effect is nothing
//	unformed  void with no alarm, Refused{no such generation} (DESIGN-DETAILS 12.2.3, QD-761 and QD-773): at every
//	          open, a body sealed to a generation the reader holds whose GenRotate was signed more than
//	          GenerationFormGrace after the body's entry; and at a writer's fold alone, a body that would wait for a
//	          generation above the reader's FormedThrough, not 0, once its entry is UnformedVoidWait before the entry at
//	          the fold asked, which both of the fold's opens use. Nothing else ends a wait
//	address   the first BridgeAddress in log order wins a host's bits; a second for an addressed host is void; a
//	          released address is a tombstone for 30 days by the log's time (I-14); the upper /17 takes a host only
//	          once the lower is full, and never inside an alias or an exposed prefix (§17.4, D-BRIDGE-20)
//	route     D-BRIDGE-8: an identical prefix is an HA replica, the same non-empty site_id, or a remap, one of the two
//	          carrying an exposed_prefix; nesting is allowed; anything else is void
//	held id   a filing of a held id changes only weight, site_id and drain_seconds and activates nothing; the bodies
//	          are compared with their approvals cleared, as the rows keep them
//	withdraw  an id a BridgeWithdraw named is void while the rows keep it: until its decision's not_after, or for a
//	          rule under a standing grant until its last filing's header could no longer be replayed; a withdrawal
//	          ahead of the id's first filing reserves it for its signer's filings, or anyone's for an admin's
//	approval  none under a standing grant, which BRIDGE-M4-16's compiler holds to §8's rules; else the verdict: the
//	          rule id the one §17.8 derives from the use's effect_key, and a decision's ids at most its uses over the
//	          rows and the entries alike, a retry adding none
//	alias     its signer an admin's device where it landed (SignerAdmin), one alias a share's target, and room in the
//	          upper /17
//
// An address is bound by its host bits, the low 16 of the IPv4 a BridgeAddress carries, since hosts keep their host
// bits across a block change (§17.4): the ledger never reads the upper 16, and ValidateBridgeAddress (BRIDGE-M4-15)
// holds a new claim to the block at filing.
//
// CheckBridgeBlock is D-BRIDGE-16's check where a head is read: a BridgeBlock rides a config head, signed by an admin,
// and a reader keeps the previous block and alarms on one outside 100.64.0.0/10 and RFC 1918, since a CLI check binds
// no other signing tool.
//
// testHookSecret runs where a body's key derives, inside OpenConfigBody. A ledger is immutable once built. On every
// leg, the ios_extension legs' included (the forwarding role compiles with it), with no connect import.

package sidecar

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §17.4's block: the shape of the address plan every reader holds addresses to, not a limit. The times and limits a
// verdict reads are BridgeLedgerSettings' fields.
const (
	// A network's block is one IPv4 /16 (§17.4).
	bridgeBlockPrefixLength = 16
	// The upper /17 of a block, in host bits: aliases and exposed prefixes from its bottom, spilled hosts from its top.
	bridgeUpperHostBits = uint32(0x8000)
	// The hosts a block's lower /17 holds: its 128 /24s less the services /24, each without .0 and .255.
	bridgeLowerHostCount = 127 * 254
	// The hosts a block's upper /17 holds.
	bridgeUpperHostCount = 128 * 254
	// §17.8's bound on a block's addresses, 64,770: every host the block's shape holds.
	BridgeAddressMaxCount = bridgeLowerHostCount + bridgeUpperHostCount
)

var (
	// A config head's BridgeBlock is not one a reader takes: the reader keeps the previous block and alarms
	// (D-BRIDGE-16; plan-BRIDGE-small-readings #17's block_refused).
	ErrBridgeBlockRefused = errors.New("bridge block refused")
	// A statement's sealed effect is void: its body does not open or breaks its rule. Its id-level effect stands.
	ErrBridgeVoid = errors.New("bridge statement void")
)

// One IPv4 prefix, its address masked to its length.
type bridgePrefix struct {
	address uint32
	length  uint32
}

// The ranges an admin may pick a block from besides 100.64.0.0/10: RFC 1918's.
var (
	bridgeSharedAddressSpace = bridgePrefix{address: 100<<24 | 64<<16, length: 10}
	bridgePrivateSpaces      = []bridgePrefix{
		{address: 10 << 24, length: 8},
		{address: 172<<24 | 16<<16, length: 12},
		{address: 192<<24 | 168<<16, length: 16},
	}
)

// The mask of a prefix length, 0 to 32.
func bridgePrefixMask(length uint32) uint32 {
	if length == 0 {
		return 0
	}
	return math.MaxUint32 << (32 - length)
}

// A wire prefix as a value, refusing none, a length past 32 or an address with bits past its length.
func bridgePrefixOf(prefix *bridge.BridgeIpv4Prefix) (bridgePrefix, error) {
	if prefix == nil {
		return bridgePrefix{}, errors.New("no prefix")
	}
	if 32 < prefix.GetLength() {
		return bridgePrefix{}, fmt.Errorf("a prefix length of %d", prefix.GetLength())
	}
	if prefix.GetAddress()&^bridgePrefixMask(prefix.GetLength()) != 0 {
		return bridgePrefix{}, errors.New("a prefix with bits past its length")
	}
	return bridgePrefix{address: prefix.GetAddress(), length: prefix.GetLength()}, nil
}

// Whether other lies inside this prefix, or is it.
func (self bridgePrefix) contains(other bridgePrefix) bool {
	return self.length <= other.length && other.address&bridgePrefixMask(self.length) == self.address
}

// Whether the address lies inside this prefix.
func (self bridgePrefix) containsAddress(address uint32) bool {
	return address&bridgePrefixMask(self.length) == self.address
}

// The prefix as the wire carries it.
func (self bridgePrefix) wire() *bridge.BridgeIpv4Prefix {
	return &bridge.BridgeIpv4Prefix{Address: self.address, Length: self.length}
}

// The prefix as text, for errors and status only.
func (self bridgePrefix) String() string {
	address := netip.AddrFrom4([4]byte{byte(self.address >> 24), byte(self.address >> 16), byte(self.address >> 8), byte(self.address)})
	return netip.PrefixFrom(address, int(self.length)).String()
}

// Whether prefix is a block a network may hold: a /16 inside 100.64.0.0/10 or RFC 1918 (owner decisions 28, 132).
func bridgeCheckBlockPrefix(wirePrefix *bridge.BridgeIpv4Prefix) (bridgePrefix, error) {
	prefix, err := bridgePrefixOf(wirePrefix)
	if err != nil {
		return bridgePrefix{}, err
	}
	if prefix.length != bridgeBlockPrefixLength {
		return bridgePrefix{}, fmt.Errorf("a /%d, and a block is a /16", prefix.length)
	}
	if bridgeSharedAddressSpace.contains(prefix) {
		return prefix, nil
	}
	for _, private := range bridgePrivateSpaces {
		if private.contains(prefix) {
			return prefix, nil
		}
	}
	return bridgePrefix{}, fmt.Errorf("%s is outside 100.64.0.0/10 and RFC 1918", prefix)
}

// D-BRIDGE-16's check of a BridgeBlock, wherever one is read or about to be signed: its prefix a /16 in 100.64.0.0/10
// or RFC 1918; a previous_prefix, the block it replaces, another such /16 with the time its drain ends; and no drain
// without one. ErrBridgeBlockRefused otherwise.
func CheckBridgeBlock(block *bridge.BridgeBlock) error {
	if block == nil {
		return fmt.Errorf("%w: no block", ErrBridgeBlockRefused)
	}
	prefix, err := bridgeCheckBlockPrefix(block.GetIpv4Prefix())
	if err != nil {
		return fmt.Errorf("%w: ipv4_prefix: %w", ErrBridgeBlockRefused, err)
	}
	if block.GetPreviousPrefix() == nil {
		if block.GetDrainUntil() != 0 {
			return fmt.Errorf("%w: drain_until with no previous_prefix", ErrBridgeBlockRefused)
		}
		return nil
	}
	previous, err := bridgeCheckBlockPrefix(block.GetPreviousPrefix())
	if err != nil {
		return fmt.Errorf("%w: previous_prefix: %w", ErrBridgeBlockRefused, err)
	}
	if previous == prefix {
		return fmt.Errorf("%w: previous_prefix is the block itself", ErrBridgeBlockRefused)
	}
	if block.GetDrainUntil() <= 0 {
		return fmt.Errorf("%w: a previous_prefix with no drain_until", ErrBridgeBlockRefused)
	}
	return nil
}

// The block a reader holds after reading a verified config head at state, the state the head's base lands on, given
// the block it held before, nil for none. A head whose bridge/block is signed by an admin's standing device and passes
// CheckBridgeBlock gives that block. One that fails either, or a head that drops the block a reader holds, gives the
// previous block back with an error wrapping ErrBridgeBlockRefused, which the reader raises as bridge_alarm's
// block_refused and otherwise ignores: the base stands (D-BRIDGE-16). A head with no block, read by a reader that held
// none, gives nil and no error (plan-BRIDGE-small-readings #13).
func ReadBridgeBlock(head *ConfigHead, state *ConfigState, previous *bridge.BridgeBlock) (*bridge.BridgeBlock, error) {
	if head == nil || state == nil {
		return previous, fmt.Errorf("%w: no head or state to read one at", ErrBridgeBlockRefused)
	}
	signed, message, err := head.signedRecord(ConfigHeadBridgeBlockPath, bridge.SignedType_SIGNED_BRIDGE_BLOCK)
	if err != nil {
		return previous, fmt.Errorf("%w: %w", ErrBridgeBlockRefused, err)
	}
	if signed == nil {
		if previous != nil {
			return previous, fmt.Errorf("%w: the head drops the block", ErrBridgeBlockRefused)
		}
		return nil, nil
	}
	if err := configHeadRecordSignedByAdmin(state, signed, bridge.SignedType_SIGNED_BRIDGE_BLOCK); err != nil {
		return previous, fmt.Errorf("%w: %w", ErrBridgeBlockRefused, err)
	}
	block := message.(*bridge.BridgeBlock)
	if err := CheckBridgeBlock(block); err != nil {
		return previous, err
	}
	return block, nil
}

// What a reader made of one statement at body level.
type BridgeDisposition int

const (
	// Its effect holds.
	BridgeDispositionActive BridgeDisposition = iota + 1
	// A filing of a held id: it activated nothing, and changed at most weight, site_id and drain_seconds.
	BridgeDispositionHeld
	// Its body is sealed to a generation the reader lacks, or its approval was not judged where it landed: its
	// id-level effect holds, and it opens once RK_g arrives and its judge runs.
	BridgeDispositionPending
	// Its body does not open or breaks its rule: its id-level effect holds and nothing else.
	BridgeDispositionVoid
)

// One unfolded statement with what a reader made of it.
type BridgeLedgerEntry struct {
	Statement   *BridgeLogStatement
	Disposition BridgeDisposition
	// Why it is void, wrapping ErrBridgeVoid. One that also wraps ErrConfigSealInvalid is the reader's alarm.
	Reason error
	// The generation a pending entry waits for, or the one a body a fold froze void as unformed was sealed to.
	Generation uint64
}

// What a reader learns from a BridgeApproval it verified.
type BridgeApprovalFacts struct {
	ApprovalId Id
	// The rule id §17.8 derives from this use's effect_key, which the statement's must equal.
	RuleId []byte
	// The budget, the smallest uses among the decisions, at least 1.
	Uses uint32
	// The earliest not_after among the decisions, ms since the epoch.
	NotAfterMs int64
}

// What a reader opens a ledger with.
type BridgeLedgerReader struct {
	// S(n), the state whose unfolded statements the ledger takes: its rows say which sidecars' addresses are released.
	// Nil releases nothing.
	State *ConfigState
	// The generation keys the reader holds: nil for one it lacks, which leaves that generation's bodies pending. Nil
	// holds none.
	RepoKeyAt func(generation uint64) *EvsRepoKey
	// The time an entry was sequenced at, for a release past the state's StateAt window; false when unknown, which
	// keeps that address a tombstone at an open and gives it the fold's time at a fold. Nil asks the state alone. A
	// log's reader answers from its kept entries (ConfigLog.EntryTimeMs).
	EntryTimeMs func(n uint64) (int64, bool)
	// The log's time the ledger reads tombstones and retention at. 0 is State's.
	TimeMs int64
	// A config writer's G for this fold, from its plan's whole read of gkm (BridgeBodyJudge.FormedThrough), which only
	// FoldBridgeLedger reads: a body that would wait for a generation above it is frozen void as unformed once its
	// entry is UnformedVoidWait before the entry at the fold asked (DESIGN-DETAILS 12.2.3). 0 voids nothing, and is
	// what a checker, a compile and every other open hold; CheckBridgeLedgerFold sets 0 whatever its caller did.
	FormedThrough uint64
	// Nil is the defaults.
	Settings *BridgeLedgerSettings
}

// One overlay address, live or a tombstone.
type BridgeLedgerAddress struct {
	SidecarId Id
	// The low 16 bits of its IPv4, which it keeps across block changes.
	HostBits uint32
	// The claim that won it: its entry, and the statement for one past the fold, nil for a row the fold holds.
	ClaimedAt uint64
	Statement *BridgeLogStatement
	// the release a folded tombstone carries, nil for an address live at the fold
	folded *bridgeRelease
}

// One released address no new holder may take yet.
type BridgeLedgerTombstone struct {
	SidecarId Id
	HostBits  uint32
	// The entry that released it, when the log released it, and whether the reader knows: an unknown time never ends
	// the tombstone.
	ReleasedAt      uint64
	ReleasedMs      int64
	ReleasedMsKnown bool
	// how long it holds from ReleasedMs: the ledger's AddressTombstoneTimeout
	holdMs int64
}

// Whether the tombstone still holds at the log's time timeMs.
func (self *BridgeLedgerTombstone) Holds(timeMs int64) bool {
	return !self.ReleasedMsKnown || timeMs < self.ReleasedMs+self.holdMs
}

// One BridgeWithdraw that binds a rule, or reserves an id no filing holds yet.
type BridgeLedgerWithdrawal struct {
	// Its entry and time.
	At     uint64
	TimeMs int64
	Mode   bridge.BridgeWithdrawMode
	// Its signer, and whether the signer was an admin's device where it landed, which binds any filer.
	Signer      Id
	SignerAdmin bool
	// The statement for one past the fold, nil for a row the fold holds.
	Statement *BridgeLogStatement
}

// The withdrawal a statement makes.
func bridgeLedgerWithdrawalOf(statement *BridgeLogStatement) *BridgeLedgerWithdrawal {
	return &BridgeLedgerWithdrawal{
		At: statement.N, TimeMs: statement.TimeMs, Mode: statement.WithdrawMode, Signer: statement.Signer,
		SignerAdmin: statement.SignerAdmin, Statement: statement,
	}
}

// Whether a withdrawal binds a rule its filer signs: an admin's binds any filer's, and anyone else's only its own.
func (self *BridgeLedgerWithdrawal) binds(filer Id) bool {
	return self.SignerAdmin || self.Signer == filer
}

// One rule the ledger holds: a route or a map, by its id.
type BridgeLedgerRule struct {
	RuleId []byte
	// SIGNED_BRIDGE_ROUTE or SIGNED_BRIDGE_MAP.
	SignedType bridge.SignedType
	// Its advertiser or host.
	Owner Id
	// Its first filing's entry and time, and its newest filing's.
	FirstAt  uint64
	FirstMs  int64
	NewestAt uint64
	NewestMs int64
	// The filings past the fold, nil where the fold holds them.
	First  *BridgeLogStatement
	Newest *BridgeLogStatement
	// The body in force, its approval cleared: the first filing's, with the weight, site_id and drain_seconds of the
	// newest filing of the held id. Exactly one is set, and none while the rule is pending or void.
	Route *bridge.BridgeRouteBody
	Map   *bridge.BridgeMapBody
	// A route's route_rule_ids and a map's expires, from the first filing.
	RouteRuleIds [][]byte
	Expires      int64
	// Whether it was filed with no approval: active only where a standing grant covers it, which the compiler holds
	// to §8's rules (§17.7).
	Standing bool
	// Its approval, when it carries one: the decision and the budget its rules share.
	ApprovalId         Id
	ApprovalNotAfterMs int64
	ApprovalUses       uint32
	// The withdrawal that binds it, nil for none.
	Withdrawn *BridgeLedgerWithdrawal
	// Whether its first filing waits for a generation or its judge, or is void: either way the id is held and nothing
	// is active.
	Pending bool
	Void    bool
}

// Whether the rule's body is in force: opened, valid and not withdrawn.
func (self *BridgeLedgerRule) Active() bool {
	return !self.Pending && !self.Void && self.Withdrawn == nil
}

// How long the rows keep a withdrawn id: until its decision's not_after and §8.6's skew, or for a rule under a
// standing grant until its newest filing's header could no longer be replayed. A void or pending rule is kept for
// good, math.MaxInt64.
func (self *BridgeLedgerRule) retainUntilMs() int64 {
	switch {
	case self.Pending || self.Void:
		return math.MaxInt64
	case self.Standing:
		return self.NewestMs + configStatementMaxLifetimeMs
	}
	return self.ApprovalNotAfterMs + aclDecisionSkewMs
}

// One subject's egress spec (§17.9).
type BridgeLedgerEgress struct {
	Subject Id
	Mode    bridge.BridgeEgressMode
	// Under exits: the exits, or the tag whose sidecars are. Empty while the body is pending or void, which leaves the
	// subject no exit.
	ExitSidecarIds []Id
	ExitTagId      []byte
	// The entry that set it, and the statement for one past the fold.
	At        uint64
	Statement *BridgeLogStatement
}

// One alias a share's accepting sidecar filed (§17.9).
type BridgeLedgerAlias struct {
	Body *bridge.BridgeAliasBody
	// The sidecar that filed it, and its entry.
	Signer Id
	At     uint64
	// The statement for one past the fold, nil for a row the fold holds.
	Statement *BridgeLogStatement
}

// A range of a block's upper /17 that an alias or an exposed prefix holds, in host bits.
type bridgeUpperRange struct {
	first uint32
	last  uint32
	// the rule that holds it, or nil for an alias
	rule *BridgeLedgerRule
}

// What a reader holding keys makes of the rows and the unfolded statements. Immutable once built.
type BridgeLedger struct {
	timeMs int64
	// the newest position the ledger reads releases at: the state's, or a fold's
	cutoffN uint64
	// whether this is a fold's ledger, which gives an unknown release its own time
	folding bool
	// the position the rows hold every statement through
	foldedThrough uint64
	entries       []*BridgeLedgerEntry

	rules map[string]*BridgeLedgerRule
	// withdrawals ahead of their rule's first filing, by the rule id they name
	reserved   map[string]*BridgeLedgerWithdrawal
	approvals  map[Id]*bridgeApprovalUse
	egress     map[Id]*BridgeLedgerEgress
	aliases    []*BridgeLedgerAlias
	upper      []bridgeUpperRange
	byHostBits map[uint32]*BridgeLedgerAddress
	bySidecar  map[Id]*BridgeLedgerAddress
	lowerCount int
	tombstones []*BridgeLedgerTombstone
	// each sidecar's release as the reader answered it once, nil for one that holds its addresses
	releases map[Id]*bridgeRelease
	// the lower /17 addresses that are or may become tombstones: the only ones a sweep can free
	releasing []*BridgeLedgerAddress
	// the opened bodies' bytes, against UnfoldedBodyMaxByteCount
	openedByteCount int
	// what keeps a fold from writing these rows, nil for nothing
	foldError error
	// a fold's void of a body sealed above every formed generation: the reader's FormedThrough, 0 at an open; the
	// time of the entry at the fold asked, which the wait is read against; and the entries frozen void so, in log order
	formedThrough uint64
	askedTimeMs   int64
	unformed      []*BridgeLedgerEntry

	reader   *BridgeLedgerReader
	settings *BridgeLedgerSettings
}

// One decision's budget as the ledger counts it.
type bridgeApprovalUse struct {
	uses    uint32
	ruleIds map[string]bool
}

// When a sidecar's addresses were released, as the reader knows it.
type bridgeRelease struct {
	// the entry that released it; every statement after it finds the sidecar gone
	n           uint64
	timeMs      int64
	timeMsKnown bool
}

// An empty ledger for reader at cutoffN and timeMs. A fold's ledger reads the reader's FormedThrough against
// askedTimeMs, the time of the entry at the fold asked; an open's reads none.
func newBridgeLedger(reader *BridgeLedgerReader, cutoffN uint64, timeMs int64, folding bool, askedTimeMs int64) *BridgeLedger {
	ledger := &BridgeLedger{
		timeMs:     timeMs,
		cutoffN:    cutoffN,
		folding:    folding,
		rules:      map[string]*BridgeLedgerRule{},
		reserved:   map[string]*BridgeLedgerWithdrawal{},
		approvals:  map[Id]*bridgeApprovalUse{},
		egress:     map[Id]*BridgeLedgerEgress{},
		byHostBits: map[uint32]*BridgeLedgerAddress{},
		bySidecar:  map[Id]*BridgeLedgerAddress{},
		releases:   map[Id]*bridgeRelease{},
		reader:     reader,
		settings:   bridgeLedgerSettingsOrDefault(reader.Settings),
	}
	if folding {
		ledger.formedThrough, ledger.askedTimeMs = reader.FormedThrough, askedTimeMs
	}
	return ledger
}

// The reader's state's position and time, or what it passes.
func bridgeLedgerReaderAt(reader *BridgeLedgerReader) (uint64, int64) {
	cutoffN, timeMs := uint64(math.MaxUint64), reader.TimeMs
	if reader.State != nil {
		cutoffN = reader.State.n
		if timeMs == 0 {
			timeMs = reader.State.TimeMs()
		}
	}
	return cutoffN, timeMs
}

// DESIGN-DETAILS 12.2.3's open: the ledger at the reader's state, S(n), from rows, the ledger files of the
// head its newest base names, and the state's unfolded statements past the rows' fold, in log order. rows nil is the
// empty ledger before any fold. An error is rows that are no ledger, rows folded below the state's base (which would
// miss statements), or bodies past the unfolded budget.
func OpenBridgeLedger(rows BridgeLedgerRows, reader *BridgeLedgerReader) (*BridgeLedger, error) {
	if reader == nil || reader.State == nil {
		return nil, errors.New("bridge ledger: no state to open at")
	}
	cutoffN, timeMs := bridgeLedgerReaderAt(reader)
	if base := reader.State.Base(); base != nil && rows != nil && rows.FoldedThrough() < base.GetFoldedThrough() {
		return nil, fmt.Errorf("%w: rows through %d under a base folded through %d", ErrBridgeLedgerMalformed, rows.FoldedThrough(), base.GetFoldedThrough())
	}
	return openBridgeLedger(rows, reader.State.Bridge().Statements(), reader, cutoffN, timeMs, false, 0)
}

// Opens the rows and every statement past their fold at or below cutoffN, at timeMs; a fold's, with askedTimeMs the
// time of the entry at the fold asked.
func openBridgeLedger(rows BridgeLedgerRows, statements []*BridgeLogStatement, reader *BridgeLedgerReader, cutoffN uint64, timeMs int64, folding bool, askedTimeMs int64) (*BridgeLedger, error) {
	ledger := newBridgeLedger(reader, cutoffN, timeMs, folding, askedTimeMs)
	if rows != nil {
		ledger.foldedThrough = rows.FoldedThrough()
		if err := ledger.loadRows(rows); err != nil {
			return nil, err
		}
	}
	for _, statement := range statements {
		if statement.N <= ledger.foldedThrough || cutoffN < statement.N {
			continue
		}
		ledger.apply(statement)
		if 0 < ledger.settings.UnfoldedBodyMaxByteCount && ledger.settings.UnfoldedBodyMaxByteCount < ledger.openedByteCount {
			return nil, fmt.Errorf("%w: the unfolded bodies pass %d bytes", ErrBridgeLedgerOverBudget, ledger.settings.UnfoldedBodyMaxByteCount)
		}
	}
	ledger.releaseAddresses()
	return ledger, nil
}

// The ledger of the log's statements alone, over no rows, as statements handed in directly read: tests, and a listing
// of the unfolded tail. reader nil holds no key and no state, so every sealed statement is pending.
func (self *BridgeLog) Open(reader *BridgeLedgerReader) *BridgeLedger {
	if reader == nil {
		reader = &BridgeLedgerReader{}
	}
	cutoffN, timeMs := bridgeLedgerReaderAt(reader)
	unbounded := *bridgeLedgerSettingsOrDefault(reader.Settings)
	unbounded.UnfoldedBodyMaxByteCount = 0
	bounded := *reader
	bounded.Settings = &unbounded
	ledger, _ := openBridgeLedger(nil, self.Statements(), &bounded, cutoffN, timeMs, false, 0)
	return ledger
}

// One statement at body level.
func (self *BridgeLedger) apply(statement *BridgeLogStatement) {
	entry := &BridgeLedgerEntry{Statement: statement, Disposition: BridgeDispositionActive}
	self.entries = append(self.entries, entry)
	var err error
	switch statement.SignedType {
	case bridge.SignedType_SIGNED_BRIDGE_ADDRESS:
		err = self.applyAddress(entry)
	case bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_MAP:
		err = self.applyRule(entry)
	case bridge.SignedType_SIGNED_BRIDGE_EGRESS:
		err = self.applyEgress(entry)
	case bridge.SignedType_SIGNED_BRIDGE_ALIAS:
		err = self.applyAlias(entry)
	case bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
		err = self.applyWithdraw(entry)
	default:
		err = fmt.Errorf("%s is no bridge statement of the log", statement.SignedType)
	}
	if err != nil && entry.Disposition != BridgeDispositionPending {
		entry.Disposition = BridgeDispositionVoid
		entry.Reason = fmt.Errorf("%w: %w", ErrBridgeVoid, err)
	}
}

// The release of a sidecar's addresses at or below the ledger's cutoff, nil while it holds them: its revocation's entry
// and time where its row carries one. A sidecar the rows no longer hold, or whose member is gone, was released at no
// position this ledger knows: at an open its address is a tombstone that never ends, which every earlier statement
// finds live, and a fold releases nothing for it, so a fold writes one row whatever position it folds through. A fold
// that cannot read a revocation's time folds nothing (foldError), since a guessed time would fork the readers that
// know it. Asked once a sidecar: a ledger reads one state.
func (self *BridgeLedger) release(sidecarId Id) *bridgeRelease {
	release, asked := self.releases[sidecarId]
	if asked {
		return release
	}
	release = func() *bridgeRelease {
		state := self.reader.State
		if state == nil {
			return nil
		}
		row := state.sidecars[sidecarId]
		if row != nil && row.GetRevokedAt() == 0 {
			if memberId, untagged := configRowMember(row); !untagged || state.members[memberId] != nil {
				return nil
			}
		}
		if row == nil || row.GetRevokedAt() == 0 {
			if self.folding {
				return nil
			}
			return &bridgeRelease{n: state.n}
		}
		if self.cutoffN < row.GetRevokedAt() {
			// released after the fold: live in its rows
			return nil
		}
		release := &bridgeRelease{n: row.GetRevokedAt()}
		if self.reader.EntryTimeMs != nil {
			release.timeMs, release.timeMsKnown = self.reader.EntryTimeMs(release.n)
		}
		if !release.timeMsKnown {
			release.timeMs, release.timeMsKnown = state.aclTimeAt(release.n)
		}
		if !release.timeMsKnown && self.folding && self.foldError == nil {
			self.foldError = fmt.Errorf("the time of entry %d, which released %s, is not held", release.n, sidecarId)
		}
		return release
	}()
	self.releases[sidecarId] = release
	return release
}

// An address's release: a folded tombstone's own, else its sidecar's.
func (self *BridgeLedger) addressRelease(address *BridgeLedgerAddress) *bridgeRelease {
	if address.folded != nil {
		return address.folded
	}
	return self.release(address.SidecarId)
}

// errBridgePending marks a body whose generation the reader lacks, or an approval no judge ran on.
var errBridgePending = errors.New("bridge body pending")

// The writer's half of DESIGN-DETAILS 12.2.3's void (QD-761), for an entry that would wait for generation: at a fold
// whose writer's whole read of gkm named every formed generation, FormedThrough, a generation above it is unformed once
// the entry is UnformedVoidWait before the entry at the fold asked, and the entry is frozen void,
// errBridgeGenerationUnformed. Nil otherwise: at every open, a read that did not count, a generation gkm names (a key
// that exists and has not reached this writer is never a void), or a wait not yet passed, which all leave it waiting.
func (self *BridgeLedger) unformedVoid(entry *BridgeLedgerEntry, generation uint64) error {
	if self.formedThrough == 0 || generation <= self.formedThrough {
		return nil
	}
	statement := entry.Statement
	// a difference taken only where it is not negative, as unsigned, so no time can wrap it
	waitMs := self.settings.UnformedVoidWait.Milliseconds()
	if self.askedTimeMs < statement.TimeMs || uint64(self.askedTimeMs-statement.TimeMs) < uint64(waitMs) {
		return nil
	}
	entry.Generation = generation
	self.unformed = append(self.unformed, entry)
	return fmt.Errorf("%w: generation %d is above every generation gkm names, %d, %d ms after its entry", errBridgeGenerationUnformed, generation, self.formedThrough, self.askedTimeMs-statement.TimeMs)
}

// Opens an entry's sealed body into body. A body whose generation the reader holds but was signed past
// GenerationFormGrace after the entry is void before its seal is opened, with no alarm; a generation the reader lacks
// marks the entry pending and answers errBridgePending, but at a fold that finds it unformed (unformedVoid); a seal that
// does not open answers ErrConfigSealInvalid, the alarm.
func (self *BridgeLedger) openBody(entry *BridgeLedgerEntry, body proto.Message) error {
	repoKeyAt := self.reader.RepoKeyAt
	if repoKeyAt == nil {
		repoKeyAt = func(generation uint64) *EvsRepoKey { return nil }
	}
	if err := bridgeGenerationLate(entry.Statement, repoKeyAt, self.settings.GenerationFormGrace); err != nil {
		return err
	}
	generation, err := OpenConfigBody(entry.Statement.SealedBody, entry.Statement.Seal, repoKeyAt, body)
	if errors.Is(err, ErrConfigSealGenerationMissing) {
		if err := self.unformedVoid(entry, generation); err != nil {
			return err
		}
		entry.Disposition, entry.Generation = BridgeDispositionPending, generation
		return errBridgePending
	}
	if err != nil {
		return err
	}
	if len(body.ProtoReflect().GetUnknown()) != 0 {
		// a newer signer's field may narrow what the rule opens, so a body this build cannot read whole opens nothing
		return errors.New("the body carries a field this build cannot name")
	}
	self.openedByteCount += proto.Size(body)
	return nil
}

// Whether host bits name a host: outside the services /24, never x.y.z.0 or x.y.z.255 (§17.4).
func bridgeHostBitsValid(hostBits uint32) bool {
	lastOctet := hostBits & 0xff
	return hostBits <= 0xffff && 0xff < hostBits && lastOctet != 0 && lastOctet != 255
}

// Takes an address into the maps, live or a tombstone.
func (self *BridgeLedger) holdAddress(address *BridgeLedgerAddress) {
	self.byHostBits[address.HostBits] = address
	if address.folded == nil {
		self.bySidecar[address.SidecarId] = address
	}
	if address.HostBits < bridgeUpperHostBits {
		self.lowerCount += 1
		if address.folded != nil || self.release(address.SidecarId) != nil {
			self.releasing = append(self.releasing, address)
		}
	}
}

// A BridgeAddress at body level.
func (self *BridgeLedger) applyAddress(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	body := &bridge.BridgeAddressBody{}
	if err := self.openBody(entry, body); err != nil {
		return err
	}
	hostBits := body.GetIpv4() & 0xffff
	if release := self.release(statement.Subject); release != nil && release.n < statement.N {
		return errors.New("an address for a released sidecar")
	}
	if self.bySidecar[statement.Subject] != nil {
		return errors.New("a second address for an addressed host")
	}
	if !bridgeHostBitsValid(hostBits) {
		return errors.New("no host address: in the block's services, or ending in 0 or 255")
	}
	if !self.hostBitsFree(hostBits, statement) {
		return errors.New("the address is held or a tombstone: the first claim in log order wins")
	}
	if bridgeUpperHostBits <= hostBits {
		if self.lowerCount == bridgeLowerHostCount {
			self.sweepLower(statement)
		}
		if self.lowerCount < bridgeLowerHostCount {
			return errors.New("an upper /17 address while the lower /17 has room")
		}
		if self.upperRangeHolding(hostBits, hostBits) != nil {
			return errors.New("an address inside an alias or an exposed prefix")
		}
	}
	self.holdAddress(&BridgeLedgerAddress{SidecarId: statement.Subject, HostBits: hostBits, ClaimedAt: statement.N, Statement: statement})
	return nil
}

// Whether a claim by statement finds hostBits free: nobody holds them, or their holder was released before the claim
// and its tombstone has run out at the claim's time, which frees them.
func (self *BridgeLedger) hostBitsFree(hostBits uint32, statement *BridgeLogStatement) bool {
	holder := self.byHostBits[hostBits]
	return holder == nil || self.freeAt(holder, statement)
}

// Whether an address is a tombstone that ran out by statement's position and time, which then leaves the ledger: what
// the fold whose time passes it drops, so a statement reads it alike whether a fold came between or not.
func (self *BridgeLedger) freeAt(address *BridgeLedgerAddress, statement *BridgeLogStatement) bool {
	release := self.addressRelease(address)
	if release == nil || statement.N <= release.n || !release.timeMsKnown || statement.TimeMs < release.timeMs+self.settings.AddressTombstoneTimeout.Milliseconds() {
		return false
	}
	self.dropAddress(address)
	return true
}

// Forgets an address whose tombstone ran out.
func (self *BridgeLedger) dropAddress(address *BridgeLedgerAddress) {
	delete(self.byHostBits, address.HostBits)
	if self.bySidecar[address.SidecarId] == address {
		delete(self.bySidecar, address.SidecarId)
	}
	if address.HostBits < bridgeUpperHostBits {
		self.lowerCount -= 1
	}
}

// Frees every lower /17 address whose tombstone ran out by a claim's position and time, so "the lower /17 is full" is
// read exactly. Runs only when the count says full.
func (self *BridgeLedger) sweepLower(statement *BridgeLogStatement) {
	self.releasing = slices.DeleteFunc(self.releasing, func(address *BridgeLedgerAddress) bool {
		if self.byHostBits[address.HostBits] != address {
			// a later claim already freed it
			return true
		}
		return self.freeAt(address, statement)
	})
}

// The upper range overlapping [first, last], nil for none.
func (self *BridgeLedger) upperRangeHolding(first uint32, last uint32) *bridgeUpperRange {
	for i := range self.upper {
		if self.upper[i].first <= last && first <= self.upper[i].last {
			return &self.upper[i]
		}
	}
	return nil
}

// The host bits an alias or an exposed prefix spans: a prefix of the upper /17, /17 or longer (D-BRIDGE-20), read by
// its low 16 bits as an address is.
func bridgeUpperRangeOf(wirePrefix *bridge.BridgeIpv4Prefix) (uint32, uint32, error) {
	prefix, err := bridgePrefixOf(wirePrefix)
	if err != nil {
		return 0, 0, err
	}
	if prefix.length < 17 {
		return 0, 0, fmt.Errorf("a /%d is wider than the upper /17", prefix.length)
	}
	first := prefix.address & 0xffff
	if first < bridgeUpperHostBits {
		return 0, 0, errors.New("outside the block's upper /17")
	}
	return first, first | (^bridgePrefixMask(prefix.length) & 0xffff), nil
}

// Whether any address, live or a tombstone still holding at statement's position and time, sits in [first, last]: a
// tombstone that ran out by then leaves the ledger.
func (self *BridgeLedger) hostInAt(first uint32, last uint32, statement *BridgeLogStatement) bool {
	held := []*BridgeLedgerAddress{}
	if int(last-first) < len(self.byHostBits) {
		for hostBits := first; hostBits <= last; hostBits += 1 {
			if address := self.byHostBits[hostBits]; address != nil {
				held = append(held, address)
			}
		}
	} else {
		for _, hostBits := range slices.Sorted(maps.Keys(self.byHostBits)) {
			if first <= hostBits && hostBits <= last {
				held = append(held, self.byHostBits[hostBits])
			}
		}
	}
	for _, address := range held {
		if !self.freeAt(address, statement) {
			return true
		}
	}
	return false
}

// Whether any address, live or a tombstone, sits in [first, last].
func (self *BridgeLedger) hostIn(first uint32, last uint32) bool {
	if int(last-first) < len(self.byHostBits) {
		for hostBits := first; hostBits <= last; hostBits += 1 {
			if self.byHostBits[hostBits] != nil {
				return true
			}
		}
		return false
	}
	for hostBits := range self.byHostBits {
		if first <= hostBits && hostBits <= last {
			return true
		}
	}
	return false
}

// A BridgeWithdraw at body level: it binds the rule it names when its signer is that rule's or an admin, and reserves
// an id no filing holds yet: its signer's filings, or anyone's for an admin's or for a second signer's, since one row
// holds one reservation and the closed reading binds them all.
func (self *BridgeLedger) applyWithdraw(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	key := string(statement.RuleId)
	rule := self.heldRule(key, statement.TimeMs)
	if rule == nil {
		reserved := self.reserved[key]
		switch {
		case reserved == nil:
			self.reserved[key] = bridgeLedgerWithdrawalOf(statement)
		case !reserved.SignerAdmin && (statement.SignerAdmin || statement.Signer != reserved.Signer):
			widened := *reserved
			widened.SignerAdmin = true
			self.reserved[key] = &widened
		}
		return nil
	}
	withdrawal := bridgeLedgerWithdrawalOf(statement)
	if !withdrawal.binds(rule.Owner) {
		return errors.New("a BridgeWithdraw by neither the rule's signer nor an admin")
	}
	if rule.Withdrawn == nil {
		rule.Withdrawn = withdrawal
		self.dropUpperRange(rule)
	}
	return nil
}

// Frees the exposed prefix a withdrawn rule held, unless an HA replica of it is still in force, which then holds it.
func (self *BridgeLedger) dropUpperRange(rule *BridgeLedgerRule) {
	for i := range self.upper {
		if self.upper[i].rule != rule {
			continue
		}
		replicaIds := []string{}
		for ruleId, other := range self.rules {
			if other != rule && other.Active() && other.Route != nil && rule.Route != nil &&
				proto.Equal(other.Route.GetExposedPrefix(), rule.Route.GetExposedPrefix()) {
				replicaIds = append(replicaIds, ruleId)
			}
		}
		if len(replicaIds) == 0 {
			self.upper = slices.Delete(self.upper, i, i+1)
		} else {
			// the lowest id, so every reader names one holder
			self.upper[i].rule = self.rules[slices.Min(replicaIds)]
		}
		return
	}
}

// The rule held under key at a statement's time, nil for none. A withdrawn rule whose retention passed by then has left
// the rows, with its count against its decision, as the fold whose time passes it drops the row: so a statement reads
// the id alike whether a fold came between or not, and the id is free again.
func (self *BridgeLedger) heldRule(key string, timeMs int64) *BridgeLedgerRule {
	rule := self.rules[key]
	if rule == nil || rule.Withdrawn == nil || timeMs <= rule.retainUntilMs() {
		return rule
	}
	delete(self.rules, key)
	if use := self.approvals[rule.ApprovalId]; use != nil && !rule.Standing {
		delete(use.ruleIds, key)
	}
	return nil
}

// A rule's body with its approval cleared, as the rows keep it.
func bridgeBodyWithoutApproval[T *bridge.BridgeRouteBody | *bridge.BridgeMapBody](body T) T {
	switch typed := any(body).(type) {
	case *bridge.BridgeRouteBody:
		cleared := proto.Clone(typed).(*bridge.BridgeRouteBody)
		cleared.Approval = nil
		return any(cleared).(T)
	case *bridge.BridgeMapBody:
		cleared := proto.Clone(typed).(*bridge.BridgeMapBody)
		cleared.Approval = nil
		return any(cleared).(T)
	}
	return body
}

// A BridgeRoute or BridgeMap at body level.
func (self *BridgeLedger) applyRule(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	key := string(statement.RuleId)
	if reserved := self.reserved[key]; reserved != nil && reserved.binds(statement.Signer) {
		return fmt.Errorf("a BridgeWithdraw at %d named this rule id", reserved.At)
	}
	if rule := self.heldRule(key, statement.TimeMs); rule != nil {
		return self.applyHeldRule(entry, rule)
	}

	rule := &BridgeLedgerRule{
		RuleId: statement.RuleId, SignedType: statement.SignedType, Owner: statement.Signer,
		FirstAt: statement.N, FirstMs: statement.TimeMs, NewestAt: statement.N, NewestMs: statement.TimeMs,
		First: statement, Newest: statement, RouteRuleIds: statement.RouteRuleIds, Expires: statement.Expires,
	}
	// the id is held from here whatever the body turns out to be
	self.rules[key] = rule
	var approval *bridge.BridgeApproval
	var exposed *bridgeUpperRange
	var routeBody *bridge.BridgeRouteBody
	var mapBody *bridge.BridgeMapBody
	if statement.SignedType == bridge.SignedType_SIGNED_BRIDGE_ROUTE {
		routeBody = &bridge.BridgeRouteBody{}
		if err := self.openBody(entry, routeBody); err != nil {
			rule.Pending, rule.Void = entry.Disposition == BridgeDispositionPending, entry.Disposition != BridgeDispositionPending
			return err
		}
		var err error
		if exposed, err = self.checkRoute(rule, routeBody); err != nil {
			rule.Void = true
			return err
		}
		approval = routeBody.GetApproval()
	} else {
		mapBody = &bridge.BridgeMapBody{}
		if err := self.openBody(entry, mapBody); err != nil {
			rule.Pending, rule.Void = entry.Disposition == BridgeDispositionPending, entry.Disposition != BridgeDispositionPending
			return err
		}
		if err := bridgeCheckMapBody(mapBody, self.settings); err != nil {
			rule.Void = true
			return err
		}
		approval = mapBody.GetApproval()
	}
	if approval == nil {
		rule.Standing = true
	} else if err := self.spendApproval(entry, rule); err != nil {
		if entry.Disposition == BridgeDispositionPending {
			rule.Pending = true
		} else {
			rule.Void = true
		}
		return err
	}
	if routeBody != nil {
		rule.Route = bridgeBodyWithoutApproval(routeBody)
		if exposed != nil {
			exposed.rule = rule
			self.upper = append(self.upper, *exposed)
		}
	} else {
		rule.Map = bridgeBodyWithoutApproval(mapBody)
	}
	return nil
}

// A filing of a held id: the same kind by the same signer, changing only weight, site_id and drain_seconds, and
// activating nothing. Bodies compare with their approvals cleared, so a filing reads alike before a fold and after it.
func (self *BridgeLedger) applyHeldRule(entry *BridgeLedgerEntry, rule *BridgeLedgerRule) error {
	statement := entry.Statement
	switch {
	case rule.Withdrawn != nil:
		return fmt.Errorf("a BridgeWithdraw at %d named this rule id", rule.Withdrawn.At)
	case rule.SignedType != statement.SignedType || rule.Owner != statement.Signer:
		return errors.New("the rule id is held by another kind or signer")
	case rule.Void:
		return errors.New("the rule id is held by a void filing")
	case rule.Pending:
		// what the first filing sealed is unknown here, so what this one changes is too
		entry.Disposition, entry.Generation = BridgeDispositionPending, 0
		if rule.First != nil {
			if generation, err := ConfigSealedGeneration(rule.First.SealedBody); err == nil {
				entry.Generation = generation
			}
		}
		return errBridgePending
	case rule.Expires != statement.Expires || !slices.EqualFunc(rule.RouteRuleIds, statement.RouteRuleIds, bytes.Equal):
		return errors.New("a filing of a held id changes more than weight, site_id and drain_seconds")
	}
	if rule.Route != nil {
		body := &bridge.BridgeRouteBody{}
		if err := self.openBody(entry, body); err != nil {
			return err
		}
		if err := bridgeCheckRouteBody(body, self.settings); err != nil {
			return err
		}
		body = bridgeBodyWithoutApproval(body)
		kept := proto.Clone(rule.Route).(*bridge.BridgeRouteBody)
		kept.Weight, kept.SiteId, kept.DrainSeconds = body.GetWeight(), body.GetSiteId(), body.GetDrainSeconds()
		if !proto.Equal(kept, body) {
			return errors.New("a filing of a held id changes more than weight, site_id and drain_seconds")
		}
		if !bytes.Equal(rule.Route.GetSiteId(), body.GetSiteId()) {
			if err := self.checkOverlap(rule, body); err != nil {
				return err
			}
		}
		rule.Route = body
	} else {
		body := &bridge.BridgeMapBody{}
		if err := self.openBody(entry, body); err != nil {
			return err
		}
		if err := bridgeCheckMapBody(body, self.settings); err != nil {
			return err
		}
		body = bridgeBodyWithoutApproval(body)
		kept := proto.Clone(rule.Map).(*bridge.BridgeMapBody)
		kept.DrainSeconds = body.GetDrainSeconds()
		if !proto.Equal(kept, body) {
			return errors.New("a filing of a held id changes more than drain_seconds")
		}
		rule.Map = body
	}
	rule.Newest, rule.NewestAt, rule.NewestMs = statement, statement.N, statement.TimeMs
	entry.Disposition = BridgeDispositionHeld
	return nil
}

// A BridgeRouteBody's own shape: a subnet route's prefixes, each at least a /1 with no bits past its length, or an
// exit with none; an exposed_prefix only on a subnet route of one prefix, of that prefix's length, so host bits map
// one to one; a site_id, weight and drain_seconds in range, by settings' limits (nil, the defaults).
func bridgeCheckRouteBody(body *bridge.BridgeRouteBody, settings *BridgeLedgerSettings) error {
	settings = bridgeLedgerSettingsOrDefault(settings)
	switch body.GetKind() {
	case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET:
		if len(body.GetPrefixes()) == 0 || settings.BodyListMaxCount < len(body.GetPrefixes()) {
			return fmt.Errorf("a subnet route of %d prefixes", len(body.GetPrefixes()))
		}
	case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT:
		if len(body.GetPrefixes()) != 0 || body.GetExposedPrefix() != nil {
			return errors.New("an exit route with prefixes")
		}
	default:
		return fmt.Errorf("route kind %d", body.GetKind())
	}
	seen := []bridgePrefix{}
	for _, wirePrefix := range body.GetPrefixes() {
		prefix, err := bridgePrefixOf(wirePrefix)
		if err != nil {
			return err
		}
		if prefix.length == 0 {
			return errors.New("a subnet route of 0.0.0.0/0, which is an exit's")
		}
		if slices.Contains(seen, prefix) {
			return errors.New("a prefix named twice")
		}
		seen = append(seen, prefix)
	}
	if body.GetExposedPrefix() != nil {
		if len(seen) != 1 || body.GetExposedPrefix().GetLength() != seen[0].length {
			return errors.New("an exposed_prefix maps one prefix of its own length")
		}
		if _, _, err := bridgeUpperRangeOf(body.GetExposedPrefix()); err != nil {
			return fmt.Errorf("exposed_prefix: %w", err)
		}
	}
	switch {
	case settings.SiteIdMaxByteCount < len(body.GetSiteId()):
		return fmt.Errorf("a site_id of %d bytes", len(body.GetSiteId()))
	case math.MaxUint16 < body.GetWeight():
		return fmt.Errorf("a weight of %d", body.GetWeight())
	case uint64(settings.DrainMaximum/time.Second) < uint64(body.GetDrainSeconds()):
		return fmt.Errorf("drain_seconds of %d", body.GetDrainSeconds())
	}
	return nil
}

// A new route's body against the ledger: its shape, D-BRIDGE-8 against every other route in force, and room for its
// exposed prefix, which it answers for the caller to hold once the rule's approval passes.
func (self *BridgeLedger) checkRoute(rule *BridgeLedgerRule, body *bridge.BridgeRouteBody) (*bridgeUpperRange, error) {
	if err := bridgeCheckRouteBody(body, self.settings); err != nil {
		return nil, err
	}
	if err := self.checkOverlap(rule, body); err != nil {
		return nil, err
	}
	if body.GetExposedPrefix() == nil {
		return nil, nil
	}
	first, last, _ := bridgeUpperRangeOf(body.GetExposedPrefix())
	if held := self.upperRangeHolding(first, last); held != nil {
		// an HA replica shares its site's exposed prefix, which checkOverlap held to one prefix and one site
		replica := held.rule != nil && held.rule.Route != nil && held.first == first && held.last == last &&
			proto.Equal(held.rule.Route.GetPrefixes()[0], body.GetPrefixes()[0])
		if !replica {
			return nil, errors.New("the exposed prefix overlaps an alias or another exposed prefix")
		}
		return nil, nil
	}
	if self.hostInAt(first, last, rule.Newest) {
		return nil, errors.New("a host sits inside the exposed prefix")
	}
	return &bridgeUpperRange{first: first, last: last}, nil
}

// D-BRIDGE-8 for one route's body against every other route in force: a prefix identical to another's is an HA
// replica, both naming one non-empty site_id, or a remap, either carrying an exposed_prefix; an exposed prefix
// identical to another's is a replica of the same prefix at the same site. Nesting passes.
func (self *BridgeLedger) checkOverlap(rule *BridgeLedgerRule, body *bridge.BridgeRouteBody) error {
	for _, other := range self.rules {
		if other == rule || other.Route == nil || !other.Active() {
			continue
		}
		sameSite := len(body.GetSiteId()) != 0 && bytes.Equal(body.GetSiteId(), other.Route.GetSiteId())
		for _, prefix := range body.GetPrefixes() {
			for _, otherPrefix := range other.Route.GetPrefixes() {
				if !proto.Equal(prefix, otherPrefix) {
					continue
				}
				remap := body.GetExposedPrefix() != nil || other.Route.GetExposedPrefix() != nil
				if !sameSite && !remap {
					return errors.New("an identical prefix that is neither an HA replica nor a remap")
				}
			}
		}
		if body.GetExposedPrefix() != nil && proto.Equal(body.GetExposedPrefix(), other.Route.GetExposedPrefix()) {
			if !sameSite || !proto.Equal(body.GetPrefixes()[0], other.Route.GetPrefixes()[0]) {
				return errors.New("an exposed prefix another site's route holds")
			}
		}
	}
	return nil
}

// A BridgeMapBody's own shape: a match_prefix of /16 or longer; TCP, UDP or ICMP; ports ascending and disjoint, none
// on ICMP; a target address of 4 or 16 bytes; a target_port only where at most one range maps onto it; drain_seconds
// in range, by settings' limits (nil, the defaults).
func bridgeCheckMapBody(body *bridge.BridgeMapBody, settings *BridgeLedgerSettings) error {
	settings = bridgeLedgerSettingsOrDefault(settings)
	matchPrefix, err := bridgePrefixOf(body.GetMatchPrefix())
	if err != nil {
		return fmt.Errorf("match_prefix: %w", err)
	}
	if matchPrefix.length < bridgeBlockPrefixLength {
		return fmt.Errorf("a match_prefix of /%d is wider than a block", matchPrefix.length)
	}
	switch body.GetProtocol() {
	case 6, 17:
	case 1:
		if len(body.GetPorts()) != 0 || body.GetTargetPort() != 0 {
			return errors.New("an ICMP map with ports")
		}
	default:
		return fmt.Errorf("protocol %d", body.GetProtocol())
	}
	if settings.BodyListMaxCount < len(body.GetPorts()) {
		return fmt.Errorf("%d port ranges", len(body.GetPorts()))
	}
	previousLast := uint32(0)
	for _, ports := range body.GetPorts() {
		if ports.GetFirst() == 0 || ports.GetLast() < ports.GetFirst() || math.MaxUint16 < ports.GetLast() || ports.GetFirst() <= previousLast {
			return errors.New("port ranges out of range or order")
		}
		previousLast = ports.GetLast()
	}
	switch {
	case len(body.GetTarget()) != 4 && len(body.GetTarget()) != 16:
		return fmt.Errorf("a target of %d bytes", len(body.GetTarget()))
	case math.MaxUint16 < body.GetTargetPort():
		return fmt.Errorf("a target_port of %d", body.GetTargetPort())
	case body.GetTargetPort() != 0 && 1 < len(body.GetPorts()):
		return errors.New("a target_port with more than one port range")
	case uint64(settings.DrainMaximum/time.Second) < uint64(body.GetDrainSeconds()):
		return fmt.Errorf("drain_seconds of %d", body.GetDrainSeconds())
	}
	return nil
}

// A new rule's approval by the verdict its judge reached where its entry landed, counted against its decision: the
// rule id the one the approval fixes, and the decision's ids at most its uses, over the rows and the entries alike. No
// verdict, or an Unopened one, leaves the rule pending, but at a fold that finds its generation unformed
// (unformedVoid); a Refused one voids it.
func (self *BridgeLedger) spendApproval(entry *BridgeLedgerEntry, rule *BridgeLedgerRule) error {
	verdict := entry.Statement.Approval
	if verdict == nil || verdict.Kind == BridgeBodyUnopened {
		generation := uint64(0)
		if sealed, err := ConfigSealedGeneration(entry.Statement.SealedBody); err == nil {
			generation = sealed
		}
		if verdict != nil {
			generation = verdict.Generation
		}
		if err := self.unformedVoid(entry, generation); err != nil {
			return err
		}
		entry.Disposition, entry.Generation = BridgeDispositionPending, generation
		return errBridgePending
	}
	switch verdict.Kind {
	case BridgeBodyRefused:
		if verdict.Reason == nil {
			return errors.New("the approval was refused where its entry landed")
		}
		return verdict.Reason
	case BridgeBodyApproved:
	default:
		return errors.New("an approval its judge did not verify")
	}
	facts := verdict.Facts
	if facts == nil || !bytes.Equal(facts.RuleId, rule.RuleId) {
		return errors.New("a rule id its approval does not fix")
	}
	if err := self.countApproval(facts.ApprovalId, facts.Uses, rule.RuleId); err != nil {
		return err
	}
	rule.ApprovalId, rule.ApprovalNotAfterMs, rule.ApprovalUses = facts.ApprovalId, facts.NotAfterMs, max(1, facts.Uses)
	return nil
}

// Counts a rule under a decision of uses, refusing one past the budget; a rule already counted adds nothing.
func (self *BridgeLedger) countApproval(approvalId Id, uses uint32, ruleId []byte) error {
	use := self.approvals[approvalId]
	if use == nil {
		use = &bridgeApprovalUse{uses: max(1, uses), ruleIds: map[string]bool{}}
		self.approvals[approvalId] = use
	}
	use.uses = min(use.uses, max(1, uses))
	if !use.ruleIds[string(ruleId)] {
		if int(use.uses) <= len(use.ruleIds) {
			return fmt.Errorf("a decision's rule past its %d uses", use.uses)
		}
		use.ruleIds[string(ruleId)] = true
	}
	return nil
}

// A BridgeEgress at body level: none and auto carry no body; exits lists its exit sidecars or names their tag. auto
// is every subject's default, so it leaves no spec.
func (self *BridgeLedger) applyEgress(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	if statement.EgressMode == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO {
		delete(self.egress, statement.Subject)
		return nil
	}
	egress := &BridgeLedgerEgress{Subject: statement.Subject, Mode: statement.EgressMode, At: statement.N, Statement: statement}
	// the mode binds at id level whatever the body turns out to be: exits with no exit read is no exit at all
	self.egress[statement.Subject] = egress
	if statement.EgressMode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS {
		return nil
	}
	body := &bridge.BridgeEgressBody{}
	if err := self.openBody(entry, body); err != nil {
		return err
	}
	if (len(body.GetExitSidecarIds()) == 0) == (len(body.GetExitTagId()) == 0) {
		return errors.New("exits names its exit sidecars or one tag, and not both")
	}
	if self.settings.BodyListMaxCount < len(body.GetExitSidecarIds()) {
		return fmt.Errorf("%d exits", len(body.GetExitSidecarIds()))
	}
	exits := []Id{}
	for _, exitBytes := range body.GetExitSidecarIds() {
		exitId, err := IdFromBytes(exitBytes)
		if err != nil || slices.Contains(exits, exitId) {
			return errors.New("an exit id malformed or named twice")
		}
		exits = append(exits, exitId)
	}
	if len(body.GetExitTagId()) != 0 && len(body.GetExitTagId()) != len(Id{}) {
		return fmt.Errorf("an exit_tag_id of %d bytes", len(body.GetExitTagId()))
	}
	egress.ExitSidecarIds, egress.ExitTagId = exits, bytes.Clone(body.GetExitTagId())
	return nil
}

// A BridgeAlias at body level: its signer an admin's device where it landed (DESIGN-DETAILS 12.2.3), its ids, one alias
// a share's target, and room in the upper /17 for its prefix. What the share itself allows, its preflight and its
// keys, and an alias's release, are BRIDGE-M6-03's, on what this holds.
func (self *BridgeLedger) applyAlias(entry *BridgeLedgerEntry) error {
	if !entry.Statement.SignerAdmin {
		return errors.New("an alias its signer filed as no admin's device")
	}
	body := &bridge.BridgeAliasBody{}
	if err := self.openBody(entry, body); err != nil {
		return err
	}
	if err := self.holdAlias(body, entry.Statement); err != nil {
		return err
	}
	self.aliases = append(self.aliases, &BridgeLedgerAlias{Body: body, Signer: entry.Statement.Signer, At: entry.Statement.N, Statement: entry.Statement})
	return nil
}

// Checks an alias's body against the ledger at statement's position and time, nil for a row the rows hold, and holds
// its range.
func (self *BridgeLedger) holdAlias(body *bridge.BridgeAliasBody, statement *BridgeLogStatement) error {
	if len(body.GetShareId()) != len(Id{}) || len(body.GetHost()) != len(Id{}) {
		return errors.New("an alias with a malformed share_id or host")
	}
	first, last, err := bridgeUpperRangeOf(body.GetAliasPrefix())
	if err != nil {
		return fmt.Errorf("alias_prefix: %w", err)
	}
	for _, alias := range self.aliases {
		if bytes.Equal(alias.Body.GetShareId(), body.GetShareId()) && alias.Body.GetTargetIndex() == body.GetTargetIndex() {
			return errors.New("a second alias for one target of a share")
		}
	}
	if self.upperRangeHolding(first, last) != nil {
		return errors.New("the alias overlaps another alias or an exposed prefix")
	}
	if (statement == nil && self.hostIn(first, last)) || (statement != nil && self.hostInAt(first, last, statement)) {
		return errors.New("a host sits inside the alias")
	}
	self.upper = append(self.upper, bridgeUpperRange{first: first, last: last})
	return nil
}

// Moves every address whose sidecar the reader's state released to a tombstone, and drops each tombstone, released
// now or folded, that ran out by the ledger's time.
func (self *BridgeLedger) releaseAddresses() {
	addresses := make([]*BridgeLedgerAddress, 0, len(self.byHostBits))
	for _, address := range self.byHostBits {
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, func(a *BridgeLedgerAddress, b *BridgeLedgerAddress) int { return cmp.Compare(a.HostBits, b.HostBits) })
	for _, address := range addresses {
		release := self.addressRelease(address)
		if release == nil {
			continue
		}
		tombstone := &BridgeLedgerTombstone{
			SidecarId: address.SidecarId, HostBits: address.HostBits, ReleasedAt: release.n, ReleasedMs: release.timeMs,
			ReleasedMsKnown: release.timeMsKnown, holdMs: self.settings.AddressTombstoneTimeout.Milliseconds(),
		}
		if self.bySidecar[address.SidecarId] == address {
			delete(self.bySidecar, address.SidecarId)
		}
		if !tombstone.Holds(self.timeMs) {
			self.dropAddress(address)
			continue
		}
		self.tombstones = append(self.tombstones, tombstone)
	}
}

// The log's time the ledger was read at.
func (self *BridgeLedger) TimeMs() int64 {
	return self.timeMs
}

// The position the ledger's rows hold every statement through, 0 for a ledger over no rows.
func (self *BridgeLedger) FoldedThrough() uint64 {
	return self.foldedThrough
}

// Every unfolded statement with what the reader made of it, in log order. The caller must not change them.
func (self *BridgeLedger) Entries() []*BridgeLedgerEntry {
	return self.entries
}

// The entries waiting for a generation or a judge.
func (self *BridgeLedger) Pending() []*BridgeLedgerEntry {
	pending := []*BridgeLedgerEntry{}
	for _, entry := range self.entries {
		if entry.Disposition == BridgeDispositionPending {
			pending = append(pending, entry)
		}
	}
	return pending
}

// The entries whose seal did not open, which the reader raises as an alarm.
func (self *BridgeLedger) Alarms() []*BridgeLedgerEntry {
	alarms := []*BridgeLedgerEntry{}
	for _, entry := range self.entries {
		if entry.Disposition == BridgeDispositionVoid && errors.Is(entry.Reason, ErrConfigSealInvalid) {
			alarms = append(alarms, entry)
		}
	}
	return alarms
}

// The live addresses, in sidecar order.
func (self *BridgeLedger) Addresses() []*BridgeLedgerAddress {
	addresses := make([]*BridgeLedgerAddress, 0, len(self.bySidecar))
	for _, address := range self.bySidecar {
		addresses = append(addresses, address)
	}
	slices.SortFunc(addresses, func(a *BridgeLedgerAddress, b *BridgeLedgerAddress) int { return a.SidecarId.Cmp(b.SidecarId) })
	return addresses
}

// The live address of one sidecar, nil for none.
func (self *BridgeLedger) Address(sidecarId Id) *BridgeLedgerAddress {
	return self.bySidecar[sidecarId]
}

// The released addresses no new holder may take at the ledger's time, in host-bit order.
func (self *BridgeLedger) Tombstones() []*BridgeLedgerTombstone {
	tombstones := slices.Clone(self.tombstones)
	slices.SortFunc(tombstones, func(a *BridgeLedgerTombstone, b *BridgeLedgerTombstone) int {
		return cmp.Compare(a.HostBits, b.HostBits)
	})
	return tombstones
}

// Whether host bits are taken at the ledger's time: a live address or a tombstone.
func (self *BridgeLedger) HostBitsTaken(hostBits uint32) bool {
	return self.byHostBits[hostBits] != nil
}

// How many of the lower /17's hosts are taken at the ledger's time, live or tombstones.
func (self *BridgeLedger) LowerTakenCount() int {
	return self.lowerCount
}

// The ranges of the upper /17 that aliases and exposed prefixes hold, as first and last host bits, in order.
func (self *BridgeLedger) UpperRanges() [][2]uint32 {
	ranges := make([][2]uint32, 0, len(self.upper))
	for _, held := range self.upper {
		ranges = append(ranges, [2]uint32{held.first, held.last})
	}
	slices.SortFunc(ranges, func(a [2]uint32, b [2]uint32) int { return cmp.Compare(a[0], b[0]) })
	return ranges
}

// Every rule the ledger holds of one kind, SIGNED_BRIDGE_ROUTE or SIGNED_BRIDGE_MAP, in rule id order: in force,
// withdrawn, pending and void alike, each saying which. A withdrawn id the rows have dropped by the ledger's time is
// left out.
func (self *BridgeLedger) Rules(signedType bridge.SignedType) []*BridgeLedgerRule {
	rules := []*BridgeLedgerRule{}
	for _, rule := range self.rules {
		if rule.SignedType != signedType || (rule.Withdrawn != nil && rule.retainUntilMs() < self.timeMs) {
			continue
		}
		rules = append(rules, rule)
	}
	slices.SortFunc(rules, func(a *BridgeLedgerRule, b *BridgeLedgerRule) int { return bytes.Compare(a.RuleId, b.RuleId) })
	return rules
}

// The rule held under an id, nil for none.
func (self *BridgeLedger) Rule(ruleId []byte) *BridgeLedgerRule {
	return self.rules[string(ruleId)]
}

// The withdrawal that reserves an id no filing holds, nil for none.
func (self *BridgeLedger) Reserved(ruleId []byte) *BridgeLedgerWithdrawal {
	return self.reserved[string(ruleId)]
}

// Each subject's egress spec, in subject order.
func (self *BridgeLedger) Egress() []*BridgeLedgerEgress {
	egress := make([]*BridgeLedgerEgress, 0, len(self.egress))
	for _, spec := range self.egress {
		egress = append(egress, spec)
	}
	slices.SortFunc(egress, func(a *BridgeLedgerEgress, b *BridgeLedgerEgress) int { return a.Subject.Cmp(b.Subject) })
	return egress
}

// The aliases in force, in the order the rows and the log gave them.
func (self *BridgeLedger) Aliases() []*BridgeLedgerAlias {
	return slices.Clone(self.aliases)
}

// Verifies a rule's BridgeApproval as §8.8 does a GrantActivate's (CheckGrantActivate), on this state, the one the
// statement's entry lands on: S(n-1) where the log judges it, R_b(n-1) where a base re-applies it (the judge,
// bridge_ledger.go), so every reader at one pin reaches one verdict:
//
//	action    this use's stored CanonicalAction parses, is a single bridge_expose and names the statement's signer as
//	          its target; a route's prefixes each lie inside one of its cidrs, and a map's target_port and expires are
//	          the action's where it sets them
//	template  with template_action set, a multi-use decision's template (owner decision 218): it parses as a stored
//	          action too, and the use matches it (ActionMatchesTemplate); every decision then hashes the template and
//	          has uses above 1, and the spend check is the template's
//	match     every decision approves, hashes the action it binds, the template or else the use, names the signer as
//	          its requester, and they share one approval_id and request_sha256
//	quorum    every decision is from a distinct approver, unexpired at the entry's time within §8.6's skew, and
//	          passes §16.6's spend check at this state's pin; a decision that does not voids the rule
//	rule id   SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key) of this approval and this use's action
//
// The budget is the smallest uses and the expiry the earliest not_after, which the ledger's count binds. Without a
// template every filing under one approval names the one use its decisions hash, so it fixes one rule id whatever
// their uses say: the single-use reading.
func (self *ConfigState) CheckBridgeApproval(statement *BridgeLogStatement, body proto.Message, approval *bridge.BridgeApproval) (*BridgeApprovalFacts, error) {
	acl, err := self.Acl()
	if err != nil {
		return nil, err
	}
	action, err := ParseStoredCanonicalAction(approval.GetCanonicalAction())
	if err != nil {
		return nil, err
	}
	if SidecarActionKind(action.Action.GetKind()) != SidecarActionExpose || action.Action.GetScope() {
		return nil, errors.New("the approved action is no single bridge_expose")
	}
	// what the decisions hash: a multi-use decision's template, which the use must fall inside, else the use itself
	bound := action
	if len(approval.GetTemplateAction()) != 0 {
		template, err := ParseStoredCanonicalAction(approval.GetTemplateAction())
		if err != nil {
			return nil, fmt.Errorf("the template: %w", err)
		}
		if !ActionMatchesTemplate(template, action) {
			return nil, errors.New("the use does not match its template")
		}
		bound = template
	}
	if !bytes.Equal(action.Action.GetTargetSidecarId(), statement.Signer.Bytes()) {
		return nil, errors.New("the approved action names another target")
	}
	if err := bridgeApprovalCovers(action.Action, statement, body); err != nil {
		return nil, err
	}
	if len(approval.GetDecisions()) == 0 {
		return nil, errors.New("an approval with no decision")
	}
	payloadSha256 := bound.PayloadSha256()
	spendCheck := self.aclSpendCheck()
	facts := &BridgeApprovalFacts{Uses: math.MaxUint32, NotAfterMs: math.MaxInt64}
	approvers := []Id{}
	var first *protocol.ApprovalDecision
	for _, signed := range approval.GetDecisions() {
		decision, err := ParseSignedApprovalDecision(signed)
		if err != nil {
			return nil, err
		}
		decisionBody := decision.Decision
		approver := Id(decisionBody.GetApproverMemberId())
		switch {
		case protocol.ApprovalVerdict(decisionBody.GetDecision()) != protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE:
			return nil, errors.New("a decision that does not approve")
		case !bytes.Equal(decisionBody.GetPayloadSha256(), payloadSha256[:]):
			return nil, errors.New("a decision for another action")
		case bound != action && decisionBody.GetUses() <= 1:
			return nil, errors.New("a template under a single-use decision")
		case !bytes.Equal(decisionBody.GetRequesterSidecarId(), statement.Signer.Bytes()):
			return nil, errors.New("a decision for another requester")
		case first != nil && (!bytes.Equal(decisionBody.GetApprovalId(), first.GetApprovalId()) || !bytes.Equal(decisionBody.GetRequestSha256(), first.GetRequestSha256())):
			return nil, errors.New("decisions of more than one request")
		case slices.Contains(approvers, approver):
			return nil, errors.New("two decisions of one approver")
		case decisionBody.GetNotAfterMillis()+aclDecisionSkewMs < statement.TimeMs:
			return nil, errors.New("a decision expired before the entry")
		}
		if err := spendCheck.Spendable(acl, decision, bound, statement.Signer, self.Pin(), aclTime(statement.TimeMs)); err != nil {
			return nil, err
		}
		if first == nil {
			first = decisionBody
		}
		approvers = append(approvers, approver)
		facts.Uses = min(facts.Uses, max(1, decisionBody.GetUses()))
		facts.NotAfterMs = min(facts.NotAfterMs, decisionBody.GetNotAfterMillis())
	}
	facts.ApprovalId = Id(first.GetApprovalId())
	ruleId := BridgeRuleId(ApprovalEffectKey(facts.ApprovalId, action.ActionId(facts.ApprovalId)))
	facts.RuleId = ruleId[:]
	return facts, nil
}

// Whether a bridge_expose action covers the rule a statement filed under it: a route's prefixes each inside one of
// the action's cidrs, and none where it lists none but for an exit; a map's target_port the action's where it names
// one, and its expires set and no later than the action's where it has one.
func bridgeApprovalCovers(action *protocol.CanonicalAction, statement *BridgeLogStatement, body proto.Message) error {
	switch typed := body.(type) {
	case *bridge.BridgeRouteBody:
		cidrs := []netip.Prefix{}
		for _, cidr := range action.GetCidrs() {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return fmt.Errorf("the approved action's cidr %q", cidr)
			}
			cidrs = append(cidrs, prefix)
		}
		exit := typed.GetKind() == bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT
		if exit != slices.Contains(cidrs, netip.MustParsePrefix("0.0.0.0/0")) {
			return errors.New("the approved action and the route differ on being an exit")
		}
		for _, wirePrefix := range typed.GetPrefixes() {
			prefix, err := bridgePrefixOf(wirePrefix)
			if err != nil {
				return err
			}
			covered := slices.ContainsFunc(cidrs, func(cidr netip.Prefix) bool {
				cidrAddress := cidr.Addr().As4()
				approved := bridgePrefix{
					address: uint32(cidrAddress[0])<<24 | uint32(cidrAddress[1])<<16 | uint32(cidrAddress[2])<<8 | uint32(cidrAddress[3]),
					length:  uint32(cidr.Bits()),
				}
				return approved.contains(prefix)
			})
			if !covered {
				return fmt.Errorf("the approved action covers no %s", prefix)
			}
		}
	case *bridge.BridgeMapBody:
		if action.GetTargetPort() != 0 && action.GetTargetPort() != typed.GetTargetPort() {
			return errors.New("the approved action names another target_port")
		}
		if action.GetExpiresMillis() != 0 && (statement.Expires == 0 || action.GetExpiresMillis() < statement.Expires) {
			return errors.New("the map outlives the approved action")
		}
	default:
		return errors.New("no rule body")
	}
	return nil
}
