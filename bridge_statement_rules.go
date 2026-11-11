//go:build !ios_extension

// §17.8's statements at body level: what a reader that holds the config's generations makes of the bridge statements
// the log took at id level (bridge_statement.go). BridgeLog.Open opens each sealed body (OpenConfigBody) in log order
// and runs the rules no keyless verifier can:
//
//	pending   the body is sealed to a generation the reader lacks: the entry keeps its id-level effect, its id held
//	          and nothing active, and opens once RK_g arrives (plan-TEAM-sealed-field-format); a bodiless
//	          BridgeWithdraw never waits
//	void      the AEAD or the padding fails, which is the reader's alarm, or the body breaks its rule below: the
//	          id-level effect stands and the sealed effect is nothing
//	address   the first BridgeAddress in log order wins a host's bits; a second for an addressed host is void; a
//	          released address is a tombstone for 30 days by the log's time (I-14); the upper /17 takes a host only
//	          once the lower is full, and never inside an alias or an exposed prefix (§17.4, D-BRIDGE-20)
//	route     D-BRIDGE-8: an identical prefix is an HA replica, the same non-empty site_id, or a remap, one of the two
//	          carrying an exposed_prefix; nesting is allowed; anything else is void
//	held id   a filing of a held id changes only weight, site_id and drain_seconds and activates nothing
//	withdraw  an id a BridgeWithdraw named is void while the fold keeps it: until its decision's not_after, or for a
//	          rule under a standing grant until its last filing's header could no longer be replayed
//	approval  none under a standing grant, which BRIDGE-M4-16's compiler holds to §8's rules; else the I-8 decisions,
//	          verified as §8.8 does a GrantActivate's with the signer every decision's requester, the rule id the one
//	          §17.8 derives from the use's effect_key, and a decision's ids at most its uses, a retry adding none
//
// An address is bound by its host bits, the low 16 of the IPv4 a BridgeAddress carries, since hosts keep their host
// bits across a block change (§17.4): the ledger never reads the upper 16, and ValidateBridgeAddress (BRIDGE-M4-15)
// holds a new claim to the block at filing.
//
// A ledger is a pure function of the log, the keys and what the reader passes, so a reader that gains a generation
// opens the log again from its start. It covers the statements the BridgeLog holds: a ConfigState's holds the unfolded
// tail, and a full reader joins the config head's history ahead of it (JoinBridgeLogs; BRIDGE-M4-16).
//
// CheckBridgeBlock is D-BRIDGE-16's check where a head is read: a BridgeBlock rides a config head, signed by an admin,
// and a reader keeps the previous block and alarms on one outside 100.64.0.0/10 and RFC 1918, since a CLI check binds
// no other signing tool.
//
// testHookSecret runs where a body's key derives, inside OpenConfigBody. A ledger is immutable once built. On every
// leg, with no connect import.

package sidecar

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

const (
	// A released overlay address routes to no new holder for this long, by the log's time (§17.4, I-14).
	BridgeAddressTombstoneMs = int64(30 * 24 * 60 * 60 * 1000)
	// A network's block is one IPv4 /16 (§17.4).
	bridgeBlockPrefixLength = 16
	// The upper /17 of a block, in host bits: aliases and exposed prefixes from its bottom, spilled hosts from its top.
	bridgeUpperHostBits = uint32(0x8000)
	// The hosts a block's lower /17 holds: its 128 /24s less the services /24, each without .0 and .255.
	bridgeLowerHostCount = 127 * 254
	// The hosts a block's upper /17 holds.
	bridgeUpperHostCount = 128 * 254
	// §17.8's bound on a block's addresses, 64,770.
	BridgeAddressMaxCount = bridgeLowerHostCount + bridgeUpperHostCount
	// drain_seconds is 3,600 s at most (§17.8's disposition).
	bridgeDrainSecondsMax = 3600
	// The most prefixes one BridgeRoute advertises, port ranges one BridgeMap names, or exits one BridgeEgress lists.
	bridgeBodyListMaxCount = 64
	// A site_id is at most this long.
	bridgeSiteIdMaxByteCount = 32
)

var (
	// A config head's BridgeBlock is not one a reader takes: the reader keeps the previous block and alarms
	// (D-BRIDGE-16; plan-BRIDGE-small-readings #17's block_refused).
	ErrBridgeBlockRefused = errors.New("bridge block refused")
	// A statement's sealed effect is void: its body does not open or breaks its rule. Its id-level effect stands.
	ErrBridgeVoid = errors.New("bridge statement void")
	// A rule's approval cannot be verified here: the state its entry landed on is no longer retained and the reader
	// passed no other check. The rule is void at this reader.
	ErrBridgeApprovalUnverifiable = fmt.Errorf("%w: approval unverifiable", ErrBridgeVoid)
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
	// Its body is sealed to a generation the reader lacks: its id-level effect holds, and it opens once RK_g arrives.
	BridgeDispositionPending
	// Its body does not open or breaks its rule: its id-level effect holds and nothing else.
	BridgeDispositionVoid
)

// One statement of the log with what a reader made of it.
type BridgeLedgerEntry struct {
	Statement   *BridgeLogStatement
	Disposition BridgeDisposition
	// Why it is void, wrapping ErrBridgeVoid. One that also wraps ErrConfigSealInvalid is the reader's alarm.
	Reason error
	// The generation a pending entry waits for.
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

// Verifies the BridgeApproval a rule's body carries, for the statement that filed it and its opened body, a
// *bridge.BridgeRouteBody or *bridge.BridgeMapBody. An error voids the rule.
type BridgeApprovalCheck func(statement *BridgeLogStatement, body proto.Message, approval *bridge.BridgeApproval) (*BridgeApprovalFacts, error)

// What a reader opens a BridgeLog with.
type BridgeLedgerReader struct {
	// S(n), the state whose log this is: its rows say which sidecars' addresses are released, and by default its
	// history verifies approvals. Nil releases nothing and verifies no approval.
	State *ConfigState
	// The generation keys the reader holds: nil for one it lacks, which leaves that generation's bodies pending. Nil
	// holds none.
	RepoKeyAt func(generation uint64) *EvsRepoKey
	// How approvals verify. Nil is State.CheckBridgeApproval, which answers ErrBridgeApprovalUnverifiable for a rule
	// filed before the history the state retains; a reader that keeps its own verdicts passes them here.
	Approvals BridgeApprovalCheck
	// The time an entry was sequenced at, for a release older than the state's history; false when unknown, which
	// keeps that address a tombstone. Nil asks the state alone. A full reader answers from the config head's records.
	EntryTimeMs func(n uint64) (int64, bool)
	// The log's time the ledger reads tombstones and retention at. 0 is State's.
	TimeMs int64
}

// One live overlay address.
type BridgeLedgerAddress struct {
	SidecarId Id
	// The low 16 bits of its IPv4, which it keeps across block changes.
	HostBits uint32
	// The claim that won it.
	Statement *BridgeLogStatement
}

// One released address no new holder may take yet.
type BridgeLedgerTombstone struct {
	SidecarId Id
	HostBits  uint32
	// When the log released it, and whether the reader knows: an unknown time never ends the tombstone.
	ReleasedMs      int64
	ReleasedMsKnown bool
}

// Whether the tombstone still holds at the log's time timeMs.
func (self *BridgeLedgerTombstone) Holds(timeMs int64) bool {
	return !self.ReleasedMsKnown || timeMs < self.ReleasedMs+BridgeAddressTombstoneMs
}

// One rule the ledger holds: a route or a map, by its id.
type BridgeLedgerRule struct {
	RuleId []byte
	// SIGNED_BRIDGE_ROUTE or SIGNED_BRIDGE_MAP.
	SignedType bridge.SignedType
	// Its advertiser or host.
	Owner Id
	// Its first filing, and its newest.
	First  *BridgeLogStatement
	Newest *BridgeLogStatement
	// The body in force: the first filing's, with the weight, site_id and drain_seconds of the newest filing of the
	// held id. Exactly one is set, and none while the rule is pending or void.
	Route *bridge.BridgeRouteBody
	Map   *bridge.BridgeMapBody
	// A route's route_rule_ids and a map's expires, from the first filing.
	RouteRuleIds [][]byte
	Expires      int64
	// Whether it was filed with no approval: active only where a standing grant covers it, which the compiler holds
	// to §8's rules (§17.7).
	Standing bool
	// Its approval, when it carries one.
	ApprovalId         Id
	ApprovalNotAfterMs int64
	// The withdrawal that binds it, nil for none.
	Withdrawn *BridgeLogStatement
	// Whether its first filing waits for a generation, or is void: either way the id is held and nothing is active.
	Pending bool
	Void    bool
}

// Whether the rule's body is in force: opened, valid and not withdrawn.
func (self *BridgeLedgerRule) Active() bool {
	return !self.Pending && !self.Void && self.Withdrawn == nil
}

// How long the fold keeps a withdrawn id: until its decision's not_after and §8.6's skew, or for a rule under a
// standing grant until its newest filing's header could no longer be replayed. A rule whose approval the reader never
// read is kept for good.
func (self *BridgeLedgerRule) retainUntilMs() int64 {
	switch {
	case self.Pending || self.Void:
		return math.MaxInt64
	case self.Standing:
		return self.Newest.TimeMs + configStatementMaxLifetimeMs
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
	Statement      *BridgeLogStatement
}

// One alias a share's accepting sidecar filed (§17.9).
type BridgeLedgerAlias struct {
	Body      *bridge.BridgeAliasBody
	Statement *BridgeLogStatement
}

// A range of a block's upper /17 that an alias or an exposed prefix holds, in host bits.
type bridgeUpperRange struct {
	first uint32
	last  uint32
	// the rule that holds it, or nil for an alias
	rule *BridgeLedgerRule
}

// What a reader holding keys makes of a BridgeLog. Immutable once built.
type BridgeLedger struct {
	timeMs  int64
	entries []*BridgeLedgerEntry

	rules      map[string]*BridgeLedgerRule
	approvals  map[Id]*bridgeApprovalUse
	egress     map[Id]*BridgeLedgerEgress
	aliases    []*BridgeLedgerAlias
	upper      []bridgeUpperRange
	byHostBits map[uint32]*BridgeLedgerAddress
	bySidecar  map[Id]*BridgeLedgerAddress
	lowerCount int
	// every binding withdrawal seen for a rule id not filed yet
	withdrawals map[string][]*BridgeLogStatement
	tombstones  []*BridgeLedgerTombstone
	// each sidecar's release as the reader answered it once, nil for one that holds its addresses
	releases map[Id]*bridgeRelease
	// the lower /17 addresses whose holder the reader says is released at some entry: the only ones a sweep can free
	releasing []*BridgeLedgerAddress

	reader *BridgeLedgerReader
}

// One decision's budget as the ledger counts it.
type bridgeApprovalUse struct {
	uses    uint32
	ruleIds map[string]bool
}

// When a sidecar's addresses were released, as the reader knows it.
type bridgeRelease struct {
	// the entry that released it; every statement at or after it finds the sidecar gone
	n           uint64
	timeMs      int64
	timeMsKnown bool
}

// The release of a sidecar's addresses, nil while it holds them: its revocation's entry and time where its row carries
// one, else, for a sidecar the rows no longer hold or whose member is gone, the state's own position at a time nobody
// knows, so every earlier statement finds it live and its address stays a tombstone.
func (self *BridgeLedgerReader) release(sidecarId Id) *bridgeRelease {
	state := self.State
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
		return &bridgeRelease{n: state.n}
	}
	release := &bridgeRelease{n: row.GetRevokedAt()}
	if self.EntryTimeMs != nil {
		release.timeMs, release.timeMsKnown = self.EntryTimeMs(release.n)
	}
	if !release.timeMsKnown {
		release.timeMs, release.timeMsKnown = state.aclTimeAt(release.n)
	}
	return release
}

// Opens the log's sealed bodies and runs §17.8's body-level rules over it, as the top of this file says. reader nil
// holds no key and no state, so every sealed statement is pending.
func (self *BridgeLog) Open(reader *BridgeLedgerReader) *BridgeLedger {
	if reader == nil {
		reader = &BridgeLedgerReader{}
	}
	ledger := &BridgeLedger{
		timeMs:      reader.TimeMs,
		rules:       map[string]*BridgeLedgerRule{},
		approvals:   map[Id]*bridgeApprovalUse{},
		egress:      map[Id]*BridgeLedgerEgress{},
		byHostBits:  map[uint32]*BridgeLedgerAddress{},
		bySidecar:   map[Id]*BridgeLedgerAddress{},
		withdrawals: map[string][]*BridgeLogStatement{},
		releases:    map[Id]*bridgeRelease{},
		reader:      reader,
	}
	if ledger.timeMs == 0 && reader.State != nil {
		ledger.timeMs = reader.State.TimeMs()
	}
	for _, statement := range self.Statements() {
		entry := &BridgeLedgerEntry{Statement: statement, Disposition: BridgeDispositionActive}
		ledger.entries = append(ledger.entries, entry)
		var err error
		switch statement.SignedType {
		case bridge.SignedType_SIGNED_BRIDGE_ADDRESS:
			err = ledger.applyAddress(entry)
		case bridge.SignedType_SIGNED_BRIDGE_ROUTE, bridge.SignedType_SIGNED_BRIDGE_MAP:
			err = ledger.applyRule(entry)
		case bridge.SignedType_SIGNED_BRIDGE_EGRESS:
			err = ledger.applyEgress(entry)
		case bridge.SignedType_SIGNED_BRIDGE_ALIAS:
			err = ledger.applyAlias(entry)
		case bridge.SignedType_SIGNED_BRIDGE_WITHDRAW:
			err = ledger.applyWithdraw(entry)
		default:
			err = fmt.Errorf("%s is no bridge statement of the log", statement.SignedType)
		}
		if err != nil && entry.Disposition != BridgeDispositionPending {
			entry.Disposition = BridgeDispositionVoid
			entry.Reason = fmt.Errorf("%w: %w", ErrBridgeVoid, err)
		}
	}
	ledger.releaseAddresses()
	return ledger
}

// The reader's answer for one sidecar's release, asked once: a ledger reads one state, so the answer never changes.
func (self *BridgeLedger) release(sidecarId Id) *bridgeRelease {
	release, asked := self.releases[sidecarId]
	if !asked {
		release = self.reader.release(sidecarId)
		self.releases[sidecarId] = release
	}
	return release
}

// errBridgePending marks a body whose generation the reader lacks.
var errBridgePending = errors.New("bridge body pending")

// Opens an entry's sealed body into body. A generation the reader lacks marks the entry pending and answers
// errBridgePending; a seal that does not open answers ErrConfigSealInvalid, the alarm.
func (self *BridgeLedger) openBody(entry *BridgeLedgerEntry, body proto.Message) error {
	repoKeyAt := self.reader.RepoKeyAt
	if repoKeyAt == nil {
		repoKeyAt = func(generation uint64) *EvsRepoKey { return nil }
	}
	generation, err := OpenConfigBody(entry.Statement.SealedBody, entry.Statement.Seal, repoKeyAt, body)
	if errors.Is(err, ErrConfigSealGenerationMissing) {
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
	return nil
}

// Whether host bits name a host: outside the services /24, never x.y.z.0 or x.y.z.255 (§17.4).
func bridgeHostBitsValid(hostBits uint32) bool {
	lastOctet := hostBits & 0xff
	return hostBits <= 0xffff && 0xff < hostBits && lastOctet != 0 && lastOctet != 255
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
	address := &BridgeLedgerAddress{SidecarId: statement.Subject, HostBits: hostBits, Statement: statement}
	self.byHostBits[hostBits], self.bySidecar[statement.Subject] = address, address
	if hostBits < bridgeUpperHostBits {
		self.lowerCount += 1
		if self.release(statement.Subject) != nil {
			self.releasing = append(self.releasing, address)
		}
	}
	return nil
}

// Whether a claim by statement finds hostBits free: nobody holds them, or their holder was released before the claim
// and its tombstone has run out at the claim's time, which frees them.
func (self *BridgeLedger) hostBitsFree(hostBits uint32, statement *BridgeLogStatement) bool {
	holder := self.byHostBits[hostBits]
	if holder == nil {
		return true
	}
	release := self.release(holder.SidecarId)
	if release == nil || statement.N <= release.n {
		return false
	}
	if !release.timeMsKnown || statement.TimeMs < release.timeMs+BridgeAddressTombstoneMs {
		return false
	}
	self.dropAddress(holder)
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
		release := self.release(address.SidecarId)
		if release.n < statement.N && release.timeMsKnown && release.timeMs+BridgeAddressTombstoneMs <= statement.TimeMs {
			self.dropAddress(address)
			return true
		}
		return false
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

// A BridgeWithdraw at body level: it binds the rule it names when its signer is that rule's or an admin, and a rule
// not filed yet from its first filing on.
func (self *BridgeLedger) applyWithdraw(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	key := string(statement.RuleId)
	rule := self.rules[key]
	if rule == nil {
		self.withdrawals[key] = append(self.withdrawals[key], statement)
		return nil
	}
	if !bridgeWithdrawalBinds(statement, rule.Owner) {
		return errors.New("a BridgeWithdraw by neither the rule's signer nor an admin")
	}
	if rule.Withdrawn == nil {
		rule.Withdrawn = statement
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

// A BridgeRoute or BridgeMap at body level.
func (self *BridgeLedger) applyRule(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	key := string(statement.RuleId)
	for _, withdrawal := range self.withdrawals[key] {
		if bridgeWithdrawalBinds(withdrawal, statement.Signer) {
			return fmt.Errorf("a BridgeWithdraw at %d named this rule id", withdrawal.N)
		}
	}
	if rule := self.rules[key]; rule != nil {
		if rule.Withdrawn != nil && rule.retainUntilMs() < statement.TimeMs {
			// the fold dropped the withdrawn id past its decision's not_after: the id is free again
			delete(self.rules, key)
		} else {
			return self.applyHeldRule(entry, rule)
		}
	}

	rule := &BridgeLedgerRule{
		RuleId: statement.RuleId, SignedType: statement.SignedType, Owner: statement.Signer, First: statement, Newest: statement,
		RouteRuleIds: statement.RouteRuleIds, Expires: statement.Expires,
	}
	// the id is held from here whatever the body turns out to be
	self.rules[key] = rule
	var approval *bridge.BridgeApproval
	var body proto.Message
	var exposed *bridgeUpperRange
	if statement.SignedType == bridge.SignedType_SIGNED_BRIDGE_ROUTE {
		routeBody := &bridge.BridgeRouteBody{}
		if err := self.openBody(entry, routeBody); err != nil {
			rule.Pending, rule.Void = entry.Disposition == BridgeDispositionPending, entry.Disposition != BridgeDispositionPending
			return err
		}
		var err error
		if exposed, err = self.checkRoute(rule, routeBody); err != nil {
			rule.Void = true
			return err
		}
		approval, body = routeBody.GetApproval(), routeBody
	} else {
		mapBody := &bridge.BridgeMapBody{}
		if err := self.openBody(entry, mapBody); err != nil {
			rule.Pending, rule.Void = entry.Disposition == BridgeDispositionPending, entry.Disposition != BridgeDispositionPending
			return err
		}
		if err := bridgeCheckMapBody(mapBody); err != nil {
			rule.Void = true
			return err
		}
		approval, body = mapBody.GetApproval(), mapBody
	}
	if approval == nil {
		rule.Standing = true
	} else if err := self.spendApproval(rule, body, approval); err != nil {
		rule.Void = true
		return err
	}
	if routeBody, ok := body.(*bridge.BridgeRouteBody); ok {
		rule.Route = routeBody
		if exposed != nil {
			exposed.rule = rule
			self.upper = append(self.upper, *exposed)
		}
	} else {
		rule.Map = body.(*bridge.BridgeMapBody)
	}
	return nil
}

// A filing of a held id: the same kind by the same signer, changing only weight, site_id and drain_seconds, and
// activating nothing.
func (self *BridgeLedger) applyHeldRule(entry *BridgeLedgerEntry, rule *BridgeLedgerRule) error {
	statement := entry.Statement
	switch {
	case rule.Withdrawn != nil:
		return fmt.Errorf("a BridgeWithdraw at %d named this rule id", rule.Withdrawn.N)
	case rule.SignedType != statement.SignedType || rule.Owner != statement.Signer:
		return errors.New("the rule id is held by another kind or signer")
	case rule.Void:
		return errors.New("the rule id is held by a void filing")
	case rule.Pending:
		// what the first filing sealed is unknown here, so what this one changes is too
		entry.Disposition, entry.Generation = BridgeDispositionPending, 0
		if generation, err := ConfigSealedGeneration(rule.First.SealedBody); err == nil {
			entry.Generation = generation
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
		if err := bridgeCheckRouteBody(body); err != nil {
			return err
		}
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
		if err := bridgeCheckMapBody(body); err != nil {
			return err
		}
		kept := proto.Clone(rule.Map).(*bridge.BridgeMapBody)
		kept.DrainSeconds = body.GetDrainSeconds()
		if !proto.Equal(kept, body) {
			return errors.New("a filing of a held id changes more than drain_seconds")
		}
		rule.Map = body
	}
	rule.Newest = statement
	entry.Disposition = BridgeDispositionHeld
	return nil
}

// A BridgeRouteBody's own shape: a subnet route's prefixes, each at least a /1 with no bits past its length, or an
// exit with none; an exposed_prefix only on a subnet route of one prefix, of that prefix's length, so host bits map
// one to one; a site_id, weight and drain_seconds in range.
func bridgeCheckRouteBody(body *bridge.BridgeRouteBody) error {
	switch body.GetKind() {
	case bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET:
		if len(body.GetPrefixes()) == 0 || bridgeBodyListMaxCount < len(body.GetPrefixes()) {
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
	case bridgeSiteIdMaxByteCount < len(body.GetSiteId()):
		return fmt.Errorf("a site_id of %d bytes", len(body.GetSiteId()))
	case math.MaxUint16 < body.GetWeight():
		return fmt.Errorf("a weight of %d", body.GetWeight())
	case bridgeDrainSecondsMax < body.GetDrainSeconds():
		return fmt.Errorf("drain_seconds of %d", body.GetDrainSeconds())
	}
	return nil
}

// A new route's body against the ledger: its shape, D-BRIDGE-8 against every other route in force, and room for its
// exposed prefix, which it answers for the caller to hold once the rule's approval passes.
func (self *BridgeLedger) checkRoute(rule *BridgeLedgerRule, body *bridge.BridgeRouteBody) (*bridgeUpperRange, error) {
	if err := bridgeCheckRouteBody(body); err != nil {
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
	if self.hostIn(first, last) {
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
// in range.
func bridgeCheckMapBody(body *bridge.BridgeMapBody) error {
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
	if bridgeBodyListMaxCount < len(body.GetPorts()) {
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
	case bridgeDrainSecondsMax < body.GetDrainSeconds():
		return fmt.Errorf("drain_seconds of %d", body.GetDrainSeconds())
	}
	return nil
}

// Verifies a new rule's approval and counts it against its decision: the rule id the one the approval fixes, and the
// decision's ids at most its uses.
func (self *BridgeLedger) spendApproval(rule *BridgeLedgerRule, body proto.Message, approval *bridge.BridgeApproval) error {
	check := self.reader.Approvals
	if check == nil {
		if self.reader.State == nil {
			return ErrBridgeApprovalUnverifiable
		}
		check = self.reader.State.CheckBridgeApproval
	}
	facts, err := check(rule.First, body, approval)
	if err != nil {
		return err
	}
	if facts == nil || !bytes.Equal(facts.RuleId, rule.RuleId) {
		return errors.New("a rule id its approval does not fix")
	}
	use := self.approvals[facts.ApprovalId]
	if use == nil {
		use = &bridgeApprovalUse{uses: max(1, facts.Uses), ruleIds: map[string]bool{}}
		self.approvals[facts.ApprovalId] = use
	}
	use.uses = min(use.uses, max(1, facts.Uses))
	if !use.ruleIds[string(rule.RuleId)] {
		if int(use.uses) <= len(use.ruleIds) {
			return fmt.Errorf("a decision's rule past its %d uses", use.uses)
		}
		use.ruleIds[string(rule.RuleId)] = true
	}
	rule.ApprovalId, rule.ApprovalNotAfterMs = facts.ApprovalId, facts.NotAfterMs
	return nil
}

// A BridgeEgress at body level: none and auto carry no body; exits lists its exit sidecars or names their tag.
func (self *BridgeLedger) applyEgress(entry *BridgeLedgerEntry) error {
	statement := entry.Statement
	egress := &BridgeLedgerEgress{Subject: statement.Subject, Mode: statement.EgressMode, Statement: statement}
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
	if bridgeBodyListMaxCount < len(body.GetExitSidecarIds()) {
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

// A BridgeAlias at body level: its ids, and room in the upper /17 for its prefix. What the share itself allows, its
// preflight and its keys, is BRIDGE-M6-03's to check on what this holds.
func (self *BridgeLedger) applyAlias(entry *BridgeLedgerEntry) error {
	body := &bridge.BridgeAliasBody{}
	if err := self.openBody(entry, body); err != nil {
		return err
	}
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
	if self.hostIn(first, last) {
		return errors.New("a host sits inside the alias")
	}
	self.upper = append(self.upper, bridgeUpperRange{first: first, last: last})
	self.aliases = append(self.aliases, &BridgeLedgerAlias{Body: body, Statement: entry.Statement})
	return nil
}

// Moves every address whose sidecar the reader's state released to a tombstone, dropping one that ran out by the
// ledger's time.
func (self *BridgeLedger) releaseAddresses() {
	for _, address := range self.Addresses() {
		release := self.release(address.SidecarId)
		if release == nil {
			continue
		}
		tombstone := &BridgeLedgerTombstone{
			SidecarId: address.SidecarId, HostBits: address.HostBits, ReleasedMs: release.timeMs, ReleasedMsKnown: release.timeMsKnown,
		}
		delete(self.bySidecar, address.SidecarId)
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

// Every statement of the log with what the reader made of it, in log order. The caller must not change them.
func (self *BridgeLedger) Entries() []*BridgeLedgerEntry {
	return self.entries
}

// The entries waiting for a generation.
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
// withdrawn, pending and void alike, each saying which. A withdrawn id the fold has dropped by the ledger's time is
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

// Each subject's egress spec, in subject order.
func (self *BridgeLedger) Egress() []*BridgeLedgerEgress {
	egress := make([]*BridgeLedgerEgress, 0, len(self.egress))
	for _, spec := range self.egress {
		egress = append(egress, spec)
	}
	slices.SortFunc(egress, func(a *BridgeLedgerEgress, b *BridgeLedgerEgress) int { return a.Subject.Cmp(b.Subject) })
	return egress
}

// The aliases in force, in log order.
func (self *BridgeLedger) Aliases() []*BridgeLedgerAlias {
	return slices.Clone(self.aliases)
}

// Verifies a rule's BridgeApproval as §8.8 does a GrantActivate's (CheckGrantActivate), on S(n-1), the state the
// statement's entry landed on, which this state's log must still retain:
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
//	          passes §16.6's spend check; a decision that does not voids the rule
//	rule id   SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key) of this approval and this use's action
//
// The budget is the smallest uses and the expiry the earliest not_after, which the ledger's count binds. Without a
// template every filing under one approval names the one use its decisions hash, so it fixes one rule id whatever
// their uses say: the single-use reading.
func (self *ConfigState) CheckBridgeApproval(statement *BridgeLogStatement, body proto.Message, approval *bridge.BridgeApproval) (*BridgeApprovalFacts, error) {
	if statement.N == 0 {
		return nil, ErrBridgeApprovalUnverifiable
	}
	chain, ok := self.chainAt(statement.N - 1)
	if !ok {
		return nil, ErrBridgeApprovalUnverifiable
	}
	before, err := self.StateAt(&bridge.AuthPin{Version: statement.N - 1, Chain: chain[:]})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBridgeApprovalUnverifiable, err)
	}
	acl, err := before.Acl()
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
	spendCheck := before.aclSpendCheck()
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
		if err := spendCheck.Spendable(acl, decision, bound, statement.Signer, before.Pin(), aclTime(statement.TimeMs)); err != nil {
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
