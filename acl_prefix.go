//go:build !ios_extension

// Client-checked prefix write rules (ACL-M6-04's prefix half; DESIGN-DETAILS 16; QD-212, QD-791, QD-792, QD-795,
// QD-801): a general repo's RepoPrefixRules sets, opened from the log, the one verdict every reader reaches on each
// change of a push, and the writer's own refusal before anything is sent. evs is told nothing: no server ever holds a
// rule, a subject, a prefix or a verdict (§8.13, I-1, I-18).
//
//	sets      OpenPrefixRuleSet opens a set's sealed body with config_seal's OpenConfigBody under the repo's own
//	          generation, and one validator, which SealPrefixRuleSet runs before it seals so no design device files
//	          a void set, says what the body is (16.2.2): opened; newer, a later release's, with a field this release
//	          does not know at any level or an action above write; void with its cause (the seal, its padding or its
//	          parse, a rule out of order or twice, a subject not 16 B, a path past 32 components or with a component
//	          §11.6 refuses, more than RuleMaxCount rules, an action of 0, a generation signed past
//	          GenerationFormGrace after its entry); or pending, its generation not held or its entry not fetched
//	cache     AclPrefixSets keeps a repo's sets by position for the rows a state holds (16.2.3): each body from the
//	          entry at its position, else the config head's fold record there, opened once and kept in the evs
//	          component's sealed store under prefix/<repo_id>. A pending set is tried again at each call, and is void
//	          once the log's time is past GenerationFormGrace plus PendingVoidMargin after its entry and a whole read
//	          of gkm made after that names no such generation. An entry that is not a RepoPrefixRules of the repo by
//	          the row's signer is section 5's alarm, and no set of that repo is judged
//	names     aclPrefixNames: whether a rule's subject names a signer by its admission alone, from its SidecarRow, a
//	          tombstone serving (QD-791): its sidecar_id, its member while it carries no tag, a tag it carries, or one
//	          of four autogroups. A group's, a role's and every other autogroup's atom names nobody; nothing here
//	          resolves an atom through the state's atoms
//	verdict   PrefixVerdict (16.2.4) over the push's signed fields, its signer's row, the repo's rows, the reader's
//	          sets and one change, in the token space of the push's path epoch. It reads no state at the push's pin
//	          and never calls StateAt, so a reader started at any base, retaining nothing below its tip, reaches the
//	          verdict of one that watched the push land (16.3's P1)
//	writer    AclEngine.AllowPrefixWrite (acl_engine.go) runs lines 1 to 3 at the installed state, in plaintext,
//	          before anything is planned, sealed or sent (16.2.7; QD-801's sequence and the path of no component)
//	filer     AclPrefixRulesFiler files the next set through CORE's act, the repo's standing admins written in for
//	          every path unless the set is filed as written (QD-792), and answers its position for the pin push
//
// A void set leaves the set below it in force; a pending or newer one makes every verdict at or above it wait or
// update, never allowed (16.2.3). A path's plaintext is its device's own and goes into no log and no error (I-13).
//
// Dark at launch (QD-1032): the rules moved to Later and stay here for their return, behind AclPrefixSettings.Enabled.
// With it off, the launch default, the filer signs nothing (ErrAclPrefixRulesDeferred), no log takes a set
// (acl_statement.go), and no reader asks PrefixVerdict or AllowPrefixWrite (evs_read.go's prefixRuled); the
// functions here are what their tests run with the switch on.
//
// On every leg but ios_extension, whose forwarding role reads no evs repo (owner decision 197). testHookSecret runs
// where config_seal and evs_key derive keys, through EvsRepoKey.DeriveKey; nothing here derives one itself.
// testHookBarrier runs around the sealed store's write of a repo's sets. Package-level functions are safe for
// concurrent use, AclPrefixSets is too, and AclPrefixRulesFiler is used by one goroutine at a time.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Identifiers of 16.2.4's lines 1 and 4, and of the sealed store's layout.
const (
	// The directory every writer of a file-mode ref writes its index under (§11.14), outside the rules.
	aclPrefixIndexDirectory = ".ur-index"
	// Where AclPrefixSets keeps a repo's sets in the evs component's sealed store: prefix/<repo_id>.
	aclPrefixStoreDirectory = "prefix/"
	// The pushes 16.2.4's line 1 leaves outside the rules: FORCE, DELETE, BASE, ERASE, CLOSURE, DROP and CUT, each
	// held to the admin right evs checks at commit.
	aclPrefixOutsideFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) | uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) | uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_CLOSURE) | uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
)

// The refs 16.2.4's line 1 leaves outside the rules: the erasure ref, and the two every writer of a ref writes by
// design (§11.14), guarded by reproduction and index_mismatch rather than by prefix.
var aclPrefixOutsideRefNames = [][]byte{[]byte("erasure"), []byte("ur/index"), []byte("ur/lfs")}

var (
	// EVS_PREFIX_RULE (§18.5): a write this device's prefix rules do not allow, or one it cannot judge because a set
	// it must read is pending or newer. AclPrefixRuleError carries the detail and the path, which neither names.
	ErrAclPrefixRule = errors.New("EVS_PREFIX_RULE: the repo's prefix rules do not allow this write")
	// A set no design device files: one 16.2.2's validator voids or reads as newer, one past SealedMaxByteCount
	// sealed, or a rule whose subject names nobody (16.2.9).
	ErrAclPrefixSetInvalid = errors.New("acl: a prefix rule set no reader would open as filed")
	// The entry at a set's position is not that set: no RepoPrefixRules of the repo by the row's signer. A base whose
	// rows do not compile from its head, section 5's alarm, and no set of the repo is judged (16.2.3).
	ErrAclPrefixRecord = errors.New("acl: the entry at a prefix rule set's position is not a RepoPrefixRules of its repo")
	// A RepoPrefixRules this device does not file: a repo the state does not hold, one that is not general or is
	// deleted, or a filing it has no key to seal under (16.9, small reading 1; QD-795).
	ErrAclPrefixRepo = errors.New("acl: no RepoPrefixRules for this repo")
)

// EVS_PREFIX_RULE's detail (§18.5; DESIGN-DETAILS 16.2.7, 16.2.10, 8.2.8).
type AclPrefixDetail int

const (
	AclPrefixDetailNone AclPrefixDetail = iota
	// a path the set in force does not give this sidecar, or no path at all where the device is held
	AclPrefixDetailRefused
	// a set the device must read is pending: its generation is not held, or its entry not fetched
	AclPrefixDetailPending
	// a set of a later release
	AclPrefixDetailUpdate
	// a reader's: more ignored versions over a path than WalkBackVersionCount (EVS1-M6-04)
	AclPrefixDetailDepth
	// a reader's: the effective version is gone from evs and this device holds none (EVS1-M6-04)
	AclPrefixDetailUnavailable
	// publish's: a new shared branch measured from nothing (QD-801), which the caller adds to a refusal
	AclPrefixDetailBase
	// publish's: a tag with no proof (QD-801), which the caller adds to a refusal
	AclPrefixDetailTag
)

// The detail's name in §18.5.
func (self AclPrefixDetail) String() string {
	switch self {
	case AclPrefixDetailRefused:
		return "refused"
	case AclPrefixDetailPending:
		return "pending"
	case AclPrefixDetailUpdate:
		return "update"
	case AclPrefixDetailDepth:
		return "depth"
	case AclPrefixDetailUnavailable:
		return "unavailable"
	case AclPrefixDetailBase:
		return "base"
	case AclPrefixDetailTag:
		return "tag"
	}
	return "none"
}

// A refusal under the prefix rules: EVS_PREFIX_RULE with its detail and the first path it refused, the caller's own
// plaintext, which Error never repeats (I-13).
type AclPrefixRuleError struct {
	Detail AclPrefixDetail
	// The refused path's raw names joined by /, empty where there is no path to name.
	Path string
}

// EVS_PREFIX_RULE and the detail, never the path.
func (self *AclPrefixRuleError) Error() string {
	return fmt.Sprintf("%s (%s)", ErrAclPrefixRule, self.Detail)
}

// ErrAclPrefixRule, so errors.Is finds the code.
func (self *AclPrefixRuleError) Unwrap() error {
	return ErrAclPrefixRule
}

// What a device holds of one rule set (16.2.2).
type AclPrefixSetState int

const (
	// its generation is not held, or its entry not fetched: every verdict at or above it waits
	AclPrefixSetPending AclPrefixSetState = iota + 1
	// its rules are read and pass the format: in force from its position
	AclPrefixSetOpened
	// a later release's set: every verdict at or above it says update
	AclPrefixSetNewer
	// changes nothing: the set below it stays in force, and readers alarm set_void once
	AclPrefixSetVoid
)

// The state's name.
func (self AclPrefixSetState) String() string {
	switch self {
	case AclPrefixSetPending:
		return "pending"
	case AclPrefixSetOpened:
		return "opened"
	case AclPrefixSetNewer:
		return "newer"
	case AclPrefixSetVoid:
		return "void"
	}
	return "unknown"
}

// Why a set is void (16.2.2's void row, 16.2.3's pending one).
type AclPrefixVoidCause int

const (
	AclPrefixVoidNone AclPrefixVoidCause = iota
	// the seal does not open under its generation's key, its padding is wrong or its plaintext does not parse: a
	// wrong key, a flipped byte, another repo's key or another statement's context; or it names generation 0
	AclPrefixVoidSeal
	// more than RuleMaxCount rules
	AclPrefixVoidRuleCount
	// rules out of the canonical order, or one twice
	AclPrefixVoidOrder
	// a subject that is not 16 B
	AclPrefixVoidSubject
	// a path past a token path's 32 components, or a component §11.6 refuses: empty, or holding a slash or a NUL
	AclPrefixVoidPath
	// an action of 0
	AclPrefixVoidAction
	// its generation's GenRotate was signed more than GenerationFormGrace after its entry
	AclPrefixVoidLateGeneration
	// pending past GenerationFormGrace plus PendingVoidMargin, its generation named by no whole read of gkm
	AclPrefixVoidUnformed
)

// The cause's name.
func (self AclPrefixVoidCause) String() string {
	switch self {
	case AclPrefixVoidNone:
		return "none"
	case AclPrefixVoidSeal:
		return "seal"
	case AclPrefixVoidRuleCount:
		return "rule_count"
	case AclPrefixVoidOrder:
		return "order"
	case AclPrefixVoidSubject:
		return "subject"
	case AclPrefixVoidPath:
		return "path"
	case AclPrefixVoidAction:
		return "action"
	case AclPrefixVoidLateGeneration:
		return "late_generation"
	case AclPrefixVoidUnformed:
		return "unformed"
	}
	return "unknown"
}

// One row's rule set as a device holds it (16.2.2, 16.2.3). Immutable once made; the caller must not change it.
type AclPrefixRuleSet struct {
	// The row's position and signer: the entry that filed the set.
	At     uint64
	Signer Id
	State  AclPrefixSetState
	// Why a void set is void, AclPrefixVoidNone otherwise.
	VoidCause AclPrefixVoidCause
	// The generation its rules are sealed to, 0 where the seal names none.
	Generation uint64
	// An opened set's rules, in their canonical order; nil otherwise.
	Rules []*protocol.PrefixRule
}

// -1, 0 or 1 by 16.2.2's canonical order: the subject's bytes, then the path's components compared in order as
// bytes, a shorter path first.
func aclPrefixRuleCompare(a *protocol.PrefixRule, b *protocol.PrefixRule) int {
	if order := bytes.Compare(a.GetSubject(), b.GetSubject()); order != 0 {
		return order
	}
	return aclPrefixPathCompare(a.GetPath(), b.GetPath())
}

// -1, 0 or 1 for two paths by components, a shorter path first where one begins the other.
func aclPrefixPathCompare(a [][]byte, b [][]byte) int {
	for i := range min(len(a), len(b)) {
		if order := bytes.Compare(a[i], b[i]); order != 0 {
			return order
		}
	}
	return cmp.Compare(len(a), len(b))
}

// Whether a parsed set is a later release's (16.2.2's newer row): a field this release does not know, at any level,
// or an action above write.
func aclPrefixRuleSetNewer(set *protocol.PrefixRuleSet) bool {
	if len(set.ProtoReflect().GetUnknown()) != 0 {
		return true
	}
	for _, rule := range set.GetRules() {
		if len(rule.ProtoReflect().GetUnknown()) != 0 || protocol.PrefixAction_PREFIX_ACTION_WRITE < rule.GetAction() {
			return true
		}
	}
	return false
}

// 16.2.2's one validator over a parsed set, which every reader applies to the same bytes and SealPrefixRuleSet to
// what it seals: newer for a later release's set, else opened unless a rule breaks the format, the first such cause
// in rule order.
func aclPrefixCheckRuleSet(set *protocol.PrefixRuleSet, settings *AclPrefixSettings) (AclPrefixSetState, AclPrefixVoidCause) {
	if aclPrefixRuleSetNewer(set) {
		return AclPrefixSetNewer, AclPrefixVoidNone
	}
	rules := set.GetRules()
	if max(0, settings.RuleMaxCount) < len(rules) {
		return AclPrefixSetVoid, AclPrefixVoidRuleCount
	}
	for i, rule := range rules {
		if rule.GetAction() != protocol.PrefixAction_PREFIX_ACTION_WRITE {
			return AclPrefixSetVoid, AclPrefixVoidAction
		}
		if len(rule.GetSubject()) != aclAtomByteCount {
			return AclPrefixSetVoid, AclPrefixVoidSubject
		}
		if EvsTokenPathMaxLength < len(rule.GetPath()) {
			return AclPrefixSetVoid, AclPrefixVoidPath
		}
		for _, name := range rule.GetPath() {
			if checkEvsPathName(name) != nil {
				return AclPrefixSetVoid, AclPrefixVoidPath
			}
		}
		if 0 < i && 0 <= aclPrefixRuleCompare(rules[i-1], rule) {
			return AclPrefixSetVoid, AclPrefixVoidOrder
		}
	}
	return AclPrefixSetOpened, AclPrefixVoidNone
}

// Rules in 16.2.2's canonical order with each (subject, path) once: what a filer seals. Each rule is a copy, its
// action write.
func AclPrefixSortRules(rules []*protocol.PrefixRule) []*protocol.PrefixRule {
	sorted := make([]*protocol.PrefixRule, 0, len(rules))
	for _, rule := range rules {
		sorted = append(sorted, &protocol.PrefixRule{
			Subject: bytes.Clone(rule.GetSubject()),
			Path:    aclPrefixClonePath(rule.GetPath()),
			Action:  protocol.PrefixAction_PREFIX_ACTION_WRITE,
		})
	}
	slices.SortStableFunc(sorted, aclPrefixRuleCompare)
	return slices.CompactFunc(sorted, func(a *protocol.PrefixRule, b *protocol.PrefixRule) bool {
		return aclPrefixRuleCompare(a, b) == 0
	})
}

// A copy of a path's components.
func aclPrefixClonePath(path [][]byte) [][]byte {
	cloned := make([][]byte, 0, len(path))
	for _, name := range path {
		cloned = append(cloned, bytes.Clone(name))
	}
	return cloned
}

// Opens a set's sealed body (16.2.2) and says what it is, with its rules where it opened. repoKeyAt answers the
// repo's key at a generation, nil where this device does not hold it; genRotateTimeAt the time that generation's
// GenRotate was signed, ms since the epoch (its time_ms; EvsRepoKey.Time), false where unknown; entryTimeMs is the
// time of the entry that carries the set. A held generation signed more than GenerationFormGrace after the entry
// voids the set before its seal is opened. The caller fills At and Signer. Nil settings are the defaults.
func OpenPrefixRuleSet(sealed []byte, context *ConfigSealContext, repoKeyAt func(generation uint64) *EvsRepoKey, genRotateTimeAt func(generation uint64) (int64, bool), entryTimeMs int64, settings *AclPrefixSettings) *AclPrefixRuleSet {
	if settings == nil {
		settings = DefaultAclPrefixSettings()
	}
	set := &AclPrefixRuleSet{State: AclPrefixSetVoid, VoidCause: AclPrefixVoidSeal}
	generation, err := ConfigSealedGeneration(sealed)
	if err != nil || generation == 0 {
		// no generation 0 exists, so a seal naming it never opens
		return set
	}
	set.Generation = generation
	var key *EvsRepoKey
	if repoKeyAt != nil {
		key = repoKeyAt(generation)
	}
	if key == nil || key.Generation() != generation || key.checkHeld() != nil {
		set.State, set.VoidCause = AclPrefixSetPending, AclPrefixVoidNone
		return set
	}
	if genRotateTimeAt != nil {
		if signedMs, ok := genRotateTimeAt(generation); ok && settings.generationLate(signedMs, entryTimeMs) {
			set.VoidCause = AclPrefixVoidLateGeneration
			return set
		}
	}
	rules := &protocol.PrefixRuleSet{}
	_, err = OpenConfigBody(sealed, context, func(asked uint64) *EvsRepoKey {
		if asked == generation {
			return key
		}
		return nil
	}, rules)
	switch {
	case errors.Is(err, ErrConfigSealGenerationMissing):
		set.State, set.VoidCause = AclPrefixSetPending, AclPrefixVoidNone
		return set
	case err != nil:
		return set
	}
	set.State, set.VoidCause = aclPrefixCheckRuleSet(rules, settings)
	if set.State == AclPrefixSetOpened {
		set.Rules = rules.GetRules()
	}
	return set
}

// Seals set for a RepoPrefixRules with the header context names, under repoKey, the repo's own key at the filer's
// newest generation (16.2.2), after the validator every reader runs: a set no reader would open as filed is
// ErrAclPrefixSetInvalid, so no design device files a void one. random is crypto/rand's reader when nil, and nil
// settings are the defaults.
func SealPrefixRuleSet(repoKey *EvsRepoKey, context *ConfigSealContext, set *protocol.PrefixRuleSet, random io.Reader, settings *AclPrefixSettings) ([]byte, error) {
	if settings == nil {
		settings = DefaultAclPrefixSettings()
	}
	if set == nil {
		return nil, fmt.Errorf("%w: no set", ErrAclPrefixSetInvalid)
	}
	if context == nil || context.SignedType != bridge.SignedType_SIGNED_REPO_PREFIX_RULES {
		return nil, fmt.Errorf("%w: a seal bound to another statement opens in no RepoPrefixRules", ErrAclPrefixSetInvalid)
	}
	if state, cause := aclPrefixCheckRuleSet(set, settings); state != AclPrefixSetOpened {
		return nil, fmt.Errorf("%w: every reader would hold it %s (%s)", ErrAclPrefixSetInvalid, state, cause)
	}
	sealed, err := SealConfigBody(repoKey, context, set, random)
	if err != nil {
		return nil, err
	}
	if !settings.SealedByteCountFits(len(sealed)) {
		return nil, fmt.Errorf("%w: %d bytes sealed, past SealedMaxByteCount's %d", ErrAclPrefixSetInvalid, len(sealed), settings.SealedMaxByteCount)
	}
	return sealed, nil
}

// 16.2.2's names: whether a rule's subject names the signer whose admission row this is, a tombstone serving, by what
// the admission fixes alone (QD-791): its sidecar_id; its member, where the row carries no tag; a tag it carries;
// autogroup:sidecar, every signer; autogroup:tagged, a row with a tag; autogroup:member, an untagged row that is not
// ephemeral; autogroup:ephemeral, an untagged one that is. Every other atom names nobody, a group's, a role's and
// autogroup:admin's among them, since a reader holding no state at a push's pin cannot resolve one.
func aclPrefixNames(subject []byte, row *bridge.SidecarRow) bool {
	if len(subject) != aclAtomByteCount || row == nil {
		return false
	}
	tagged := len(row.GetTagIds()) != 0
	if aclAtomHasAutogroupForm(Id(subject)) {
		autogroup, _ := aclAtomAutogroup(Id(subject))
		switch autogroup {
		case protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR:
			return true
		case protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED:
			return tagged
		case protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER:
			return !tagged && !row.GetEphemeral()
		case protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL:
			return !tagged && row.GetEphemeral()
		}
		return false
	}
	if bytes.Equal(subject, row.GetSidecarId()) {
		return true
	}
	if !tagged {
		return bytes.Equal(subject, row.GetMemberId())
	}
	for _, tagId := range row.GetTagIds() {
		if bytes.Equal(subject, tagId) {
			return true
		}
	}
	return false
}

// Whether 16.2.4's line 1 leaves a push outside the rules: a ref that is not shared, the erasure ref, ur/index or
// ur/lfs, a repo that is not general, or a flag held to the admin right.
func aclPrefixOutside(repoKind protocol.RepoKind, refKind protocol.EvsRefKind, refName []byte, flags uint32) bool {
	if refKind != protocol.EvsRefKind_EVS_REF_SHARED || repoKind != protocol.RepoKind_REPO_KIND_GENERAL {
		return true
	}
	if flags&aclPrefixOutsideFlags != 0 {
		return true
	}
	return slices.ContainsFunc(aclPrefixOutsideRefNames, func(name []byte) bool { return bytes.Equal(name, refName) })
}

// The set a device holds at a position, nil for none: sets are in position order.
func aclPrefixSetAt(sets []*AclPrefixRuleSet, at uint64) *AclPrefixRuleSet {
	i, found := slices.BinarySearchFunc(sets, at, func(set *AclPrefixRuleSet, at uint64) int {
		return cmp.Compare(set.At, at)
	})
	if !found {
		return nil
	}
	return sets[i]
}

// 16.2.4's line 2 at a pin over the repo's rows, in position order, and the sets this device holds for them: newest
// first, a void set passed over, a pending one or a row this device holds no set for waits, a newer one updates, and
// the first opened one is the set in force. decided is true where the verdict is already the answer: that wait, that
// update, no set in force (allowed), or rows out of position order (wait, as for a base this device cannot use).
func aclPrefixSetInForce(rows []*protocol.AclRepoPrefixRulesRow, sets []*AclPrefixRuleSet, pin uint64) (*AclPrefixRuleSet, AclPrefixVerdict, bool) {
	for i := 1; i < len(rows); i += 1 {
		if rows[i].GetAt() <= rows[i-1].GetAt() {
			return nil, AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonRows}, true
		}
	}
	for i := len(rows) - 1; 0 <= i; i -= 1 {
		at := rows[i].GetAt()
		if pin < at {
			continue
		}
		set := aclPrefixSetAt(sets, at)
		if set == nil || !bytes.Equal(set.Signer[:], rows[i].GetSigner()) {
			return nil, AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonPending, SetAt: at}, true
		}
		switch set.State {
		case AclPrefixSetVoid:
			continue
		case AclPrefixSetOpened:
			return set, AclPrefixVerdict{SetAt: at}, false
		case AclPrefixSetNewer:
			return nil, AclPrefixVerdict{Outcome: AclPrefixUpdate, Reason: AclPrefixReasonNewer, SetAt: at}, true
		default:
			return nil, AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonPending, SetAt: at}, true
		}
	}
	return nil, AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoSet}, true
}

// One set's rules in one path epoch's token space (16.2.4's line 3; 16.4's token table): each rule's path as a token
// path under K_path of the epoch, the empty one for a rule with no path, and .ur-index's for line 4. Built once per
// (set, epoch); immutable, so safe for concurrent use.
type AclPrefixTokenTable struct {
	setAt uint64
	epoch uint64
	// by rule index
	ruleTokenPaths []EvsTokenPath
	indexTokenPath EvsTokenPath
}

// The table of an opened set in pathKey's epoch: one HMAC per component of each rule's path (16.4).
func NewAclPrefixTokenTable(set *AclPrefixRuleSet, pathKey *EvsPathKey) (*AclPrefixTokenTable, error) {
	if set == nil || set.State != AclPrefixSetOpened {
		return nil, fmt.Errorf("%w: a token table of a set that is not opened", ErrAclPrefixSetInvalid)
	}
	if err := pathKey.checkHeld(); err != nil {
		return nil, err
	}
	table := &AclPrefixTokenTable{setAt: set.At, epoch: pathKey.Epoch(), ruleTokenPaths: make([]EvsTokenPath, 0, len(set.Rules))}
	for _, rule := range set.Rules {
		tokenPath, err := EvsPathTokens(pathKey, rule.GetPath())
		if err != nil {
			return nil, err
		}
		table.ruleTokenPaths = append(table.ruleTokenPaths, tokenPath)
	}
	indexTokenPath, err := EvsPathTokens(pathKey, [][]byte{[]byte(aclPrefixIndexDirectory)})
	if err != nil {
		return nil, err
	}
	table.indexTokenPath = indexTokenPath
	return table, nil
}

// The tables a judge with no cache builds: a fresh one per set in pathKey's epoch.
func AclPrefixTokenTableOf(pathKey *EvsPathKey) func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error) {
	return func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error) {
		return NewAclPrefixTokenTable(set, pathKey)
	}
}

// The position of the set the table was built for.
func (self *AclPrefixTokenTable) SetAt() uint64 {
	return self.setAt
}

// The path epoch whose tokens it holds.
func (self *AclPrefixTokenTable) Epoch() uint64 {
	return self.epoch
}

// Line 3's A: the token paths of the set's rules that name the signer whose row this is.
func (self *AclPrefixTokenTable) Prefixes(set *AclPrefixRuleSet, row *bridge.SidecarRow) []EvsTokenPath {
	prefixes := []EvsTokenPath{}
	for i, rule := range set.Rules {
		if i < len(self.ruleTokenPaths) && aclPrefixNames(rule.GetSubject(), row) {
			prefixes = append(prefixes, self.ruleTokenPaths[i])
		}
	}
	return prefixes
}

// Whether prefix begins tokenPath, equal counting.
func aclPrefixTokenPathHasPrefix(tokenPath EvsTokenPath, prefix EvsTokenPath) bool {
	return len(prefix) <= len(tokenPath) && slices.Equal(tokenPath[:len(prefix)], prefix)
}

// 16.2.4's under(T): some prefix begins the token path, equal counting.
func AclPrefixUnder(prefixes []EvsTokenPath, tokenPath EvsTokenPath) bool {
	return slices.ContainsFunc(prefixes, func(prefix EvsTokenPath) bool { return aclPrefixTokenPathHasPrefix(tokenPath, prefix) })
}

// Whether the token path is a proper prefix of some prefix: a directory on the way to one.
func aclPrefixOnTheWay(prefixes []EvsTokenPath, tokenPath EvsTokenPath) bool {
	return slices.ContainsFunc(prefixes, func(prefix EvsTokenPath) bool {
		return len(tokenPath) < len(prefix) && aclPrefixTokenPathHasPrefix(prefix, tokenPath)
	})
}

// A delta's added row under T, child token t of kind k (16.2.4's line 5): T+[t] begins some prefix, and where it is a
// proper prefix of every prefix it begins, k is a directory.
func aclPrefixRowLeads(prefixes []EvsTokenPath, tokenPath EvsTokenPath, token EvsToken, kind protocol.EvsEntryKind) bool {
	for _, prefix := range prefixes {
		if len(prefix) <= len(tokenPath) || prefix[len(tokenPath)] != token || !aclPrefixTokenPathHasPrefix(prefix, tokenPath) {
			continue
		}
		if len(prefix) == len(tokenPath)+1 || kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			return true
		}
	}
	return false
}

// A delta's removed token under T (16.2.4's line 5): T+[t] is a prefix itself, the only row above a prefix its writer
// may remove.
func aclPrefixRowIsPrefix(prefixes []EvsTokenPath, tokenPath EvsTokenPath, token EvsToken) bool {
	return slices.ContainsFunc(prefixes, func(prefix EvsTokenPath) bool {
		return len(prefix) == len(tokenPath)+1 && prefix[len(tokenPath)] == token && aclPrefixTokenPathHasPrefix(prefix, tokenPath)
	})
}

// What PrefixVerdict decides (16.2.4).
type AclPrefixOutcome int

const (
	// the reader shows, serves and builds on the change
	AclPrefixAllowed AclPrefixOutcome = iota + 1
	// the reader does not follow the change, and alarms prefix_rule naming its signer
	AclPrefixIgnored
	// a set the reader must read is pending: it shows what it accepted before, state held
	AclPrefixWait
	// a set of a later release: it shows what it accepted before, state update
	AclPrefixUpdate
)

// The outcome's name.
func (self AclPrefixOutcome) String() string {
	switch self {
	case AclPrefixAllowed:
		return "allowed"
	case AclPrefixIgnored:
		return "ignored"
	case AclPrefixWait:
		return "wait"
	case AclPrefixUpdate:
		return "update"
	}
	return "unknown"
}

// Which line of 16.2.4 decided a verdict.
type AclPrefixReason int

const (
	// line 1: a ref that is not shared, the erasure ref, ur/index or ur/lfs, a repo that is not general, or a push
	// flagged FORCE, DELETE, BASE, DROP, ERASE, CUT or CLOSURE
	AclPrefixReasonScope AclPrefixReason = iota + 1
	// line 2: no set in force at the pin
	AclPrefixReasonNoSet
	// line 2: a set at or below the pin, above the one in force, is pending, or no set at all for its row
	AclPrefixReasonPending
	// line 2: a later release's set at or below the pin, above the one in force
	AclPrefixReasonNewer
	// line 3: the push's path epoch has no key or table here, so nothing can be compared yet
	AclPrefixReasonTokens
	// line 4: under .ur-index/ on a file-mode ref
	AclPrefixReasonIndex
	// line 5: under a prefix the set gives the signer
	AclPrefixReasonUnder
	// line 5: a directory above every prefix whose every row leads to one, or its own creation on the way
	AclPrefixReasonOnTheWay
	// line 5: a file's version or removal, a directory's removal or one created beside the way, under no prefix
	AclPrefixReasonNotUnder
	// line 5: a delta's row off the way: beside it, a file row on it, over a row of another kind, or a removal on it
	AclPrefixReasonDeltaRow
	// a push of no change, the pin push (16.2.9)
	AclPrefixReasonNoChange
	// the rows are out of position order, as no fold leaves them: no verdict until the reader holds good rows
	AclPrefixReasonRows
)

// The reason's name.
func (self AclPrefixReason) String() string {
	switch self {
	case AclPrefixReasonScope:
		return "scope"
	case AclPrefixReasonNoSet:
		return "no_set"
	case AclPrefixReasonPending:
		return "pending"
	case AclPrefixReasonNewer:
		return "newer"
	case AclPrefixReasonTokens:
		return "tokens"
	case AclPrefixReasonIndex:
		return "index"
	case AclPrefixReasonUnder:
		return "under"
	case AclPrefixReasonOnTheWay:
		return "on_the_way"
	case AclPrefixReasonNotUnder:
		return "not_under"
	case AclPrefixReasonDeltaRow:
		return "delta_row"
	case AclPrefixReasonNoChange:
		return "no_change"
	case AclPrefixReasonRows:
		return "rows"
	}
	return "unknown"
}

// One verdict and what decided it.
type AclPrefixVerdict struct {
	Outcome AclPrefixOutcome
	Reason  AclPrefixReason
	// The position of the set that decided: the set in force, or the pending or newer one; 0 for none.
	SetAt uint64
}

// One change of a push as 16.2.4's line 5 judges it.
type AclPrefixChange struct {
	// c.token_path, in the push's path epoch, as the statement or the proof's leaf carries it.
	TokenPath EvsTokenPath
	// The change removes its path (entry_sha256 empty).
	Removal bool
	// Its entry is a directory's, where the reader holds the entry: its rows are judged by the delta rule. A file's
	// change, or one whose entry the reader does not hold, is judged by its own path alone.
	Directory bool
	// base_entry_version is 0: the change creates its path.
	Creates bool
	// A directory's rows: the ones it adds and the tokens it removes (EvsEntryVersion.names).
	Names *protocol.EvsNameTable
	// The table the delta applies to, as the reader holds it: the kind of its row for a child's token, false for
	// none. Nil holds none. A directory the change creates holds none whatever this says.
	Table func(token EvsToken) (protocol.EvsEntryKind, bool)
}

// What PrefixVerdict reads (16.2.4): the push's signed fields and its signer's row, the repo's rows and the sets this
// reader holds for them, one change, and the token table of a set in the push's path epoch. Nothing at the push's
// pin: no ConfigState, so no StateAt.
type AclPrefixVerdictArgs struct {
	// The repo's kind, which never changes.
	RepoKind protocol.RepoKind
	// The push's ref_kind and ref_mode.
	RefKind protocol.EvsRefKind
	RefMode protocol.EvsRefMode
	// The ref's name as this reader holds it, which tells ur/index and ur/lfs from the other shared refs.
	RefName []byte
	// The push's flags.
	Flags uint32
	// u.auth.version: the position of the push's authorization pin.
	PinVersion uint64
	// The signer's admission row, from the state the reader verified the push in or any later one: a tombstone
	// serves, since what names reads never changes.
	Signer *bridge.SidecarRow
	// The repo's AclRepo.prefix_rules in any state of this log at or above the pin, in position order.
	Rows []*protocol.AclRepoPrefixRulesRow
	// The repo's sets this reader holds, in position order (AclPrefixSets): a row with none is pending.
	Sets []*AclPrefixRuleSet
	// The token table of a set in the push's path epoch: a judge's cache, or AclPrefixTokenTableOf over the epoch's
	// key. Nil, or an error, waits.
	TokenTable func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error)
	// The change judged; nil for a push that carries none.
	Change *AclPrefixChange
}

// 16.2.4's verdict on one change of a verified push: allowed, ignored, wait or update, with the line that decided.
// One pure function of the push's signed bytes, the repo's rows and the signer's row, so every reader that holds them
// reaches the same verdict, whatever base it started at and whatever it retains (16.3's P1). It runs after §11.9's
// checks.
func PrefixVerdict(args *AclPrefixVerdictArgs) AclPrefixVerdict {
	if aclPrefixOutside(args.RepoKind, args.RefKind, args.RefName, args.Flags) {
		return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonScope}
	}
	set, verdict, decided := aclPrefixSetInForce(args.Rows, args.Sets, args.PinVersion)
	if decided {
		return verdict
	}
	change := args.Change
	if change == nil {
		return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoChange, SetAt: set.At}
	}
	if args.TokenTable == nil {
		return AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonTokens, SetAt: set.At}
	}
	table, err := args.TokenTable(set)
	if err != nil || table == nil || table.setAt != set.At || len(table.ruleTokenPaths) != len(set.Rules) {
		return AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonTokens, SetAt: set.At}
	}
	judged := func(outcome AclPrefixOutcome, reason AclPrefixReason) AclPrefixVerdict {
		return AclPrefixVerdict{Outcome: outcome, Reason: reason, SetAt: set.At}
	}
	if args.RefMode == protocol.EvsRefMode_EVS_REF_FILE && aclPrefixTokenPathHasPrefix(change.TokenPath, table.indexTokenPath) {
		return judged(AclPrefixAllowed, AclPrefixReasonIndex)
	}
	prefixes := table.Prefixes(set, args.Signer)
	tokenPath := change.TokenPath
	if AclPrefixUnder(prefixes, tokenPath) {
		return judged(AclPrefixAllowed, AclPrefixReasonUnder)
	}
	if change.Removal || !change.Directory {
		return judged(AclPrefixIgnored, AclPrefixReasonNotUnder)
	}
	// a directory above every prefix: its creation only on the way to one, and each row as the delta rule says
	if change.Creates && !aclPrefixOnTheWay(prefixes, tokenPath) {
		return judged(AclPrefixIgnored, AclPrefixReasonNotUnder)
	}
	held := change.Table
	if change.Creates {
		held = nil
	}
	for _, name := range change.Names.GetNames() {
		token, err := EvsTokenFromBytes(name.GetToken())
		if err != nil || !aclPrefixRowLeads(prefixes, tokenPath, token, protocol.EvsEntryKind(name.GetKind())) {
			return judged(AclPrefixIgnored, AclPrefixReasonDeltaRow)
		}
		if held != nil {
			if kind, ok := held(token); ok && kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
				return judged(AclPrefixIgnored, AclPrefixReasonDeltaRow)
			}
		}
	}
	for _, removed := range change.Names.GetRemovedTokens() {
		token, err := EvsTokenFromBytes(removed)
		if err != nil || !aclPrefixRowIsPrefix(prefixes, tokenPath, token) {
			return judged(AclPrefixIgnored, AclPrefixReasonDeltaRow)
		}
	}
	return judged(AclPrefixAllowed, AclPrefixReasonOnTheWay)
}

// The rules of a set that name the signer whose row this is: what line 3 gives it, in plaintext.
func aclPrefixNamedRules(set *AclPrefixRuleSet, row *bridge.SidecarRow) []*protocol.PrefixRule {
	named := []*protocol.PrefixRule{}
	for _, rule := range set.Rules {
		if aclPrefixNames(rule.GetSubject(), row) {
			named = append(named, rule)
		}
	}
	return named
}

// Whether some rule's path begins a path given as its names, by components in plaintext (16.2.7), equal counting.
func aclPrefixRulesCoverNames(rules []*protocol.PrefixRule, names []string) bool {
	return slices.ContainsFunc(rules, func(rule *protocol.PrefixRule) bool {
		path := rule.GetPath()
		if len(names) < len(path) {
			return false
		}
		for i, name := range path {
			if string(name) != names[i] {
				return false
			}
		}
		return true
	})
}

// The keys of one repo as AclPrefixSets and the verdict's token tables read them, which the evs client implements
// (EVS1-M6-04), so this file imports nothing of evs's client.
type AclPrefixRepoKeys interface {
	// RK_g of the repo, nil while this device does not hold generation g.
	RepoKeyAt(generation uint64) *EvsRepoKey
	// K_path of path epoch p, nil while this device does not hold it.
	PathKeyAt(epoch uint64) *EvsPathKey
	// The time generation g's GenRotate was signed, ms since the epoch (its time_ms, EvsRepoKey.Time), false while
	// this device does not hold g.
	GenRotateTimeAt(generation uint64) (int64, bool)
}

// One read of gkm's generation listing for a repo's group, as 16.2.3's pending rule takes it: made after the device
// applied the log's entry at AppliedThrough, read to the listing's end, with no fork at the repo's generation pin,
// naming generations 1 to Newest. The composition fills it from its sync of the repo's group (GkmGroupClient's), never
// from a cache or an earlier read.
type AclPrefixGenerationRead struct {
	AppliedThrough uint64
	Whole          bool
	Forked         bool
	Newest         uint64
	// The sync's failure, nil where it reached the listing's end.
	Err error
}

// What AclPrefixSets reads one repo's sets from, at one state (16.2.3).
type AclPrefixSetsArgs struct {
	// The state whose rows list the sets: the reader's own, never one at a push's pin.
	State  *ConfigState
	RepoId Id
	// The entry this device keeps at a position, false where it keeps none: the log's retained entries from its
	// retention point. AclPrefixLogEntries serves them on the log's goroutine and AclPrefixStateEntries anywhere, from
	// the state's window. Nil keeps none.
	EntryAt func(n uint64) (*bridge.AuthEntry, bool)
	// The config head of the state's newest base, whose fold records hold every entry it folds verbatim; nil, or a
	// read that fails, leaves a set whose entry the device does not keep pending.
	Heads ConfigHeadReader
	// The repo's keys; nil holds none, so every set stays pending.
	Keys AclPrefixRepoKeys
	// The device's newest read of gkm's generation listing for the repo; nil voids no pending set.
	Generations *AclPrefixGenerationRead
}

// The entries a state's window keeps, from its previous base to its tip, read with no lock: EntryAt for a caller off
// the log's goroutine. A log restored at a base keeps its window from that base until the next base moves it, so a set
// between the base's folded_through and the base reads as pending there until then, the closed direction.
func AclPrefixStateEntries(state *ConfigState) func(n uint64) (*bridge.AuthEntry, bool) {
	return func(n uint64) (*bridge.AuthEntry, bool) {
		kept := state.keptEntryAt(n)
		if kept == nil {
			return nil, false
		}
		return kept.entry, true
	}
}

// The entries a log retains, from its retention point to its tip: EntryAt for the log's own applying goroutine, as
// an entry callback runs on, which every position a fold record does not hold falls inside.
func AclPrefixLogEntries(log *ConfigLog) func(n uint64) (*bridge.AuthEntry, bool) {
	return func(n uint64) (*bridge.AuthEntry, bool) {
		kept := log.keptEntry(n)
		if kept == nil {
			return nil, false
		}
		return kept.entry, true
	}
}

// One set's sealed body as its entry carries it, which a pending or newer set keeps to be opened again.
type aclPrefixBody struct {
	sealed      []byte
	context     *ConfigSealContext
	entryTimeMs int64
}

// One repo's sets on this device: every set by position, and the bodies of those not final yet. Final sets, opened
// and void, are what the sealed store keeps.
type aclPrefixRepoSets struct {
	sets   map[uint64]*AclPrefixRuleSet
	bodies map[uint64]*aclPrefixBody
}

// A repo's final sets as the sealed store keeps them, JSON with byte fields in base64.
type aclPrefixStoredSets struct {
	Sets []*aclPrefixStoredSet `json:"sets"`
}

// One final set as the sealed store keeps it.
type aclPrefixStoredSet struct {
	At         uint64 `json:"at"`
	Signer     []byte `json:"signer"`
	State      int    `json:"state"`
	VoidCause  int    `json:"void_cause,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	// an opened set's PrefixRuleSet, deterministically encoded
	Rules []byte `json:"rules,omitempty"`
}

// A device's rule sets of every repo it reads or writes (16.2.3), by position, from the rows of the states it is
// given. Each body comes from the entry at its position, else the config head's fold record there, and is opened once:
// opened and void sets are final and kept in the evs component's sealed store under prefix/<repo_id>, so a restart
// opens none again, while a pending or newer set's body stays in memory and is tried again at each call that finds it,
// which the composition makes at each entry its log applies and each generation the repo's key ring gains. Bulk state
// stays on disk (QD-641): memory holds the working sets. Safe for concurrent use; a call that finds every set final
// takes no lock past a map read, and the rest run one at a time.
type AclPrefixSets struct {
	store    SidecarStore
	settings *AclPrefixSettings

	// one refresh at a time, so two never write one repo's file over each other; held across I/O and never inside
	// stateLock
	refreshLock sync.Mutex

	stateLock sync.Mutex
	repos     map[Id]*aclPrefixRepoSets
}

// The sets of a device whose evs component's sealed store is store; nil keeps them in memory alone. Nil settings are
// the defaults.
func NewAclPrefixSets(store SidecarStore, settings *AclPrefixSettings) *AclPrefixSets {
	if settings == nil {
		settings = DefaultAclPrefixSettings()
	}
	return &AclPrefixSets{store: store, settings: settings, repos: map[Id]*aclPrefixRepoSets{}}
}

// The store's name for a repo's sets.
func aclPrefixStoreName(repoId Id) string {
	return aclPrefixStoreDirectory + repoId.String()
}

// The repo's sets for every row args.State holds, in position order, one per row: final ones as this device holds
// them, the rest opened where they can be now, pending where not. ErrAclPrefixRecord where an entry at a set's position
// is not that set, and then no set of the repo is judged; a store that fails answers its error and changes nothing.
func (self *AclPrefixSets) Sets(ctx context.Context, args *AclPrefixSetsArgs) ([]*AclPrefixRuleSet, error) {
	if args == nil || args.State == nil {
		return nil, fmt.Errorf("%w: no state", ErrAclPrefixRecord)
	}
	rows := args.State.Repo(args.RepoId).GetPrefixRules()
	if len(rows) == 0 {
		return []*AclPrefixRuleSet{}, nil
	}
	if sets, ok := self.finalSets(args.RepoId, rows); ok {
		return sets, nil
	}
	self.refreshLock.Lock()
	defer self.refreshLock.Unlock()
	repoSets, err := self.load(args.RepoId)
	if err != nil {
		return nil, err
	}
	refresh := &aclPrefixRefresh{sets: self, args: args, ctx: ctx}
	result := make([]*AclPrefixRuleSet, 0, len(rows))
	opened := map[uint64]*AclPrefixRuleSet{}
	keptBodies := map[uint64]*aclPrefixBody{}
	changed := false
	for _, row := range rows {
		signer, err := IdFromBytes(row.GetSigner())
		if err != nil {
			return nil, fmt.Errorf("%w: a row at %d with no signer", ErrAclPrefixRecord, row.GetAt())
		}
		at := row.GetAt()
		if known := repoSets.sets[at]; known != nil && known.Signer == signer && aclPrefixSetFinal(known) {
			result = append(result, known)
			continue
		}
		body := repoSets.bodies[at]
		if body == nil {
			if body, err = refresh.body(at, signer); err != nil {
				return nil, err
			}
		}
		if body == nil {
			result = append(result, &AclPrefixRuleSet{At: at, Signer: signer, State: AclPrefixSetPending})
			continue
		}
		set := self.open(args, body)
		set.At, set.Signer = at, signer
		if aclPrefixSetFinal(set) {
			opened[at] = set
			changed = true
		} else {
			keptBodies[at] = body
		}
		result = append(result, set)
	}
	if changed {
		if err := self.save(args.RepoId, repoSets, opened); err != nil {
			return nil, err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for at, set := range opened {
			repoSets.sets[at] = set
			delete(repoSets.bodies, at)
		}
		for at, body := range keptBodies {
			repoSets.bodies[at] = body
		}
		for _, set := range result {
			if !aclPrefixSetFinal(set) {
				repoSets.sets[set.At] = set
			}
		}
	}()
	return result, nil
}

// Whether a set is final: opened or void, which no later call changes.
func aclPrefixSetFinal(set *AclPrefixRuleSet) bool {
	return set.State == AclPrefixSetOpened || set.State == AclPrefixSetVoid
}

// The sets for rows when this device holds every one final already, in memory, with no I/O.
func (self *AclPrefixSets) finalSets(repoId Id, rows []*protocol.AclRepoPrefixRulesRow) ([]*AclPrefixRuleSet, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repoSets := self.repos[repoId]
	if repoSets == nil {
		return nil, false
	}
	sets := make([]*AclPrefixRuleSet, 0, len(rows))
	for _, row := range rows {
		set := repoSets.sets[row.GetAt()]
		if set == nil || !aclPrefixSetFinal(set) || !bytes.Equal(set.Signer[:], row.GetSigner()) {
			return nil, false
		}
		sets = append(sets, set)
	}
	return sets, true
}

// A repo's sets in memory, read from the sealed store the first time. A stored set that no longer parses or passes
// the format is dropped, to be opened again.
func (self *AclPrefixSets) load(repoId Id) (*aclPrefixRepoSets, error) {
	loaded := func() *aclPrefixRepoSets {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.repos[repoId]
	}()
	if loaded != nil {
		return loaded, nil
	}
	repoSets := &aclPrefixRepoSets{sets: map[uint64]*AclPrefixRuleSet{}, bodies: map[uint64]*aclPrefixBody{}}
	if self.store != nil {
		stored := &aclPrefixStoredSets{}
		found, err := aclPrefixReadStoreJson(self.store, aclPrefixStoreName(repoId), stored)
		if err != nil {
			return nil, err
		}
		if found {
			for _, storedSet := range stored.Sets {
				if set := self.unstored(storedSet); set != nil {
					repoSets.sets[set.At] = set
				}
			}
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held := self.repos[repoId]; held != nil {
		return held, nil
	}
	self.repos[repoId] = repoSets
	return repoSets, nil
}

// A stored set as this device held it, nil for one that no longer reads as final.
func (self *AclPrefixSets) unstored(stored *aclPrefixStoredSet) *AclPrefixRuleSet {
	signer, err := IdFromBytes(stored.Signer)
	if err != nil {
		return nil
	}
	set := &AclPrefixRuleSet{
		At: stored.At, Signer: signer, State: AclPrefixSetState(stored.State), VoidCause: AclPrefixVoidCause(stored.VoidCause),
		Generation: stored.Generation,
	}
	switch set.State {
	case AclPrefixSetVoid:
		return set
	case AclPrefixSetOpened:
		rules := &protocol.PrefixRuleSet{}
		if proto.Unmarshal(stored.Rules, rules) != nil {
			return nil
		}
		if state, _ := aclPrefixCheckRuleSet(rules, self.settings); state != AclPrefixSetOpened {
			return nil
		}
		set.Rules = rules.GetRules()
		return set
	}
	return nil
}

// Writes the repo's final sets, those held and those just opened, as one file of the sealed store.
func (self *AclPrefixSets) save(repoId Id, repoSets *aclPrefixRepoSets, opened map[uint64]*AclPrefixRuleSet) error {
	if self.store == nil {
		return nil
	}
	final := func() map[uint64]*AclPrefixRuleSet {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		final := map[uint64]*AclPrefixRuleSet{}
		for at, set := range repoSets.sets {
			if aclPrefixSetFinal(set) {
				final[at] = set
			}
		}
		return final
	}()
	for at, set := range opened {
		final[at] = set
	}
	stored := &aclPrefixStoredSets{Sets: []*aclPrefixStoredSet{}}
	for _, at := range slices.Sorted(maps.Keys(final)) {
		set := final[at]
		storedSet := &aclPrefixStoredSet{
			At: set.At, Signer: set.Signer.Bytes(), State: int(set.State), VoidCause: int(set.VoidCause), Generation: set.Generation,
		}
		if set.State == AclPrefixSetOpened {
			rules, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.PrefixRuleSet{Rules: set.Rules})
			if err != nil {
				return err
			}
			storedSet.Rules = rules
		}
		stored.Sets = append(stored.Sets, storedSet)
	}
	data, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	testHookBarrier("acl_prefix.sets.store.before", repoId.String())
	err = aclPrefixWriteStoreFile(self.store, aclPrefixStoreName(repoId), data)
	testHookBarrier("acl_prefix.sets.store.after", repoId.String())
	return err
}

// Opens one body with the args' keys, and voids a pending one whose generation gkm's whole listing does not name once
// the wait is past (16.2.3).
func (self *AclPrefixSets) open(args *AclPrefixSetsArgs, body *aclPrefixBody) *AclPrefixRuleSet {
	var repoKeyAt func(generation uint64) *EvsRepoKey
	var genRotateTimeAt func(generation uint64) (int64, bool)
	if args.Keys != nil {
		repoKeyAt, genRotateTimeAt = args.Keys.RepoKeyAt, args.Keys.GenRotateTimeAt
	}
	set := OpenPrefixRuleSet(body.sealed, body.context, repoKeyAt, genRotateTimeAt, body.entryTimeMs, self.settings)
	if set.State == AclPrefixSetPending && self.unformed(args, body, set.Generation) {
		set.State, set.VoidCause = AclPrefixSetVoid, AclPrefixVoidUnformed
	}
	return set
}

// 16.2.3's void of a set whose generation never forms: a whole read of gkm's listing, with no fork, made after the
// device applied an entry timed past GenerationFormGrace plus PendingVoidMargin after the set's, names no such
// generation. A read that does not count, a generation gkm names (a key that exists and has not reached this device),
// or a wait not yet past leaves the set pending.
func (self *AclPrefixSets) unformed(args *AclPrefixSetsArgs, body *aclPrefixBody, generation uint64) bool {
	read := args.Generations
	if read == nil || read.Err != nil || !read.Whole || read.Forked || generation <= read.Newest {
		return false
	}
	state := args.State
	var timeMs int64
	switch {
	case read.AppliedThrough == state.Pin().GetVersion():
		timeMs = state.TimeMs()
	case read.AppliedThrough < state.Pin().GetVersion() && args.EntryAt != nil:
		entry, ok := args.EntryAt(read.AppliedThrough)
		if !ok {
			return false
		}
		timeMs = entry.GetTimeMs()
	default:
		return false
	}
	return self.settings.pendingVoidDue(timeMs, body.entryTimeMs)
}

// What one call of Sets reads bodies through: the entries the device keeps, then the head's fold records, read once.
type aclPrefixRefresh struct {
	sets *AclPrefixSets
	args *AclPrefixSetsArgs
	ctx  context.Context
	// the head's records by position, once read; headRead is set either way
	headRead    bool
	headRecords map[uint64]*protocol.ConfigRecord
}

// The body of the set at a position by signer: the entry this device keeps there, else the head's fold record; nil
// with no error where it holds neither, which leaves the set pending, and ErrAclPrefixRecord where what it holds there
// is not that set.
func (self *aclPrefixRefresh) body(at uint64, signer Id) (*aclPrefixBody, error) {
	if self.args.EntryAt != nil {
		if entry, ok := self.args.EntryAt(at); ok {
			if entry.GetN() != at || entry.GetKind() != bridge.AuthEntryKindStatement {
				return nil, fmt.Errorf("%w: the entry at %d is no statement", ErrAclPrefixRecord, at)
			}
			return self.parse(at, signer, entry.GetBody(), entry.GetTimeMs())
		}
	}
	if !self.headRead {
		self.headRead = true
		self.headRecords = self.readHead()
	}
	record := self.headRecords[at]
	if record == nil {
		return nil, nil
	}
	if record.GetKind() != bridge.AuthEntryKindStatement {
		return nil, fmt.Errorf("%w: the record at %d is no statement", ErrAclPrefixRecord, at)
	}
	return self.parse(at, signer, record.GetBody(), record.GetTimeMs())
}

// The fold records of the state's newest base's head by position, nil where there is no head to read.
func (self *aclPrefixRefresh) readHead() map[uint64]*protocol.ConfigRecord {
	base := self.args.State.Base()
	if self.args.Heads == nil || base == nil {
		return nil
	}
	head, err := self.args.Heads.ReadConfigHead(self.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil || head == nil {
		return nil
	}
	records, err := head.RecordsIn(0, head.FoldedThrough())
	if err != nil {
		return nil
	}
	byPosition := make(map[uint64]*protocol.ConfigRecord, len(records))
	for _, record := range records {
		byPosition[record.GetN()] = record
	}
	return byPosition
}

// A Signed RepoPrefixRules of the args' repo by signer, as its entry or fold record carries it, else
// ErrAclPrefixRecord.
func (self *aclPrefixRefresh) parse(at uint64, signer Id, signedBytes []byte, entryTimeMs int64) (*aclPrefixBody, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: at %d", ErrAclPrefixRecord, at)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_REPO_PREFIX_RULES || !bytes.Equal(signed.GetSignerId(), signer[:]) {
		return nil, fmt.Errorf("%w: at %d, another statement or signer", ErrAclPrefixRecord, at)
	}
	message, err := ParseConfigStatement(bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, signed.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: at %d: %w", ErrAclPrefixRecord, at, err)
	}
	statement := message.(*protocol.RepoPrefixRules)
	if !bytes.Equal(statement.GetRepoId(), self.args.RepoId[:]) {
		return nil, fmt.Errorf("%w: at %d, another repo", ErrAclPrefixRecord, at)
	}
	return &aclPrefixBody{
		sealed:      bytes.Clone(statement.GetSealedRules()),
		context:     NewConfigSealContext(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, statement.GetHeader()),
		entryTimeMs: entryTimeMs,
	}, nil
}

// Reads a JSON file of a sealed store into value; false when there is none.
func aclPrefixReadStoreJson(store SidecarStore, name string, value any) (bool, error) {
	reader, err := store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return false, fmt.Errorf("%w: %s does not parse", ErrSidecarStoreFailed, name)
	}
	return true, nil
}

// Replaces a file of a sealed store, durably.
func aclPrefixWriteStoreFile(store SidecarStore, name string, data []byte) error {
	writer, err := store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// What a filing changes in the set in force (16.2.9's ur evs rules).
type AclPrefixRulesChange int

const (
	// adds a rule {Subject, path} for each of Paths, a path of no component naming every path
	AclPrefixRulesAllow AclPrefixRulesChange = iota + 1
	// takes away every rule whose subject is Subject
	AclPrefixRulesDeny
	// Rules replace the set
	AclPrefixRulesSet
	// the one rule {autogroup:sidecar, every path}: the set that binds nobody
	AclPrefixRulesLift
)

// One filing of a repo's next set.
type AclPrefixRulesRequest struct {
	RepoId Id
	Change AclPrefixRulesChange
	// Allow's and Deny's subject: a sidecar, a member, a tag, or autogroup:sidecar, member, tagged or ephemeral.
	Subject Id
	// Allow's paths, each its raw names (§11.6); one of no component is every path.
	Paths [][][]byte
	// Set's rules, in any order.
	Rules []*protocol.PrefixRule
	// Set's --as-written: files Rules alone, the repo's standing admins not written in.
	AsWritten bool
}

// What a filing filed.
type AclPrefixRulesFiled struct {
	// The set's entry (n, A_n): its pin push carries a pin at or above n, so the filer waits for its own log to apply
	// the entry before it sends one (16.2.9).
	Pin *bridge.AuthPin
	// The set as filed, in its canonical order.
	Set *protocol.PrefixRuleSet
	// The repo's standing admins the state admits whom the set names in no rule, who write nothing while it is in
	// force: what set --as-written says it leaves unable to write.
	UnnamedAdmins []Id
}

// The verified state a filing builds the next set at: ConfigClient is one.
type AclPrefixRulesConfig interface {
	// The newest verified state, nil before one.
	State() *ConfigState
}

// What a filer runs on.
type AclPrefixRulesFilerArgs struct {
	// The sidecar that files: its identity and its acts.
	Sidecar *Sidecar
	Config  AclPrefixRulesConfig
	// The repo's current key, which seals the set (16.2.2): the GkmClient's CurrentRepoKey. Nil files nothing.
	RepoKey func(ctx context.Context, repoId Id) (*EvsRepoKey, error)
	// The repo's sets this device holds at a state (AclPrefixSets.Sets), which an Allow or a Deny builds from. Nil
	// holds none, so an Allow or a Deny on a repo with sets is refused as pending.
	Sets func(ctx context.Context, state *ConfigState, repoId Id) ([]*AclPrefixRuleSet, error)
	// crypto/rand's reader when nil: the seal's nonce.
	Random   io.Reader
	Settings *AclPrefixSettings
}

// Files RepoPrefixRules for one Sidecar (16.2.9): the next set built from the one in force at the newest verified
// state, with a rule {sidecar:<id>, every path} for each standing admin of the repo that the set does not name for
// every path already (QD-792), sorted, checked as every reader checks it, sealed to the repo's own current generation
// and signed through CORE's act on the person's confirmation alone. Used by one goroutine at a time.
type AclPrefixRulesFiler struct {
	args     AclPrefixRulesFilerArgs
	settings *AclPrefixSettings
}

// A filer over args.
func NewAclPrefixRulesFiler(args *AclPrefixRulesFilerArgs) *AclPrefixRulesFiler {
	settings := args.Settings
	if settings == nil {
		settings = DefaultAclPrefixSettings()
	}
	return &AclPrefixRulesFiler{args: *args, settings: settings}
}

// Builds, seals, signs and posts the request's next set as the person confirmed it (origin, never MCP or a hook),
// answering its position once it lands. api and every reader judge the signer (16.2.2: a repo admin or a config
// writer). A subject that names nobody, a group's or a role's among them, is refused before anything is signed, as is
// a set no reader would open, and an Allow or a Deny where the set in force is pending or newer here: a device that
// cannot read the rules in force does not build on them (EVS_PREFIX_RULE, pending or update). While the filer's settings
// keep the rules dark, the launch default, nothing is built or signed: ErrAclPrefixRulesDeferred (QD-1032).
func (self *AclPrefixRulesFiler) File(ctx context.Context, request *AclPrefixRulesRequest, origin SidecarActOrigin, check SidecarPresenceCheck) (*AclPrefixRulesFiled, error) {
	if !self.settings.Enabled {
		return nil, ErrAclPrefixRulesDeferred
	}
	if origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	if self.args.Sidecar == nil || self.args.Config == nil {
		return nil, ErrSidecarActNoAuthority
	}
	state := self.args.Config.State()
	if state == nil {
		return nil, ErrSidecarActNoAuthority
	}
	repo := state.Repo(request.RepoId)
	switch {
	case repo == nil:
		return nil, fmt.Errorf("%w: the state holds no such repo", ErrAclPrefixRepo)
	case repo.GetKind() != protocol.RepoKind_REPO_KIND_GENERAL:
		return nil, fmt.Errorf("%w: a %s repo takes no prefix rules", ErrAclPrefixRepo, repo.GetKind())
	case repo.GetDeletion().GetDeletedAt() != 0 && repo.GetDeletion().GetRestoredAt() == 0:
		return nil, fmt.Errorf("%w: a deleted repo", ErrAclPrefixRepo)
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, err
	}
	rules, err := self.nextRules(ctx, state, repo, request)
	if err != nil {
		return nil, err
	}
	if !request.AsWritten {
		rules = aclPrefixWithAdmins(state, repo, rules)
	}
	for _, rule := range rules {
		if !aclPrefixSubjectNamesSomeone(state, acl, rule.GetSubject()) {
			return nil, fmt.Errorf("%w: a rule whose subject names nobody: a group, a role, another autogroup or an unknown id (16.2.9)", ErrAclPrefixSetInvalid)
		}
	}
	next := &protocol.PrefixRuleSet{Rules: AclPrefixSortRules(rules)}
	if setState, cause := aclPrefixCheckRuleSet(next, self.settings); setState != AclPrefixSetOpened {
		return nil, fmt.Errorf("%w: every reader would hold it %s (%s)", ErrAclPrefixSetInvalid, setState, cause)
	}
	if self.args.RepoKey == nil {
		return nil, fmt.Errorf("%w: no key to seal the set under", ErrAclPrefixRepo)
	}
	repoKey, err := self.args.RepoKey(ctx, request.RepoId)
	if err != nil {
		return nil, fmt.Errorf("%w: no key to seal the set under: %w", ErrAclPrefixRepo, err)
	}
	act, err := self.args.Sidecar.newAct(origin)
	if err != nil {
		return nil, err
	}
	err = act.AddSealed(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, &protocol.RepoPrefixRules{RepoId: request.RepoId.Bytes()},
		func(header *bridge.StatementHeader, statement proto.Message) error {
			sealed, err := SealPrefixRuleSet(repoKey, NewConfigSealContext(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, header), next, self.args.Random, self.settings)
			if err != nil {
				return err
			}
			statement.(*protocol.RepoPrefixRules).SealedRules = sealed
			return nil
		})
	if err != nil {
		return nil, err
	}
	pins, err := act.Run(ctx, check)
	if err != nil {
		return nil, err
	}
	if len(pins) != 1 || pins[0] == nil {
		return nil, fmt.Errorf("%w: the set has no entry", ErrSidecarActRefused)
	}
	filed := &AclPrefixRulesFiled{Pin: pins[0], Set: next}
	for _, adminId := range aclPrefixStandingAdmins(repo) {
		sidecar := state.Sidecar(adminId)
		if sidecar == nil {
			continue
		}
		if !slices.ContainsFunc(next.GetRules(), func(rule *protocol.PrefixRule) bool { return aclPrefixNames(rule.GetSubject(), sidecar.Row) }) {
			filed.UnnamedAdmins = append(filed.UnnamedAdmins, adminId)
		}
	}
	return filed, nil
}

// The request's next rules, before the admins: an Allow or a Deny from the set in force at the state, which must be
// one this device reads (or none); a Set's rules; a Lift's one rule.
func (self *AclPrefixRulesFiler) nextRules(ctx context.Context, state *ConfigState, repo *protocol.AclRepo, request *AclPrefixRulesRequest) ([]*protocol.PrefixRule, error) {
	switch request.Change {
	case AclPrefixRulesSet:
		return request.Rules, nil
	case AclPrefixRulesLift:
		return []*protocol.PrefixRule{{
			Subject: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR).Bytes(), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE,
		}}, nil
	case AclPrefixRulesAllow, AclPrefixRulesDeny:
	default:
		return nil, fmt.Errorf("%w: no such change", ErrAclPrefixSetInvalid)
	}
	var sets []*AclPrefixRuleSet
	if self.args.Sets != nil && len(repo.GetPrefixRules()) != 0 {
		var err error
		if sets, err = self.args.Sets(ctx, state, request.RepoId); err != nil {
			return nil, err
		}
	}
	inForce, verdict, decided := aclPrefixSetInForce(repo.GetPrefixRules(), sets, state.Pin().GetVersion())
	if decided && verdict.Outcome != AclPrefixAllowed {
		detail := AclPrefixDetailPending
		if verdict.Outcome == AclPrefixUpdate {
			detail = AclPrefixDetailUpdate
		}
		return nil, &AclPrefixRuleError{Detail: detail}
	}
	rules := []*protocol.PrefixRule{}
	if inForce != nil {
		for _, rule := range inForce.Rules {
			if request.Change == AclPrefixRulesDeny && bytes.Equal(rule.GetSubject(), request.Subject[:]) {
				continue
			}
			rules = append(rules, rule)
		}
	}
	if request.Change == AclPrefixRulesAllow {
		for _, path := range request.Paths {
			rules = append(rules, &protocol.PrefixRule{Subject: request.Subject.Bytes(), Path: aclPrefixClonePath(path), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE})
		}
	}
	return rules, nil
}

// The repo's standing admins, sorted (QD-743's rows that are not removed).
func aclPrefixStandingAdmins(repo *protocol.AclRepo) []Id {
	adminIds := []Id{}
	for _, admin := range repo.GetAdmins() {
		if !AclRepoAdminStands(admin) {
			continue
		}
		if adminId, err := IdFromBytes(admin.GetSidecarId()); err == nil && !slices.Contains(adminIds, adminId) {
			adminIds = append(adminIds, adminId)
		}
	}
	slices.SortFunc(adminIds, Id.Cmp)
	return adminIds
}

// rules with a rule {sidecar:<id>, every path} for each standing admin they do not name for every path already
// (QD-792), so a set that already lets every signer write everywhere, Lift's, gains none. An admin row whose sidecar
// the state holds no admission row for any more signs nothing and would name nobody, so it gains none either, and no
// filing is refused for it.
func aclPrefixWithAdmins(state *ConfigState, repo *protocol.AclRepo, rules []*protocol.PrefixRule) []*protocol.PrefixRule {
	withAdmins := slices.Clone(rules)
	for _, adminId := range aclPrefixStandingAdmins(repo) {
		sidecar := state.Sidecar(adminId)
		if sidecar == nil {
			continue
		}
		everywhere := slices.ContainsFunc(rules, func(rule *protocol.PrefixRule) bool {
			return len(rule.GetPath()) == 0 && aclPrefixNames(rule.GetSubject(), sidecar.Row)
		})
		if !everywhere {
			withAdmins = append(withAdmins, &protocol.PrefixRule{Subject: adminId.Bytes(), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE})
		}
	}
	return withAdmins
}

// Whether a subject names anyone a filer may name (16.2.9; QD-791): autogroup:sidecar, member, tagged or ephemeral; a
// sidecar or a member the state holds; or a tag, an id an admitted sidecar carries or a tag's atom in the rows, which
// carries no member, client, network, role or principal. A group's atom, a role's or principal's, any other autogroup
// and an id the state does not hold name nobody, and a filer refuses them.
func aclPrefixSubjectNamesSomeone(state *ConfigState, acl *AclState, subject []byte) bool {
	if len(subject) != aclAtomByteCount {
		return false
	}
	atom := Id(subject)
	if aclAtomHasAutogroupForm(atom) {
		autogroup, _ := aclAtomAutogroup(atom)
		switch autogroup {
		case protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR, protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER,
			protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED, protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL:
			return true
		}
		return false
	}
	if state.Sidecar(atom) != nil || state.Member(atom) != nil {
		return true
	}
	for _, row := range acl.Rows().GetAtoms() {
		if bytes.Equal(row.GetAtom(), subject) {
			return len(row.GetMemberIds()) == 0 && len(row.GetClientIds()) == 0 && len(row.GetNetworkIds()) == 0 &&
				row.GetRole() == "" && row.GetPrincipal() == ""
		}
	}
	for _, sidecarId := range state.SidecarIds() {
		if sidecar := state.Sidecar(sidecarId); sidecar != nil && slices.ContainsFunc(sidecar.Row.GetTagIds(), func(tagId []byte) bool { return bytes.Equal(tagId, subject) }) {
			return true
		}
	}
	return false
}
