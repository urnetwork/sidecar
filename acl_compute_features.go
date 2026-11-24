// §16.6's authorization features (DESIGN-COMPUTE §16.6, D-CACL-8, R2-02; CACL-M11-02): each format DESIGN-COMPUTE adds to
// the authorization log, its rows or key delivery is a feature a network turns on at a base of its own, so that a
// release reaching devices at different times never leaves two readers agreeing on a position while differing on who
// is admitted, which repo kinds stand and who receives keys.
//
//	reserve   ServiceSettings.auth_features (11) and ProjectionSettings.auth_features (3), uint32 bits: agent_repos 1,
//	          compute_policy 2, listeners 4, enclaves 8 (AuthFeature); SIDECAR_CAPABILITY_ENCLAVE (8), capability
//	          bit 3, beside them, which admissions keep refusing as an unknown bit until ENC's admission under enclaves
//	compile   each base's rows carry ProjectionSettings.auth_features from its head's ServiceSettings
//	          (ConfigProjectionSettings), and a network's first head sets every feature its creating release
//	          implements (BootstrapNetwork); bits only accumulate: a base whose rows clear a bit the base before set is
//	          withheld by every reader (ErrAuthFeatureCleared) and refused by api (ConfigLog.CheckBase)
//	point     a feature is on from the first base whose rows carry its bit (ConfigState.AuthFeatureOn)
//	before    ConfigState.RequireAuthFeature(feature, position) is the one check every area's entry rule calls (SKILL's
//	          agents and agent RepoCreate and the team marker, LSTN's listeners kind and block, ENC's bit-3 admission
//	          and IndexerSet naming an enclave, CACL-M12-03's block and CACL-M12-04's resources): it refuses an entry at
//	          a position before the base alike in a reader that implements the feature and in one that predates it,
//	          which refuses the entry as one it cannot read, so no entry is ever judged two ways
//	implicit  the implicit document's rules a feature adds compile into rows only once it is on, after the frozen
//	          implicit document (aclImplicitFeatureRules), their ids from a domain of their own, so every release
//	          compiles the same rows before the base and acl_implicit.hujson's golden never moves
//	hold      a reader that meets a bit its release does not implement, at that base or at a later one it starts
//	          from, applies nothing from there: its log stops there through the fork stop, a ConfigForkError whose
//	          UpgradeRequired names the features it lacks, so every path the fork stop stops stops, but with no fork
//	          alarm: the client raises upgrade_required instead (SidecarEventUpgradeRequired), and what it holds stays
//	          readable
//	older     a build from before the reservation compiles rows without field 3, so it fails the compile check of the
//	          base that turns a feature on and goes no further, before any entry uses the feature
//	update    the hold lives in memory alone, so an updated build resumes where its kept log stopped, below the base,
//	          and applies that base as any reader does, its rows checked against its head's compile, before it judges
//	          on; a build whose kept log holds a base it did not implement, a faulty one, re-derives from the newest
//	          base it keeps and writes nothing until its next base's rows and tail verdicts agree (ConfigClient)
//
// AuthFeaturesImplemented is this build's identifier set, never a tunable: a feature's owner registers it from its own
// file once every reader of this build implements it (registerAuthFeature), with the implicit fragment the feature
// adds, which is part of the feature's definition, so every build that implements a feature compiles the same rows.
// A fragment registers with its feature bit and nothing else: any condition a compile read beside the head, a clock, a
// policy version or an acknowledgment's grace, would let two readers compile different rows from one head
// (acl_compile.go's purity), so a condition such as the network's acknowledgment of listeners:publish is judged at the
// host's hook, never in rows (CONTRACTS C-33). Turning a feature on is CACL-M11-03's.
//
// On every leg, the forwarding role's and the page Worker's included, since every reader of the log holds at a base it
// cannot read: root Id, no connect type. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A set of §16.6's authorization features: ServiceSettings.auth_features' and ProjectionSettings.auth_features' bits.
type AuthFeature uint32

const (
	// The agents and agent repo kinds, the team inbox marker and the implicit document's deposit rule (§20.4).
	AuthFeatureAgentRepos AuthFeature = 1
	// §16.2's resources and actions, the document's compute block and the implicit model, buy, search and fetch rules.
	AuthFeatureComputePolicy AuthFeature = 2
	// The listeners kind, the listener: resource, the document's listeners block and the listeners rule (§26.6).
	AuthFeatureListeners AuthFeature = 4
	// Capability bit 3 and the predicates that read it, the claimed tag:enclave-<id>, the implicit ssh,
	// compute:enclave and tag:enclave owners rules, and an IndexerSet naming an enclave (§11.4, §11.10).
	AuthFeatureEnclaves AuthFeature = 8
)

// Every feature the format names, in bit order, with its name (§16.6's table).
var authFeatureNames = []struct {
	feature AuthFeature
	name    string
}{
	{feature: AuthFeatureAgentRepos, name: "agent_repos"},
	{feature: AuthFeatureComputePolicy, name: "compute_policy"},
	{feature: AuthFeatureListeners, name: "listeners"},
	{feature: AuthFeatureEnclaves, name: "enclaves"},
}

// Every bit the format names.
const authFeaturesKnown = AuthFeatureAgentRepos | AuthFeatureComputePolicy | AuthFeatureListeners | AuthFeatureEnclaves

// The domain of the implicit fragments' rule ids, beside the implicit document's own (aclImplicitRuleId).
const aclImplicitFeatureRuleDomain = "urnetwork-sidecar-v1/acl-implicit-feature-rule"

var (
	// An entry that uses a feature at a position before the base that turns it on, or a feature this state does not
	// hold on: refused at its position, alike by every reader (§16.6's before row).
	ErrAuthFeatureOff = fmt.Errorf("%w: its authorization feature is not on", ErrConfigRule)
	// A base turning on a feature this build does not implement, which api refuses before it appends it.
	ErrAuthFeatureUnsupported = fmt.Errorf("%w: an authorization feature this release does not implement", ErrConfigRefused)
	// A base whose rows clear a feature the base before set: every reader withholds it, the log staying where it is.
	ErrAuthFeatureCleared = fmt.Errorf("%w: the base clears an authorization feature", ErrConfigHeadUnavailable)
	// The log holds at a base turning on a feature this release does not implement (§16.6's hold): it applies
	// nothing from there until an update. A held ConfigForkError unwraps to it, never to ErrConfigFork.
	ErrConfigUpgradeRequired = errors.New("config log held: this release lacks an authorization feature the network turned on")
	// A name that is no feature's.
	ErrAuthFeatureUnknown = errors.New("not an authorization feature")
	// The log re-derives its state after a faulty build applied a base turning on a feature it did not implement
	// (§16.6's update row): it applies on, and nothing acts on it until the network's next base confirms it. A
	// re-derivation's ConfigForkError unwraps to it.
	ErrConfigRederiving = errors.New("config log re-deriving: nothing acts on it until the next base confirms it")
)

// A reader that lacks a feature the network turned on holds, applying nothing from that base until it is updated
// (§16.6's hold): AuthFeatures names what it lacks. A kind beside head_alarm, which `ur status` and the apps show with
// the update that ends it.
const SidecarEventUpgradeRequired SidecarEventKind = "upgrade_required"

// The feature's names, in bit order; a bit the format does not name reads as bit<n>.
func (self AuthFeature) Names() []string {
	names := []string{}
	for bit := range 32 {
		feature := AuthFeature(1) << bit
		if self&feature == 0 {
			continue
		}
		index := slices.IndexFunc(authFeatureNames, func(entry struct {
			feature AuthFeature
			name    string
		}) bool {
			return entry.feature == feature
		})
		if index < 0 {
			names = append(names, fmt.Sprintf("bit%d", bit))
			continue
		}
		names = append(names, authFeatureNames[index].name)
	}
	return names
}

// The names, joined by commas; empty for none.
func (self AuthFeature) String() string {
	return strings.Join(self.Names(), ",")
}

// The features names gives, comma separated as String writes them, a bit<n> name its bit; a name that is neither
// gives nothing. For a set that crossed a wire as its names, such as a daemon event's.
func ParseAuthFeatureNames(names string) AuthFeature {
	features := AuthFeature(0)
	for _, name := range strings.Split(names, ",") {
		if feature, err := ParseAuthFeature(name); err == nil {
			features |= feature
			continue
		}
		var bit int
		if _, err := fmt.Sscanf(name, "bit%d", &bit); err == nil && 0 <= bit && bit < 32 && fmt.Sprintf("bit%d", bit) == name {
			features |= AuthFeature(1) << bit
		}
	}
	return features
}

// The feature named name, one of §16.6's four.
func ParseAuthFeature(name string) (AuthFeature, error) {
	for _, entry := range authFeatureNames {
		if entry.name == name {
			return entry.feature, nil
		}
	}
	return 0, ErrAuthFeatureUnknown
}

// One feature this build implements: its bit, and the implicit fragment it adds, nil for none.
type authFeatureRegistration struct {
	feature  AuthFeature
	fragment []byte
}

// Every feature this build implements, as their owners' files registered them, in bit order. Written only during the
// package's init, so read without a lock after it. A test may swap it for a set of its own, and puts the original back.
var authFeatureRegistrations = []*authFeatureRegistration{}

// Registers feature as one this build implements, from an init in its owner's file, once every reader of this build
// implements it, with fragment, the implicit document's rules it adds (§16.5), nil for none: HuJSON holding grants and
// requests alone, which compile after the frozen implicit document while the feature is on. A bit that is not one
// feature, a feature registered twice, or a fragment that does not parse or holds more than grants and requests is a
// build error, which panics as registerComputeComponent does.
func registerAuthFeature(feature AuthFeature, fragment []byte) {
	if bits.OnesCount32(uint32(feature)) != 1 || feature&^authFeaturesKnown != 0 {
		panic(fmt.Sprintf("authorization feature %d is not one feature", feature))
	}
	if slices.ContainsFunc(authFeatureRegistrations, func(registration *authFeatureRegistration) bool {
		return registration.feature == feature
	}) {
		panic(fmt.Sprintf("authorization feature %s registered twice", feature))
	}
	if fragment != nil {
		if err := checkAuthFeatureFragment(fragment); err != nil {
			panic(fmt.Sprintf("authorization feature %s's implicit fragment: %v", feature, err))
		}
	}
	authFeatureRegistrations = append(authFeatureRegistrations, &authFeatureRegistration{feature: feature, fragment: append([]byte{}, fragment...)})
	slices.SortFunc(authFeatureRegistrations, func(a *authFeatureRegistration, b *authFeatureRegistration) int {
		return int(a.feature) - int(b.feature)
	})
}

// Whether a fragment is one aclImplicitFeatureRules compiles: a document holding grants and requests alone, since
// their atoms are the implicit document's (tags, groups and hosts are the document's to declare) and the implicit
// document's own defaults stand.
func checkAuthFeatureFragment(fragment []byte) error {
	policy, err := ParseAclPolicy(fragment)
	if err != nil {
		return err
	}
	if 0 < len(policy.Groups) || 0 < len(policy.TagOwners) || 0 < len(policy.Hosts) || policy.Audit != nil || 0 < len(policy.Tests) {
		return errors.New("a fragment holds grants and requests alone")
	}
	return nil
}

// The features this build implements: those their owners registered. The identifier set every reader holds a base's
// bits to, never a tunable.
func AuthFeaturesImplemented() AuthFeature {
	implemented := AuthFeature(0)
	for _, registration := range authFeatureRegistrations {
		implemented |= registration.feature
	}
	return implemented
}

// The features on at this state: its newest base's rows' bits, none before base 1.
func (self *ConfigState) AuthFeatures() AuthFeature {
	return AuthFeature(self.Settings().GetAuthFeatures())
}

// Whether every feature of feature is on at this state: its newest base's rows carry each bit (§16.6's point row).
func (self *ConfigState) AuthFeatureOn(feature AuthFeature) bool {
	return feature != 0 && self.base != nil && self.AuthFeatures()&feature == feature
}

// Nil where an entry at position may use feature: this state's newest base carries each of feature's bits and lies
// before position. Else ErrAuthFeatureOff, which refuses the entry at its position as a refusal every reader reaches
// alike, a reader without the feature refusing such an entry as one it cannot read (§16.6's before row). An entry is
// judged on the state at position-1, whose newest base lies before it; a state newer than that, whose newest base lies
// at or past position, cannot say when the feature turned on and refuses.
func (self *ConfigState) RequireAuthFeature(feature AuthFeature, position uint64) error {
	switch {
	case feature == 0 || feature&^authFeaturesKnown != 0:
		return fmt.Errorf("%w: %d names no feature", ErrAuthFeatureOff, feature)
	case !self.AuthFeatureOn(feature):
		return fmt.Errorf("%w: %s is not on at position %d", ErrAuthFeatureOff, feature, position)
	case position <= self.base.n:
		return fmt.Errorf("%w: position %d is not past the base at %d", ErrAuthFeatureOff, position, self.base.n)
	}
	return nil
}

// Whether a row is an agents' enclave's incarnation: capability bit 3 (§11.4), which no admission carries before the
// enclaves feature, since every admission refuses a bit it does not know.
func configRowEnclave(row *bridge.SidecarRow) bool {
	return row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_ENCLAVE) != 0
}

// ProjectionRows' settings field (bridge/auth.proto).
const configRowsSettingsField = protowire.Number(8)

// The features a base's rows carry, read from their bytes without parsing the rows whole: their settings'
// auth_features, every occurrence of the field merged as protobuf merges a message given twice, 0 where there is none.
func configRowsAuthFeatures(rows []byte) (AuthFeature, error) {
	message := &bridge.ProjectionSettings{}
	merge := proto.UnmarshalOptions{Merge: true}
	for len(rows) != 0 {
		number, wireType, length := protowire.ConsumeTag(rows)
		if length < 0 {
			return 0, protowire.ParseError(length)
		}
		rows = rows[length:]
		if number != configRowsSettingsField || wireType != protowire.BytesType {
			skipped := protowire.ConsumeFieldValue(number, wireType, rows)
			if skipped < 0 {
				return 0, protowire.ParseError(skipped)
			}
			rows = rows[skipped:]
			continue
		}
		settings, length := protowire.ConsumeBytes(rows)
		if length < 0 {
			return 0, protowire.ParseError(length)
		}
		rows = rows[length:]
		if err := merge.Unmarshal(settings, message); err != nil {
			return 0, err
		}
	}
	return AuthFeature(message.GetAuthFeatures()), nil
}

// §16.6's base rows for a base at kept whose rows are rowsBytes, landing on state: a bit this log's release does not
// implement holds the log there (the hold row), with nothing applied; a bit the base before set and these rows clear
// withholds the base (bits only accumulate). Nil where the base goes on to its checks.
func (self *ConfigLog) checkBaseAuthFeatures(state *ConfigState, kept *configKeptEntry, rowsBytes []byte) error {
	features, err := configRowsAuthFeatures(rowsBytes)
	if err != nil {
		return self.baseFork(kept, "rows: %v", err)
	}
	if lacking := features &^ self.authFeatures; lacking != 0 {
		return self.holdAtBase(kept, lacking)
	}
	if cleared := state.AuthFeatures() &^ features; state.base != nil && cleared != 0 {
		self.log.Errorf("[config]%s base %d clears %s, which the base before set: withheld", self.networkId, kept.n, cleared)
		return fmt.Errorf("%w: %s at base %d", ErrAuthFeatureCleared, cleared, kept.n)
	}
	return nil
}

// api's check of a base's features before it appends one (ConfigLog.CheckBase): ErrAuthFeatureUnsupported for a bit
// implemented outside implemented, api's own release's, and ErrConfigRule for rows clearing a bit the base before set,
// so neither base reaches the log. Whether every gate serving the network implements a feature is api's to check
// beside this (CACL-M11-03's feature_unsupported).
func configCheckBaseAuthFeatures(state *ConfigState, rowsBytes []byte, implemented AuthFeature) error {
	features, err := configRowsAuthFeatures(rowsBytes)
	if err != nil {
		return fmt.Errorf("%w: rows: %w", ErrConfigRule, err)
	}
	if lacking := features &^ implemented; lacking != 0 {
		return fmt.Errorf("%w: %s", ErrAuthFeatureUnsupported, lacking)
	}
	if cleared := state.AuthFeatures() &^ features; state.base != nil && cleared != 0 {
		return fmt.Errorf("%w: the base clears %s, which the base before set", ErrConfigRule, cleared)
	}
	return nil
}

// Holds the log at the base kept, which turns on lacking, features this release does not implement (§16.6's hold):
// the fork stop with UpgradeRequired set, so every later entry is refused as at a fork and every path the stop stops
// stops, logged as a warning, never a fork's error, and alarmed by the client as upgrade_required, never head_alarm.
func (self *ConfigLog) holdAtBase(kept *configKeptEntry, lacking AuthFeature) error {
	hold := &ConfigForkError{
		N:               kept.n,
		RemoteChain:     kept.chain,
		Entry:           append([]byte{}, kept.entryBytes...),
		Reason:          fmt.Sprintf("the base turns on %s, which this release does not implement", lacking),
		UpgradeRequired: lacking,
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.fork = hold
	}()
	self.log.Warningf("[config]%s held at base %d: this release lacks %s", self.networkId, kept.n, lacking)
	return hold
}

// The statements a held reader still signs (§16.6's hold): those that only take rights away, revocations, a grant's or
// a repo's revoke and a suspension, which a device stopped at a fork signs too, since removes and revocations never stop
// (§6.4). An admission, a confirmation, a grant, a share or any other act waits for the update, and so does every
// approval (ApprovalApprover), so a held reader admits and approves nothing on a state the network has moved past.
var authFeatureHoldSignedTypes = map[bridge.SignedType]bool{
	bridge.SignedType_SIGNED_GRANT_REVOKE:      true,
	bridge.SignedType_SIGNED_SUSPEND:           true,
	bridge.SignedType_SIGNED_REPO_REVOKE:       true,
	bridge.SignedType_SIGNED_MEMBER_REVOKE:     true,
	bridge.SignedType_SIGNED_SIDECAR_REVOKE:    true,
	bridge.SignedType_SIGNED_KEY_REVOKE:        true,
	bridge.SignedType_SIGNED_DELEGATION_REVOKE: true,
}

// The hold, or a re-derivation's wait, the authority's log stands at (the client's stop, Fork), nil for none and for
// an authority that follows no log of this build's, as a test's fake does.
func sidecarAuthorityHold(authority SidecarAuthority) *ConfigForkError {
	configAuthority, ok := authority.(*ConfigAuthority)
	if !ok || configAuthority == nil || configAuthority.client == nil {
		return nil
	}
	if fork := configAuthority.client.Fork(); fork.Held() {
		return fork
	}
	return nil
}

// The upgrade_required event of a hold.
func authFeatureUpgradeEvent(hold *ConfigForkError) SidecarEvent {
	return SidecarEvent{Kind: SidecarEventUpgradeRequired, AuthFeatures: hold.UpgradeRequired}
}

// The id of rule index of feature's implicit fragment: the first 16 bytes of SHA-256(domain || 0x00 || u32be(feature)
// || u32be(index)), grants first and then requests, as aclImplicitRuleId derives the implicit document's.
func aclImplicitFeatureRuleId(feature AuthFeature, index uint32) Id {
	hash := sha256.New()
	hash.Write([]byte(aclImplicitFeatureRuleDomain))
	hash.Write([]byte{0})
	hash.Write(binary.BigEndian.AppendUint32(nil, uint32(feature)))
	hash.Write(binary.BigEndian.AppendUint32(nil, index))
	var digest [sha256.Size]byte
	hash.Sum(digest[:0])
	return Id(digest[:aclAtomByteCount])
}

// Compiles each registered feature's implicit fragment that the head turns on, in bit order, after the frozen implicit
// document: its grants into rows and the local policy, then its requests, each with its feature rule id. Only a network
// with no document takes the implicit document, so only it takes these (§16.5); a document names its own rules.
func (self *aclCompiler) aclImplicitFeatureRules(rows *protocol.AclRows, ruleIds map[Id]bool, requestIds map[Id]bool) error {
	if self.hasDocument {
		return nil
	}
	for _, registration := range authFeatureRegistrations {
		if self.input.AuthFeatures&registration.feature == 0 || registration.fragment == nil {
			continue
		}
		policy, err := ParseAclPolicy(registration.fragment)
		if err != nil {
			return fmt.Errorf("%w: %s's implicit rules: %w", ErrAclCompile, registration.feature, err)
		}
		for i := range policy.Grants {
			ruleId := aclImplicitFeatureRuleId(registration.feature, uint32(i))
			if ruleIds[ruleId] {
				continue
			}
			ruleIds[ruleId] = true
			rule, local, err := self.compileGrant(ruleId, &policy.Grants[i])
			if err != nil {
				return fmt.Errorf("%s's grants[%d]: %w", registration.feature, i, err)
			}
			rows.Rules = append(rows.Rules, rule)
			self.local.Rules = append(self.local.Rules, local)
		}
		for j := range policy.Requests {
			ruleId := aclImplicitFeatureRuleId(registration.feature, uint32(len(policy.Grants)+j))
			if requestIds[ruleId] {
				continue
			}
			requestIds[ruleId] = true
			request, local, err := self.compileRequest(ruleId, &policy.Requests[j])
			if err != nil {
				return fmt.Errorf("%s's requests[%d]: %w", registration.feature, j, err)
			}
			rows.Requests = append(rows.Requests, request)
			self.local.Requests = append(self.local.Requests, local)
		}
	}
	return nil
}
