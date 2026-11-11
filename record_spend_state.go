//go:build !ios_extension

// What §16.6's spend check reads of P, the spender's current AuthPin (D-MCP-12, AD3, AD4): SpendState and the rule
// that governs an action there, SpendRule. Spendable (record_spend.go) is one pure function that the executing daemon,
// every server gate and every reader's GrantActivate check call, so all it knows of the network comes through here and
// it reads no local state or clock of its own.
//
// ConfigSpendState answers from §7.9's S(n), a ConfigState and its AclState, which both a daemon's log and a gate's
// rows-only log build (TEAM-M2-11), so a daemon and a gate answer alike from the same position:
//
//	pin              S(n)'s (n, A_n)
//	chain            A_k for every k the state retains (every position since its previous base, each kept base's
//	                 (n, A_n), and the genesis's A_0), §7.9's retain row
//	forked           what the caller knows: its log stopped at a fork or HeadCheck found one (AD3); a reader judging an
//	                 entry passes false, since a fork stops its log before any entry applies
//	approval capable §16.6's approval_capable(d, M) as the log can tell it: consented for M, untagged, not ephemeral,
//	                 read_only or suspended (AclState.ApprovalCapable); whether d's host renders and signs is no log's
//	presence key     a KeyRow of purpose presence registered to M, not revoked, not void and before its not_after at
//	                 S(n)'s time (§7.9's presence row, config_keys.go)
//	governing rule   a grant action, one naming rule_id (QD-064's fields 8, 10, 11, 28 and 29): the requests rule
//	                 MatchAclRequest finds for it at S(n), its approvers resolved for the grant's subject and
//	                 destinations, §8.6's admin clause counting an admin wherever the grant touches another member's
//	                 devices, a share or autogroup:public, its evidence the row's effective list (the format's three
//	                 channels where the row lists none), k its approvers; any other action, which no requests rule
//	                 names: the requester's owner or sponsor (§8.6's default, autogroup:self, autogroup:admin where
//	                 none stands), k = 1, and the document's evidenceDefault, which rows do not carry, so only a
//	                 caller holding the compiled policy knows it (question mcp-m3-03-evidence-default-at-gates)
//
// AD4: neither type takes a run id, an agent id, a recipient or a preview, since a gate holds none of them.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. A ConfigSpendState is immutable and
// safe for concurrent use. On every leg but the ios_extension legs, the sidecar_http page Worker's included: root Id, no
// connect type.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the spend check reads of P (§16.6's spendable). Answers never change for one value, and a value is safe for
// concurrent use.
type SpendState interface {
	// P: the spender's current (n, A_n).
	Pin() *bridge.AuthPin
	// A_k at a version the spender retains, false where it retains none (§7.9's retain row).
	ChainAt(version uint64) ([sha256.Size]byte, bool)
	// Whether the spender knows this projection forked (AD3).
	Forked() bool
	// The identity key P admits for a sidecar, a revoked one's included, nil for none.
	IdentityKey(sidecarId Id) []byte
	// Whether the sidecar is an approval-capable device of the member at P: consented for it, untagged, not
	// ephemeral, read_only or suspended (§16.6's approval_capable, D-MCP-14).
	ApprovalCapable(sidecarId Id, memberId Id) bool
	// The presence key registered to the member under key_id, live at P, else nil. The caller must not change it.
	PresenceKey(keyId []byte, memberId Id) *bridge.KeyRow
	// The rule that governs action for spender at P at time now, or an error where a rule should govern and none takes
	// the action: no rule has its rule_id, the rule no longer takes it, or its subject is not the spender.
	Govern(action *StoredCanonicalAction, spender Id, now time.Time) (SpendRule, error)
}

// The rule that governs one action at P, as the spend check reads it (§16.6, §8.6).
type SpendRule interface {
	// The governing evidence list: the matching requests rule's, else the document's evidenceDefault. False where the
	// state does not know it, which refuses every channel.
	Evidence() ([]protocol.ApprovalChannel, bool)
	// k: how many distinct eligible approvers a decision set needs, at least 1.
	ApproverCount() int
	// Whether the member approves under the rule at P.
	Eligible(memberId Id) bool
	// Whether distinct approvers meet §8.6's admin clause, true where the rule asks none.
	AdminClauseMet(memberIds []Id) bool
}

// The format's evidence list where a rule's row lists none: every §16.6 channel (§8.8's AclRequestRule).
var spendAllChannels = []protocol.ApprovalChannel{
	protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
	protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE,
	protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS,
}

// Why a state cannot answer for the spend check.
var ErrSpendStateInvalid = errors.New("spend state invalid")

// SpendState over §7.9's S(n), a daemon's or a gate's.
type ConfigSpendState struct {
	config *ConfigState
	acl    *AclState
	forked bool
	// nil where this verifier does not hold the document's evidenceDefault
	evidenceDefault []protocol.ApprovalChannel
}

// The spend state of config, with forked what the caller knows of a fork (AD3) and evidenceDefault the compiled
// document's, nil where the caller does not hold it, as a gate and every rows-only reader do not. evidenceDefault is
// copied; a channel outside §16.6's three is refused.
func NewConfigSpendState(config *ConfigState, forked bool, evidenceDefault []protocol.ApprovalChannel) (*ConfigSpendState, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: no state", ErrSpendStateInvalid)
	}
	acl, err := config.Acl()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSpendStateInvalid, err)
	}
	for _, channel := range evidenceDefault {
		if !slices.Contains(spendAllChannels, channel) {
			return nil, fmt.Errorf("%w: evidence channel %d", ErrSpendStateInvalid, channel)
		}
	}
	state := &ConfigSpendState{config: config, acl: acl, forked: forked}
	if evidenceDefault != nil {
		state.evidenceDefault = slices.Clone(evidenceDefault)
	}
	return state, nil
}

// The state's (n, A_n).
func (self *ConfigSpendState) Pin() *bridge.AuthPin {
	return self.config.Pin()
}

// A_k from the chains the state keeps, a kept base's pin, or the genesis's A_0.
func (self *ConfigSpendState) ChainAt(version uint64) ([sha256.Size]byte, bool) {
	if chain, ok := self.config.chainAt(version); ok {
		return chain, true
	}
	for _, basePin := range self.config.basePins {
		if basePin.n == version && basePin.n <= self.config.n {
			return basePin.chain, true
		}
	}
	if version == 0 {
		return self.config.genesisChain, true
	}
	return [sha256.Size]byte{}, false
}

// What the caller said.
func (self *ConfigSpendState) Forked() bool {
	return self.forked
}

// The state's identity key of the sidecar.
func (self *ConfigSpendState) IdentityKey(sidecarId Id) []byte {
	return self.config.IdentityKey(sidecarId)
}

// AclState's approval-capable device, consented for this member.
func (self *ConfigSpendState) ApprovalCapable(sidecarId Id, memberId Id) bool {
	return self.acl.ApprovalCapable(sidecarId) && self.acl.ConsentedFor(sidecarId, memberId)
}

// The row of key_id when it is a presence key of the member, not revoked, not void and before its not_after at the
// state's time, as LiveKeys judges its signer's keys.
func (self *ConfigSpendState) PresenceKey(keyId []byte, memberId Id) *bridge.KeyRow {
	if len(keyId) == 0 {
		return nil
	}
	key := self.config.RegisteredKey(keyId)
	switch {
	case key == nil,
		key.GetPurpose() != bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		!bytes.Equal(key.GetMemberId(), memberId.Bytes()),
		key.GetRevokedAt() != 0,
		key.GetNotAfter() <= self.config.timeMs,
		self.config.CascadeVoids(key.GetSigner(), key.GetAt()):
		return nil
	}
	return key
}

// A grant action's requests rule, else the default approvers. See the file header.
func (self *ConfigSpendState) Govern(action *StoredCanonicalAction, spender Id, now time.Time) (SpendRule, error) {
	if action == nil || action.Action == nil {
		return nil, fmt.Errorf("%w: no action", ErrAclRequestNoMatch)
	}
	if len(action.Action.GetRuleId()) == 0 {
		// no requests rule names the action: the requester's owner or sponsor approve (§8.6)
		selfAtom := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)
		approvers := self.acl.ResolveApprovers([][]byte{selfAtom.Bytes()}, AclSidecarSubject(spender), nil, now)
		rule := &configSpendRule{acl: self.acl, approvers: approvers, count: 1}
		if self.evidenceDefault != nil {
			rule.evidence = slices.Clone(self.evidenceDefault)
			rule.evidenceKnown = true
		}
		return rule, nil
	}

	ask, err := ParseAclGrantAction(action.Action)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclRequestNoMatch, err)
	}
	if ask.Subject != spender {
		return nil, fmt.Errorf("%w: a grant for another subject", ErrAclRequestNoMatch)
	}
	match, err := MatchAclRequest(self.acl, ask, now)
	if err != nil {
		return nil, err
	}
	adminOnly, touchedMemberIds := self.acl.grantTouches(ask, protocol.AclAudience(action.Action.GetAudience()), now.UnixMilli())
	rule := &configSpendRule{
		acl:              self.acl,
		request:          match.Rule,
		ask:              ask,
		now:              now,
		approvers:        self.acl.ResolveApprovers(match.Rule.GetApproverAtoms(), AclSidecarSubject(spender), ask.Dst, now),
		count:            max(1, int(match.Rule.GetApprovers())),
		adminOnly:        adminOnly,
		touchedMemberIds: touchedMemberIds,
		evidenceKnown:    true,
	}
	for _, channel := range match.Rule.GetEvidence() {
		rule.evidence = append(rule.evidence, protocol.ApprovalChannel(channel))
	}
	if len(rule.evidence) == 0 {
		rule.evidence = slices.Clone(spendAllChannels)
	}
	return rule, nil
}

// One governing rule at one AclState.
type configSpendRule struct {
	acl *AclState
	// the requests rule, its ask and the time it was matched at; nil for an action no requests rule names
	request *protocol.AclRequestRule
	ask     *AclGrantAsk
	now     time.Time

	approvers *AclApprovers
	count     int
	// §8.6's admin clause for a grant: only an admin meets it, or it reaches these other members' devices
	adminOnly        bool
	touchedMemberIds []Id

	evidence      []protocol.ApprovalChannel
	evidenceKnown bool
}

// The rule's list, or the document's default, or unknown.
func (self *configSpendRule) Evidence() ([]protocol.ApprovalChannel, bool) {
	return self.evidence, self.evidenceKnown
}

// The rule's approvers, at least 1.
func (self *configSpendRule) ApproverCount() int {
	return self.count
}

// The rule's resolved approvers, and an admin wherever §8.6's admin clause asks one, since an admin's approval counts
// toward k there even where the rule names no admin (acl_grant.go's quorum).
func (self *configSpendRule) Eligible(memberId Id) bool {
	if self.acl.Approves(self.approvers, memberId) {
		return true
	}
	return self.adminNeeded() && self.acl.memberAdmin(memberId)
}

// At least one admin among the approvers wherever the grant needs one, or the destinations' one owner approving as
// autogroup:dst-owner for reach to its own devices (owner decision 180).
func (self *configSpendRule) AdminClauseMet(memberIds []Id) bool {
	if !self.adminNeeded() {
		return true
	}
	if slices.ContainsFunc(memberIds, self.acl.memberAdmin) {
		return true
	}
	return !self.adminOnly && self.acl.dstOwnerApproved(self.request, self.ask, self.touchedMemberIds, memberIds, self.now)
}

// Whether the clause applies: a grant touching another member's devices, a share or autogroup:public.
func (self *configSpendRule) adminNeeded() bool {
	return self.request != nil && (self.adminOnly || 0 < len(self.touchedMemberIds))
}
