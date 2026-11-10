// The real SidecarAuthority (CORE-M2-01's seam, C-10): §5's device acts read §7.9's verified state through it, and
// TEAM-M2-10's ConfigClient supplies it, replacing sidecartest.FakeAuthority with no CORE code changed. Each answer is
// ConfigState's own, the one definition: an admission is its row; a member's devices its untagged admissions; consent
// §8.5's one predicate (AclState.ConsentedFor); a binding, the presence rule, live keys and the cascade the state's;
// and each applied entry reaches AddEntryCallback once, from the client's one follower.
//
// It also answers SidecarAuthorityCatchUp (a follow now), SidecarIndexerAuthority (§7.9's IndexerSet) and
// SidecarAuthorityProposals, DESIGN-DETAILS 5.7's PendingProposal and Settings, which CORE-M3-03's acts watch a k-of-n
// proposal and read self_admit by. The last is an interface beside SidecarAuthority rather than two more methods on it,
// so CORE's other implementers, its tests' fakes, keep compiling; an authority without it holds no proposal.
//
// Every answer is a copy the caller may keep. Before the client reads its first state, every answer is empty and the
// pin is (0, A_0). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What an authority answers of §7.9's open proposals and the settings a verifier judges by (DESIGN-DETAILS 5.7's
// SidecarAuthority line). Optional beside SidecarAuthority.
type SidecarAuthorityProposals interface {
	// The row of a proposal open at the newest state, as ProjectionRows carries it; nil for one closed, expired or
	// unknown.
	PendingProposal(proposalId []byte) *bridge.ProposalRow
	// The ServiceSettings values every verifier judges by (ProjectionRows.settings): self_admit and scim_signer.
	Settings() *bridge.ProjectionSettings
}

// The authority a ConfigClient's verified state gives.
type ConfigAuthority struct {
	client *ConfigClient
}

var (
	_ SidecarAuthority          = (*ConfigAuthority)(nil)
	_ SidecarAuthorityCatchUp   = (*ConfigAuthority)(nil)
	_ SidecarIndexerAuthority   = (*ConfigAuthority)(nil)
	_ SidecarAuthorityProposals = (*ConfigAuthority)(nil)
)

// The authority over this client's verified state, which a host installs with Sidecar.InstallAuthority.
func (self *ConfigClient) Authority() *ConfigAuthority {
	return &ConfigAuthority{client: self}
}

// The newest verified (n, A_n); (0, A_0) before the first read.
func (self *ConfigAuthority) Pin() *bridge.AuthPin {
	if pin := self.client.Pin(); pin != nil {
		return pin
	}
	genesisChain := self.client.args.GenesisChain
	return &bridge.AuthPin{Version: 0, Chain: genesisChain[:]}
}

// The sidecar's admission row, revoked tombstones included; nil for one no SidecarAdmit names.
func (self *ConfigAuthority) Admission(sidecarId Id) *AclSidecar {
	state := self.client.State()
	if state == nil {
		return nil
	}
	return configCloneAclSidecar(state.Sidecar(sidecarId))
}

// Every sidecar whose untagged admission names memberId, revoked ones included, in id order.
func (self *ConfigAuthority) MemberDevices(memberId Id) []*AclSidecar {
	devices := []*AclSidecar{}
	state := self.client.State()
	if state == nil {
		return devices
	}
	for _, sidecarId := range state.SidecarIds() {
		if rowMemberId, untagged := configRowMember(state.SidecarRow(sidecarId)); untagged && rowMemberId == memberId {
			if admission := state.Sidecar(sidecarId); admission != nil {
				devices = append(devices, configCloneAclSidecar(admission))
			}
		}
	}
	return devices
}

// §8.5's consented(d, M), ACL's one predicate.
func (self *ConfigAuthority) Consented(sidecarId Id, memberId Id) bool {
	state := self.client.State()
	if state == nil {
		return false
	}
	acl, err := state.Acl()
	return err == nil && acl.ConsentedFor(sidecarId, memberId)
}

// The member's recovery binding in effect; nil for none.
func (self *ConfigAuthority) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	state := self.client.State()
	if state == nil {
		return nil
	}
	binding := state.CurrentBinding(memberId)
	if binding == nil {
		return nil
	}
	return proto.Clone(binding).(*bridge.RecoveryBindingRow)
}

// Whether §7.9's presence row covers the statement as signed by its signer, from the log.
func (self *ConfigAuthority) PresenceRequired(statement *SidecarStatement) bool {
	state := self.client.State()
	return state != nil && state.PresenceRequired(statement)
}

// The presence keys the sidecar registered that are live at the newest state.
func (self *ConfigAuthority) LiveKeys(sidecarId Id) []*bridge.KeyRow {
	keys := []*bridge.KeyRow{}
	state := self.client.State()
	if state == nil {
		return keys
	}
	for _, key := range state.LiveKeys(sidecarId) {
		keys = append(keys, proto.Clone(key).(*bridge.KeyRow))
	}
	return keys
}

// What a compromise revocation of targetId from sinceN parks and voids, and what stands: the state's CascadePlan.
func (self *ConfigAuthority) Cascade(targetId Id, sinceN uint64) ([]DeviceRevokeItem, error) {
	state := self.client.State()
	if state == nil {
		return nil, ErrConfigClientClosed
	}
	plan, err := state.CascadePlan(targetId, sinceN)
	if err != nil {
		return nil, err
	}
	return plan.Items(), nil
}

// The first retained entry timed at or after lostAt, and its time; false when none is.
func (self *ConfigAuthority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	self.client.followLock.Lock()
	defer self.client.followLock.Unlock()
	log := self.client.configLog.Load()
	if log == nil {
		return 0, time.Time{}, false
	}
	for _, kept := range log.kept {
		if lostAt.UnixMilli() <= kept.entry.GetTimeMs() {
			return kept.n, time.UnixMilli(kept.entry.GetTimeMs()), true
		}
	}
	return 0, time.Time{}, false
}

// Calls callback with each entry applied from now on; the answer removes it.
func (self *ConfigAuthority) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	return self.client.AddEntryCallback(callback)
}

// A follow now, answering once it ran.
func (self *ConfigAuthority) CatchUp(ctx context.Context) error {
	return self.client.CatchUp(ctx)
}

// The IndexerSet designations naming sidecarId that stand.
func (self *ConfigAuthority) IndexerDesignations(sidecarId Id) []SidecarIndexerDesignation {
	state := self.client.State()
	if state == nil {
		return nil
	}
	return state.IndexerDesignations(sidecarId)
}

// The row of a proposal open at the newest state; nil for one closed, expired or unknown.
func (self *ConfigAuthority) PendingProposal(proposalId []byte) *bridge.ProposalRow {
	state := self.client.State()
	if state == nil || len(proposalId) != sha256.Size {
		return nil
	}
	proposal := state.proposals[[sha256.Size]byte(proposalId)]
	if proposal == nil || !proposal.open(state.timeMs) {
		return nil
	}
	return proto.Clone(proposal.row).(*bridge.ProposalRow)
}

// The ServiceSettings values every verifier judges by.
func (self *ConfigAuthority) Settings() *bridge.ProjectionSettings {
	state := self.client.State()
	if state == nil {
		return &bridge.ProjectionSettings{}
	}
	return proto.Clone(state.Settings()).(*bridge.ProjectionSettings)
}

// A copy of an admission sharing nothing with the state, nil for nil.
func configCloneAclSidecar(admission *AclSidecar) *AclSidecar {
	if admission == nil {
		return nil
	}
	clone := *admission
	clone.TagIds = append([]Id(nil), admission.TagIds...)
	if admission.Row != nil {
		clone.Row = proto.Clone(admission.Row).(*bridge.SidecarRow)
	}
	return &clone
}
