//go:build !ios_extension && !sidecar_http

// An agent repo's keyed label (DESIGN-COMPUTE §20.4, §20.7; QD-1434; SKILL-M11-01): RepoCreate's label_mac, which binds
// an agent repo to its name for every admitted sidecar of the network and to nothing for api, which sees a per-network
// value that names no agent and links nothing across networks.
//
//	key    K_label = HKDF-SHA256(K_ref of the config repo, salt network_id, info "urnetwork-sidecar-v1/agent-repo-label"),
//	       32 B. K_ref derives from the config repo's RK_1 with g = 1 at every generation (§10.5, D-KEYS-22), so every
//	       admitted sidecar, each a reader of the config repo, derives the same K_label for the network's life from any
//	       generation it holds, its ladder giving RK_1, and a label filed under one generation verifies under every later
//	       one. A reader that has lost the network can still test a guessed name against a label it saw, as with the
//	       config's ref ids, and nothing more
//	label  label_mac = the first 16 bytes of HMAC-SHA256(K_label, "agent/" || name), the agent repo's label as §20.4 writes
//	       it, filed by the creating device in the agent repo's RepoCreate
//	check  a reader recomputes it for the name a card or message gives and compares it in constant time with the row the
//	       log folded, beside the member the row binds (AclState.MemberAgentRepoLabeled): what SKILL-M13-01's
//	       cross-member check of to.repo and from.repo reads; within a member the card binds name to repo (§20.5)
//
// testHookSecret sees K_ref and K_label at their derivations. On the compute legs.

package sidecar

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// K_label's HKDF info, beside §10.5's purposes' own domain.
const agentRepoLabelKeyInfo = "urnetwork-sidecar-v1/agent-repo-label"

// K_label's size, a SHA-256's.
const agentRepoLabelKeyByteCount = sha256.Size

// What label_mac covers: §20.4's agent/<name>.
const agentRepoLabelPrefix = "agent/"

// No K_label: the config repo's key is not held at a generation whose ladder reached RK_1, or the key given is
// another repo's.
var ErrAgentRepoLabelKey = errors.New("agents: no agent repo label key")

// One network's K_label (QD-1434). Immutable, so safe for concurrent use.
type AgentRepoLabelKey struct {
	networkId Id
	key       []byte
}

// K_label from configKey, the network's config repo's key at any generation whose ladder reached RK_1.
func NewAgentRepoLabelKey(networkId Id, configRepoId Id, configKey *EvsRepoKey) (*AgentRepoLabelKey, error) {
	if networkId == (Id{}) || configRepoId == (Id{}) || configKey == nil || configKey.RepoId() != configRepoId {
		return nil, fmt.Errorf("%w: not the config repo's key", ErrAgentRepoLabelKey)
	}
	refKey, err := configKey.DeriveKey(EvsKeyPurposeRef, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentRepoLabelKey, err)
	}
	defer clear(refKey)
	return newAgentRepoLabelKey(networkId, refKey)
}

// K_label from the config repo's K_ref.
func newAgentRepoLabelKey(networkId Id, refKey []byte) (*AgentRepoLabelKey, error) {
	if len(refKey) != agentRepoLabelKeyByteCount {
		return nil, fmt.Errorf("%w: a K_ref of %d bytes", ErrAgentRepoLabelKey, len(refKey))
	}
	key, err := hkdf.Key(sha256.New, refKey, networkId.Bytes(), agentRepoLabelKeyInfo, agentRepoLabelKeyByteCount)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAgentRepoLabelKey, err)
	}
	testHookSecret("K_agent_label", key)
	return &AgentRepoLabelKey{networkId: networkId, key: key}, nil
}

// The network whose key this is.
func (self *AgentRepoLabelKey) NetworkId() Id {
	return self.networkId
}

// label_mac of the agent repo named name: the first AgentRepoLabelMacByteCount bytes of HMAC-SHA256(K_label,
// "agent/" || name).
func (self *AgentRepoLabelKey) Mac(name AgentName) []byte {
	mac := hmac.New(sha256.New, self.key)
	mac.Write([]byte(agentRepoLabelPrefix))
	mac.Write([]byte(name))
	return mac.Sum(nil)[:AgentRepoLabelMacByteCount]
}

// Whether labelMac is name's, compared in constant time.
func (self *AgentRepoLabelKey) Labels(labelMac []byte, name AgentName) bool {
	return len(labelMac) == AgentRepoLabelMacByteCount && hmac.Equal(labelMac, self.Mac(name))
}

// K_label at this sidecar: the config repo's generation 1 from its key client, whose ladder gives RK_1, at the network
// the verified state's Genesis names. ErrEvsNoConfig before a verified state.
func (self *EvsClient) AgentRepoLabelKey(ctx context.Context) (*AgentRepoLabelKey, error) {
	if self.args.Config == nil || self.args.Gkm == nil {
		return nil, ErrEvsNoConfig
	}
	view := self.args.Config()
	if view == nil {
		return nil, ErrEvsNoConfig
	}
	state, ok := view.(interface{ Genesis() *bridge.Genesis })
	if !ok || state.Genesis() == nil {
		return nil, ErrEvsNoConfig
	}
	configRepoId, err := IdFromBytes(state.Genesis().GetConfigRepoId())
	if err != nil {
		return nil, fmt.Errorf("%w: the Genesis names no config repo", ErrAgentRepoLabelKey)
	}
	configKey, err := self.args.Gkm.RepoKey(ctx, configRepoId, 1)
	if err != nil {
		return nil, fmt.Errorf("%w: the config repo's first generation: %w", ErrAgentRepoLabelKey, err)
	}
	return NewAgentRepoLabelKey(self.args.NetworkId, configRepoId, configKey)
}
