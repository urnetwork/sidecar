//go:build !ios_extension

// CanonicalAction.sealed_detail at version 5 (DESIGN-COMPUTE §16.3; D-CACL-5; CACL-M12-01): what the broker's gates,
// kinds 19 and 21, carry and must not read, a CanonicalActionDetail5 sealed as version 4's detail is (record_action_detail.go)
// in the one format every sealed field of a config record takes (config_seal.go), under the config repo's key
// generation, bound to the action's own clear fields as stored (QD-771's nonce), and under SignedType
// SIGNED_APPROVAL_DECISION rather than SIGNED_GRANT_ACTIVATE (CanonicalActionDetail5SealContext), so neither form's
// detail opens under the other's context. The approving device and the requesting one open it; no server does.
//
//	19  name   the enclave's name, which the clear field 42 leaves empty
//	    role   1 agents or 2 indexer, whose card says it "will read every member's incoming mail and the mailboxes
//	           members grant it" (§11.10)
//	    harness the harness the enclave runs, where one is named
//	21  grant_id a gateway grant the raise passes (§8.6), where it raises one; an agent's raise names its agent in the
//	           clear field 43 instead, so one action names the agent or the grant, never both
//
// §16.3's prose and Appendix D seal a detail "for kinds 19-24" while field 38's row lists 19 and 21, the two the broker
// gates: this seals 19's and 21's alone, kinds 20 and 22 to 26 reaching no server, so what they hold stays in the clear
// fields an approver reads (reported in CACL-M12-01's report).
//
// EvsRepoKey.DeriveKey runs testHookSecret at the statement key. Package-level functions are safe for concurrent use.
// On every leg but the ios_extension legs, whose forwarding role builds and approves nothing.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Opens a version-5 action's sealed_detail on an approver's or the requester's device: the config repo's key of the
// generation the detail names, under what the action's own bytes derive (CanonicalActionDetail5SealContext) in the
// device's network. nil with no error for an action that carries none; ErrConfigSealGenerationMissing while the device
// lacks the generation; ErrConfigSealInvalid or ErrCanonicalActionDetailInvalid for one that does not open or is not
// its action's. Sidecar is the device's. Safe for concurrent use.
type CanonicalActionDetail5Opener interface {
	OpenActionDetail5(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail5, error)
}

// Builds a version-5 action whose sealed_detail it seals: clear, its clear fields final, with detail sealed under the
// config repo's current key, bound to those fields in the device's network (NewSealedCanonicalAction5), for ENC's kind
// 19 and BAL's kind 21. Sidecar is the device's. Safe for concurrent use.
type CanonicalActionDetail5Sealer interface {
	SealActionDetail5(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5) (*StoredCanonicalAction, error)
}

var (
	_ CanonicalActionDetail5Opener = (*Sidecar)(nil)
	_ CanonicalActionDetail5Sealer = (*Sidecar)(nil)
)

// Holds a version-5 detail to the action that carries it, the file header's table: kind 19's names its enclave and its
// role and no grant; kind 21's names no enclave, role or harness, and a grant only where field 43 names no agent; and
// no field this build cannot name. action nil checks the detail's own shape alone.
func CheckCanonicalActionDetail5(action *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5) error {
	if detail == nil {
		return fmt.Errorf("%w: no detail", ErrCanonicalActionDetailInvalid)
	}
	if len(detail.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("%w: a field this build cannot name", ErrCanonicalActionDetailInvalid)
	}
	role := detail.GetRole()
	if role != 0 && role != approvalComputeDetailRoleAgents && role != approvalComputeDetailRoleIndexer {
		return fmt.Errorf("%w: role %d", ErrCanonicalActionDetailInvalid, role)
	}
	if action == nil {
		return nil
	}
	// the values stay out of the errors, which a log may carry (I-13)
	switch SidecarActionKind(action.GetKind()) {
	case SidecarActionEnclaveCreate:
		if detail.GetName() == "" || role == 0 || len(detail.GetGrantId()) != 0 {
			return fmt.Errorf("%w: an enclave_create's detail without its name and role, or naming a grant", ErrCanonicalActionDetailInvalid)
		}
	case SidecarActionComputeBudgetRaise:
		if detail.GetName() != "" || role != 0 || detail.GetHarness() != "" {
			return fmt.Errorf("%w: a compute_budget_raise's detail naming an enclave", ErrCanonicalActionDetailInvalid)
		}
		if len(detail.GetGrantId()) != 0 && len(action.GetBudget().GetAgentId()) != 0 {
			return fmt.Errorf("%w: a compute_budget_raise naming an agent and a grant", ErrCanonicalActionDetailInvalid)
		}
	default:
		return fmt.Errorf("%w: kind %d seals no detail at version 5", ErrCanonicalActionDetailInvalid, action.GetKind())
	}
	return nil
}

// The stored version-5 action of kind 19 or 21, its detail sealed: clear holds the action's clear fields as
// NewCanonicalAction takes them, each final, and detail what its sealed_detail opens to, held to clear and sealed
// under repoKey, bound to clear's fields as stored in networkId's network (CanonicalActionDetail5SealContext). The
// stored bytes are checked to derive what the detail was sealed to before they are answered. The caller's messages
// are not changed.
func NewSealedCanonicalAction5(clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5, repoKey *EvsRepoKey, networkId Id, random io.Reader) (*StoredCanonicalAction, error) {
	return newSealedCanonicalAction5(clear, detail, repoKey, networkId, random, CanonicalActionVersionKnown)
}

// NewSealedCanonicalAction5, given which versions are known: CanonicalActionVersionKnown outside tests.
func newSealedCanonicalAction5(clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5, repoKey *EvsRepoKey,
	networkId Id, random io.Reader, known func(version uint32) bool) (*StoredCanonicalAction, error) {
	if clear == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	if len(clear.GetSealedDetail()) != 0 {
		return nil, fmt.Errorf("%w: an action sealed already", ErrCanonicalActionInvalid)
	}
	if version := clear.GetVersion(); version != 0 && version != canonicalActionVersionCompute {
		return nil, fmt.Errorf("%w: a version-5 detail beside version %d", ErrCanonicalActionInvalid, version)
	}
	if err := CheckCanonicalActionDetail5(clear, detail); err != nil {
		return nil, err
	}
	clearBytes, err := canonicalActionClearBytes(clear)
	if err != nil {
		return nil, err
	}
	sealContext, err := CanonicalActionDetail5SealContext(networkId, clearBytes)
	if err != nil {
		return nil, err
	}
	sealed, err := SealConfigBody(repoKey, sealContext, detail, random)
	if err != nil {
		return nil, err
	}
	action := proto.Clone(clear).(*protocol.CanonicalAction)
	action.SealedDetail = sealed
	stored, err := newCanonicalAction(action, known)
	if err != nil {
		return nil, err
	}
	// every reader derives its context from the stored bytes, so they must give the one sealed under
	storedContext, err := CanonicalActionDetail5SealContext(networkId, stored.Bytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(storedContext.Nonce, sealContext.Nonce) {
		return nil, fmt.Errorf("%w: the stored clear fields are not those the detail was sealed beside", ErrCanonicalActionInvalid)
	}
	return stored, nil
}

// Opens a version-5 action's sealed_detail with the key of the generation it names, which repoKeyAt answers (nil holds
// none), under the context the action's own stored bytes derive in networkId's network
// (CanonicalActionDetail5SealContext), and holds it to the action. nil with no error for an action that carries none;
// an action at another version is refused, its detail being version 3's or 4's (OpenCanonicalActionDetail). See
// CanonicalActionDetail5Opener for the errors.
func OpenCanonicalActionDetail5(action *StoredCanonicalAction, networkId Id, repoKeyAt func(generation uint64) *EvsRepoKey) (*protocol.CanonicalActionDetail5, error) {
	if action == nil || action.Action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	sealed := action.Action.GetSealedDetail()
	if len(sealed) == 0 {
		return nil, nil
	}
	if action.Action.GetVersion() != canonicalActionVersionCompute {
		return nil, fmt.Errorf("%w: a version-%d detail opened as version 5's", ErrCanonicalActionInvalid, action.Action.GetVersion())
	}
	sealContext, err := CanonicalActionDetail5SealContext(networkId, action.Bytes)
	if err != nil {
		return nil, err
	}
	if repoKeyAt == nil {
		repoKeyAt = func(generation uint64) *EvsRepoKey { return nil }
	}
	detail := &protocol.CanonicalActionDetail5{}
	if _, err := OpenConfigBody(sealed, sealContext, repoKeyAt, detail); err != nil {
		return nil, err
	}
	if err := CheckCanonicalActionDetail5(action.Action, detail); err != nil {
		return nil, err
	}
	return detail, nil
}

// What a version-5 action's sealed_detail opens to on this device (CanonicalActionDetail5Opener): the config repo's key
// of the generation it names, in this sidecar's network, under the context the action's own bytes derive, never one a
// caller makes. With no config keys installed it answers ErrConfigSealGenerationMissing, so an approver lists deny
// alone.
func (self *Sidecar) OpenActionDetail5(action *StoredCanonicalAction) (*protocol.CanonicalActionDetail5, error) {
	if action == nil || action.Action == nil {
		return nil, fmt.Errorf("%w: no action", ErrCanonicalActionInvalid)
	}
	if len(action.Action.GetSealedDetail()) == 0 {
		return nil, nil
	}
	networkId, configKeys, err := self.actionDetailKeys()
	if err != nil {
		return nil, err
	}
	return OpenCanonicalActionDetail5(action, networkId, configKeys.ConfigKeyAt)
}

// The stored version-5 action of clear with detail sealed in its sealed_detail on this device
// (CanonicalActionDetail5Sealer): under the config repo's current key, bound to clear's fields, which the caller has
// made final, in this sidecar's network (NewSealedCanonicalAction5). With no config keys installed it seals nothing.
func (self *Sidecar) SealActionDetail5(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5) (*StoredCanonicalAction, error) {
	networkId, configKeys, err := self.actionDetailKeys()
	if err != nil {
		return nil, err
	}
	repoKey, err := configKeys.CurrentConfigKey(ctx)
	if err != nil {
		return nil, err
	}
	if repoKey == nil {
		return nil, fmt.Errorf("%w: no current config key", ErrConfigSealGenerationMissing)
	}
	return NewSealedCanonicalAction5(clear, detail, repoKey, networkId, nil)
}
