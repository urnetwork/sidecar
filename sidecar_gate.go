// §5.4's outward-action gate (CORE-M3-01, D-CORE-11, R-CORE-14, I-8, I-9, FI-7): every outward method, MCP's,
// control mode's, the CLI's, local SMTP submission's and the sdk remote backend's, calls Sidecar.Authorize, one entry
// point, before its effect. Authorize holds the action to its shape and hands it to the installed SidecarGate, §16's
// ledger and spend check (MCP's track), which passes it under an active approved grant (§8) or a §16.6 decision whose
// spend check passes, the use reserved durably before the effect (D-MCP-11), or writes an ApprovalRequest and answers
// *ApprovalPendingError, which Authorize announces as approval_pending.
//
// Fail closed: until §16's track installs a gate, sidecarGateDeny refuses every action, and a nil gate never passes.
// The run binding (RunId, AgentId) and the decision pass through unchanged, so §16's gate judges a tainted run's
// fresh decision and the requests rule's harness evidence (TS1, owner decision 142); a server-visible action carries
// the decision on to §8.10's gate in its effect. sidecarGateKinds is §5.4's whole list, held equal to record.proto's
// SidecarActionKind by a test, so a kind added there with no row here fails rather than reaching no gate.
//
// On every leg: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No gate has been installed, so every outward action is refused (I-8).
	ErrSidecarGateDenied = errors.New("no outward-action gate is installed, so every outward action is refused")
	// The action is not one Authorize takes: no kind, a kind §5.4 does not list, no canonical bytes, or no risk.
	ErrSidecarActionInvalid = errors.New("the outward action is malformed")
)

// §16's ledger and spend check behind Authorize, which MCP's track installs. Safe for concurrent use.
type SidecarGate interface {
	// Passes action under an active approved grant or decision, a §16.6 ApprovalDecision whose spend check passes,
	// reserving the use before it answers nil; else writes an ApprovalRequest and answers *ApprovalPendingError, or
	// refuses with another error. decision may be nil.
	Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
}

// The gate until one is installed: refuses every action, never an implied allow.
type sidecarGateDeny struct{}

// Refuses.
func (self sidecarGateDeny) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	return ErrSidecarGateDenied
}

// §5.4's whole list of outward actions, in SidecarActionKind's order: a kind Authorize takes is one here. Its length
// is the list's, so a kind appended to SidecarActionKind needs its row, which TestEveryKindReachesGate holds against
// record.proto's enum.
var sidecarGateKinds = [...]SidecarActionKind{
	SidecarActionPublish,
	SidecarActionListen,
	SidecarActionForward,
	SidecarActionExpose,
	SidecarActionEgressChange,
	SidecarActionInvite,
	SidecarActionShare,
	SidecarActionAliasCreate,
	SidecarActionAliasDelete,
	SidecarActionAgentConfigWrite,
	SidecarActionAgentConfigDelete,
	SidecarActionDnsSet,
	SidecarActionDnsDelete,
	SidecarActionMail,
	SidecarActionAccessRequest,
	SidecarActionPayment,
	SidecarActionRestore,
}

// Whether kind is one of §5.4's.
func sidecarGateKindKnown(kind SidecarActionKind) bool {
	for _, known := range sidecarGateKinds {
		if known == kind {
			return true
		}
	}
	return false
}

// The installed gate, under its own lock.
type sidecarGates struct {
	stateLock sync.Mutex
	gate      SidecarGate
}

// An outward action from what the daemon built: action, a CanonicalAction held to its kind's row and stored
// (NewCanonicalAction), never an agent's words; its risk the largest of the policy's, the daemon classifier's and what
// the agent asked, so an agent may only raise it (CanonicalActionRisk); and the run binding a decision binds.
func NewSidecarAction(action *StoredCanonicalAction, policyRisk SidecarRisk, agentAskedRisk SidecarRisk, runId *Id, agentId *Id) (*SidecarAction, error) {
	if action == nil || action.Action == nil || len(action.Bytes) == 0 {
		return nil, ErrSidecarActionInvalid
	}
	kind := SidecarActionKind(action.Action.GetKind())
	if !sidecarGateKindKnown(kind) {
		return nil, fmt.Errorf("%w: kind %d", ErrSidecarActionInvalid, kind)
	}
	sidecarAction := &SidecarAction{
		Kind:      kind,
		Canonical: append([]byte{}, action.Bytes...),
		Risk:      CanonicalActionRisk(action, policyRisk, agentAskedRisk),
	}
	if runId != nil {
		id := *runId
		sidecarAction.RunId = &id
	}
	if agentId != nil {
		id := *agentId
		sidecarAction.AgentId = &id
	}
	return sidecarAction, nil
}

// SHA-256 of the canonical bytes as stored: the payload_sha256 a decision and its use bind (§16.8).
func (self *SidecarAction) PayloadSha256() [sha256.Size]byte {
	return sha256.Sum256(self.Canonical)
}

// Installs gate behind Authorize, replacing any before; the answer removes it, if it is still the installed one, and
// Authorize refuses every action again. nil refuses every action.
func (self *Sidecar) InstallGate(gate SidecarGate) func() {
	self.gates.stateLock.Lock()
	self.gates.gate = gate
	self.gates.stateLock.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.gates.stateLock.Lock()
			defer self.gates.stateLock.Unlock()
			if self.gates.gate == gate {
				self.gates.gate = nil
			}
		})
	}
}

// The gate Authorize runs: the installed one, else sidecarGateDeny.
func (self *Sidecar) gate() SidecarGate {
	self.gates.stateLock.Lock()
	defer self.gates.stateLock.Unlock()
	if self.gates.gate == nil {
		return sidecarGateDeny{}
	}
	return self.gates.gate
}

// §5.4's gate, the one entry point every outward method calls before its effect (D-CORE-11): nil when the installed
// gate passed action under an approved grant or a decision, the use reserved; *ApprovalPendingError while it waits for
// a person, approval_pending raised with its id; any other error refuses. A malformed action is refused before any
// gate sees it, and with no gate installed every action is refused (I-8). decision may be nil; the run binding passes
// through unchanged.
func (self *Sidecar) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	if action == nil || !sidecarGateKindKnown(action.Kind) || len(action.Canonical) == 0 ||
		(action.Risk != SidecarRiskNormal && action.Risk != SidecarRiskHigh) {
		return ErrSidecarActionInvalid
	}
	testHookBarrier("sidecar.authorize.before", fmt.Sprint(int(action.Kind)))
	err := self.gate().Authorize(ctx, action, decision)
	testHookBarrier("sidecar.authorize.after", fmt.Sprint(int(action.Kind)))
	pending := &ApprovalPendingError{}
	if errors.As(err, &pending) {
		approvalId := pending.ApprovalId
		self.emitEvent(SidecarEvent{Kind: SidecarEventApprovalPending, ApprovalId: &approvalId})
	}
	return err
}
