//go:build !ios_extension

// The team directory's half in the core (§16.11, §5.4, §5.8; CORE-M6-02), on every leg the directory runs on: the
// access_request outward action a directory request passes §5.4's gate as, and the three events the directory raises.
//
//	gate      a directory request is O (§16.11's endorse row): its filer builds a CanonicalAction of kind
//	          access_request at version 3, in fields 8, 10, 11, 14, 26 and 29, with a worker's port and its port
//	          text sealed in field 38 and nowhere in the clear (QD-740; RECORD-M6-18's DirectoryAccessAction,
//	          through MCP-M3-02's builder), and files nothing before AuthorizeAccessRequest
//	          passes it, under the member's decision: harness under harness_ok in an untainted run, device or presence
//	          in a tainted one (owner decisions 74, 75, 142), which the installed gate judges with §16.6's TS1.
//	          Approvers know version 3 (CanonicalActionVersionKnown, MCP-M6-01), and with no gate installed Authorize
//	          refuses every action, so nothing passes before one is
//	events    access_request: a pending request for a target this device approves (§16.11's notify row);
//	          access_decided: the requester's, with its outcome, approved, denied, cancelled or expired (the receipt
//	          and expire rows; QD-178); directory_erasure: a repo owner's revocation still waiting for the directory's
//	          erasure runner past 24 h, pending, then done (the revoke row). Each names its request by id, and the
//	          erasure its repo, never any prose
//
// Root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// access_request's CanonicalAction version (§16.8's version comment, 16.11).
const sidecarAccessRequestVersion = 3

// access_decided's outcomes (§5.4's SidecarEvent.Outcome).
const (
	SidecarAccessDecidedApproved  = "approved"
	SidecarAccessDecidedDenied    = "denied"
	SidecarAccessDecidedCancelled = "cancelled"
	SidecarAccessDecidedExpired   = "expired"
)

// directory_erasure's outcomes (§5.4's SidecarEvent.Outcome).
const (
	SidecarDirectoryErasurePending = "pending"
	SidecarDirectoryErasureDone    = "done"
)

// An event whose fields are not its kind's: no id, or an outcome its kind does not take. Nothing was raised.
var ErrSidecarEventInvalid = errors.New("an event's fields are not its kind's")

// Passes a directory request's access_request action through §5.4's gate before anything is filed (§16.11's endorse
// row): action is the filer's, built by MCP-M3-02's builder at version 3 and stored, its risk the largest of the
// policy's and what the agent asked (CanonicalActionRisk), and the run binding the endorsement binds. nil once the gate
// passed it, the use reserved; *ApprovalPendingError while the member's decision is awaited; any other error refuses.
// An action of another kind or version, or whose stored bytes say otherwise, is refused before any gate sees it.
func (self *Sidecar) AuthorizeAccessRequest(ctx context.Context, action *StoredCanonicalAction, policyRisk SidecarRisk,
	agentAskedRisk SidecarRisk, runId *Id, agentId *Id, decision *bridge.Signed) error {
	if action == nil || len(action.Bytes) == 0 {
		return fmt.Errorf("%w: no access request", ErrSidecarActionInvalid)
	}
	// the gate judges the stored bytes, so they are what is held to the kind
	stored := &protocol.CanonicalAction{}
	if err := proto.Unmarshal(action.Bytes, stored); err != nil ||
		SidecarActionKind(stored.GetKind()) != SidecarActionAccessRequest || stored.GetVersion() != sidecarAccessRequestVersion {
		return fmt.Errorf("%w: not a version-3 access_request", ErrSidecarActionInvalid)
	}
	sidecarAction, err := NewSidecarAction(&StoredCanonicalAction{Action: stored, Bytes: action.Bytes}, policyRisk, agentAskedRisk, runId, agentId)
	if err != nil {
		return err
	}
	return self.Authorize(ctx, sidecarAction, decision)
}

// Raises access_request for a pending request a target of this device's waits on (§16.11's notify row).
func (self *Sidecar) RaiseAccessRequest(requestId Id) error {
	if requestId == (Id{}) {
		return fmt.Errorf("%w: access_request names no request", ErrSidecarEventInvalid)
	}
	self.emitEvent(SidecarEvent{Kind: SidecarEventAccessRequest, RequestId: &requestId})
	return nil
}

// Raises access_decided for this device's own request, with its outcome: approved, denied, cancelled or expired.
func (self *Sidecar) RaiseAccessDecided(requestId Id, outcome string) error {
	outcomes := []string{SidecarAccessDecidedApproved, SidecarAccessDecidedDenied, SidecarAccessDecidedCancelled, SidecarAccessDecidedExpired}
	if requestId == (Id{}) || !slices.Contains(outcomes, outcome) {
		return fmt.Errorf("%w: access_decided", ErrSidecarEventInvalid)
	}
	self.emitEvent(SidecarEvent{Kind: SidecarEventAccessDecided, RequestId: &requestId, Outcome: outcome})
	return nil
}

// Raises directory_erasure for a repo owner's revocation of repoId, its erasure request requestId, pending past 24 h or
// done.
func (self *Sidecar) RaiseDirectoryErasure(repoId Id, requestId Id, outcome string) error {
	if repoId == (Id{}) || requestId == (Id{}) || (outcome != SidecarDirectoryErasurePending && outcome != SidecarDirectoryErasureDone) {
		return fmt.Errorf("%w: directory_erasure", ErrSidecarEventInvalid)
	}
	self.emitEvent(SidecarEvent{Kind: SidecarEventDirectoryErasure, RepoId: &repoId, RequestId: &requestId, Outcome: outcome})
	return nil
}
