//go:build !ios_extension && !sidecar_http

// The outward-action gate as a Harness run uses it (DESIGN-COMPUTE §7.8, I-8, I-9, DESIGN §5.4, §16.6): an O tool's
// before-hook calls HarnessRun.Authorize, which builds the action with the run's and agent's binding
// (NewSidecarAction) and presents it to Sidecar.Authorize. While the gate waits for a person (*ApprovalPendingError)
// the run emits approval_pending, with the action's canonical text as the daemon built it and the evidence a decision
// may carry, then waits on the requester's inbox for that approval with no polling: each change of the approval wakes
// it, and it presents the action to the gate again, so the decision is spent by the gate, its use reserved before the
// effect runs, never taken as spent here. A decision the gate does not count (a harness prompt in a tainted run, where
// I-9 asks a person on another approval-capable device or a presence key) leaves the action waiting for the next. It
// emits approval_resolved once the gate passes or a person refuses.
//
// A decision the device's safety classifier made, channel auto (§27.9), shows as the note "approved automatically by
// this device's check", never as the person's approval. Which channels count, and when the classifier may decide
// first (kinds 23-27 in their tainted cases, §7.8's last bullet), is the gate's and SAFE's: this file presents and
// waits.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The gate refused the action: a person denied or cancelled it, or it expired before a decision.
	ErrHarnessApprovalRefused = errors.New("the outward action was refused")
	// The action waits for a person, and this Harness has no approvals to wait on.
	ErrHarnessApprovalUnavailable = errors.New("no approvals are wired to wait on")
)

// §5.4's gate: Sidecar.Authorize.
type HarnessGate interface {
	Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
}

var _ HarnessGate = (*Sidecar)(nil)

// The requester's approvals as a waiting action watches them: the installed §16.6 gate's inbox and ledger.
type HarnessApprovals interface {
	// Calls callback with each approval whose state changes from now on; the answer removes it.
	AddUpdateCallback(callback ApprovalUpdateFunction) func()
	// Where one approval stands.
	Status(approvalId Id) (*ApprovalStatus, error)
	// What an approver's device shows of the request: the daemon-built action, never the agent's words as the action.
	Render(approvalId Id) (*ApprovalRender, error)
}

// SAFE's record of an automatic decision (§27.9's auto_verdict): why the device's check let the action go ahead, and
// its score.
type HarnessAutoVerdicts interface {
	Verdict(approvalId Id) (*HarnessAutoVerdict, error)
}

// What a tool's before-hook asks the gate for: the action the daemon built (NewCanonicalAction, never the agent's
// words), its risks, what binds it on this device, and its effect, which the gate runs once its use is reserved.
type HarnessAuthorizeRequest struct {
	// The kind the tool means to take, which the action must be.
	Kind   SidecarActionKind
	Action *StoredCanonicalAction
	// The policy's and the daemon classifier's risk, and what the agent asked, which may only raise it.
	PolicyRisk     SidecarRisk
	AgentAskedRisk SidecarRisk
	Detail         *SidecarActionDetail
	Uses           uint32
	Template       []byte
	// The agent's own words about the action, shown to an approver as untrusted text.
	Summary string
	// Required: the effect the gate runs.
	Effect SidecarEffect
}

// The channel's name, as record.proto's enum names it.
func harnessApprovalChannelName(channel protocol.ApprovalChannel) string {
	switch channel {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE:
		return "device"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		return "presence"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
		return "harness"
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO:
		return "auto"
	}
	return "unknown"
}

// The evidence a decision for this run may come by, which a view shows beside the request: device and presence
// always, a harness prompt only in an untainted run (I-9; owner decision 142). Which one counts is the gate's.
func (self *HarnessRun) evidenceWanted() []string {
	if self.Tainted() {
		return []string{"device", "presence"}
	}
	return []string{"device", "presence", "harness"}
}

// Presents request's action to the gate from a tool's before-hook and waits for a person where it must, as the file
// header says. Answers the effect's outcome once the gate passed, ErrHarnessApprovalRefused where a person refused
// or the request expired, ctx's error where the run stopped waiting, or the gate's own refusal.
func (self *HarnessRun) Authorize(ctx context.Context, request *HarnessAuthorizeRequest) (*SidecarOutcome, error) {
	if request == nil || request.Action == nil || request.Action.Action == nil || request.Effect == nil {
		return nil, ErrSidecarActionInvalid
	}
	if SidecarActionKind(request.Action.Action.GetKind()) != request.Kind {
		return nil, fmt.Errorf("%w: kind %d asked for an action of kind %d", ErrSidecarActionInvalid, request.Kind,
			request.Action.Action.GetKind())
	}
	if self.gate == nil {
		return nil, ErrSidecarGateDenied
	}
	runId, agentId := self.runId, self.agentId
	action, err := NewSidecarAction(request.Action, request.PolicyRisk, request.AgentAskedRisk, &runId, &agentId)
	if err != nil {
		return nil, err
	}
	action.Detail = request.Detail
	action.Uses = request.Uses
	action.Template = request.Template
	action.Summary = request.Summary
	action.Effect = request.Effect

	// every change of any approval wakes the wait, which reads its own approval again; subscribed before the first
	// presentation, and coalesced, so a change is never lost: a signal is dropped only while one is already waiting
	changed := make(chan struct{}, 1)
	removeCallback := func() {}
	if self.approvals != nil {
		removeCallback = self.approvals.AddUpdateCallback(func(approvalId Id) {
			select {
			case changed <- struct{}{}:
			default:
			}
		})
	}
	defer removeCallback()

	announcedIds := []Id{}
	// the approval's status read just before the latest presentation, nil before one is known
	var presentedWith *ApprovalStatus
	for {
		err := self.gate.Authorize(ctx, action, nil)
		pending := &ApprovalPendingError{}
		if !errors.As(err, &pending) {
			if err == nil {
				for _, approvalId := range announcedIds {
					self.emitResolved(approvalId)
				}
			}
			return action.Outcome, err
		}
		if self.approvals == nil {
			return nil, fmt.Errorf("%w: approval %s waits for a person", ErrHarnessApprovalUnavailable, pending.ApprovalId)
		}
		approvalId := pending.ApprovalId
		if !slices.Contains(announcedIds, approvalId) {
			announcedIds = append(announcedIds, approvalId)
			self.emitPending(approvalId)
		}
		status, err := self.approvals.Status(approvalId)
		if err != nil {
			return nil, err
		}
		switch status.State {
		case ApprovalStatusDenied, ApprovalStatusCancelled, ApprovalStatusExpired:
			self.emitResolved(approvalId)
			return nil, fmt.Errorf("%w: approval %s is %s", ErrHarnessApprovalRefused, approvalId, status.State)
		}
		if status.State != ApprovalStatusPending && (presentedWith == nil || presentedWith.ApprovalId != approvalId ||
			harnessApprovalMoved(presentedWith, status)) {
			// a decision the last presentation may not have seen: present it again at once
			presentedWith = status
			continue
		}
		// nothing new for the gate (no decision yet, or one it did not count): wait for the approval to move
		for moved := false; !moved; {
			select {
			case <-changed:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			now, err := self.approvals.Status(approvalId)
			if err != nil {
				return nil, err
			}
			moved = harnessApprovalMoved(status, now)
			presentedWith = now
		}
	}
}

// Whether an approval moved between two reads: its state, a decision kept, a use reserved.
func harnessApprovalMoved(before *ApprovalStatus, after *ApprovalStatus) bool {
	return before.State != after.State || len(before.Channels) != len(after.Channels) ||
		before.UsedCount != after.UsedCount || before.Uses != after.Uses
}

// Emits approval_pending for the request: its kind and canonical text as an approver's device renders it, and the
// evidence wanted. A request the approvals cannot render shows its id alone.
func (self *HarnessRun) emitPending(approvalId Id) {
	if self.emit == nil {
		return
	}
	pending := &HarnessApprovalPending{ApprovalId: approvalId, Evidence: self.evidenceWanted(), Tainted: self.Tainted()}
	if render, err := self.approvals.Render(approvalId); err == nil {
		pending.Kind = render.KindName
		pending.Text = render.Text()
		pending.Tainted = render.Tainted
	}
	self.emit(self.agentId, NewHarnessApprovalPendingEvent(pending))
}

// Emits approval_resolved: where the approval stands, the channels of its kept decisions, and for a decision the
// device's check made alone, its verdict and the note, never the person's approval.
func (self *HarnessRun) emitResolved(approvalId Id) {
	if self.emit == nil || self.approvals == nil {
		return
	}
	resolved := &HarnessApprovalResolved{ApprovalId: approvalId, State: string(ApprovalStatusApproved)}
	if status, err := self.approvals.Status(approvalId); err == nil {
		resolved.State = string(status.State)
		automatic := 0 < len(status.Channels)
		for _, channel := range status.Channels {
			resolved.Channels = append(resolved.Channels, harnessApprovalChannelName(channel))
			if channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO {
				automatic = false
			}
		}
		if automatic {
			resolved.Auto = &HarnessAutoVerdict{}
			if self.autoVerdicts != nil {
				if verdict, err := self.autoVerdicts.Verdict(approvalId); err == nil && verdict != nil {
					resolved.Auto = verdict
				}
			}
		}
	}
	self.emit(self.agentId, NewHarnessApprovalResolvedEvent(resolved))
}

// The installed §16.6 gate's inbox and ledger, as a Harness run waits on them.
type harnessGateApprovals struct {
	gate *ApprovalGate
}

// The approvals of the gate installed on sidecar, or an error where none is.
func newHarnessGateApprovals(sidecar *Sidecar) (HarnessApprovals, error) {
	gate, err := sidecar.ApprovalGate()
	if err != nil {
		return nil, err
	}
	return &harnessGateApprovals{gate: gate}, nil
}

func (self *harnessGateApprovals) AddUpdateCallback(callback ApprovalUpdateFunction) func() {
	return self.gate.Inbox().AddUpdateCallback(callback)
}

func (self *harnessGateApprovals) Status(approvalId Id) (*ApprovalStatus, error) {
	return self.gate.Inbox().Status(approvalId)
}

func (self *harnessGateApprovals) Render(approvalId Id) (*ApprovalRender, error) {
	state, err := self.gate.args.Ledger.State(approvalId)
	if err != nil {
		return nil, err
	}
	if state.Request == nil {
		return nil, fmt.Errorf("%w: %s", ErrApprovalUnknown, approvalId)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		return nil, err
	}
	return RenderApprovalRequest(request), nil
}
