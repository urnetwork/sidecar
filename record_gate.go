//go:build !ios_extension

// §5.4's real gate, which replaces sidecarGateDeny behind Sidecar.Authorize (MCP-M3-06; R-MCP-9, D-MCP-4, D-MCP-11,
// D-MCP-12, I-8, I-9, TS1, AU1-AU4, FI-2, FI-7, R-TRUST-6). Under §16.6 Authorize runs the whole spend, so the effect
// comes in with the action (plan-MCP-effect-seam), in this order:
//
//	1  tainted, from the run file now: true for a run file that does not read (D-MCP-16); no run, an app's or a
//	   typed ur command's action, is untainted
//	2  untainted and a standing grant covers it (ACL-M4-02's AclEngine.ActiveGrant): the effect under an empty key,
//	   no ledger row; in a tainted run no standing grant passes (TS1)
//	3  the decisions: the one passed, kept first through the inbox's intake, else an approval of this action, its
//	   detail (the socket name, local port, weight and ALPNs its request binds, QD-740, QD-772), run and agent the
//	   inbox holds: one whose
//	   use of this action is reserved, the retry path, else the newest approved, one filed in a tainted run first
//	   where this run is tainted
//	4  none: the request found or filed (ApprovalRouter), then ApprovalHarnessEvidence asked for a harness decision on
//	   it (MCP-M3-10); none answers *ApprovalPendingError with the request's id
//	5  §16.6's spend steps (record_gate_spend.go): the approval's mutex, spendable, the step 3 refusals, the Reserve's
//	   fsync, the effect under effect_key, the Outcome, the use's approval_use entry
//
// A request whose newest decision for this action denies, or that an approver cancelled, refuses rather than filing
// again, so a person's no stops the agent instead of asking again. An action whose request expired with no use
// reserved files a new one. A retry of an action whose use is done or not_done answers that outcome, the effect not
// run again (AU4).
//
// The gate holds no lock of its own across a step: the ledger's per-approval mutex covers steps 1 to 4 of the spend
// and nothing else, the router's filing lock a filing, the inbox's intake lock an intake. Safe for concurrent use. On
// every leg but the ios_extension legs, whose forwarding role spends nothing.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// The newest decision on this action's request denies it.
	ErrApprovalDenied = errors.New("approval denied")
	// The approval's use of this action would come past its not_after (§16.6's spend step 3).
	ErrApprovalExpired = errors.New("approval expired")
	// The action's kind has no registered Lookup, so no use of it is reserved (plan-MCP-effect-seam).
	ErrApprovalNoLookup = errors.New("the action's kind registers no lookup")
)

// ACL-M4-02's standing grants as the gate asks them, faked until M4: whether an active approved grant covers the
// action for the spender at now. The gate never asks in a tainted run (TS1).
type ApprovalStandingGrants interface {
	ActiveGrant(action *StoredCanonicalAction, spender Id, now time.Time) bool
}

// MCP-M3-10's harness evidence as the gate asks it: a harness decision this sidecar signed on request under §16.6's
// harness_ok, its Signed as stored, or nil where no evidence counts. An error counts as none.
type ApprovalHarnessEvidence interface {
	HarnessDecision(ctx context.Context, action *SidecarAction, request *StoredApprovalRequest) ([]byte, error)
}

// What the gate asks beyond the requester's approval state.
type ApprovalGateArgs struct {
	// nil: no standing grant passes, so every action takes a decision
	Grants ApprovalStandingGrants
	// nil: no harness evidence, so a member with no other device or presence key waits for one
	Harness ApprovalHarnessEvidence
	// Each kind's registered Lookup (Sidecar.RegisterEffectLookup); nil, or nil for a kind, refuses it before its
	// Reserve.
	Lookups func(kind SidecarActionKind) SidecarEffectLookup
}

// §16.6's gate for one sidecar. Safe for concurrent use.
type ApprovalGate struct {
	args    *ApprovalArgs
	inbox   *ApprovalInbox
	router  *ApprovalRouter
	grants  ApprovalStandingGrants
	harness ApprovalHarnessEvidence
	lookups func(kind SidecarActionKind) SidecarEffectLookup
	log     Logger
	flights *approvalFlights
}

var _ SidecarGate = (*ApprovalGate)(nil)

// A gate over args, its inbox and router, and gateArgs.
func NewApprovalGate(args *ApprovalArgs, inbox *ApprovalInbox, router *ApprovalRouter, gateArgs *ApprovalGateArgs) (*ApprovalGate, error) {
	if err := args.check(); err != nil {
		return nil, err
	}
	if inbox == nil || router == nil {
		return nil, fmt.Errorf("%w: a gate needs its inbox and router", errInvalidSettings)
	}
	if gateArgs == nil {
		gateArgs = &ApprovalGateArgs{}
	}
	return &ApprovalGate{
		args:    args,
		inbox:   inbox,
		router:  router,
		grants:  gateArgs.Grants,
		harness: gateArgs.Harness,
		lookups: gateArgs.Lookups,
		log:     loggerOrDefault(args.Log),
		flights: newApprovalFlights(),
	}, nil
}

// The gate's inbox, whose Receive and ReceiveCancel take what the record's hints deliver.
func (self *ApprovalGate) Inbox() *ApprovalInbox {
	return self.inbox
}

// The gate's router.
func (self *ApprovalGate) Router() *ApprovalRouter {
	return self.router
}

// The Lookup of kind, nil for none.
func (self *ApprovalGate) lookup(kind SidecarActionKind) SidecarEffectLookup {
	if self.lookups == nil {
		return nil
	}
	return self.lookups(kind)
}

// §5.4's gate as §16.6 runs it: nil once the action's effect has an outcome, set in action.Outcome;
// *ApprovalPendingError while it waits for a person; any other error refuses, the effect not run. See the file
// header for the steps.
func (self *ApprovalGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	if action == nil || action.Effect == nil {
		return fmt.Errorf("%w: an action with no effect", ErrSidecarActionInvalid)
	}
	stored, err := ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSidecarActionInvalid, err)
	}
	if SidecarActionKind(stored.Action.GetKind()) != action.Kind {
		return fmt.Errorf("%w: kind %d for an action of kind %d", ErrSidecarActionInvalid, action.Kind, stored.Action.GetKind())
	}
	if err := self.inbox.ensureLoaded(); err != nil {
		return err
	}
	now := self.args.Clock.Now()

	// 1: the run's taint, now
	tainted := action.RunId != nil && self.args.Runs.RunTainted(*action.RunId)

	// 2: a standing grant, in an untainted run alone
	if !tainted && self.grants != nil && self.grants.ActiveGrant(stored, self.args.SidecarId, now) {
		effectRef, runErr := action.Effect.Run(ctx, nil)
		action.Outcome = approvalOutcomeOfRun(effectRef, runErr, false)
		return nil
	}

	// 3: the decisions
	var approvalId Id
	found := false
	if decision != nil {
		storedSigned, err := proto.Marshal(decision)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrApprovalRefused, err)
		}
		approvalId, err = self.inbox.Receive(ctx, storedSigned)
		if err != nil {
			return err
		}
		found = true
	} else {
		approvalId, found, err = self.candidate(stored, action, tainted, now)
		if err != nil {
			return err
		}
	}

	// 4: no decision yet: the request, and the harness's evidence on it
	if !found {
		request, err := self.router.findOrFile(ctx, action, stored, tainted)
		if err != nil {
			return err
		}
		if storedSigned := self.harnessDecision(ctx, action, request); storedSigned != nil {
			if harnessApprovalId, err := self.inbox.Receive(ctx, storedSigned); err == nil && harnessApprovalId == request.ApprovalId() {
				approvalId, found = harnessApprovalId, true
			} else if err != nil {
				self.log.Warningf("[approval]a harness decision on approval %s was not kept: %s", request.ApprovalId(), err)
			}
		}
		if !found {
			return &ApprovalPendingError{ApprovalId: request.ApprovalId()}
		}
	}

	// 5: the spend
	return self.spend(ctx, action, stored, approvalId, tainted)
}

// The harness decision MCP-M3-10's evidence signs on request, its Signed as stored, nil for none.
func (self *ApprovalGate) harnessDecision(ctx context.Context, action *SidecarAction, request *StoredApprovalRequest) []byte {
	if self.harness == nil {
		return nil
	}
	storedSigned, err := self.harness.HarnessDecision(ctx, action, request)
	if err != nil {
		if self.log.V(1).Enabled() {
			self.log.Infof("[approval]no harness evidence for approval %s: %s", request.ApprovalId(), err)
		}
		return nil
	}
	return storedSigned
}

// Step 3 without a decision passed: the approval the inbox holds for this action, run and agent that the spend takes,
// and false for none, where step 4 files. An approval whose use of this action is reserved comes first, the retry
// path; then the newest whose decisions approve it, filed tainted first where this run is tainted, so the spend's
// stale refusal meets only an untainted request the run has no tainted one beside. A newest decided approval that
// denies or was cancelled refuses.
func (self *ApprovalGate) candidate(action *StoredCanonicalAction, sidecarAction *SidecarAction, tainted bool, now time.Time) (Id, bool, error) {
	candidates := self.inbox.candidates(action, sidecarAction.Detail, sidecarAction.RunId, sidecarAction.AgentId)
	approved := []Id{}
	approvedTaintMatch := []Id{}
	// the newest decided request for exactly this action, of the run's taint and of the other: a denial or a cancel
	// there refuses ahead of an approval of the other taint, which would only be stale and ask again
	var refusal, refusalTaintMatch error
	decidedTaintMatch := false
	decidedOther := false
	for _, candidate := range candidates {
		approvalId := candidate.request.ApprovalId()
		actionId := ApprovalActionId(approvalId, action.Bytes)
		state, err := self.args.Ledger.State(approvalId)
		if err != nil {
			// a file that does not read spends nothing (D-CORE-15)
			self.log.Warningf("[approval]approval %s does not read: %s", approvalId, err)
			continue
		}
		if state.FindReserve(actionId[:]) != nil {
			return approvalId, true, nil
		}
		if !candidate.decided {
			continue
		}
		logCancelled := self.inbox.logCancelled(approvalId)
		taintMatch := candidate.request.Request.GetTainted() == tainted
		if approvalUsable(state, logCancelled, now) {
			approved = append(approved, approvalId)
			if taintMatch {
				approvedTaintMatch = append(approvedTaintMatch, approvalId)
			}
		}
		if !bytesEqualAction(candidate.request.Action, action) {
			continue
		}
		var answer error
		switch approvalStatusOf(state, candidate.request, logCancelled, now).State {
		case ApprovalStatusDenied:
			answer = fmt.Errorf("%w: approval %s", ErrApprovalDenied, approvalId)
		case ApprovalStatusCancelled:
			answer = fmt.Errorf("%w: approval %s", ErrApprovalCancelled, approvalId)
		}
		// only the newest decided request of each taint speaks for it
		if taintMatch && !decidedTaintMatch {
			decidedTaintMatch = true
			refusalTaintMatch = answer
		} else if !taintMatch && !decidedOther {
			decidedOther = true
			refusal = answer
		}
	}
	switch {
	case 0 < len(approvedTaintMatch):
		return approvedTaintMatch[0], true, nil
	case refusalTaintMatch != nil:
		return Id{}, false, refusalTaintMatch
	case 0 < len(approved):
		return approved[0], true, nil
	case refusal != nil:
		return Id{}, false, refusal
	}
	return Id{}, false, nil
}

// Whether a request's action is exactly this one, not a template it falls inside.
func bytesEqualAction(requested *StoredCanonicalAction, action *StoredCanonicalAction) bool {
	return bytes.Equal(requested.Bytes, action.Bytes)
}

// What a host gives §16.6's gate beyond the sidecar's own ledger, run store, record and effect lookups.
type ApprovalGateSources struct {
	// P now: NewConfigApprovalStates over the ConfigClient's verified state and the compiled policy. Nil files no
	// request and keeps no decision, so every action is refused.
	States func() (ApprovalStates, error)
	// ACL-M4-02's standing grants; nil for none.
	Grants ApprovalStandingGrants
	// MCP-M3-10's harness evidence; nil for none.
	Harness ApprovalHarnessEvidence
}

// The requester's approval arguments over this sidecar's own state: its identity, its network's ledger and record, its
// run store and its presence counts, with states for P. ErrSidecarStoreLocked before enrollment and
// ErrSidecarNoIdentity before an identity.
func (self *Sidecar) ApprovalArgs(states func() (ApprovalStates, error)) (*ApprovalArgs, error) {
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	ledger, err := self.ApprovalLedger()
	if err != nil {
		return nil, err
	}
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	counter, err := NewApprovalPresenceCounts(self.LocalStore())
	if err != nil {
		return nil, err
	}
	return &ApprovalArgs{
		SidecarId: identity.SidecarId,
		Ledger:    ledger,
		Approvals: record.Approvals(),
		Runs:      self,
		States:    states,
		Counter:   counter,
		Clock:     self.settings.ClockOrReal(),
		Settings:  self.settings.Mcp,
		Spend:     DefaultSpendSettings(),
		Log:       self.log,
	}, nil
}

// Builds §16.6's gate over this sidecar's ledger, record, run store, presence counts and registered lookups, with
// sources for the rest, and installs it behind Authorize in place of whatever gate stood (InstallGate). Answers the gate
// and its removal. The host runs the gate's Reconcile once before it serves, and its inbox's Run for the poll.
func (self *Sidecar) InstallApprovalGate(sources *ApprovalGateSources) (*ApprovalGate, func(), error) {
	if sources == nil {
		sources = &ApprovalGateSources{}
	}
	args, err := self.ApprovalArgs(sources.States)
	if err != nil {
		return nil, nil, err
	}
	inbox, err := NewApprovalInbox(args)
	if err != nil {
		return nil, nil, err
	}
	router, err := NewApprovalRouter(args, inbox)
	if err != nil {
		return nil, nil, err
	}
	gate, err := NewApprovalGate(args, inbox, router, &ApprovalGateArgs{
		Grants:  sources.Grants,
		Harness: sources.Harness,
		Lookups: self.effectLookup,
	})
	if err != nil {
		return nil, nil, err
	}
	return gate, self.InstallGate(gate), nil
}

// The installed §16.6 gate, or ErrApprovalNoState where another gate, or none, stands.
func (self *Sidecar) ApprovalGate() (*ApprovalGate, error) {
	gate, ok := self.gate().(*ApprovalGate)
	if !ok {
		return nil, fmt.Errorf("%w: no approval gate is installed", ErrApprovalNoState)
	}
	return gate, nil
}

// Where one of this sidecar's approvals stands, the data behind ur://approval/{id} and RECORD-M3-09's approval_status:
// its log asked first for a decision while it waits, so the answer is the newest the log holds. ErrApprovalUnknown for
// a request this sidecar never filed, ErrApprovalNoState with no approval gate installed.
func (self *Sidecar) ApprovalStatus(ctx context.Context, approvalId Id) (*ApprovalStatus, error) {
	gate, err := self.ApprovalGate()
	if err != nil {
		return nil, err
	}
	return gate.inbox.freshStatus(ctx, approvalId)
}

// Status after a poll of the approval's log while the request waits; a failed poll leaves the ledger's answer.
func (self *ApprovalInbox) freshStatus(ctx context.Context, approvalId Id) (*ApprovalStatus, error) {
	if err := self.ensureLoaded(); err != nil {
		return nil, err
	}
	waiting := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		indexed, ok := self.approvalIdRequests[approvalId]
		return ok && !indexed.decided && !self.logCancelledApprovalIds[approvalId]
	}()
	if waiting {
		if err := self.pollOne(ctx, approvalId); err != nil && ctx.Err() != nil {
			return nil, err
		}
	}
	return self.Status(approvalId)
}
