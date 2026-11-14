// §22.7's decisions row through the real gate on an approval world (MCP-M3-24; §16.6's spend check, D-MCP-12, AD1,
// AD3): a decision is spent only by its requester, a second daemon presenting the first's unspent decision refused; a
// decision whose auth_pin digest differs from the one the spender retains at that version is refused; and at k = 2 one
// approver's decision does not spend, a non-eligible signer's adds nothing, and two eligible approvers' spend. Each
// refusal beside the twin that must succeed. An approver revoked after signing is FS-29's (fault/fs29.go), and a
// replayed GrantActivate is ACL-M4-02's grant component, which has not landed.

package sidecartest

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A world on a Net of its own, and its exact mail action filed and pending.
func newApprovalSuiteWorld(t *testing.T, name string, net *Net) (*ApprovalWorld, *sidecar.StoredCanonicalAction, sidecar.Id) {
	t.Helper()
	world, err := NewApprovalWorld(net, name)
	if err != nil {
		t.Fatal(err)
	}
	action, err := world.MailAction("someone@recipient.example")
	if err != nil {
		t.Fatal(err)
	}
	err = world.Authorize(t.Context(), world.Action(action))
	pending := &sidecar.ApprovalPendingError{}
	if !errors.As(err, &pending) {
		t.Fatalf("the first call: %v", err)
	}
	return world, action, pending.ApprovalId
}

// A Signed as stored, as Authorize takes it.
func approvalSuiteSigned(t *testing.T, stored []byte) *bridge.Signed {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(stored, signed); err != nil {
		t.Fatal(err)
	}
	return signed
}

// AD1: a second daemon presenting the first's unspent decision for the same action is refused and spends nothing; the
// first daemon presenting it spends.
func TestDecisionSpentOnlyByItsRequester(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	first, action, approvalId := newApprovalSuiteWorld(t, "daemon", net)
	second, err := NewApprovalWorld(net, "daemon2")
	if err != nil {
		t.Fatal(err)
	}
	decision, err := first.SignDecision(approvalId, 1, net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout), first.Phone, first.State().Pin())
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Gate().Authorize(t.Context(), second.Action(action), approvalSuiteSigned(t, decision)); err == nil {
		t.Fatal("another daemon spent the decision")
	}
	if second.Sink(sidecar.SidecarActionMail).EffectCount() != 0 {
		t.Fatal("another daemon's refused spend ran an effect")
	}
	// twin: its requester spends it
	presented := first.Action(action)
	if err := first.Gate().Authorize(t.Context(), presented, approvalSuiteSigned(t, decision)); err != nil || presented.Outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("the requester's spend: %v %+v", err, presented.Outcome)
	}
	if err := first.CheckEffects(false); err != nil {
		t.Error(err)
	}
}

// A decision made at the spender's pin version with another digest, a projection that forked from the spender's, is
// refused and spends nothing; its twin, on a world of its own so no refused decision is kept beside it, the decision at
// the retained digest, spends.
func TestDecisionWithAnotherDigestRefused(t *testing.T) {
	present := func(forked bool) (*ApprovalWorld, *sidecar.SidecarAction, error) {
		net := NewNet(t.Context(), nil)
		defer net.Close()
		world, action, approvalId := newApprovalSuiteWorld(t, "daemon", net)
		pin := world.State().Pin()
		if forked {
			forkedChain := sha256.Sum256([]byte("another projection's chain"))
			pin = &bridge.AuthPin{Version: pin.GetVersion(), Chain: forkedChain[:]}
		}
		notAfter := net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
		decision, err := world.SignDecision(approvalId, 1, notAfter, world.Phone, pin)
		if err != nil {
			t.Fatal(err)
		}
		presented := world.Action(action)
		err = world.Gate().Authorize(t.Context(), presented, approvalSuiteSigned(t, decision))
		return world, presented, err
	}
	world, presented, err := present(true)
	if err == nil {
		t.Fatalf("a decision at another digest spent: %+v", presented.Outcome)
	}
	if world.Sink(sidecar.SidecarActionMail).EffectCount() != 0 {
		t.Fatal("a refused decision ran an effect")
	}
	world, presented, err = present(false)
	if err != nil || presented.Outcome.State != sidecar.ApprovalOutcomeDone || world.Sink(sidecar.SidecarActionMail).EffectCount() != 1 {
		t.Fatalf("the honest decision: %v %+v", err, presented.Outcome)
	}
}

// At k = 2, one eligible approver's decision does not spend and a non-eligible signer's adds nothing; a second eligible
// approver's makes the set, which spends.
func TestTwoApproversNeeded(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	world, err := NewApprovalWorld(net, "daemon")
	if err != nil {
		t.Fatal(err)
	}
	world.SetApprovers(2, world.Member, world.Other.MemberId)
	action, err := world.MailAction("someone@recipient.example")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pending := &sidecar.ApprovalPendingError{}
	if err := world.Authorize(ctx, world.Action(action)); !errors.As(err, &pending) {
		t.Fatalf("the first call: %v", err)
	}
	notAfter := net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
	if err := world.Approve(ctx, pending.ApprovalId, 1, notAfter, nil); err != nil {
		t.Fatal(err)
	}
	if err := world.Authorize(ctx, world.Action(action)); err == nil {
		t.Fatal("one approver of two spent")
	}
	stranger, err := world.SignDecision(pending.ApprovalId, 1, notAfter, world.Stranger, world.State().Pin())
	if err != nil {
		t.Fatal(err)
	}
	if err := world.Gate().Authorize(ctx, world.Action(action), approvalSuiteSigned(t, stranger)); err == nil {
		t.Fatal("a non-eligible signer made the set")
	}
	if world.Sink(sidecar.SidecarActionMail).EffectCount() != 0 {
		t.Fatal("an incomplete set ran an effect")
	}
	// twin: the second eligible approver's decision makes the set
	other, err := world.SignDecision(pending.ApprovalId, 1, notAfter, world.Other, world.State().Pin())
	if err != nil {
		t.Fatal(err)
	}
	presented := world.Action(action)
	if err := world.Gate().Authorize(ctx, presented, approvalSuiteSigned(t, other)); err != nil || presented.Outcome.State != sidecar.ApprovalOutcomeDone {
		t.Fatalf("two eligible approvers: %v %+v", err, presented.Outcome)
	}
	if err := world.CheckEffects(false); err != nil {
		t.Error(err)
	}
}

// A decision whose ledger row was appended and whose append's answer was lost still counts: the inbox's next poll
// finds it kept and notes the request decided, so the action spends it rather than waiting on a request already decided
// until a restart rebuilds the index (§22.8's unknown rule; the inbox's intake, MCP-M3-05). The twin loses nothing.
func TestDecisionWhoseAnswerWasLostStillCounts(t *testing.T) {
	for _, lose := range []bool{true, false} {
		func() {
			net := NewNet(t.Context(), nil)
			defer net.Close()
			world, action, approvalId := newApprovalSuiteWorld(t, "daemon", net)
			if lose {
				// the next write to the approval's ledger is the decision's row: applied, its answer lost
				if _, err := net.Faults().Add(&FaultPlan{Op: FaultOpPut, KeyPrefix: "approvals/" + approvalId.String(), Result: ApplyThenDrop}); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			notAfter := net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
			if err := world.Approve(ctx, approvalId, 1, notAfter, nil); err != nil {
				t.Fatal(err)
			}
			// the inbox's next poll, as its Run makes one
			if err := world.Gate().Inbox().Poll(ctx); err != nil {
				t.Fatal(err)
			}
			presented := world.Action(action)
			if err := world.Authorize(ctx, presented); err != nil || presented.Outcome == nil || presented.Outcome.State != sidecar.ApprovalOutcomeDone {
				t.Fatalf("lost %t: the use: %v %+v", lose, err, presented.Outcome)
			}
			if count := len(world.Log().ApprovalIds()); count != 1 {
				t.Errorf("lost %t: %d requests filed", lose, count)
			}
		}()
	}
}

// FI-7's oracle bites: a world whose sink holds an effect under a key no Reserve holds fails AU2, and its twin, the
// same world with nothing done, passes.
func TestApprovalEffectsOracleBites(t *testing.T) {
	net := NewNet(t.Context(), nil)
	defer net.Close()
	world, _, _ := newApprovalSuiteWorld(t, "daemon", net)
	if err := world.CheckEffects(true); err != nil {
		t.Fatalf("a world with nothing done: %v", err)
	}
	world.Sink(sidecar.SidecarActionMail).DoneUnder(sha256.New().Sum(nil))
	if err := world.CheckEffects(false); err == nil {
		t.Error("an effect under a key no Reserve holds passed")
	}
}
