// ur approve for requests: the list, a request's render on /dev/tty with the daemon-built action apart from the
// agent's untrusted text and every control character dropped, a decision only on a yes, uses passed for a template, a
// request shown refused never prompted, no terminal refused, a cancel, and the deciding methods Confirm ones.

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A daemon target serving the authority approvals and the requests, as a test sets them.
type testUrRequestsTarget struct {
	testUrApprovalsTarget
	requests         []*sidecar.SidecarRequestItem
	requestDecisions []string
	cancels          []sidecar.Id
}

func (self *testUrRequestsTarget) pendingRequests(ctx context.Context) ([]*sidecar.SidecarRequestItem, error) {
	return self.requests, nil
}

func (self *testUrRequestsTarget) decideRequest(ctx context.Context, approvalId sidecar.Id, decision *sidecar.SidecarRequestDecision) error {
	self.requestDecisions = append(self.requestDecisions, approvalId.String()+" "+decision.Decision+" "+strings.Repeat("+", int(decision.Uses)))
	return nil
}

func (self *testUrRequestsTarget) cancelApproval(ctx context.Context, approvalId sidecar.Id) error {
	self.cancels = append(self.cancels, approvalId)
	return nil
}

// A dns_set request whose agent text claims other rdata than its action carries, as the approver's device renders it.
func testUrDnsRequestItem(t *testing.T, summary string) *sidecar.SidecarRequestItem {
	t.Helper()
	action, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionDnsSet), DnsName: "app.example", DnsType: "A", DnsValue: "198.51.100.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	approvalId := sidecar.NewId()
	actionId := action.ActionId(approvalId)
	payloadSha256 := action.PayloadSha256()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], CanonicalAction: action.Bytes, PayloadSha256: payloadSha256[:],
		Summary: summary, Risk: uint32(sidecar.SidecarRiskNormal), RequesterSidecarId: sidecar.NewId().Bytes(),
		Approvers: [][]byte{sidecar.NewId().Bytes()}, NotAfterMillis: time.Now().Add(time.Hour).UnixMilli(), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := sidecar.ParseStoredApprovalRequest(stored)
	if err != nil {
		t.Fatal(err)
	}
	return &sidecar.SidecarRequestItem{
		ApprovalId: approvalId,
		EntryId:    sidecar.NewId(),
		Render:     sidecar.RenderApprovalRequest(request),
		Decisions:  []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionDeny},
	}
}

// §22.7's actions row on the printed text: ur approve <id> shows the action's own dns_value as the action and the
// agent's claim only as untrusted text, every control character dropped, and decides only on a yes.
func TestPreviewClaimingOtherRdataShowsDnsValue(t *testing.T) {
	item := testUrDnsRequestItem(t, "set app.example A 192.0.2.10\x1b[2J‮")
	target := &testUrRequestsTarget{requests: []*sidecar.SidecarRequestItem{item}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "approve"}); code != urExitOk || !strings.Contains(stdout.String(), item.ApprovalId.String()+"  request dns_set") {
		t.Fatalf("the list: exit %d: %s", code, stdout.String())
	}
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", item.ApprovalId.String()}); code != urExitOk || len(target.requestDecisions) != 0 {
		t.Fatalf("a no decided: exit %d, %v", code, target.requestDecisions)
	}
	printed := tty.written.String()
	action, untrusted, found := strings.Cut(printed, "untrusted text")
	if !found || !strings.Contains(action, "dns_value: 198.51.100.7") || strings.Contains(action, "192.0.2.10") ||
		!strings.Contains(untrusted, "192.0.2.10") {
		t.Errorf("the terminal showed:\n%s", printed)
	}
	if strings.ContainsAny(printed, "\x1b‮") {
		t.Errorf("a control character reached the terminal: %q", printed)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "approve", item.ApprovalId.String(), "--deny"}); code != urExitOk ||
		len(target.requestDecisions) != 1 || target.requestDecisions[0] != item.ApprovalId.String()+" deny " {
		t.Errorf("a yes to deny: exit %d, %v", code, target.requestDecisions)
	}
}

// Control characters a daemon's answer carries never reach the terminal, whatever the daemon sent.
func TestControlCharactersDroppedFromPrintedText(t *testing.T) {
	item := testUrDnsRequestItem(t, "")
	target := &testUrRequestsTarget{requests: []*sidecar.SidecarRequestItem{item}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	item.Render.KindName = "dns_set\x1b]0;title\x07"
	item.Render.Summary = "line\rover⁦write\u0085"
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", item.ApprovalId.String()}); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	for _, control := range []string{"\x1b", "\x07", "\r", "⁦", "\u0085"} {
		if strings.Contains(tty.written.String(), control) {
			t.Errorf("%q reached the terminal", control)
		}
	}
}

// §22.5's M3 row at the command: a request whose action version this build does not know lists refused, and ur approve
// asks nothing of the person about it; one this device may not decide is refused before any prompt.
func TestApproverRefusesUnknownActionVersion(t *testing.T) {
	refused := &sidecar.SidecarRequestItem{EntryId: sidecar.NewId(), Refused: "approval version unknown: canonical action version 9", Decisions: []string{}}
	notOurs := testUrDnsRequestItem(t, "")
	notOurs.Decisions = []string{}
	target := &testUrRequestsTarget{requests: []*sidecar.SidecarRequestItem{refused, notOurs}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "approve"}); code != urExitOk ||
		!strings.Contains(stdout.String(), "refused  entry "+refused.EntryId.String()) {
		t.Fatalf("the list: exit %d: %s", code, stdout.String())
	}
	tty := &testTty{lines: []string{"yes"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", refused.EntryId.String()}); code != urExitFailed {
		t.Errorf("approving a refused request's entry: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "approve", notOurs.ApprovalId.String()}); code != urExitFailed {
		t.Errorf("approving another member's request: exit %d", code)
	}
	if tty.written.Len() != 0 || len(target.requestDecisions) != 0 {
		t.Errorf("the person was asked, or something decided: %q, %v", tty.written.String(), target.requestDecisions)
	}
}

// With no terminal, ur approve <id> and ur approve cancel <id> refuse and decide nothing, never reading stdin.
func TestApproveRequestNeedsATerminal(t *testing.T) {
	item := testUrDnsRequestItem(t, "")
	target := &testUrRequestsTarget{requests: []*sidecar.SidecarRequestItem{item}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	cli.stdin = strings.NewReader("yes\n")
	if code := cli.main(context.Background(), []string{"ur", "approve", item.ApprovalId.String()}); code != urExitFailed {
		t.Errorf("no terminal: exit %d", code)
	}
	if code := cli.main(context.Background(), []string{"ur", "approve", "cancel", item.ApprovalId.String()}); code != urExitFailed {
		t.Errorf("no terminal for a cancel: exit %d", code)
	}
	if !strings.Contains(stderr.String(), "terminal") || len(target.requestDecisions) != 0 || len(target.cancels) != 0 {
		t.Errorf("%q, %v, %v", stderr.String(), target.requestDecisions, target.cancels)
	}
}

// A template's approval passes the person's uses; a cancel goes on a yes.
func TestApproveRequestUsesAndCancel(t *testing.T) {
	item := testUrDnsRequestItem(t, "")
	target := &testUrRequestsTarget{requests: []*sidecar.SidecarRequestItem{item}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"y"}}, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", item.ApprovalId.String(), "--uses=3"}); code != urExitOk ||
		len(target.requestDecisions) != 1 || target.requestDecisions[0] != item.ApprovalId.String()+" approve +++" {
		t.Errorf("--uses: exit %d, %v", code, target.requestDecisions)
	}
	if code := cli.main(context.Background(), []string{"ur", "approve", "cancel", item.ApprovalId.String()}); code != urExitOk ||
		len(target.cancels) != 1 || target.cancels[0] != item.ApprovalId {
		t.Errorf("cancel: exit %d, %v", code, target.cancels)
	}
}

// approvals.request and approvals.cancel are Confirm methods, so no mcp or hook session and no unconfirmed call reaches
// them; the list is not.
func TestRequestMethodsAreConfirmOnly(t *testing.T) {
	methods := urApproveRequestMethods(&testUrRequestsTarget{})
	if len(methods) != 3 {
		t.Fatalf("%d methods", len(methods))
	}
	for _, method := range methods {
		wantConfirm := method.Name != urMethodApprovalsRequests
		if method.Confirm != wantConfirm {
			t.Errorf("%s: Confirm %v", method.Name, method.Confirm)
		}
	}
	if methods := urApproveRequestMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the request methods")
	}
}
