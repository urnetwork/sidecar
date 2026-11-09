// ur approve: the list, a decision confirmed on /dev/tty with the safety number shown first, a no that decides
// nothing, and the decide method a Confirm one, so nothing but a confirmed control call reaches it (D-CORE-13).

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a Sidecar's approvals, as a test sets them.
type testUrApprovalsTarget struct {
	testUrDaemonTarget
	items     []*sidecar.SidecarApprovalItem
	decisions []string
}

func (self *testUrApprovalsTarget) pendingApprovals() ([]*sidecar.SidecarApprovalItem, error) {
	return self.items, nil
}

func (self *testUrApprovalsTarget) decideApproval(ctx context.Context, approvalId sidecar.Id, decision string) error {
	self.decisions = append(self.decisions, approvalId.String()+" "+decision)
	return nil
}

// TestApproveShowsSafetyNumber's CLI half: ur approve <id> prints the device's safety number to the terminal before it
// asks, decides only on a yes, and the list names each item with what this device may answer.
func TestApproveShowsSafetyNumber(t *testing.T) {
	approvalId := sidecar.NewId()
	subject := sidecar.NewId()
	number := strings.Repeat("0123456789", 6)
	target := &testUrApprovalsTarget{items: []*sidecar.SidecarApprovalItem{{
		ApprovalId:   approvalId,
		Kind:         sidecar.SidecarApprovalAdmissionAlarm,
		SidecarId:    &subject,
		SafetyNumber: number,
		Decisions:    []string{sidecar.SidecarDecisionApprove, sidecar.SidecarDecisionRevoke, sidecar.SidecarDecisionDeny},
	}}}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "approve"}); code != urExitOk || !strings.Contains(stdout.String(), approvalId.String()) {
		t.Fatalf("the list: exit %d: %s", code, stdout.String())
	}

	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String()}); code != urExitOk || len(target.decisions) != 0 {
		t.Fatalf("a no decided: exit %d, %v", code, target.decisions)
	}
	if !strings.Contains(tty.written.String(), sidecar.FormatSafetyNumber(number)) {
		t.Errorf("the terminal showed no safety number: %q", tty.written.String())
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String()}); code != urExitOk || len(target.decisions) != 1 || target.decisions[0] != approvalId.String()+" approve" {
		t.Fatalf("a yes: exit %d, %v", code, target.decisions)
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String(), "--deny"}); code != urExitOk || target.decisions[1] != approvalId.String()+" deny" {
		t.Errorf("--deny: exit %d, %v", code, target.decisions)
	}
}

// approvals.decide is a Confirm method: only a confirmed control call runs it, never MCP or an unconfirmed call.
func TestApprovalsDecideIsConfirmOnly(t *testing.T) {
	methods := urApproveMethods(&testUrApprovalsTarget{})
	for _, method := range methods {
		if method.Name == urMethodApprovalsDecide && !method.Confirm {
			t.Error("approvals.decide runs unconfirmed")
		}
	}
	if len(methods) != 2 {
		t.Errorf("%d methods", len(methods))
	}
	if methods := urApproveMethods(&testUrDaemonTarget{}); len(methods) != 0 {
		t.Error("a target with no Sidecar serves the approve methods")
	}
}
