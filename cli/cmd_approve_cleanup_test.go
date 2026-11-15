// ur approve's cleanup kind (CORE-M6-04, §7.10's cleanup row): --revoke prints the list it signs before it asks, each
// page Worker with its admission time from the rows, revokes only on a yes, and prints the proposal_id of each
// revocation that awaits another admin's cosign. approvals.cleanup_list, which signs nothing, and
// approvals.cleanup_revoke, a Confirm method, are served only by a target that answers them.

package main

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A daemon target that runs a Sidecar's approvals and answers the cleanup list and its revoke, as a test sets them.
type testUrCleanupTarget struct {
	testUrApprovalsTarget
	list       *sidecar.SidecarCleanupList
	revocation *sidecar.SidecarCleanupRevocation
	listed     int
	revoked    []sidecar.Id
}

func (self *testUrCleanupTarget) approvalCleanupList(ctx context.Context, approvalId sidecar.Id) (*sidecar.SidecarCleanupList, error) {
	self.listed += 1
	return self.list, nil
}

func (self *testUrCleanupTarget) approvalCleanupRevoke(ctx context.Context, approvalId sidecar.Id) (*sidecar.SidecarCleanupRevocation, error) {
	self.revoked = append(self.revoked, approvalId)
	return self.revocation, nil
}

func TestApproveCleanupPrintsTheListItSigns(t *testing.T) {
	approvalId, memberId, workerId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	admittedTime := time.Date(2026, time.March, 1, 2, 3, 4, 0, time.UTC)
	proposalId := strings.Repeat("ab", 32)
	target := &testUrCleanupTarget{
		testUrApprovalsTarget: testUrApprovalsTarget{items: []*sidecar.SidecarApprovalItem{{
			ApprovalId: approvalId,
			Kind:       sidecar.SidecarApprovalCleanup,
			Decisions:  []string{sidecar.SidecarDecisionRevoke, sidecar.SidecarDecisionDeny},
		}}},
		list: &sidecar.SidecarCleanupList{
			AdmissionCount: 9,
			AdmissionCap:   10,
			Members: []sidecar.SidecarCleanupMember{{MemberId: memberId, Workers: []sidecar.SidecarCleanupWorker{{
				SidecarId:    workerId,
				AdmittedAt:   7,
				AdmittedTime: admittedTime,
				Signatures:   2,
			}}}},
		},
		revocation: &sidecar.SidecarCleanupRevocation{Revoked: []sidecar.Id{workerId}, Proposals: map[sidecar.Id][]byte{workerId: bytesOfHex(proposalId)}},
	}
	daemon := startTestControlDaemon(t, target, nil)
	cli, stdout, _ := newTestUrCli(daemon.socketPath)
	tty := &testTty{lines: []string{"n"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String(), "--revoke"}); code != urExitOk || len(target.revoked) != 0 || target.listed != 1 {
		t.Fatalf("a no: exit %d, revoked %v, listed %d", code, target.revoked, target.listed)
	}
	written := tty.written.String()
	for _, want := range []string{workerId.String(), memberId.String(), "entry 7", admittedTime.Format(time.RFC3339), "9 of the network's 10", "a proposal 2 admins sign"} {
		if !strings.Contains(written, want) {
			t.Errorf("the terminal does not show %q: %q", want, written)
		}
	}
	tty = &testTty{lines: []string{"yes"}}
	if code := cli.main(context.Background(), []string{"ur", "approve", approvalId.String(), "--revoke"}); code != urExitOk || len(target.revoked) != 1 || target.revoked[0] != approvalId {
		t.Fatalf("a yes: exit %d, revoked %v", code, target.revoked)
	}
	if len(target.decisions) != 0 || !strings.Contains(stdout.String(), "revoked 1 page Workers") || !strings.Contains(stdout.String(), "ur approve "+proposalId) {
		t.Errorf("the revoke: decided %v, printed %q", target.decisions, stdout.String())
	}

	served := func(methods []*sidecar.DaemonMethod, name string) *sidecar.DaemonMethod {
		for _, method := range methods {
			if method.Name == name {
				return method
			}
		}
		return nil
	}
	for _, name := range []string{urMethodApprovalsCleanupList, urMethodApprovalsCleanupRevoke} {
		if served(urApproveMethods(&testUrApprovalsTarget{}), name) != nil {
			t.Errorf("a target that answers no cleanup serves %s", name)
		}
	}
	if method := served(urApproveMethods(target), urMethodApprovalsCleanupList); method == nil || method.Confirm {
		t.Errorf("approvals.cleanup_list: %+v", method)
	}
	if method := served(urApproveMethods(target), urMethodApprovalsCleanupRevoke); method == nil || !method.Confirm {
		t.Errorf("approvals.cleanup_revoke runs unconfirmed: %+v", method)
	}
}

// A hex string's bytes, for a fixture.
func bytesOfHex(text string) []byte {
	decoded, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return decoded
}
