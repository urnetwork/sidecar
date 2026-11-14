// §22.7's privacy assert for a gate's view of a grant (ACL-M4-04; AD4, §2.8 api-10, I-13): what a gate reads of a
// requested grant, the GrantActivate a verifier checks and the rule it folds into rows, holds no run id, agent id,
// recipient or preview. The run and agent ids and the preview live in the ApprovalRequest, which stays with the
// requester and its approvers; a decision names that request only by its hash and has no field for any of them; and
// a dial or route grant's CanonicalAction admits no recipient or preview.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestAclGateViewOfAGrantHoldsNoRunAgentRecipientOrPreview(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	member := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	selfRule := fixture.requestRule([]Id{member}, []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
		[]protocol.AclAction{protocol.AclAction_ACL_ACTION_DIAL}, []Id{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)}, 0)
	state := fixture.state(t)
	grant := newAclTestGrant(t, selfRule, cast.laptop, []string{aclTestDst(cast.phone) + ":tcp:22"}, []string{"dial"}, 0)

	// the requester's request, which carries the run, the agent and the agent's text
	runId, agentId := []byte("canary-run-id-0001"), []byte("canary-agent-id-01")
	recipient, preview := "canary-recipient@example.com", "canary preview of the agent's text"
	request := &protocol.ApprovalRequest{
		ApprovalId: grant.approvalId.Bytes(), RunId: runId, AgentId: agentId, CanonicalAction: grant.actionBytes,
		Summary: preview, RequesterSidecarId: cast.laptop.Bytes(), Version: 1,
	}
	requestBytes := testConfigMarshal(t, request)
	grant.requestSha = sha256.Sum256(requestBytes)
	grant.approve(t, cast.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, aclTestDecisionNotAfter)
	activate := grant.activate()
	statement := fixture.statement(bridge.SignedType_SIGNED_GRANT_ACTIVATE, activate, cast.laptop)
	verdict, err := state.CheckStatement(statement, &aclTestSpendCheck{})
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	for name, view := range map[string][]byte{"the GrantActivate": testConfigMarshal(t, activate), "the rows": testConfigMarshal(t, rows)} {
		for _, canary := range [][]byte{runId, agentId, []byte(recipient), []byte(preview)} {
			if bytes.Contains(view, canary) {
				t.Errorf("%s holds %q", name, canary)
			}
		}
	}

	// a decision has no field to carry any of them
	for _, field := range []protoreflect.Name{"run_id", "agent_id", "recipients", "preview", "summary"} {
		if (&protocol.ApprovalDecision{}).ProtoReflect().Descriptor().Fields().ByName(field) != nil {
			t.Errorf("ApprovalDecision has a %s field", field)
		}
	}
	// and a grant's action refuses a recipient or a preview
	for name, edit := range map[string]func(action *protocol.CanonicalAction){
		"a recipient": func(action *protocol.CanonicalAction) { action.Recipients = []string{recipient} },
		"a preview":   func(action *protocol.CanonicalAction) { action.Preview = preview },
	} {
		action := &protocol.CanonicalAction{}
		if err := proto.Unmarshal(grant.actionBytes, action); err != nil {
			t.Fatal(err)
		}
		action.SealedDetail = nil
		edit(action)
		if _, err := NewCanonicalAction(action); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a grant's action with %s: %v", name, err)
		}
	}
}
