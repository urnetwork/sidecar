//go:build !js && !ios && !android && !sdk_mobile_bind

// SKILL-M11-01 (QD-1433): a rule over every repo of a kind shows in the team tools' rows as the policy names it,
// evs:kind:agent, never as the * a target of no kind reads as.

package mcp

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestMcpAclTargetTextNamesARepoKind(t *testing.T) {
	if text := mcpAclTargetText(&protocol.AclTarget{RepoKind: protocol.RepoKind_REPO_KIND_AGENT}); text != "evs:kind:agent" {
		t.Fatalf("the agent kind's target reads %q", text)
	}
}
