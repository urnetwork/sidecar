//go:build !ios_extension

// SKILL-M11-01 (QD-1433): ur://acl/grants shows a rule over every repo of a kind by its kind, never as unknown.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

func TestAclGrantsTargetNamesARepoKind(t *testing.T) {
	if text := aclGrantsTarget(&protocol.AclTarget{RepoKind: protocol.RepoKind_REPO_KIND_AGENT}); text != "repo:kind:agent" {
		t.Fatalf("the agent kind's target reads %q", text)
	}
}
