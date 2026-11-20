package fault

import (
	"testing"
)

func TestFs19Team(t *testing.T) {
	RunRow(t, "FS-19", "team", nil)
}

func TestFs19Invite(t *testing.T) {
	RunRow(t, "FS-19", "invite", nil)
}

func TestAclS13GrantSteps(t *testing.T) {
	aclRun(t, AclS13GrantSteps)
}

func TestAclMemberAddsOnlyForReaders(t *testing.T) {
	aclRun(t, AclMemberAddsOnlyForReaders)
}

func TestAclMemberRemovalDropsEveryRight(t *testing.T) {
	aclRun(t, AclMemberRemovalDropsEveryRight)
}

func TestFs85AclRepoRequest(t *testing.T) {
	RunRegisteredClause(t, "FS-85", "acl repo request", nil)
}

func TestFs85AclOwnerBoundRequest(t *testing.T) {
	RunRegisteredClause(t, "FS-85", "acl owner-bound request", nil)
}

func TestFs85AclWorkerRequest(t *testing.T) {
	RunRegisteredClause(t, "FS-85", "acl worker request", nil)
}

func TestFs85AclCopiedDecision(t *testing.T) {
	RunRegisteredClause(t, "FS-85", "acl copied decision", nil)
}
