// ACL-M2-16's schedules on T2 (fs_acl.go): FS-19's config read under every rule §22.8 gives its case, and each named
// clause's schedule fixed. server's sidecart3 runs the T3 parts on server's sequencer.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs19ConfigRead(t *testing.T) {
	RunRow(t, "FS-19", "config-read", nil)
}

func TestFs14AclSuspendOrders(t *testing.T) {
	RunRegisteredClause(t, "FS-14", "acl suspend orders", nil)
}

func TestFs14AclRepoRevoke(t *testing.T) {
	RunRegisteredClause(t, "FS-14", "acl repo revoke", nil)
}

func TestFs14AclOwnerConfirm(t *testing.T) {
	RunRegisteredClause(t, "FS-14", "acl owner confirm", nil)
}

func TestFs14AclTwoRemovals(t *testing.T) {
	RunRegisteredClause(t, "FS-14", "acl two removals", nil)
}

func TestFs14AclForkedReaders(t *testing.T) {
	RunRegisteredClause(t, "FS-14", "acl forked readers", nil)
}

func TestFs62AclGate(t *testing.T) {
	RunRegisteredClause(t, "FS-62", "acl gate", nil)
}

// One schedule fixed on a Net of its own, failing t with the trace if it fails: §22.5's and §22.7's acl rows, which no
// FS row registers.
func aclRun(t *testing.T, builder Builder) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	if result := Run(t.Context(), builder(net), net); result.Err != nil {
		t.Fatalf("%s", result)
	}
}

func TestAclReadersRowsEqualTheWritersCompile(t *testing.T) {
	aclRun(t, AclRowsEqualTheWriters)
}

func TestAclLowerAndForkedVersionsRefused(t *testing.T) {
	aclRun(t, AclVersionsRefused)
}

func TestAclNoDocumentRulesAtEveryReader(t *testing.T) {
	aclRun(t, AclNoDocumentRules)
}

func TestAclRemovedMembersTaggedAgentsKeepTheirTagsGrants(t *testing.T) {
	aclRun(t, AclRevocationTaggedAgents)
}

func TestAclDeclaredTagsAndGroupsNoRuleNamesApplyAtEveryReader(t *testing.T) {
	aclRun(t, AclDeclaredAtoms)
}

func TestAclRowsALyingWriterForksEveryFullReader(t *testing.T) {
	aclRun(t, AclRowsALyingWriter)
}

func TestAclS3aAddsAndWrapsOnlyForReaders(t *testing.T) {
	aclRun(t, AclAddsOnlyForReaders)
}

func TestAclS4aRemovalDropsEveryRightAtEveryReader(t *testing.T) {
	aclRun(t, AclRemovalDropsEveryRight)
}
