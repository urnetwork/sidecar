// ACL-M2-16's schedules on T2 (fs_acl.go): FS-19's config read under every rule §22.8 gives its case, and each named
// clause's schedule fixed. server's sidecart3 runs the T3 parts on server's sequencer.

package fault

import (
	"testing"
)

func TestFs19ConfigRead(t *testing.T) {
	RunRow(t, "FS-19", "config-read", nil)
}

func TestFs14AclSuspendAndUnsuspendInBothOrders(t *testing.T) {
	RunClause(t, "FS-14", "acl suspend orders", Fs14AclSuspendOrders, nil)
}

func TestFs14AclConfigWritersRepoRevokeStands(t *testing.T) {
	RunClause(t, "FS-14", "acl repo revoke", Fs14AclRepoRevoke, nil)
}

func TestFs14AclOwnerConfirmAtEveryReader(t *testing.T) {
	RunClause(t, "FS-14", "acl owner confirm", Fs14AclOwnerConfirm, nil)
}

func TestFs14AclRotationCoveringOneOfTwoRemovals(t *testing.T) {
	RunClause(t, "FS-14", "acl two removals", Fs14AclTwoRemovals, nil)
}

func TestFs14AclForkedReadersReportBothChains(t *testing.T) {
	RunClause(t, "FS-14", "acl forked readers", Fs14AclForkedReaders, nil)
}
