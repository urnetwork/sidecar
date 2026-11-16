// FS-97's and FS-124's Team cases on T2 (TEAM-M6-12): each registered case under every rule §22.8 gives it, and each
// named clause's schedule (fs_team_m6.go) fixed, the verifiers' agreement checked after every step, with S3b's and
// S4b's statement schedules. server's T3 tests run the same builders on server's sequencer
// (server/api/fs_team_m6_db_test.go).

package fault

import (
	"testing"
)

func TestFs97Team(t *testing.T) {
	RunRow(t, "FS-97", "team", nil)
}

func TestFs97TeamAnAdminSetMembersStaleWorkersGoByProposals(t *testing.T) {
	fsTeamRun(t, Fs97TeamAdminSetMember)
}

func TestFs97TeamCleanupAtNinetyPercentOfConfigAdmissions(t *testing.T) {
	fsTeamRun(t, Fs97TeamCleanup)
}

func TestFs124Team(t *testing.T) {
	RunRow(t, "FS-124", "team", nil)
}

func TestS3bMemberAdmitStatements(t *testing.T) {
	fsTeamRun(t, TeamMemberAdmitStatements)
}

func TestS4bMemberRevokeStatements(t *testing.T) {
	fsTeamRun(t, TeamMemberRevokeStatements)
}
