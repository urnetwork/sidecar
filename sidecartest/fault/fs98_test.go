//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's and FS-124's CLI cases on T2 (CORE-M3-04): each registered case under every rule §22.8 gives it, and each
// named clause's schedule (fs98.go) fixed, the verifiers' agreement checked after every step. server's T3 test runs the
// same schedules on server's sequencer (server/api/fs98_db_test.go).

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs98Cli(t *testing.T) {
	RunRow(t, "FS-98", "cli", nil)
}

func TestFs98CliMemberRevokesItsLostPhone(t *testing.T) {
	fsTeamRun(t, Fs98CliMember)
}

func TestFs98CliCompromiseParksWhatThePhoneAdmitted(t *testing.T) {
	fsTeamRun(t, Fs98CliCompromise)
}

func TestFs98CliProposalIsApprovedByAnotherAdmin(t *testing.T) {
	fsTeamRun(t, Fs98CliProposal)
}

func TestFs98CliExpiredProposalLeavesThePhoneSuspended(t *testing.T) {
	fsTeamRun(t, Fs98CliProposalExpires)
}

func TestFs124Cli(t *testing.T) {
	RunRow(t, "FS-124", "cli", nil)
}

func TestFs124CliApprovalsSignUnderTheDaemonsPrompt(t *testing.T) {
	fsTeamRun(t, Fs124CliApprovals)
}

func TestFs124CliRecoveryRotateSignsUnderTheDaemonsPrompt(t *testing.T) {
	fsTeamRun(t, Fs124CliRecoveryRotate)
}

func TestFs124CliCosignSignsUnderTheDaemonsPrompt(t *testing.T) {
	fsTeamRun(t, Fs124CliCosign)
}

// §22.7's revocation suite with X revoked by its own member as lost and as a compromise: each way named, and CORE's
// check judging in both.
func TestRevocationSuiteOwnDeviceForm(t *testing.T) {
	report := sidecartest.RunRevocationSuite(t, sidecartest.RevocationFormOwnDevice, nil)
	for _, way := range sidecartest.RevocationFormOwnDevice.Ways() {
		judged := false
		for _, result := range report.Of(way) {
			judged = judged || (result.CheckId == Fs98RevocationCheck.Id && result.Err == nil && result.Open == "")
		}
		if !judged {
			t.Errorf("%s: CORE's check did not judge", way)
		}
	}
}
