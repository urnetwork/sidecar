//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's Team cases on T2 (CORE-M6-04): the registered case under every rule §22.8 gives it, and each named clause's
// schedule (fs98_team.go) fixed, the verifiers' agreement checked after every step. server's T3 test runs the same
// schedules on server's sequencer (server/api/fs98_team_db_test.go).

package fault

import (
	"testing"
)

func TestFs98Team(t *testing.T) {
	RunRow(t, "FS-98", "team", nil)
}

func TestFs98TeamMemberRevokesItsLostPhoneWithSelfAdmitOn(t *testing.T) {
	fsTeamRun(t, Fs98TeamSelfAdmitOn)
}

func TestFs98TeamMemberRevokesItsLostPhoneWithSelfAdmitOff(t *testing.T) {
	fsTeamRun(t, Fs98TeamSelfAdmitOff)
}

func TestFs98TeamSelfAdmitOffRevokesAnUnconfirmedDeviceAndNoOtherMembers(t *testing.T) {
	fsTeamRun(t, Fs98TeamSelfAdmitOffBounds)
}

func TestFs98TeamCompromiseParksWhatThePhoneAloneConfirmed(t *testing.T) {
	fsTeamRun(t, Fs98TeamCompromiseSelfAdmitOff)
}

func TestFs98TeamSuspendedTargetIsRevokedAtAnotherAdminsCosign(t *testing.T) {
	fsTeamRun(t, Fs98TeamSuspendedTargetRevokedAtCosign)
}
