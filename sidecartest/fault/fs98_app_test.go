//go:build !js && !ios && !android && !sdk_mobile_bind

// FS-98's and FS-124's app-host cases on T2 (CORE-M8-03): each registered case under every rule §22.8 gives it, and
// each named clause's schedule (fs98_app.go) fixed, the verifiers' agreement checked after every step. server's T3
// test runs the same schedules on server's sequencer (server/api/fs98_app_db_test.go).

package fault

import (
	"testing"
)

func TestFs98AppHost(t *testing.T) {
	RunRow(t, "FS-98", "app-host", nil)
}

func TestFs98AppHostPhoneRevokesALostLaptopAndAnEvictedWorker(t *testing.T) {
	fsTeamRun(t, Fs98AppHostPhone)
}

func TestFs98AppHostRemoteDesktopSignsTheFirstCallsBytes(t *testing.T) {
	fsTeamRun(t, Fs98AppHostRemote)
}

func TestFs124AppHost(t *testing.T) {
	RunRow(t, "FS-124", "app-host", nil)
}
