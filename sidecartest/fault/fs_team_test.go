// FS-14, FS-16, FS-102 and FS-124 on T2 (TEAM-M2-19): each registered case under every rule §22.8 gives it, and each
// named clause's schedule (fs_team.go) fixed, the verifiers' agreement checked after every step. server's sidecart3
// runs the T3 cases on server's sequencer.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// One clause's schedule on a Net of its own, failing t with the trace if it fails.
func fsTeamRun(t *testing.T, builder Builder) {
	t.Helper()
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	if result := Run(t.Context(), builder(net), net); result.Err != nil {
		t.Fatalf("%s", result)
	}
}

func TestFs14(t *testing.T) {
	RunRow(t, "FS-14", "", nil)
}

func TestFs14BaseLosesItsPositionAndLandsReSigned(t *testing.T) {
	fsTeamRun(t, Fs14ReSignedBase)
}

func TestFs14StaleCompileIsRefusedAndForksIfAppended(t *testing.T) {
	fsTeamRun(t, Fs14StaleCompile)
}

func TestFs14ReplayRulesAtEveryReader(t *testing.T) {
	fsTeamRun(t, Fs14ReplayRules)
}

func TestFs14VetoedReplayAfterAFoldIsRefused(t *testing.T) {
	fsTeamRun(t, Fs14VetoedReplayAfterAFold)
}

func TestFs16(t *testing.T) {
	RunRow(t, "FS-16", "", nil)
}

func TestFs16ActivationAcrossFolds(t *testing.T) {
	fsTeamRun(t, Fs16ActivationAcrossFolds)
}

func TestFs102(t *testing.T) {
	RunRow(t, "FS-102", "", nil)
}

func TestFs102Forged(t *testing.T) {
	RunRow(t, "FS-102", "forged", nil)
}

func TestFs102RemovedAgentLeavesItsDelegationAdmitting(t *testing.T) {
	fsTeamRun(t, Fs102RemovedAgent)
}

func TestFs102MaxAdmitsHoldAcrossAFold(t *testing.T) {
	fsTeamRun(t, Fs102MaxAdmits)
}

func TestFs124(t *testing.T) {
	RunRow(t, "FS-124", "", nil)
}

func TestFs124Forged(t *testing.T) {
	RunRow(t, "FS-124", "forged", nil)
}

func TestFs124FiveStatementActLandsInAnyOrder(t *testing.T) {
	fsTeamRun(t, Fs124FiveStatementAct)
}

func TestFs124NoKeyAndASignOutNeedNoCountersignature(t *testing.T) {
	fsTeamRun(t, Fs124NoKeyAndSignOut)
}
