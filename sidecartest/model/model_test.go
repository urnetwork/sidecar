//go:build sidecar_tlc

// §22.8's model checks under TLC (TEST-M2-08; D-TEST-10, D-PHASE-7, FI-30): each model at its cfg's
// bounds, its mutants, each of which TLC must refuse with its invariant violated, its liveness under
// weak fairness, and EvsCommit's M10 stories, each through run-tlc.sh, reporting states, depth and time.
//
// TLC is the command the TLC variable names, as run-tlc.sh reads it, such as
// TLC="java -cp tla2tools.jar tlc2.TLC"; this repository carries no jar. SIDECAR_TLC_MODE=gate, which
// test.sh's gate cadence sets, makes a model whose sources changed since its last passing runs in
// modelled.yml run them all, and fails, naming the missing tool, when no TLC is set: a gate never
// passes a model TLC has not checked. Otherwise, a merge, the mutants run where TLC is, and a missing TLC
// reads not run (a skip, which no gate counts as a pass); the models at their bounds take hours, so a
// merge leaves them to the gate.
//
// Each passing mode prints the line to record in modelled.yml, with the sources' digest, so the next
// gate lets the run stand while nothing it modelled changed.
//
// The models of modelled.yml's details list, DESIGN-DETAILS.md's that stand alone under details/, run only
// at a gate, each by its own run script through the owner's TLC (ROOT/.stack/tools/tlc, with tla2tools.jar
// beside it): its design configurations, its twins and its reach configurations, a group at a time, each
// group whose passing run does not stand at the model's sources. Where the jar is missing the gate fails,
// naming the model not run. A merge runs none of them: on a shared host they wait for the gate's model step.

package model

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tlcMode() string {
	if os.Getenv("SIDECAR_TLC_MODE") == "gate" {
		return "gate"
	}
	return "merge"
}

// One mode of one model through run-tlc.sh: model, twins (the mutants), live or stories.
func checkTlc(t *testing.T, spec string, mode string) {
	modelled := readModelled(t)
	var model *modelledModel
	for _, candidate := range modelled.Models {
		if candidate.Spec == spec {
			model = candidate
		}
	}
	if model == nil {
		t.Fatalf("modelled.yml has no %s", spec)
	}
	sources, err := modelSources(monoroot(t), model.Sources, model.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	tlcCommand := os.Getenv("TLC")
	missingTool := ""
	if tlcCommand == "" {
		missingTool = "no tla2tools.jar (set TLC to a command that runs tlc2.TLC)"
	}
	action, reason := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, tlcMode(), sources, missingTool)
	switch action {
	case tlcUnchanged:
		t.Logf("%s; TLC need not rerun %s", reason, mode)
		return
	case tlcNotRun:
		t.Skip(reason)
	case tlcFail:
		t.Fatal(reason)
	}
	recordMode := mode
	if mode == "twins" {
		recordMode = "mutants"
	}
	if tlcMode() != "gate" && mode != "twins" {
		t.Skipf("%s's %s runs at a gate (SIDECAR_TLC_MODE=gate): at §22.8's bounds it takes hours", spec, mode)
	}

	started := time.Now()
	command := exec.Command("bash", "run-tlc.sh", mode, spec)
	command.Env = append(os.Environ(), "TLC="+tlcCommand)
	if os.Getenv("TMPDIR") == "" {
		command.Env = append(command.Env, "TMPDIR="+t.TempDir())
	}
	output, err := command.CombinedOutput()
	seconds := int64(time.Since(started).Seconds())

	summary := summarizeTlc(output)
	for _, verdict := range summary.passes {
		t.Logf("TLC %s: %s %s", summary.revision, spec, verdict)
	}
	for _, verdict := range summary.failures {
		t.Errorf("TLC %s: %s %s", summary.revision, spec, verdict)
	}
	if err != nil && len(summary.failures) == 0 {
		t.Fatalf("run-tlc.sh %s %s ended with %v and no verdict:\n%s", mode, spec, err, output)
	}
	if len(summary.passes) == 0 && len(summary.failures) == 0 {
		t.Fatalf("run-tlc.sh %s %s gave no verdict:\n%s", mode, spec, output)
	}
	if summary.revision == "" {
		t.Errorf("TLC printed no revision, which a result must name")
	}
	if 0 < len(summary.failures) {
		return
	}
	commit, _ := exec.Command("git", "rev-parse", "HEAD").Output()
	t.Logf("record in modelled.yml under %s's runs:\n%s", spec, runRecordLine(&modelledRun{
		At:            started.Format("2006-01-02"),
		Commit:        strings.TrimSpace(string(commit)),
		Tlc:           summary.revision,
		Mode:          recordMode,
		Result:        "pass",
		SourcesSha256: sources.digest,
		States:        summary.states,
		Depth:         summary.depth,
		Seconds:       seconds,
	}))
}

// The gate's model step for modelled.yml's details list: each model's run script, group by group, where
// the model's sources changed since that group's newest passing run, and the gate failing, naming the
// model not run, where the owner's tla2tools.jar is missing.
func TestDetailsModelsPassTheirRunScriptsAtAGate(t *testing.T) {
	if tlcMode() != "gate" {
		t.Skip("not run: a details model runs at a gate (SIDECAR_TLC_MODE=gate), by its own run script, and never at a merge")
	}
	root := monoroot(t)
	// the run scripts name the TLC state they keep under ROOT/.stack/scratch by it: in a track's worktree,
	// the track's own name
	track := filepath.Base(root)

	// One group, as <run> <track> <group>: a verdict line a configuration, each of which must pass and name
	// TLC's revision. A passing group prints the line to record under the model's runs.
	runGroup := func(detail *modelledDetail, group string, digest string) {
		started := time.Now()
		command := exec.Command("bash", detail.Run, track, group)
		command.Env = os.Environ()
		if os.Getenv("TMPDIR") == "" {
			command.Env = append(command.Env, "TMPDIR="+t.TempDir())
		}
		output, err := command.CombinedOutput()
		seconds := int64(time.Since(started).Seconds())

		summary := summarizeTlc(output)
		for _, verdict := range summary.passes {
			t.Logf("TLC %s: %s %s", summary.revision, detail.Model, verdict)
		}
		for _, verdict := range summary.failures {
			t.Errorf("TLC %s: %s %s", summary.revision, detail.Model, verdict)
		}
		if err != nil && len(summary.failures) == 0 {
			t.Errorf("%s %s %s ended with %v and no failing verdict:\n%s", detail.Run, track, group, err, output)
			return
		}
		if len(summary.passes) == 0 && len(summary.failures) == 0 {
			t.Errorf("%s %s %s gave no verdict:\n%s", detail.Run, track, group, output)
			return
		}
		if summary.revision == "" {
			t.Errorf("%s's %s run named no TLC revision, which a result must name", detail.Model, group)
			return
		}
		if 0 < len(summary.failures) {
			return
		}
		commit, _ := exec.Command("git", "rev-parse", "HEAD").Output()
		t.Logf("record in modelled.yml under %s's runs:\n%s", detail.Model, runRecordLine(&modelledRun{
			At:            started.Format("2006-01-02"),
			Commit:        strings.TrimSpace(string(commit)),
			Tlc:           summary.revision,
			Mode:          group,
			Result:        "pass",
			SourcesSha256: digest,
			States:        summary.states,
			Depth:         summary.depth,
			Seconds:       seconds,
		}))
	}

	for _, detail := range readModelled(t).Details {
		sources, err := modelSources(root, detail.Sources, detail.Exclude)
		if err != nil {
			t.Errorf("%s: %v", detail.Model, err)
			continue
		}
		action, reason := tlcVerdict(detail.Model, detail.Runs, detailsRequiredModes, "gate", sources, detailsTlcMissing(detail.Run))
		switch action {
		case tlcUnchanged:
			t.Logf("%s; TLC need not rerun it", reason)
			continue
		case tlcFail:
			t.Errorf("not run: %s", reason)
			continue
		}
		t.Logf("%s: its run script runs", reason)
		for _, group := range detailsRequiredModes {
			if run := standingRun(detail.Runs, group, sources.digest); run != nil {
				t.Logf("%s's %s run of %s stands at these sources", detail.Model, group, run.At)
				continue
			}
			runGroup(detail, group, sources.digest)
		}
	}
}

func TestEvsCommitPassesTlcAtItsBounds(t *testing.T) {
	checkTlc(t, "EvsCommit", "model")
}

func TestEvsCommitMutantsFailTlc(t *testing.T) {
	checkTlc(t, "EvsCommit", "twins")
}

func TestEvsCommitLivenessHolds(t *testing.T) {
	checkTlc(t, "EvsCommit", "live")
}

// EvsCommit's M10 part, story by story (EVSB-M10-07).
func TestEvsCommitStoriesPassTlc(t *testing.T) {
	checkTlc(t, "EvsCommit", "stories")
}

func TestStoreSettlePassesTlcAtItsBounds(t *testing.T) {
	checkTlc(t, "StoreSettle", "model")
}

func TestStoreSettleMutantsFailTlc(t *testing.T) {
	checkTlc(t, "StoreSettle", "twins")
}

func TestStoreSettleLivenessHolds(t *testing.T) {
	checkTlc(t, "StoreSettle", "live")
}

func TestIndexRollupPassesTlcAtItsBounds(t *testing.T) {
	checkTlc(t, "IndexRollup", "model")
}

func TestIndexRollupMutantsFailTlc(t *testing.T) {
	checkTlc(t, "IndexRollup", "twins")
}

func TestIndexRollupLivenessHolds(t *testing.T) {
	checkTlc(t, "IndexRollup", "live")
}
