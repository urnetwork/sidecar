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

package model

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TLC's banner names its revision, which a report must name with any result.
var tlcRevisionPattern = regexp.MustCompile(`\(rev: ([0-9a-f]+)\)`)

// A run-tlc.sh verdict line: "== PASS twin-X: ..." or "== FAIL model: ...".
var tlcVerdictPattern = regexp.MustCompile(`^== (PASS|FAIL) ([^:]+): (.*)$`)

var tlcStatesPattern = regexp.MustCompile(`([0-9,]+) (?:distinct states|states generated)`)

var tlcDepthPattern = regexp.MustCompile(`depth ([0-9]+)`)

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
	sources, err := modelSources(monoroot(t), model)
	if err != nil {
		t.Fatal(err)
	}
	tlcCommand := os.Getenv("TLC")
	action, reason := tlcVerdict(model, tlcMode(), sources, tlcCommand != "")
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

	revision := ""
	if match := tlcRevisionPattern.FindSubmatch(output); match != nil {
		revision = string(match[1])
	}
	passes := 0
	failures := 0
	states := int64(0)
	depth := int64(0)
	for _, line := range strings.Split(string(output), "\n") {
		match := tlcVerdictPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if stateMatch := tlcStatesPattern.FindStringSubmatch(match[3]); stateMatch != nil {
			count, _ := strconv.ParseInt(strings.ReplaceAll(stateMatch[1], ",", ""), 10, 64)
			states += count
		}
		if depthMatch := tlcDepthPattern.FindStringSubmatch(match[3]); depthMatch != nil {
			if value, _ := strconv.ParseInt(depthMatch[1], 10, 64); depth < value {
				depth = value
			}
		}
		if match[1] == "PASS" {
			passes += 1
			t.Logf("TLC %s: %s %s: %s", revision, spec, match[2], match[3])
		} else {
			failures += 1
			t.Errorf("TLC %s: %s %s: %s", revision, spec, match[2], match[3])
		}
	}
	if err != nil && failures == 0 {
		t.Fatalf("run-tlc.sh %s %s ended with %v and no verdict:\n%s", mode, spec, err, output)
	}
	if passes == 0 && failures == 0 {
		t.Fatalf("run-tlc.sh %s %s gave no verdict:\n%s", mode, spec, output)
	}
	if revision == "" {
		t.Errorf("TLC printed no revision, which a result must name")
	}
	if 0 < failures {
		return
	}
	commit, _ := exec.Command("git", "rev-parse", "HEAD").Output()
	t.Logf("record in modelled.yml under %s's runs:\n      - {at: %s, commit: %s, tlc: %s, mode: %s, result: pass, sources_sha256: %s, states: %d, depth: %d, seconds: %d}",
		spec, started.Format("2006-01-02"), strings.TrimSpace(string(commit)), revision, recordMode, sources.digest, states, depth, seconds)
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
