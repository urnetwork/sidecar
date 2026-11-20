// The program around §22.8's TLA+ models (TEST-M2-08; D-TEST-10, D-PHASE-7, FI-30), the part that needs
// no TLC: modelled.yml's sources and the digest a gate compares, the modes each gate needs of a model by
// its milestones and the rule that decides a gate's rerun, run-tlc.sh's parts each run as modes of their
// own (QD-1116), mutants/mutants.yml held to run-tlc.sh's twin tables and each cfg's invariants,
// IndexRollup's design grounds held to its spec's reach states and its cfg, and modelled.yml's details
// list, the models of DESIGN-DETAILS.md that stand alone under details/, each held to its run script and
// to real files and rerun at a gate by its own script. It also reads what a run script prints, which
// model_test.go, under sidecar_tlc, records when it runs TLC itself.

package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The specs this directory holds.
var modelSpecs = []string{"EvsCommit", "StoreSettle", "IndexRollup"}

// The run-tlc.sh modes every spec has, each a group of runs a recorded run names (recordedMode); a spec with
// parts adds twins-<part> and stories-<part> for each, and live-<part> for one with liveness runs (run-tlc.sh
// list-parts).
var modelRunModes = []string{"model", "twins", "live"}

// The groups of a details model's run script, each of which a gate needs passing at the model's sources
// before it lets the runs stand, and which a recorded run names as its mode: the design configurations,
// which must pass; the twins, each of which must end with the invariant its cfg names violated; and the
// reach configurations, each of which must reach the state its cfg's last invariant denies.
var detailsRequiredModes = []string{"design", "twins", "reach"}

type modelledFile struct {
	Models  []*modelledModel  `yaml:"models"`
	Details []*modelledDetail `yaml:"details"`
}

// One model: what it keeps, the code that implements that, the gates that need it, and its recorded runs.
type modelledModel struct {
	Spec       string               `yaml:"spec"`
	Owners     []string             `yaml:"owners"`
	Milestones []*modelledMilestone `yaml:"milestones"`
	Objects    string               `yaml:"objects"`
	// models of the same objects under details/, each run by its own script there
	Companions []string       `yaml:"companions"`
	Sources    []string       `yaml:"sources"`
	Exclude    []string       `yaml:"exclude"`
	Runs       []*modelledRun `yaml:"runs"`
}

// The first gate whose freeze needs a model's modes passing, and the modes it adds: that gate and every one after it
// need them (gateModes).
type modelledMilestone struct {
	// the gate tool's name: Mn-in, milestone n's entry review, or Mn, its exit review
	Gate string `yaml:"gate"`
	// recorded modes (recordedMode), each named by one milestone of the model alone
	Modes []string `yaml:"modes"`
}

// One model that stands alone under details/: no spec in this directory keeps its objects, so it is no
// spec's companion, and its own run script is the check a gate runs.
type modelledDetail struct {
	// details/<Name>, whose spec is details/<Name>.tla
	Model string `yaml:"model"`
	// its script under details/, run as <Run> <track> <group> for each of detailsRequiredModes
	Run        string         `yaml:"run"`
	Owners     []string       `yaml:"owners"`
	Milestones []string       `yaml:"milestones"`
	Objects    string         `yaml:"objects"`
	Sources    []string       `yaml:"sources"`
	Exclude    []string       `yaml:"exclude"`
	Runs       []*modelledRun `yaml:"runs"`
}

// One recorded TLC run of a mode.
type modelledRun struct {
	At            string `yaml:"at"`
	Commit        string `yaml:"commit"`
	Tlc           string `yaml:"tlc"`
	Mode          string `yaml:"mode"`
	Result        string `yaml:"result"`
	SourcesSha256 string `yaml:"sources_sha256"`
	States        int64  `yaml:"states"`
	Depth         int64  `yaml:"depth"`
	Seconds       int64  `yaml:"seconds"`
}

type mutantsFile struct {
	Models []*mutantsModel `yaml:"models"`
}

type mutantsModel struct {
	Spec       string          `yaml:"spec"`
	Invariants []*mutantsEntry `yaml:"invariants"`
}

// One invariant of a cfg and the twins that must break it, or why none does yet.
type mutantsEntry struct {
	Invariant string   `yaml:"invariant"`
	Mutants   []string `yaml:"mutants"`
	None      string   `yaml:"none"`
}

// Decodes one strict YAML document: a field the target lacks, a duplicate key, a tab or a second
// document fails.
func decodeStrict(data []byte, target any) error {
	if index := bytes.IndexByte(data, '\t'); 0 <= index {
		return fmt.Errorf("line %d holds a tab", 1+bytes.Count(data[:index], []byte("\n")))
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("a second document: %v", err)
	}
	return nil
}

func readModelled(t *testing.T) *modelledFile {
	t.Helper()
	data, err := os.ReadFile("modelled.yml")
	if err != nil {
		t.Fatal(err)
	}
	modelled := &modelledFile{}
	if err := decodeStrict(data, modelled); err != nil {
		t.Fatalf("modelled.yml: %v", err)
	}
	return modelled
}

func readMutants(t *testing.T) *mutantsFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("mutants", "mutants.yml"))
	if err != nil {
		t.Fatal(err)
	}
	mutants := &mutantsFile{}
	if err := decodeStrict(data, mutants); err != nil {
		t.Fatalf("mutants/mutants.yml: %v", err)
	}
	return mutants
}

// The directory holding this repository and its siblings: two above the repository's top, which is two
// above this package.
func monoroot(t *testing.T) string {
	t.Helper()
	directory, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

// What a model's sources are now: the files its globs match under root, test files and excluded ones
// left out, and a digest over each file's path and content, so any edit, addition or removal changes
// it. A glob whose repository is not beside this one is unreadable, and the digest is then empty.
type sourcesState struct {
	files      []string
	digest     string
	unreadable []string
	empty      []string
}

func modelSources(root string, sourcePatterns []string, excludePatterns []string) (*sourcesState, error) {
	state := &sourcesState{}
	excluded := map[string]bool{}
	for _, pattern := range excludePatterns {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			excluded[match] = true
		}
	}
	seen := map[string]bool{}
	for _, pattern := range sourcePatterns {
		repo, _, _ := strings.Cut(pattern, "/")
		if _, err := os.Stat(filepath.Join(root, repo)); err != nil {
			state.unreadable = append(state.unreadable, pattern)
			continue
		}
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", pattern, err)
		}
		counted := 0
		for _, match := range matches {
			if excluded[match] || strings.HasSuffix(match, "_test.go") || seen[match] {
				continue
			}
			seen[match] = true
			counted += 1
			relative, err := filepath.Rel(root, match)
			if err != nil {
				return nil, err
			}
			state.files = append(state.files, filepath.ToSlash(relative))
		}
		if counted == 0 {
			state.empty = append(state.empty, pattern)
		}
	}
	if 0 < len(state.unreadable) {
		return state, nil
	}
	slices.Sort(state.files)
	hash := sha256.New()
	for _, file := range state.files {
		content, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			return nil, err
		}
		contentHash := sha256.Sum256(content)
		fmt.Fprintf(hash, "%s\n%s\n", file, hex.EncodeToString(contentHash[:]))
	}
	state.digest = hex.EncodeToString(hash.Sum(nil))
	return state, nil
}

// What a model's TLC checks do in a run of mode, gate or merge.
type tlcAction string

const (
	// a passing run of every required mode stands at these sources
	tlcUnchanged tlcAction = "unchanged"
	// TLC runs now
	tlcRun tlcAction = "run"
	// merge, with no TLC here: reported, never passed
	tlcNotRun tlcAction = "not run"
	// a gate that needs a run and cannot have one
	tlcFail tlcAction = "fail"
	// a mode this run does not need: a gate whose milestones do not name it, or one a merge leaves to a gate
	tlcNotNeeded tlcAction = "not needed"
)

// §22.8's cadence for one model, by its name, its recorded runs and the modes a gate needs passing: at a
// gate, the newest passing runs stand while the sources they ran at are unchanged, and otherwise TLC runs, or
// the gate fails naming the missing tool and each mode whose run does not stand; at a merge, TLC runs where it
// is, and is reported not run where it is not. missingTool says why TLC cannot run here, and is empty where it
// can.
func tlcVerdict(name string, runs []*modelledRun, requiredModes []string, mode string, sources *sourcesState, missingTool string) (tlcAction, string) {
	if mode == "gate" {
		if 0 < len(sources.unreadable) {
			return tlcFail, fmt.Sprintf("%s's sources %v are not beside this checkout, so whether they changed is unknown", name, sources.unreadable)
		}
		missing := []string{}
		for _, required := range requiredModes {
			if standingRun(runs, required, sources.digest) == nil {
				missing = append(missing, required)
			}
		}
		if len(missing) == 0 {
			return tlcUnchanged, fmt.Sprintf("%s's sources are unchanged since its passing runs, which stand", name)
		}
		if missingTool != "" {
			return tlcFail, fmt.Sprintf("%s has no passing %s run at these sources: they changed since its last passing runs, or none is recorded, and TLC has not run: %s", name, strings.Join(missing, ", "), missingTool)
		}
		return tlcRun, fmt.Sprintf("%s has no passing %s run at these sources: they changed since its last passing runs, or none is recorded", name, strings.Join(missing, ", "))
	}
	if missingTool != "" {
		return tlcNotRun, fmt.Sprintf("%s: TLC has not run: %s", name, missingTool)
	}
	return tlcRun, name + "'s mutants run at each merge"
}

// A gate as the gate tool names it: Mn-in, milestone n's entry review, or Mn, its exit review, which the catalog
// writes Mn-out.
var tlcGatePattern = regexp.MustCompile(`^M([0-9]{1,3})(-in|-out)?$`)

// Where gate falls in the build's order, milestone by milestone, each one's entry before its exit, and false for a
// name that is no gate.
func tlcGateOrder(gate string) (int, bool) {
	match := tlcGatePattern.FindStringSubmatch(gate)
	if match == nil {
		return 0, false
	}
	milestone, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, false
	}
	if match[2] == "-in" {
		return 2 * milestone, true
	}
	return 2*milestone + 1, true
}

// The modes a gate needs passing of a model: each mode of its milestones at or before the gate, in their order, so
// a gate needs what §22.10 names of a model by then and nothing a later gate adds (QD-1116). An empty gate, a run in
// gate mode that names none, needs every milestone's modes, the most any gate needs. A gate or a milestone's gate that
// is no gate's name is an error, never a gate that needs nothing.
func gateModes(milestones []*modelledMilestone, gate string) ([]string, error) {
	order := -1
	if gate != "" {
		at, ok := tlcGateOrder(gate)
		if !ok {
			return nil, fmt.Errorf("%q names no gate: Mn-in for milestone n's entry, or Mn or Mn-out for its exit", gate)
		}
		order = at
	}
	modes := []string{}
	for _, milestone := range milestones {
		at, ok := tlcGateOrder(milestone.Gate)
		if !ok {
			return nil, fmt.Errorf("a milestone's gate %q names no gate: Mn-in for milestone n's entry, or Mn or Mn-out for its exit", milestone.Gate)
		}
		if order < 0 || at <= order {
			modes = append(modes, milestone.Modes...)
		}
	}
	return modes, nil
}

// The mode a recorded run names for a run-tlc.sh mode: its twins as mutants, a part's twins (twins-<part>) as
// mutants-<part>, and any other mode as itself.
func recordedMode(runMode string) string {
	if part, found := strings.CutPrefix(runMode, "twins-"); found {
		return "mutants-" + part
	}
	if runMode == "twins" {
		return "mutants"
	}
	return runMode
}

// What one model test does with its run-tlc.sh mode, in a run of tlcMode (gate or merge) at gate, the gate tool's
// name or empty. At a gate the modes it needs are the model's milestones' (gateModes), and a mode it does not need is
// not run: M10's entry needs EvsCommit's purger, and only its exit the drop extension. A mode it needs passes where
// every mode the gate needs of the model stands at these sources, its own among them, so no mode can stand on the
// others' runs; otherwise it runs where its own run does not stand and TLC is here, passes on its own run where that
// stands, each other mode running in its own test, and fails, saying TLC has not run and naming each mode whose run
// does not stand, where TLC is missing. At a merge the twin modes run where TLC is, and the rest wait for a gate.
func modeVerdict(model *modelledModel, runMode string, tlcMode string, gate string, sources *sourcesState, missingTool string) (tlcAction, string) {
	mode := recordedMode(runMode)
	if tlcMode != "gate" {
		action, reason := tlcVerdict(model.Spec, model.Runs, nil, "merge", sources, missingTool)
		if action == tlcRun && runMode != "twins" && !strings.HasPrefix(runMode, "twins-") {
			return tlcNotNeeded, fmt.Sprintf("%s's %s runs at a gate (SIDECAR_TLC_MODE=gate): at §22.8's bounds it takes hours", model.Spec, runMode)
		}
		return action, reason
	}
	needed, err := gateModes(model.Milestones, gate)
	if err != nil {
		return tlcFail, fmt.Sprintf("%s's milestones in modelled.yml: %v", model.Spec, err)
	}
	named := gate
	if named == "" {
		named = "a gate that names none, which needs every milestone's modes,"
	}
	if !slices.Contains(needed, mode) {
		return tlcNotNeeded, fmt.Sprintf("%s needs no %s run of %s: no milestone of its in modelled.yml names that mode at or before it", named, mode, model.Spec)
	}
	action, reason := tlcVerdict(model.Spec, model.Runs, needed, "gate", sources, missingTool)
	if action == tlcRun {
		if run := standingRun(model.Runs, mode, sources.digest); run != nil {
			return tlcUnchanged, fmt.Sprintf("%s; its %s run of %s stands at these sources, and each mode %s needs that does not runs in its own test", reason, mode, run.At, named)
		}
	}
	return action, reason
}

// Every mode a model's milestones name, in their order: what its recorded runs may name.
func milestoneModes(model *modelledModel) []string {
	modes := []string{}
	for _, milestone := range model.Milestones {
		modes = append(modes, milestone.Modes...)
	}
	return modes
}

// The passing run of mode recorded at the sources' digest, or nil: a run at other sources, or one that
// failed, never stands.
func standingRun(runs []*modelledRun, mode string, digest string) *modelledRun {
	for _, run := range runs {
		if run.Mode == mode && run.Result == "pass" && digest != "" && run.SourcesSha256 == digest {
			return run
		}
	}
	return nil
}

// Why the owner's TLC a details run script runs cannot run here, or empty where it can. Every script under
// details/ runs "$ROOT/.stack/tools/tlc" with its own ROOT, the monoroot, and that wrapper refuses to run
// without the owner's tla2tools.jar beside it (plan-EVS1-tlc-tool), so the jar and the wrapper are what a
// gate looks for before it lets a script run.
func detailsTlcMissing(script string) string {
	data, err := os.ReadFile(script)
	if err != nil {
		return fmt.Sprintf("no tla2tools.jar found: %v", err)
	}
	match := detailsScriptRootPattern.FindSubmatch(data)
	if match == nil || !bytes.Contains(data, []byte(`"$ROOT/.stack/tools/tlc"`)) {
		return fmt.Sprintf("no tla2tools.jar found: %s runs no owner's TLC under a ROOT of its own", script)
	}
	tools := filepath.Join(string(match[1]), ".stack", "tools")
	jar := filepath.Join(tools, "tla2tools.jar")
	if _, err := os.Stat(jar); err != nil {
		return fmt.Sprintf("no tla2tools.jar at %s, whose TLC %s runs", jar, script)
	}
	wrapper := filepath.Join(tools, "tlc")
	if info, err := os.Stat(wrapper); err != nil || info.Mode()&0o111 == 0 {
		return fmt.Sprintf("no TLC at %s to run tla2tools.jar, which %s runs", wrapper, script)
	}
	return ""
}

// A details run script's ROOT, the monoroot whose .stack/tools holds the owner's TLC.
var detailsScriptRootPattern = regexp.MustCompile(`(?m)^[ \t]*ROOT="?([^"\s]+)"?[ \t]*$`)

// TLC's banner names its revision, which a report must name with any result; a details run script's verdict
// line names it in its facts, as "tlc <rev>, exit <code>".
var tlcRevisionPattern = regexp.MustCompile(`\(rev: ([0-9a-f]+)\)`)

var detailsRevisionPattern = regexp.MustCompile(`\btlc ([0-9a-f]+), exit\b`)

// A run script's verdict line: "== PASS twin-X: ..." or "== FAIL model: ...".
var tlcVerdictPattern = regexp.MustCompile(`^== (PASS|FAIL) ([^:]+): (.*)$`)

var tlcStatesPattern = regexp.MustCompile(`([0-9,]+) (?:distinct states|states generated)`)

var tlcDepthPattern = regexp.MustCompile(`depth ([0-9]+)`)

// What a run script printed, over its runs: TLC's revision, each verdict line by how it ended, as
// "<configuration>: <facts>", the states the lines report summed and the deepest search.
type tlcSummary struct {
	revision string
	passes   []string
	failures []string
	states   int64
	depth    int64
}

// Reads run-tlc.sh's output and a details run script's alike: a verdict line each run, TLC's revision in its
// banner or in a verdict's facts.
func summarizeTlc(output []byte) *tlcSummary {
	summary := &tlcSummary{}
	if match := tlcRevisionPattern.FindSubmatch(output); match != nil {
		summary.revision = string(match[1])
	} else if match := detailsRevisionPattern.FindSubmatch(output); match != nil {
		summary.revision = string(match[1])
	}
	for _, line := range strings.Split(string(output), "\n") {
		match := tlcVerdictPattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		if stateMatch := tlcStatesPattern.FindStringSubmatch(match[3]); stateMatch != nil {
			count, _ := strconv.ParseInt(strings.ReplaceAll(stateMatch[1], ",", ""), 10, 64)
			summary.states += count
		}
		if depthMatch := tlcDepthPattern.FindStringSubmatch(match[3]); depthMatch != nil {
			if value, _ := strconv.ParseInt(depthMatch[1], 10, 64); summary.depth < value {
				summary.depth = value
			}
		}
		verdict := match[2] + ": " + match[3]
		if match[1] == "PASS" {
			summary.passes = append(summary.passes, verdict)
		} else {
			summary.failures = append(summary.failures, verdict)
		}
	}
	return summary
}

// The line that records a passing run under a model's runs in modelled.yml.
func runRecordLine(run *modelledRun) string {
	return fmt.Sprintf("      - {at: %s, commit: %s, tlc: %s, mode: %s, result: %s, sources_sha256: %s, states: %d, depth: %d, seconds: %d}",
		run.At, run.Commit, run.Tlc, run.Mode, run.Result, run.SourcesSha256, run.States, run.Depth, run.Seconds)
}

var runAtPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

var runCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var runTlcPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

var runDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// What is wrong with a model's recorded runs: a mode that is none of modes, a result other than pass or
// fail, or a date, commit, TLC revision or digest out of form. Such a run never stands at a gate, and reads
// as though it did.
func runFindings(name string, runs []*modelledRun, modes []string) []string {
	findings := []string{}
	for index, run := range runs {
		which := fmt.Sprintf("%s's run %d", name, 1+index)
		if !slices.Contains(modes, run.Mode) {
			findings = append(findings, fmt.Sprintf("%s has mode %q, which is none of %v", which, run.Mode, modes))
		}
		if run.Result != "pass" && run.Result != "fail" {
			findings = append(findings, fmt.Sprintf("%s has result %q, which is neither pass nor fail", which, run.Result))
		}
		for _, field := range []struct {
			name    string
			value   string
			pattern *regexp.Regexp
		}{
			{name: "at", value: run.At, pattern: runAtPattern},
			{name: "commit", value: run.Commit, pattern: runCommitPattern},
			{name: "tlc", value: run.Tlc, pattern: runTlcPattern},
			{name: "sources_sha256", value: run.SourcesSha256, pattern: runDigestPattern},
		} {
			if !field.pattern.MatchString(field.value) {
				findings = append(findings, fmt.Sprintf("%s has %s %q, which is out of form", which, field.name, field.value))
			}
		}
	}
	return findings
}

// modelled.yml names each spec once, with owners and milestones, and its globs match real files: every
// spec, cfg and run-tlc.sh, each companion's spec, cfgs and own run script, and code for each model. Each
// recorded run is in a form a gate can read, of a mode the model's milestones name.
func TestModelledNamesEachModelsSources(t *testing.T) {
	modelled := readModelled(t)
	root := monoroot(t)
	specs := []string{}
	for _, model := range modelled.Models {
		specs = append(specs, model.Spec)
		if len(model.Owners) == 0 || len(model.Milestones) == 0 || model.Objects == "" {
			t.Errorf("%s: no owners, milestones or objects", model.Spec)
		}
		for _, file := range []string{model.Spec + ".tla", model.Spec + ".cfg", "run-tlc.sh"} {
			if !slices.Contains(model.Sources, "sidecar/sidecartest/model/"+file) {
				t.Errorf("%s's sources leave out %s, whose change needs a rerun too", model.Spec, file)
			}
		}
		// a companion's spec, its cfgs and its run script are sources too, so a change to either model
		// reruns the spec at a gate
		for _, companion := range model.Companions {
			if !strings.HasPrefix(companion, "details/") || slices.Contains(modelSpecs, companion) {
				t.Errorf("%s's companion %s is not a model under details/", model.Spec, companion)
			}
			if _, err := os.Stat(companion + ".tla"); err != nil {
				t.Errorf("%s's companion %s has no spec: %v", model.Spec, companion, err)
			}
			for _, pattern := range []string{companion + ".tla", companion + "*.cfg"} {
				if !slices.Contains(model.Sources, "sidecar/sidecartest/model/"+pattern) {
					t.Errorf("%s's sources leave out its companion's %s, whose change needs a rerun too", model.Spec, pattern)
				}
			}
			// its own script: a run script under details/ among the sources that runs the companion's spec
			companionScript := slices.ContainsFunc(model.Sources, func(source string) bool {
				script, found := strings.CutPrefix(source, "sidecar/sidecartest/model/")
				if !found || !strings.HasPrefix(script, "details/run-") || !strings.HasSuffix(script, ".sh") {
					return false
				}
				data, err := os.ReadFile(script)
				return err == nil && bytes.Contains(data, []byte(path.Base(companion)+".tla"))
			})
			if !companionScript {
				t.Errorf("%s's sources name no run script that runs its companion %s", model.Spec, companion)
			}
		}
		for _, finding := range runFindings(model.Spec, model.Runs, milestoneModes(model)) {
			t.Error(finding)
		}
		sources, err := modelSources(root, model.Sources, model.Exclude)
		if err != nil {
			t.Fatal(err)
		}
		if 0 < len(sources.unreadable) {
			t.Logf("%s: %v not beside this checkout", model.Spec, sources.unreadable)
		}
		for _, pattern := range sources.empty {
			t.Logf("%s: %s matches nothing yet", model.Spec, pattern)
		}
		code := 0
		for _, file := range sources.files {
			if strings.HasSuffix(file, ".go") {
				code += 1
			}
		}
		if code == 0 && len(sources.unreadable) == 0 {
			t.Errorf("%s's sources match no code", model.Spec)
		}
		t.Logf("%s: %d source files, digest %s, %d runs recorded", model.Spec, len(sources.files), sources.digest, len(model.Runs))
	}
	if !slices.Equal(specs, modelSpecs) {
		t.Errorf("modelled.yml names %v, want %v", specs, modelSpecs)
	}
}

// A changed modelled file forces a rerun at a gate: runs recorded at a digest stand until a source
// changes, and then TLC runs, or without it the gate fails naming the missing tool, while a merge
// reports not run.
func TestChangedModelledFileForcesARerunAtAGate(t *testing.T) {
	root := t.TempDir()
	for name, content := range map[string]string{
		"sidecar/sidecartest/model/Toy.tla": "---- MODULE Toy ----\n====\n",
		"sidecar/toy_head.go":               "package sidecar\n",
		"sidecar/toy_head_test.go":          "package sidecar\n",
	} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	model := &modelledModel{Spec: "Toy", Sources: []string{"sidecar/sidecartest/model/Toy.tla", "sidecar/toy_*.go"}}
	// the modes M2's gates need of a model, as modelled.yml's milestones name them
	required := []string{"model", "mutants", "live"}
	noTlc := "no tla2tools.jar (set TLC to a command that runs tlc2.TLC)"
	before, err := modelSources(root, model.Sources, model.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before.files, []string{"sidecar/sidecartest/model/Toy.tla", "sidecar/toy_head.go"}) {
		t.Fatalf("sources %v: a test file counted, or a source was missed", before.files)
	}
	for _, mode := range required {
		model.Runs = append(model.Runs, &modelledRun{Mode: mode, Result: "pass", SourcesSha256: before.digest})
	}
	if action, _ := tlcVerdict(model.Spec, model.Runs, required, "gate", before, noTlc); action != tlcUnchanged {
		t.Errorf("unchanged sources at a gate: %s", action)
	}

	// a test file's edit changes nothing; a source's does
	if err := os.WriteFile(filepath.Join(root, "sidecar/toy_head_test.go"), []byte("package sidecar\n\n// edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if again, _ := modelSources(root, model.Sources, model.Exclude); again.digest != before.digest {
		t.Error("a test file's edit changed the digest")
	}
	if err := os.WriteFile(filepath.Join(root, "sidecar/toy_head.go"), []byte("package sidecar\n\nconst toyFold = 64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := modelSources(root, model.Sources, model.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	if after.digest == before.digest {
		t.Fatal("a source's edit left the digest")
	}
	if action, reason := tlcVerdict(model.Spec, model.Runs, required, "gate", after, noTlc); action != tlcFail || !strings.Contains(reason, "no tla2tools.jar") {
		t.Errorf("changed sources at a gate with no TLC: %s, %s", action, reason)
	}
	if action, _ := tlcVerdict(model.Spec, model.Runs, required, "gate", after, ""); action != tlcRun {
		t.Errorf("changed sources at a gate with TLC: %s", action)
	}
	if action, reason := tlcVerdict(model.Spec, model.Runs, required, "merge", after, noTlc); action != tlcNotRun || !strings.Contains(reason, "has not run") {
		t.Errorf("a merge with no TLC: %s, %s", action, reason)
	}

	// a run that failed, or one mode short, does not stand
	model.Runs = []*modelledRun{
		{Mode: "model", Result: "pass", SourcesSha256: after.digest},
		{Mode: "mutants", Result: "fail", SourcesSha256: after.digest},
		{Mode: "live", Result: "pass", SourcesSha256: after.digest},
	}
	if action, _ := tlcVerdict(model.Spec, model.Runs, required, "gate", after, noTlc); action != tlcFail {
		t.Errorf("a failed mutants run stood at a gate: %s", action)
	}

	// a sibling the sources name and this machine lacks leaves the gate unable to decide
	model.Sources = append(model.Sources, "minio/cmd/settle-*.go")
	missing, err := modelSources(root, model.Sources, model.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	if action, reason := tlcVerdict(model.Spec, model.Runs, required, "gate", missing, ""); action != tlcFail || !strings.Contains(reason, "not beside") {
		t.Errorf("a missing sibling at a gate: %s, %s", action, reason)
	}
}

// A gate's place in the build's order reads the gate tool's names: each milestone's entry before its exit, milestone
// n's gates before n+1's, so M10's come after M2's though "M10" sorts first as text, and Mn-out is Mn. Anything else is
// no gate.
func TestGateOrderReadsTheGateToolsNames(t *testing.T) {
	last := -1
	for _, gate := range []string{"M0-in", "M0", "M1-in", "M2-in", "M2", "M3-in", "M9", "M10-in", "M10"} {
		order, ok := tlcGateOrder(gate)
		if !ok || order <= last {
			t.Errorf("%s reads %d, %t, after %d", gate, order, ok, last)
		}
		last = order
	}
	for _, same := range [][2]string{{"M2", "M2-out"}, {"M10", "M10-out"}} {
		exit, _ := tlcGateOrder(same[0])
		out, ok := tlcGateOrder(same[1])
		if !ok || exit != out {
			t.Errorf("%s reads %d and %s %d, %t", same[0], exit, same[1], out, ok)
		}
	}
	for _, name := range []string{"", "G0", "Later", "m2", "M2-exit", "M-in", "M10in", "M2-in ", "every", "next"} {
		if order, ok := tlcGateOrder(name); ok {
			t.Errorf("%q reads as a gate at %d", name, order)
		}
	}
}

// A gate needs the modes of each milestone at or before it and none a later gate adds, and a run that names no gate
// needs them all; a gate, or a milestone's gate, that is no gate's name is an error, never a gate that needs nothing.
func TestGateModesNeedEachMilestoneFromItsGateOn(t *testing.T) {
	milestones := []*modelledMilestone{
		{Gate: "M2-in", Modes: []string{"model", "mutants", "live"}},
		{Gate: "M10-in", Modes: []string{"mutants-purge", "stories-purge"}},
		{Gate: "M10", Modes: []string{"mutants-drop", "stories-drop"}},
	}
	m2 := []string{"model", "mutants", "live"}
	purge := append(slices.Clone(m2), "mutants-purge", "stories-purge")
	all := append(slices.Clone(purge), "mutants-drop", "stories-drop")
	for _, c := range []struct {
		gate string
		want []string
	}{
		{gate: "M1", want: []string{}},
		{gate: "M2-in", want: m2},
		{gate: "M2", want: m2},
		{gate: "M9", want: m2},
		{gate: "M10-in", want: purge},
		{gate: "M10", want: all},
		{gate: "M10-out", want: all},
		{gate: "", want: all},
	} {
		got, err := gateModes(milestones, c.gate)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("gate %q needs %v, %v; want %v", c.gate, got, err, c.want)
		}
	}
	if _, err := gateModes(milestones, "M10-exit"); err == nil || !strings.Contains(err.Error(), "names no gate") {
		t.Errorf("an unknown gate: %v", err)
	}
	later := append(slices.Clone(milestones), &modelledMilestone{Gate: "Later", Modes: []string{"live-drop"}})
	if _, err := gateModes(later, "M2-in"); err == nil || !strings.Contains(err.Error(), "Later") {
		t.Errorf("a milestone at no gate: %v", err)
	}
}

// modelled.yml's milestones give each gate what §22.10 names of each model and no more (QD-1116): EvsCommit's model,
// mutants and live from M2's entry, the purger's mutants and stories from M10's entry and the drop extension's
// mutants, stories and liveness (QD-1119) only from its exit; StoreSettle's three from M2's entry; IndexRollup's three
// from M10's entry. Each model's milestones
// are in gate order, each at a gate of the tool's, and together name every mode run-tlc.sh runs of the spec, each
// once, so a mode no gate needs is never run unread.
func TestModelledMilestonesNameEachGatesModes(t *testing.T) {
	m2 := []string{"model", "mutants", "live"}
	purge := append(slices.Clone(m2), "mutants-purge", "stories-purge")
	drop := append(slices.Clone(purge), "mutants-drop", "stories-drop", "live-drop")
	wants := map[string]map[string][]string{
		"EvsCommit":   {"M1": {}, "M2-in": m2, "M2": m2, "M9": m2, "M10-in": purge, "M10": drop},
		"StoreSettle": {"M1": {}, "M2-in": m2, "M2": m2, "M10-in": m2, "M10": m2},
		"IndexRollup": {"M2-in": {}, "M2": {}, "M9": {}, "M10-in": m2, "M10": m2},
	}
	modelled := readModelled(t)
	for _, model := range modelled.Models {
		last := -1
		named := map[string]bool{}
		for _, milestone := range model.Milestones {
			order, ok := tlcGateOrder(milestone.Gate)
			if !ok {
				t.Errorf("%s's milestone %q is at no gate of the tool's", model.Spec, milestone.Gate)
				continue
			}
			if order <= last {
				t.Errorf("%s's milestone %s is out of gate order, or a gate named twice", model.Spec, milestone.Gate)
			}
			last = order
			if len(milestone.Modes) == 0 {
				t.Errorf("%s's milestone %s names no mode", model.Spec, milestone.Gate)
			}
			for _, mode := range milestone.Modes {
				if named[mode] {
					t.Errorf("%s's milestones name %s twice", model.Spec, mode)
				}
				named[mode] = true
			}
		}
		recorded := []string{}
		for _, runMode := range specRunModes(t, model.Spec) {
			recorded = append(recorded, recordedMode(runMode))
		}
		modes := milestoneModes(model)
		slices.Sort(recorded)
		slices.Sort(modes)
		if !slices.Equal(modes, recorded) {
			t.Errorf("%s's milestones name %v, and run-tlc.sh records %v", model.Spec, modes, recorded)
		}
		want, found := wants[model.Spec]
		if !found {
			t.Errorf("modelled.yml names %s, which this test does not hold to §22.10", model.Spec)
		}
		for gate, wantModes := range want {
			got, err := gateModes(model.Milestones, gate)
			if err != nil || !slices.Equal(got, wantModes) {
				t.Errorf("%s at %s needs %v, %v; §22.10 names %v", model.Spec, gate, got, err, wantModes)
			}
		}
	}
	if len(modelled.Models) != len(wants) {
		t.Errorf("modelled.yml names %d models, and this test holds %d", len(modelled.Models), len(wants))
	}
}

// Each model test's verdict takes the modes its gate needs from the model's milestones (QD-1116). At M10's entry the
// purger's stories stand only on a stories-purge run of their own, never on the model's other runs, and the drop
// extension's runs are never needed, so their absence never holds the entry; at M10's exit they are needed too; at
// M2's gates neither part is; a run that names no gate needs every mode. A mode whose own run stands passes while
// another the gate needs reruns in its own test; with no TLC every test of the model says TLC has not run, naming each
// mode whose run does not stand, and a failed run never stands. At a merge the twin modes run where TLC is and the
// stories wait for a gate.
func TestModeVerdictTakesEachGatesModes(t *testing.T) {
	sources := &sourcesState{digest: strings.Repeat("ab", 32)}
	noTlc := "no tla2tools.jar (set TLC to a command that runs tlc2.TLC)"
	m2 := []string{"model", "mutants", "live"}
	purge := append(slices.Clone(m2), "mutants-purge", "stories-purge")
	all := append(slices.Clone(purge), "mutants-drop", "stories-drop", "live-drop")
	purgeMutants := append(slices.Clone(m2), "mutants-purge")
	dropSafety := append(slices.Clone(purge), "mutants-drop", "stories-drop")
	model := func(standing []string, failed ...string) *modelledModel {
		runs := []*modelledRun{}
		for _, mode := range standing {
			runs = append(runs, &modelledRun{At: "2026-11-19", Mode: mode, Result: "pass", SourcesSha256: sources.digest})
		}
		for _, mode := range failed {
			runs = append(runs, &modelledRun{At: "2026-11-19", Mode: mode, Result: "fail", SourcesSha256: sources.digest})
		}
		// a passing run at other sources stands for nothing
		runs = append(runs, &modelledRun{At: "2026-11-18", Mode: "stories-purge", Result: "pass", SourcesSha256: strings.Repeat("cd", 32)})
		return &modelledModel{
			Spec: "EvsCommit",
			Milestones: []*modelledMilestone{
				{Gate: "M2-in", Modes: m2},
				{Gate: "M10-in", Modes: []string{"mutants-purge", "stories-purge"}},
				{Gate: "M10", Modes: []string{"mutants-drop", "stories-drop", "live-drop"}},
			},
			Runs: runs,
		}
	}
	cases := []struct {
		name        string
		model       *modelledModel
		runMode     string
		tlcMode     string
		gate        string
		missingTool string
		action      tlcAction
		reason      string
	}{
		{name: "the purger's stories on M2's and the purger's mutants' runs", model: model(purgeMutants), runMode: "stories-purge", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcFail, reason: "no passing stories-purge run at these sources"},
		{name: "the same with TLC here", model: model(purgeMutants), runMode: "stories-purge", tlcMode: "gate", gate: "M10-in", action: tlcRun, reason: "no passing stories-purge run"},
		{name: "the purger's stories failed at these sources", model: model(purgeMutants, "stories-purge"), runMode: "stories-purge", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcFail, reason: "TLC has not run"},
		{name: "the entry's modes standing and the drop's not", model: model(purge), runMode: "stories-purge", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcUnchanged, reason: "unchanged since its passing runs"},
		{name: "the entry's model test with the drop's missing", model: model(purge), runMode: "model", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcUnchanged, reason: "unchanged since its passing runs"},
		{name: "the drop's stories at the entry", model: model(purge), runMode: "stories-drop", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcNotNeeded, reason: "M10-in needs no stories-drop run of EvsCommit"},
		{name: "the drop's mutants at the entry", model: model(nil), runMode: "twins-drop", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcNotNeeded, reason: "M10-in needs no mutants-drop run"},
		{name: "the drop's stories at the exit, not standing", model: model(purge), runMode: "stories-drop", tlcMode: "gate", gate: "M10", missingTool: noTlc, action: tlcFail, reason: "no passing mutants-drop, stories-drop, live-drop run"},
		{name: "the drop's liveness at the entry", model: model(purge), runMode: "live-drop", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcNotNeeded, reason: "M10-in needs no live-drop run of EvsCommit"},
		{name: "the drop's liveness at the exit, its safety standing", model: model(dropSafety), runMode: "live-drop", tlcMode: "gate", gate: "M10", missingTool: noTlc, action: tlcFail, reason: "no passing live-drop run"},
		{name: "the drop's stories at the exit, its liveness not standing", model: model(dropSafety), runMode: "stories-drop", tlcMode: "gate", gate: "M10", missingTool: noTlc, action: tlcFail, reason: "no passing live-drop run"},
		{name: "the same with TLC here", model: model(dropSafety), runMode: "stories-drop", tlcMode: "gate", gate: "M10", action: tlcUnchanged, reason: "its stories-drop run of 2026-11-19 stands"},
		{name: "the purger's mutants at the exit, the drop's not standing", model: model(purge), runMode: "twins-purge", tlcMode: "gate", gate: "M10", missingTool: noTlc, action: tlcFail, reason: "TLC has not run"},
		{name: "every mode standing at the exit", model: model(all), runMode: "stories-drop", tlcMode: "gate", gate: "M10-out", missingTool: noTlc, action: tlcUnchanged},
		{name: "the purger's mutants at M2's entry", model: model(nil), runMode: "twins-purge", tlcMode: "gate", gate: "M2-in", missingTool: noTlc, action: tlcNotNeeded, reason: "M2-in needs no mutants-purge run"},
		{name: "the purger's stories at M2's exit", model: model(m2), runMode: "stories-purge", tlcMode: "gate", gate: "M2", missingTool: noTlc, action: tlcNotNeeded},
		{name: "M2's mutants at M2's exit", model: model(m2), runMode: "twins", tlcMode: "gate", gate: "M2", missingTool: noTlc, action: tlcUnchanged},
		{name: "no gate named needs the drop's too", model: model(purge), runMode: "stories-purge", tlcMode: "gate", missingTool: noTlc, action: tlcFail, reason: "mutants-drop, stories-drop, live-drop"},
		{name: "its own run standing, another not, TLC here", model: model(purgeMutants), runMode: "twins-purge", tlcMode: "gate", gate: "M10-in", action: tlcUnchanged, reason: "its mutants-purge run of 2026-11-19 stands"},
		{name: "its own run standing, another not, no TLC", model: model(purgeMutants), runMode: "twins-purge", tlcMode: "gate", gate: "M10-in", missingTool: noTlc, action: tlcFail, reason: "no passing stories-purge run"},
		{name: "a gate that is no gate", model: model(all), runMode: "model", tlcMode: "gate", gate: "M10-exit", missingTool: noTlc, action: tlcFail, reason: "names no gate"},
		{name: "a merge runs the purger's mutants", model: model(nil), runMode: "twins-purge", tlcMode: "merge", action: tlcRun},
		{name: "a merge runs the M2 part's mutants", model: model(nil), runMode: "twins", tlcMode: "merge", action: tlcRun},
		{name: "a merge leaves the drop's stories to a gate", model: model(nil), runMode: "stories-drop", tlcMode: "merge", action: tlcNotNeeded, reason: "runs at a gate"},
		{name: "a merge leaves the drop's liveness to a gate", model: model(nil), runMode: "live-drop", tlcMode: "merge", action: tlcNotNeeded, reason: "runs at a gate"},
		{name: "a merge with no TLC", model: model(nil), runMode: "twins-drop", tlcMode: "merge", missingTool: noTlc, action: tlcNotRun, reason: "TLC has not run"},
	}
	for _, c := range cases {
		action, reason := modeVerdict(c.model, c.runMode, c.tlcMode, c.gate, sources, c.missingTool)
		if action != c.action || !strings.Contains(reason, c.reason) {
			t.Errorf("%s: %s, %q; want %s with %q", c.name, action, reason, c.action, c.reason)
		}
	}
}

// One part of a spec, as run-tlc.sh's list-parts prints it: its twins, its stories and its liveness runs, in their
// tables' order.
type modelPart struct {
	name    string
	twins   []string
	stories []string
	lives   []string
}

// run-tlc.sh's parts of spec, as its list-parts mode prints them.
func partsTable(t *testing.T, spec string) []*modelPart {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("not run: this leg cannot run run-tlc.sh: %v", err)
	}
	output, err := exec.Command("bash", "run-tlc.sh", "list-parts", spec).Output()
	if err != nil {
		t.Fatalf("run-tlc.sh list-parts %s: %v", spec, err)
	}
	parts := []*modelPart{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			t.Fatalf("run-tlc.sh list-parts %s: %q", spec, line)
		}
		index := slices.IndexFunc(parts, func(part *modelPart) bool { return part.name == fields[0] })
		if index < 0 {
			parts = append(parts, &modelPart{name: fields[0]})
			index = len(parts) - 1
		}
		switch fields[1] {
		case "twins":
			parts[index].twins = append(parts[index].twins, fields[2:]...)
		case "stories":
			parts[index].stories = append(parts[index].stories, fields[2:]...)
		case "lives":
			parts[index].lives = append(parts[index].lives, fields[2:]...)
		default:
			t.Fatalf("run-tlc.sh list-parts %s: %q is no part's twins, stories or liveness runs", spec, line)
		}
	}
	return parts
}

// The run-tlc.sh modes that run a group of spec's runs a recorded run names: every spec's, then each part's twins and
// stories, and its liveness runs where it has them.
func specRunModes(t *testing.T, spec string) []string {
	t.Helper()
	modes := slices.Clone(modelRunModes)
	for _, part := range partsTable(t, spec) {
		modes = append(modes, "twins-"+part.name, "stories-"+part.name)
		if 0 < len(part.lives) {
			modes = append(modes, "live-"+part.name)
		}
	}
	return modes
}

// A run line run-tlc.sh prints before each TLC run it starts: "== twin-PurgeUnseen: <the cfg it runs>".
var runTlcStartPattern = regexp.MustCompile(`(?m)^== (\S+): (.*)$`)

// The runs run-tlc.sh starts for args, under a stand-in for TLC that checks nothing and passes, so each run's
// label shows what the mode runs, whatever its verdict, and its exit code.
func runTlcLabels(t *testing.T, args ...string) ([]string, int) {
	t.Helper()
	starts, code := runTlcStarts(t, args...)
	labels := []string{}
	for _, start := range starts {
		labels = append(labels, start[0])
	}
	return labels, code
}

// The runs run-tlc.sh starts for args under the stand-in, each its label and the cfg it shows, a line, and its exit
// code.
func runTlcStarts(t *testing.T, args ...string) ([][2]string, int) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("not run: this leg cannot run run-tlc.sh: %v", err)
	}
	directory := t.TempDir()
	standIn := filepath.Join(directory, "tlc")
	if err := os.WriteFile(standIn, []byte("#!/bin/sh\necho 'TLC2 stand-in (rev: 0000000)'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", append([]string{"run-tlc.sh"}, args...)...)
	command.Env = append(os.Environ(), "TLC="+standIn, "TLC_FLAGS=", "TMPDIR="+directory)
	output, err := command.CombinedOutput()
	if command.ProcessState == nil {
		t.Fatalf("run-tlc.sh %v did not start: %v", args, err)
	}
	starts := [][2]string{}
	for _, match := range runTlcStartPattern.FindAllStringSubmatch(string(output), -1) {
		starts = append(starts, [2]string{match[1], match[2]})
	}
	return starts, command.ProcessState.ExitCode()
}

// run-tlc.sh's parts (QD-1116, QD-1119): EvsCommit's M10 part runs as the purger's twins and stories and the drop
// extension's twins, stories and liveness, each group by a mode of its own that runs exactly its rows, and twins runs
// the M2 part's alone, so no part's run is recorded with another's; the drop extension's liveness runs each drop story
// under LiveSpec with F2DropsEnd on one instance. list keeps every twin, so mutants.yml still names each, and twin and
// control find a part's by name. StoreSettle and IndexRollup have no parts, a part no spec has is refused, as are
// liveness runs of the purger, which has none, and the stories mode that ran both parts' stories as one.
func TestRunTlcRunsEachPartApart(t *testing.T) {
	parts := partsTable(t, "EvsCommit")
	wants := []*modelPart{
		{name: "purge", twins: []string{"PurgeNoAllowance", "PurgeIgnoresHold", "PurgeUnseen", "EvacDropsNewest"}, stories: []string{"purgeA", "purgeB", "purgeC", "purgeD", "purgeE"}},
		{name: "drop", twins: []string{"DropNoFence", "DropNoAgeCheck", "DropIgnoresHold"}, stories: []string{"dropA", "dropB", "dropC"}, lives: []string{"dropA", "dropB", "dropC"}},
	}
	if len(parts) != len(wants) {
		t.Fatalf("EvsCommit's parts: %d, want %d", len(parts), len(wants))
	}
	for index, want := range wants {
		part := parts[index]
		if part.name != want.name || !slices.Equal(part.twins, want.twins) || !slices.Equal(part.stories, want.stories) || !slices.Equal(part.lives, want.lives) {
			t.Errorf("EvsCommit's part %d: %+v, want %+v", index, part, want)
		}
	}
	for _, spec := range []string{"StoreSettle", "IndexRollup"} {
		if others := partsTable(t, spec); len(others) != 0 {
			t.Errorf("%s has parts %v", spec, others)
		}
	}

	twins := twinTable(t, "EvsCommit")
	inPart := map[string]bool{}
	for _, part := range parts {
		for _, twin := range part.twins {
			if _, found := twins[twin]; !found {
				t.Errorf("run-tlc.sh list leaves out %s, the %s part's twin", twin, part.name)
			}
			if inPart[twin] {
				t.Errorf("%s is two parts' twin", twin)
			}
			inPart[twin] = true
		}
	}
	m2 := []string{}
	for twin := range twins {
		if !inPart[twin] {
			m2 = append(m2, "twin-"+twin)
		}
	}
	slices.Sort(m2)
	ran, _ := runTlcLabels(t, "twins", "EvsCommit")
	slices.Sort(ran)
	if len(m2) == 0 || !slices.Equal(ran, m2) {
		t.Errorf("twins EvsCommit ran %v, want the M2 part's %v", ran, m2)
	}
	for _, part := range parts {
		want := []string{}
		for _, twin := range part.twins {
			want = append(want, "twin-"+twin)
		}
		if ran, _ := runTlcLabels(t, "twins-"+part.name, "EvsCommit"); !slices.Equal(ran, want) {
			t.Errorf("twins-%s EvsCommit ran %v, want %v", part.name, ran, want)
		}
		want = []string{}
		for _, story := range part.stories {
			want = append(want, "story-"+story)
		}
		ran, code := runTlcLabels(t, "stories-"+part.name, "EvsCommit")
		if !slices.Equal(ran, want) || code != 0 {
			t.Errorf("stories-%s EvsCommit ran %v, exit %d, want %v passing on the stand-in", part.name, ran, code, want)
		}
	}
	// the drop extension's liveness: each drop story under LiveSpec with F2DropsEnd, no invariant, on one instance
	starts, code := runTlcStarts(t, "live-drop", "EvsCommit")
	if len(starts) != 3 || code != 0 {
		t.Errorf("live-drop EvsCommit ran %v, exit %d, want each drop story passing on the stand-in", starts, code)
	}
	for index, start := range starts {
		story := wants[1].lives[min(index, len(wants[1].lives)-1)]
		for _, fragment := range []string{"SPECIFICATION LiveSpec", "PROPERTY RemovalGates DueEpochCommits F2DropsEnd", "Instances = {i1}", `F2Run = "` + story + `"`} {
			if start[0] != "live-"+story || !strings.Contains(start[1], fragment) {
				t.Errorf("live-drop's run %s: want live-%s showing %q in %q", start[0], story, fragment, start[1])
			}
		}
		if strings.Contains(start[1], "INVARIANT") || strings.Contains(start[1], "SPECIFICATION Spec ") {
			t.Errorf("live-drop's run %s checks invariants or the plain spec: %q", start[0], start[1])
		}
	}
	if ran, _ := runTlcLabels(t, "twin", "EvsCommit", "DropNoFence"); !slices.Equal(ran, []string{"twin-DropNoFence"}) {
		t.Errorf("twin EvsCommit DropNoFence ran %v", ran)
	}
	if ran, _ := runTlcLabels(t, "control", "EvsCommit", "PurgeUnseen"); !slices.Equal(ran, []string{"control-PurgeUnseen"}) {
		t.Errorf("control EvsCommit PurgeUnseen ran %v", ran)
	}
	for _, args := range [][]string{{"twins-nope", "EvsCommit"}, {"stories-purge", "StoreSettle"}, {"twins-drop", "IndexRollup"}, {"live-purge", "EvsCommit"}, {"live-drop", "StoreSettle"}, {"stories", "EvsCommit"}} {
		if ran, code := runTlcLabels(t, args...); code != 64 || len(ran) != 0 {
			t.Errorf("run-tlc.sh %v ran %v, exit %d, want refused with 64", args, ran, code)
		}
	}
}

// A model test model_test.go declares under sidecar_tlc: one call of checkTlc with a spec and a run-tlc.sh mode.
var modelTestPattern = regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9]+)\(t \*testing\.T\) \{\n\tcheckTlc\(t, "([A-Za-z]+)", "([a-z-]+)"\)\n\}$`)

// model_test.go has a test for each mode modelled.yml's milestones name, one each, and every test runs a mode
// run-tlc.sh runs of its spec that a milestone names: a gate runs the model tests, so a mode with no test would never
// run at one, and the gate would read on the other modes alone.
func TestModelTestsRunEachModeAGateNeeds(t *testing.T) {
	data, err := os.ReadFile("model_test.go")
	if err != nil {
		t.Fatal(err)
	}
	runModes := map[string][]string{}
	tests := map[string]map[string][]string{}
	matches := modelTestPattern.FindAllStringSubmatch(string(data), -1)
	for _, match := range matches {
		name, spec, runMode := match[1], match[2], match[3]
		if _, found := runModes[spec]; !found {
			runModes[spec] = specRunModes(t, spec)
		}
		if !slices.Contains(runModes[spec], runMode) {
			t.Errorf("%s runs %s of %s, which run-tlc.sh does not run", name, runMode, spec)
		}
		if tests[spec] == nil {
			tests[spec] = map[string][]string{}
		}
		tests[spec][recordedMode(runMode)] = append(tests[spec][recordedMode(runMode)], name)
	}
	if calls := strings.Count(string(data), "\tcheckTlc(t, "); calls != len(matches) {
		t.Errorf("model_test.go calls checkTlc %d times and %d tests read as one call each", calls, len(matches))
	}
	for _, model := range readModelled(t).Models {
		modes := milestoneModes(model)
		for _, mode := range modes {
			if names := tests[model.Spec][mode]; len(names) != 1 {
				t.Errorf("%s's %s mode, which a milestone names, has the tests %v: want one", model.Spec, mode, names)
			}
		}
		for mode, names := range tests[model.Spec] {
			if !slices.Contains(modes, mode) {
				t.Errorf("%v run %s's %s, which no milestone names", names, model.Spec, mode)
			}
		}
	}
}

// The details form's half of TEST-M2-08's cadence: a details model's groups stand, each by its own passing
// run, while its sources are unchanged; a changed source reruns each group at a gate, and with no
// tla2tools.jar the gate fails and says the model has not run, never a pass; a merge runs none. A group
// whose passing run stands is not rerun beside one that must be.
func TestChangedDetailsSourceRerunsItsGroupsAtAGate(t *testing.T) {
	root := t.TempDir()
	// the monoroot the toy script names as its ROOT, whose .stack/tools holds the owner's TLC or not
	scriptRoot := filepath.Join(t.TempDir(), "monoroot")
	stackTools := filepath.Join(scriptRoot, ".stack", "tools")
	script := filepath.Join(root, "sidecar/sidecartest/model/details/run-toy.sh")
	for name, content := range map[string]string{
		"sidecar/sidecartest/model/details/Toy.tla":        "---- MODULE Toy ----\n====\n",
		"sidecar/sidecartest/model/details/ToyTwin-No.cfg": "INVARIANT\n    Held\n",
		"sidecar/sidecartest/model/details/run-toy.sh":     "#!/usr/bin/env bash\nROOT=" + scriptRoot + "\n(cd here && \"$ROOT/.stack/tools/tlc\" \"$track\" Toy.tla)\n",
		"sidecar/toy_head.go":                              "package sidecar\n",
	} {
		file := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	detail := &modelledDetail{
		Model: "details/Toy",
		Run:   "details/run-toy.sh",
		Sources: []string{
			"sidecar/sidecartest/model/details/Toy.tla",
			"sidecar/sidecartest/model/details/Toy*.cfg",
			"sidecar/sidecartest/model/details/run-toy.sh",
			"sidecar/toy_*.go",
		},
	}
	before, err := modelSources(root, detail.Sources, detail.Exclude)
	if err != nil {
		t.Fatal(err)
	}

	// the script's TLC: no jar beside the wrapper is no TLC, and the reason says so
	missing := detailsTlcMissing(script)
	if !strings.Contains(missing, "no tla2tools.jar") {
		t.Fatalf("no jar beside the script's TLC: %q", missing)
	}
	if err := os.MkdirAll(stackTools, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stackTools, "tla2tools.jar"), []byte("jar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if reason := detailsTlcMissing(script); !strings.Contains(reason, "no TLC at") {
		t.Errorf("a jar with no wrapper to run it: %q", reason)
	}
	if err := os.WriteFile(filepath.Join(stackTools, "tlc"), []byte("#!/usr/bin/env bash\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if reason := detailsTlcMissing(script); reason != "" {
		t.Errorf("the jar and its wrapper are there: %q", reason)
	}
	if reason := detailsTlcMissing(filepath.Join(root, "sidecar/toy_head.go")); !strings.Contains(reason, "no owner's TLC") {
		t.Errorf("a file that runs no TLC: %q", reason)
	}

	// every group passing at these sources stands, with no TLC here
	for _, group := range detailsRequiredModes {
		detail.Runs = append(detail.Runs, &modelledRun{Mode: group, Result: "pass", SourcesSha256: before.digest})
	}
	if action, reason := tlcVerdict(detail.Model, detail.Runs, detailsRequiredModes, "gate", before, missing); action != tlcUnchanged {
		t.Errorf("unchanged sources at a gate: %s, %s", action, reason)
	}

	// a cfg added to the model is a source like the spec
	if err := os.WriteFile(filepath.Join(root, "sidecar/sidecartest/model/details/ToyReach-Seen.cfg"), []byte("INVARIANT\n    NeverSeen\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := modelSources(root, detail.Sources, detail.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	if after.digest == before.digest {
		t.Fatal("a new cfg of the model left the digest")
	}
	if action, reason := tlcVerdict(detail.Model, detail.Runs, detailsRequiredModes, "gate", after, missing); action != tlcFail || !strings.Contains(reason, "has not run") || !strings.Contains(reason, "no tla2tools.jar") {
		t.Errorf("changed sources at a gate with no jar: %s, %s", action, reason)
	}
	if action, _ := tlcVerdict(detail.Model, detail.Runs, detailsRequiredModes, "gate", after, ""); action != tlcRun {
		t.Errorf("changed sources at a gate with the jar: %s", action)
	}
	if action, reason := tlcVerdict(detail.Model, detail.Runs, detailsRequiredModes, "merge", after, missing); action != tlcNotRun || !strings.Contains(reason, "has not run") {
		t.Errorf("a merge with no jar: %s, %s", action, reason)
	}

	// design and twins passed at the new sources and reach failed: reach alone reruns
	detail.Runs = append(detail.Runs,
		&modelledRun{Mode: "design", Result: "pass", SourcesSha256: after.digest},
		&modelledRun{Mode: "twins", Result: "pass", SourcesSha256: after.digest},
		&modelledRun{Mode: "reach", Result: "fail", SourcesSha256: after.digest},
	)
	if action, _ := tlcVerdict(detail.Model, detail.Runs, detailsRequiredModes, "gate", after, ""); action != tlcRun {
		t.Errorf("a failed reach run stood at a gate: %s", action)
	}
	rerun := []string{}
	for _, group := range detailsRequiredModes {
		if standingRun(detail.Runs, group, after.digest) == nil {
			rerun = append(rerun, group)
		}
	}
	if !slices.Equal(rerun, []string{"reach"}) {
		t.Errorf("groups rerun %v, want only reach", rerun)
	}
}

// Both kinds of run script print what a record needs, and a failing verdict is never read as a pass:
// run-tlc.sh's lines after TLC's banner, and a details script's lines, each naming the revision in its facts.
func TestRunScriptOutputIsSummarized(t *testing.T) {
	details := strings.Join([]string{
		"== PASS PrefixRules: every invariant holds, tlc d8fb231, exit 0, 37,275 distinct states, depth 5, 23s",
		"== PASS PrefixRules-Deep: every invariant holds, tlc d8fb231, exit 0, 300,450 distinct states, depth 6, 01min 18s",
		"== PASS PrefixRulesTwin-NoNewRefFence: NewRefFence violated as it must, a trace of 3 states, tlc d8fb231, exit 12, 19 distinct states, depth ?, 01s",
		"Error: Invariant NewRefFence is violated.",
		"",
	}, "\n")
	summary := summarizeTlc([]byte(details))
	if summary.revision != "d8fb231" || len(summary.passes) != 3 || len(summary.failures) != 0 {
		t.Errorf("details lines: revision %q, %d passes, %d failures", summary.revision, len(summary.passes), len(summary.failures))
	}
	if summary.states != 37275+300450+19 || summary.depth != 6 {
		t.Errorf("details lines: %d states, depth %d", summary.states, summary.depth)
	}

	spec := strings.Join([]string{
		"TLC2 Version 2.19 of Day Month 20?? (rev: d8fb231)",
		"== PASS model: 697,346 distinct states found, depth 21",
		"== FAIL twin-NoSettle: expected NoStaleQuorum violated, got 12 states generated",
		"",
	}, "\n")
	summary = summarizeTlc([]byte(spec))
	if summary.revision != "d8fb231" || len(summary.passes) != 1 || len(summary.failures) != 1 {
		t.Errorf("run-tlc.sh lines: revision %q, %d passes, %d failures", summary.revision, len(summary.passes), len(summary.failures))
	}
	if len(summary.failures) == 1 && !strings.HasPrefix(summary.failures[0], "twin-NoSettle: expected NoStaleQuorum") {
		t.Errorf("the failing verdict reads %q", summary.failures[0])
	}

	// a run whose TLC never started names no revision, so no record can be made of it
	summary = summarizeTlc([]byte("== FAIL CertOrder: error, tlc , exit 65, ? distinct states, depth ?, ?, 0 MB on disk at most\n"))
	if summary.revision != "" || len(summary.failures) != 1 {
		t.Errorf("a run with no TLC: revision %q, %d failures", summary.revision, len(summary.failures))
	}

	line := runRecordLine(&modelledRun{At: "2026-11-13", Commit: strings.Repeat("ab", 20), Tlc: "d8fb231", Mode: "twins", Result: "pass", SourcesSha256: strings.Repeat("0f", 32), States: 19, Depth: 0, Seconds: 1})
	record := &modelledRun{}
	if err := decodeStrict([]byte(strings.TrimPrefix(strings.TrimSpace(line), "- ")), record); err != nil {
		t.Fatalf("the record line %q does not read back: %v", line, err)
	}
	if findings := runFindings("details/Toy", []*modelledRun{record}, detailsRequiredModes); len(findings) != 0 {
		t.Errorf("the record line reads back out of form: %v", findings)
	}
}

// The runs rule refuses a run no gate could match, and passes a whole one.
func TestRunsRuleCatchesARunOutOfForm(t *testing.T) {
	whole := &modelledRun{At: "2026-11-13", Commit: strings.Repeat("1a", 20), Tlc: "d8fb231", Mode: "design", Result: "pass", SourcesSha256: strings.Repeat("c3", 32)}
	if findings := runFindings("details/Toy", []*modelledRun{whole}, detailsRequiredModes); len(findings) != 0 {
		t.Errorf("a whole run drew findings: %v", findings)
	}
	bad := &modelledRun{At: "13 Nov", Commit: "1a2b", Tlc: "", Mode: "mutants", Result: "passed", SourcesSha256: strings.Repeat("c3", 31)}
	findings := runFindings("details/Toy", []*modelledRun{whole, bad}, detailsRequiredModes)
	wants := []string{
		"details/Toy's run 2 has mode \"mutants\", which is none of [design twins reach]",
		"details/Toy's run 2 has result \"passed\", which is neither pass nor fail",
		"details/Toy's run 2 has at \"13 Nov\", which is out of form",
		"details/Toy's run 2 has commit \"1a2b\", which is out of form",
		"details/Toy's run 2 has tlc \"\", which is out of form",
		"details/Toy's run 2 has sources_sha256 \"" + strings.Repeat("c3", 31) + "\", which is out of form",
	}
	if !slices.Equal(findings, wants) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(wants, "\n"))
	}
}

// modelled.yml's details list names each model that stands alone under details/ once, with owners,
// milestones and objects, and holds it to real files: its spec, a run script under details/ that runs that
// spec and takes each group a gate runs, the spec, its cfgs and the script among its sources, and every
// source glob matching a file. A model under details/ that no list holds is reported open, as is a
// registered model whose code has not landed.
func TestModelledDetailsHoldTheirGlobsToRealFiles(t *testing.T) {
	modelled := readModelled(t)
	root := monoroot(t)
	companions := map[string]bool{}
	for _, model := range modelled.Models {
		for _, companion := range model.Companions {
			companions[companion] = true
		}
	}
	named := map[string]bool{}
	for _, detail := range modelled.Details {
		name, found := strings.CutPrefix(detail.Model, "details/")
		if !found || name == "" || strings.ContainsAny(name, "/*?[") {
			t.Errorf("%q is not a model under details/", detail.Model)
			continue
		}
		if named[detail.Model] {
			t.Errorf("modelled.yml's details list names %s twice", detail.Model)
		}
		named[detail.Model] = true
		if companions[detail.Model] {
			t.Errorf("%s is a spec's companion, which reruns with that spec; the details list holds models that stand alone", detail.Model)
		}
		if len(detail.Owners) == 0 || len(detail.Milestones) == 0 || detail.Objects == "" {
			t.Errorf("%s: no owners, milestones or objects", detail.Model)
		}
		spec := detail.Model + ".tla"
		if _, err := os.Stat(spec); err != nil {
			t.Errorf("%s has no spec: %v", detail.Model, err)
		}
		if !strings.HasPrefix(detail.Run, "details/run-") || !strings.HasSuffix(detail.Run, ".sh") || path.Clean(detail.Run) != detail.Run || strings.Count(detail.Run, "/") != 1 {
			t.Errorf("%s's run %q is no run script under details/", detail.Model, detail.Run)
		} else if script, err := os.ReadFile(detail.Run); err != nil {
			t.Errorf("%s's run script: %v", detail.Model, err)
		} else {
			if !bytes.Contains(script, []byte(name+".tla")) {
				t.Errorf("%s's run script %s never names %s.tla, so it does not run the model", detail.Model, detail.Run, name)
			}
			// the groups the script's case arms take
			groups := []string{}
			for _, group := range detailsRequiredModes {
				if regexp.MustCompile(`(?m)^\s*` + group + `\)`).Match(script) {
					groups = append(groups, group)
				}
			}
			if !slices.Equal(groups, detailsRequiredModes) {
				t.Errorf("%s's run script %s takes the groups %v, and a gate runs %v", detail.Model, detail.Run, groups, detailsRequiredModes)
			}
		}
		for _, pattern := range []string{spec, detail.Model + "*.cfg", detail.Run} {
			if !slices.Contains(detail.Sources, "sidecar/sidecartest/model/"+pattern) {
				t.Errorf("%s's sources leave out %s, whose change needs a rerun too", detail.Model, pattern)
			}
		}
		for _, finding := range runFindings(detail.Model, detail.Runs, detailsRequiredModes) {
			t.Error(finding)
		}
		sources, err := modelSources(root, detail.Sources, detail.Exclude)
		if err != nil {
			t.Fatal(err)
		}
		if 0 < len(sources.unreadable) {
			t.Logf("%s: %v not beside this checkout", detail.Model, sources.unreadable)
		}
		for _, pattern := range sources.empty {
			t.Errorf("%s's source %s matches no file", detail.Model, pattern)
		}
		code := 0
		for _, file := range sources.files {
			if strings.HasSuffix(file, ".go") {
				code += 1
			}
		}
		if code == 0 && len(sources.unreadable) == 0 {
			t.Logf("open: %s's sources hold no code yet, which its owners %v add as it lands", detail.Model, detail.Owners)
		}
		t.Logf("%s: %d source files, digest %s, %d runs recorded", detail.Model, len(sources.files), sources.digest, len(detail.Runs))
	}
	specs, err := filepath.Glob(filepath.Join("details", "*.tla"))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		model := strings.TrimSuffix(filepath.ToSlash(spec), ".tla")
		if !named[model] && !companions[model] {
			t.Logf("open: %s is in neither list of modelled.yml, so no gate reruns it", model)
		}
	}
}

// Each cfg's invariants, from its INVARIANT section: names on its line or indented below it.
func cfgInvariants(t *testing.T, spec string) []string {
	t.Helper()
	data, err := os.ReadFile(spec + ".cfg")
	if err != nil {
		t.Fatal(err)
	}
	invariants := []string{}
	inSection := false
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "INVARIANT"):
			inSection = true
			invariants = append(invariants, strings.Fields(strings.TrimPrefix(line, "INVARIANT"))...)
		case inSection && strings.HasPrefix(line, " "):
			invariants = append(invariants, strings.Fields(line)...)
		default:
			inSection = false
		}
	}
	return invariants
}

// run-tlc.sh's twin table for spec, as its list mode prints it: twin to the invariant it must break.
func twinTable(t *testing.T, spec string) map[string]string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("not run: this leg cannot run run-tlc.sh: %v", err)
	}
	output, err := exec.Command("bash", "run-tlc.sh", "list", spec).Output()
	if err != nil {
		t.Fatalf("run-tlc.sh list %s: %v", spec, err)
	}
	twins := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("run-tlc.sh list %s: %q", spec, line)
		}
		twins[fields[0]] = fields[1]
	}
	return twins
}

// Every invariant of every cfg names the mutants that must break it, each a twin run-tlc.sh runs
// against that invariant, and every twin is some invariant's mutant; an invariant no mutant breaks says
// why, and reads open.
func TestEveryInvariantNamesItsMutants(t *testing.T) {
	mutants := readMutants(t)
	specs := []string{}
	for _, model := range mutants.Models {
		specs = append(specs, model.Spec)
		invariants := cfgInvariants(t, model.Spec)
		twins := twinTable(t, model.Spec)
		listed := []string{}
		listedTwins := map[string]bool{}
		for _, entry := range model.Invariants {
			listed = append(listed, entry.Invariant)
			if !slices.Contains(invariants, entry.Invariant) {
				t.Errorf("%s: mutants.yml lists %s, which its cfg does not check", model.Spec, entry.Invariant)
			}
			if (len(entry.Mutants) == 0) == (entry.None == "") {
				t.Errorf("%s's %s: name its mutants, or say why it has none, and not both", model.Spec, entry.Invariant)
			}
			for _, mutant := range entry.Mutants {
				listedTwins[mutant] = true
				broken, found := twins[mutant]
				if !found {
					t.Errorf("%s's %s names %s, which run-tlc.sh has no twin of", model.Spec, entry.Invariant, mutant)
				} else if broken != entry.Invariant {
					t.Errorf("%s's %s names %s, which run-tlc.sh runs against %s", model.Spec, entry.Invariant, mutant, broken)
				}
			}
			if entry.None != "" {
				t.Logf("open: %s's %s has no mutant: %s", model.Spec, entry.Invariant, entry.None)
			}
		}
		for _, invariant := range invariants {
			if !slices.Contains(listed, invariant) {
				t.Errorf("%s's cfg checks %s, which mutants.yml does not list", model.Spec, invariant)
			}
		}
		for twin := range twins {
			if !listedTwins[twin] {
				t.Errorf("%s's twin %s is no invariant's mutant in mutants.yml", model.Spec, twin)
			}
		}
	}
	if !slices.Equal(specs, modelSpecs) {
		t.Errorf("mutants.yml names %v, want %v", specs, modelSpecs)
	}
}

// The words run-tlc.sh takes beside a cfg's constants to shape a run (with_constants there).
var runShapingWords = []string{"Quiet", "Simulate", "Traces", "Seed", "Script"}

// A spec's reach states: each Never... operator denies a state the design must reach, so a ground that
// passes is shown not to pass vacuously there.
var reachStatePattern = regexp.MustCompile(`(?m)^(Never[A-Za-z0-9]+) ==`)

// One row of run-tlc.sh's design grounds: how its run must end and the constants it sets.
type modelGround struct {
	name   string
	expect string
	bounds []string
}

// run-tlc.sh's design grounds for spec, as its list-grounds mode prints them.
func groundTable(t *testing.T, spec string) []*modelGround {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skipf("not run: this leg cannot run run-tlc.sh: %v", err)
	}
	output, err := exec.Command("bash", "run-tlc.sh", "list-grounds", spec).Output()
	if err != nil {
		t.Fatalf("run-tlc.sh list-grounds %s: %v", spec, err)
	}
	grounds := []*modelGround{}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("run-tlc.sh list-grounds %s: %q", spec, line)
		}
		grounds = append(grounds, &modelGround{name: fields[0], expect: fields[1], bounds: fields[2:]})
	}
	return grounds
}

// What the grounds rule finds wrong with spec's design grounds: two rows of one name, a row that ends as
// no ground can (a pass, liveness holding, or an invariant its cfg checks or one of the spec's reach
// states violated), a constant its cfg lacks, a reach state no row checks, or no passing or liveness row.
func groundFindings(spec string, grounds []*modelGround, reachStates []string, invariants []string, constants map[string]string) []string {
	findings := []string{}
	named := map[string]bool{}
	reached := map[string]bool{}
	passes := 0
	lives := 0
	for _, ground := range grounds {
		if named[ground.name] {
			findings = append(findings, fmt.Sprintf("%s has two grounds named %s", spec, ground.name))
		}
		named[ground.name] = true
		switch {
		case ground.expect == "pass":
			passes += 1
		case ground.expect == "live":
			lives += 1
		case slices.Contains(reachStates, ground.expect):
			reached[ground.expect] = true
		case slices.Contains(invariants, ground.expect):
		default:
			findings = append(findings, fmt.Sprintf("%s's ground %s must end with %s, which is no pass, live, cfg invariant or reach state", spec, ground.name, ground.expect))
		}
		for _, bound := range ground.bounds {
			name, _, found := strings.Cut(bound, "=")
			if !found {
				findings = append(findings, fmt.Sprintf("%s's ground %s sets %q, which is no Name=value", spec, ground.name, bound))
			} else if _, set := constants[name]; !set && !slices.Contains(runShapingWords, name) {
				findings = append(findings, fmt.Sprintf("%s's ground %s sets %s, which its cfg has no constant of", spec, ground.name, name))
			}
		}
	}
	for _, state := range reachStates {
		if !reached[state] {
			findings = append(findings, fmt.Sprintf("%s's reach state %s is no ground's check, so no run shows the design reaches it", spec, state))
		}
	}
	if passes == 0 || lives == 0 {
		findings = append(findings, fmt.Sprintf("%s's grounds hold %d passing and %d liveness rows: want both", spec, passes, lives))
	}
	return findings
}

// IndexRollup's cfg bounds do not finish breadth-first on a shared host, so run-tlc.sh's design grounds
// carry its passing runs, and they reach every reach state its spec defines.
func TestIndexRollupGroundsReachEveryState(t *testing.T) {
	spec := "IndexRollup"
	data, err := os.ReadFile(spec + ".tla")
	if err != nil {
		t.Fatal(err)
	}
	reachStates := []string{}
	for _, match := range reachStatePattern.FindAllStringSubmatch(string(data), -1) {
		reachStates = append(reachStates, match[1])
	}
	if len(reachStates) == 0 {
		t.Fatalf("%s.tla defines no reach state", spec)
	}
	grounds := groundTable(t, spec)
	for _, finding := range groundFindings(spec, grounds, reachStates, cfgInvariants(t, spec), cfgConstants(t, spec)) {
		t.Error(finding)
	}
	t.Logf("%s: %d grounds, reach states %v", spec, len(grounds), reachStates)
}

// StoreSettle's cfg runs only the first of §22.8's breadth-first runs, so run-tlc.sh's design grounds
// carry the rest, bounded as details/Settle.tla's configurations are, and the two traces of the question
// its DELETE rule answered (QD-744); its liveness rows, which live mode runs, are grounds too. Each row
// ends as a ground can and sets only constants the cfg has. The spec defines no reach state.
func TestStoreSettleGroundsSetOnlyItsConstants(t *testing.T) {
	spec := "StoreSettle"
	grounds := groundTable(t, spec)
	for _, finding := range groundFindings(spec, grounds, nil, cfgInvariants(t, spec), cfgConstants(t, spec)) {
		t.Error(finding)
	}
	t.Logf("%s: %d grounds", spec, len(grounds))
}

// The grounds rule catches a reach state no row checks, a constant the cfg lacks, two rows of one name, a
// row that ends as no ground can and a table with no liveness row, and passes a table with none of them.
func TestGroundsRuleCatchesAnUncheckedReachState(t *testing.T) {
	reachStates := []string{"NeverRolled", "NeverPromoted"}
	invariants := []string{"ResultsHold"}
	constants := map[string]string{"Events": "8", "Still": "{}"}
	good := []*modelGround{
		{name: "rolls", expect: "pass", bounds: []string{"Events=2", "Still={\"erase\"}"}},
		{name: "rolls-live", expect: "live", bounds: []string{"Events=1", "Simulate=40"}},
		{name: "reach-rolled", expect: "NeverRolled", bounds: []string{"Events=1"}},
		{name: "reach-promoted", expect: "NeverPromoted", bounds: nil},
		{name: "finding", expect: "ResultsHold", bounds: []string{"Events=3"}},
	}
	if findings := groundFindings("Toy", good, reachStates, invariants, constants); len(findings) != 0 {
		t.Errorf("a whole table drew findings: %v", findings)
	}
	bad := []*modelGround{
		{name: "rolls", expect: "pass", bounds: []string{"Evnets=2"}},
		{name: "rolls", expect: "NeverRolled", bounds: []string{"Events"}},
		{name: "sometimes", expect: "Eventually", bounds: nil},
	}
	findings := groundFindings("Toy", bad, reachStates, invariants, constants)
	wants := []string{
		"Toy's ground rolls sets Evnets, which its cfg has no constant of",
		"Toy has two grounds named rolls",
		"Toy's ground rolls sets \"Events\", which is no Name=value",
		"Toy's ground sometimes must end with Eventually, which is no pass, live, cfg invariant or reach state",
		"Toy's reach state NeverPromoted is no ground's check, so no run shows the design reaches it",
		"Toy's grounds hold 1 passing and 0 liveness rows: want both",
	}
	if !slices.Equal(findings, wants) {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(findings, "\n"), strings.Join(wants, "\n"))
	}
}
