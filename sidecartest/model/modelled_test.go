// The program around §22.8's TLA+ models (TEST-M2-08; D-TEST-10, D-PHASE-7, FI-30), the part that needs
// no TLC: modelled.yml's sources and the digest a gate compares, the rule that decides a gate's rerun,
// mutants/mutants.yml held to run-tlc.sh's twin tables and each cfg's invariants, IndexRollup's design
// grounds held to its spec's reach states and its cfg, and modelled.yml's details list, the models of
// DESIGN-DETAILS.md that stand alone under details/, each held to its run script and to real files and
// rerun at a gate by its own script. It also reads what a run script prints, which model_test.go, under
// sidecar_tlc, records when it runs TLC itself.

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

// What a gate needs passing at a model's sources before it lets the run stand.
var modelRequiredModes = []string{"model", "mutants", "live"}

// The modes a model's recorded run may name, as model_test.go records run-tlc.sh's: its twins as mutants.
var modelRecordedModes = []string{"model", "mutants", "live", "stories"}

// The groups of a details model's run script, each of which a gate needs passing at the model's sources
// before it lets the runs stand, and which a recorded run names as its mode: the design configurations,
// which must pass; the twins, each of which must end with the invariant its cfg names violated; and the
// reach configurations, each of which must reach the state its cfg's last invariant denies.
var detailsRequiredModes = []string{"design", "twins", "reach"}

type modelledFile struct {
	Models  []*modelledModel  `yaml:"models"`
	Details []*modelledDetail `yaml:"details"`
}

// One model: what it keeps, the code that implements that, and its recorded runs.
type modelledModel struct {
	Spec       string   `yaml:"spec"`
	Owners     []string `yaml:"owners"`
	Milestones []string `yaml:"milestones"`
	Objects    string   `yaml:"objects"`
	// models of the same objects under details/, each run by its own script there
	Companions []string       `yaml:"companions"`
	Sources    []string       `yaml:"sources"`
	Exclude    []string       `yaml:"exclude"`
	Runs       []*modelledRun `yaml:"runs"`
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
)

// §22.8's cadence for one model, named name, whose runs need each of requiredModes: at a gate, the newest
// passing runs stand while the sources they ran at are unchanged, and otherwise TLC runs, or the gate fails
// naming the missing tool; at a merge, TLC runs where it is, and is reported not run where it is not.
// missingTool says why TLC cannot run here, and is empty where it can.
func tlcVerdict(name string, runs []*modelledRun, requiredModes []string, mode string, sources *sourcesState, missingTool string) (tlcAction, string) {
	if mode == "gate" {
		if 0 < len(sources.unreadable) {
			return tlcFail, fmt.Sprintf("%s's sources %v are not beside this checkout, so whether they changed is unknown", name, sources.unreadable)
		}
		standing := 0
		for _, required := range requiredModes {
			if standingRun(runs, required, sources.digest) != nil {
				standing += 1
			}
		}
		if standing == len(requiredModes) {
			return tlcUnchanged, fmt.Sprintf("%s's sources are unchanged since its passing runs, which stand", name)
		}
		if missingTool != "" {
			return tlcFail, fmt.Sprintf("%s's sources changed since its last passing runs, or none is recorded, and TLC has not run: %s", name, missingTool)
		}
		return tlcRun, fmt.Sprintf("%s's sources changed since its last passing runs, or none is recorded", name)
	}
	if missingTool != "" {
		return tlcNotRun, fmt.Sprintf("%s: TLC has not run: %s", name, missingTool)
	}
	return tlcRun, name + "'s mutants run at each merge"
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

// What is wrong with a model's recorded runs: a run of a mode the model has no runs of, a result other than
// pass or fail, or a date, commit, TLC revision or digest out of form. Such a run never stands at a gate,
// and reads as though it did.
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
// recorded run is in a form a gate can read.
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
		for _, finding := range runFindings(model.Spec, model.Runs, modelRecordedModes) {
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
	noTlc := "no tla2tools.jar (set TLC to a command that runs tlc2.TLC)"
	before, err := modelSources(root, model.Sources, model.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before.files, []string{"sidecar/sidecartest/model/Toy.tla", "sidecar/toy_head.go"}) {
		t.Fatalf("sources %v: a test file counted, or a source was missed", before.files)
	}
	for _, mode := range modelRequiredModes {
		model.Runs = append(model.Runs, &modelledRun{Mode: mode, Result: "pass", SourcesSha256: before.digest})
	}
	if action, _ := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, "gate", before, noTlc); action != tlcUnchanged {
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
	if action, reason := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, "gate", after, noTlc); action != tlcFail || !strings.Contains(reason, "no tla2tools.jar") {
		t.Errorf("changed sources at a gate with no TLC: %s, %s", action, reason)
	}
	if action, _ := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, "gate", after, ""); action != tlcRun {
		t.Errorf("changed sources at a gate with TLC: %s", action)
	}
	if action, reason := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, "merge", after, noTlc); action != tlcNotRun || !strings.Contains(reason, "has not run") {
		t.Errorf("a merge with no TLC: %s, %s", action, reason)
	}

	// a run that failed, or one mode short, does not stand
	model.Runs = []*modelledRun{
		{Mode: "model", Result: "pass", SourcesSha256: after.digest},
		{Mode: "mutants", Result: "fail", SourcesSha256: after.digest},
		{Mode: "live", Result: "pass", SourcesSha256: after.digest},
	}
	if action, _ := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, "gate", after, noTlc); action != tlcFail {
		t.Errorf("a failed mutants run stood at a gate: %s", action)
	}

	// a sibling the sources name and this machine lacks leaves the gate unable to decide
	model.Sources = append(model.Sources, "minio/cmd/settle-*.go")
	missing, err := modelSources(root, model.Sources, model.Exclude)
	if err != nil {
		t.Fatal(err)
	}
	if action, reason := tlcVerdict(model.Spec, model.Runs, modelRequiredModes, "gate", missing, ""); action != tlcFail || !strings.Contains(reason, "not beside") {
		t.Errorf("a missing sibling at a gate: %s, %s", action, reason)
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
