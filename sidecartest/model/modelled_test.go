// The program around §22.8's TLA+ models (TEST-M2-08; D-TEST-10, D-PHASE-7, FI-30), the part that needs
// no TLC: modelled.yml's sources and the digest a gate compares, the rule that decides a gate's rerun,
// mutants/mutants.yml held to run-tlc.sh's twin tables and each cfg's invariants, and IndexRollup's
// design grounds held to its spec's reach states and its cfg. model_test.go, under sidecar_tlc, runs TLC
// itself.

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
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The specs this directory holds.
var modelSpecs = []string{"EvsCommit", "StoreSettle", "IndexRollup"}

// What a gate needs passing at a model's sources before it lets the run stand.
var modelRequiredModes = []string{"model", "mutants", "live"}

type modelledFile struct {
	Models []*modelledModel `yaml:"models"`
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

func modelSources(root string, model *modelledModel) (*sourcesState, error) {
	state := &sourcesState{}
	excluded := map[string]bool{}
	for _, pattern := range model.Exclude {
		matches, err := filepath.Glob(filepath.Join(root, pattern))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			excluded[match] = true
		}
	}
	seen := map[string]bool{}
	for _, pattern := range model.Sources {
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

// §22.8's cadence for one model: at a gate, the newest passing runs stand while the sources they ran at
// are unchanged, and otherwise TLC runs, or the gate fails naming the missing tool; at a merge, TLC
// runs where it is, and is reported not run where it is not.
func tlcVerdict(model *modelledModel, mode string, sources *sourcesState, tlcAvailable bool) (tlcAction, string) {
	if mode == "gate" {
		if 0 < len(sources.unreadable) {
			return tlcFail, fmt.Sprintf("%s's sources %v are not beside this checkout, so whether they changed is unknown", model.Spec, sources.unreadable)
		}
		standing := []string{}
		for _, required := range modelRequiredModes {
			for _, run := range model.Runs {
				if run.Mode == required && run.Result == "pass" && run.SourcesSha256 == sources.digest {
					standing = append(standing, required)
					break
				}
			}
		}
		if len(standing) == len(modelRequiredModes) {
			return tlcUnchanged, fmt.Sprintf("%s's sources are unchanged since its passing runs, which stand", model.Spec)
		}
		if !tlcAvailable {
			return tlcFail, fmt.Sprintf("%s's sources changed since its last passing runs, or none is recorded, and TLC has not run: no tla2tools.jar (set TLC to a command that runs tlc2.TLC)", model.Spec)
		}
		return tlcRun, fmt.Sprintf("%s's sources changed since its last passing runs, or none is recorded", model.Spec)
	}
	if !tlcAvailable {
		return tlcNotRun, fmt.Sprintf("%s: TLC has not run: no tla2tools.jar (set TLC to a command that runs tlc2.TLC)", model.Spec)
	}
	return tlcRun, model.Spec + "'s mutants run at each merge"
}

// modelled.yml names each spec once, with owners and milestones, and its globs match real files: every
// spec, cfg and run-tlc.sh, and code for each model.
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
			companionScript := slices.ContainsFunc(model.Sources, func(source string) bool {
				return strings.HasPrefix(source, "sidecar/sidecartest/model/details/run-") && strings.HasSuffix(source, ".sh")
			})
			if !companionScript {
				t.Errorf("%s's sources name no run script for its companion %s", model.Spec, companion)
			}
		}
		sources, err := modelSources(root, model)
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
	before, err := modelSources(root, model)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(before.files, []string{"sidecar/sidecartest/model/Toy.tla", "sidecar/toy_head.go"}) {
		t.Fatalf("sources %v: a test file counted, or a source was missed", before.files)
	}
	for _, mode := range modelRequiredModes {
		model.Runs = append(model.Runs, &modelledRun{Mode: mode, Result: "pass", SourcesSha256: before.digest})
	}
	if action, _ := tlcVerdict(model, "gate", before, false); action != tlcUnchanged {
		t.Errorf("unchanged sources at a gate: %s", action)
	}

	// a test file's edit changes nothing; a source's does
	if err := os.WriteFile(filepath.Join(root, "sidecar/toy_head_test.go"), []byte("package sidecar\n\n// edited\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if again, _ := modelSources(root, model); again.digest != before.digest {
		t.Error("a test file's edit changed the digest")
	}
	if err := os.WriteFile(filepath.Join(root, "sidecar/toy_head.go"), []byte("package sidecar\n\nconst toyFold = 64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := modelSources(root, model)
	if err != nil {
		t.Fatal(err)
	}
	if after.digest == before.digest {
		t.Fatal("a source's edit left the digest")
	}
	if action, reason := tlcVerdict(model, "gate", after, false); action != tlcFail || !strings.Contains(reason, "no tla2tools.jar") {
		t.Errorf("changed sources at a gate with no TLC: %s, %s", action, reason)
	}
	if action, _ := tlcVerdict(model, "gate", after, true); action != tlcRun {
		t.Errorf("changed sources at a gate with TLC: %s", action)
	}
	if action, reason := tlcVerdict(model, "merge", after, false); action != tlcNotRun || !strings.Contains(reason, "has not run") {
		t.Errorf("a merge with no TLC: %s, %s", action, reason)
	}

	// a run that failed, or one mode short, does not stand
	model.Runs = []*modelledRun{
		{Mode: "model", Result: "pass", SourcesSha256: after.digest},
		{Mode: "mutants", Result: "fail", SourcesSha256: after.digest},
		{Mode: "live", Result: "pass", SourcesSha256: after.digest},
	}
	if action, _ := tlcVerdict(model, "gate", after, false); action != tlcFail {
		t.Errorf("a failed mutants run stood at a gate: %s", action)
	}

	// a sibling the sources name and this machine lacks leaves the gate unable to decide
	model.Sources = append(model.Sources, "minio/cmd/settle-*.go")
	missing, err := modelSources(root, model)
	if err != nil {
		t.Fatal(err)
	}
	if action, reason := tlcVerdict(model, "gate", missing, true); action != tlcFail || !strings.Contains(reason, "not beside") {
		t.Errorf("a missing sibling at a gate: %s, %s", action, reason)
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
