package sidecartest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// One row of testdata/targets.yml, R-TEST-7's target ledger (TEST-M2-13).
type loadTarget struct {
	Id      string   `yaml:"id"`
	Section string   `yaml:"section"`
	Path    string   `yaml:"path"`
	Target  string   `yaml:"target"`
	Metric  string   `yaml:"metric"`
	Limit   *float64 `yaml:"limit"`
	Tier    string   `yaml:"tier"`
	Owners  []string `yaml:"owners"`
	// TestName in this module, or server:TestName in the sibling server checkout
	Test string `yaml:"test"`
	Open string `yaml:"open"`
}

type loadTargetLedger struct {
	Targets []*loadTarget `yaml:"targets"`
}

// The sections R-TEST-7 names, and §9.8 for §22.8's sockets row.
var loadTargetSections = []string{"§8.9", "§9.8", "§10.6", "§11.13", "§11.15", "§13.5", "§17.5", "D-SMTP-16"}

var loadTargetTiers = []string{"T2", "T3", "T4", "T5", "production"}

var loadTargetOwnerPattern = regexp.MustCompile(`^[A-Z0-9]+-M[0-9]+-[0-9]{2}$`)

var loadTargetIdPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// The repository's top, the nearest ancestor of the working directory holding testdata/targets.yml.
func loadTargetTop(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		if _, err := os.Stat(filepath.Join(directory, "testdata", "targets.yml")); err == nil {
			return directory
		}
		if directory == filepath.Dir(directory) {
			t.Fatalf("no testdata/targets.yml above %s", workingDirectory)
		}
	}
}

// Parses the ledger strictly: a field no row has, a duplicate key, a tab or a second document fails.
func parseLoadTargetLedger(data []byte) (*loadTargetLedger, error) {
	if index := bytes.IndexByte(data, '\t'); 0 <= index {
		return nil, fmt.Errorf("line %d holds a tab", 1+bytes.Count(data[:index], []byte("\n")))
	}
	ledger := &loadTargetLedger{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(ledger); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("it holds a second document: %v", err)
	}
	return ledger, nil
}

// Whether a top-level test of that name is declared in a _test.go file under root.
func testDeclaredUnder(root string, testName string) (bool, error) {
	declaration := []byte("func " + testName + "(")
	found := false
	err := filepath.WalkDir(root, func(walkPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "testdata", "third_party", "design":
				return filepath.SkipDir
			}
			return nil
		}
		if found || !strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		data, err := os.ReadFile(walkPath)
		if err != nil {
			return err
		}
		found = bytes.Contains(data, declaration)
		return nil
	})
	return found, err
}

// What a row's test resolves to: "" when it names a test that exists, else why the row reads open,
// and an error for a test it names that does not exist.
func resolveLoadTarget(top string, target *loadTarget) (open string, err error) {
	if target.Test == "" {
		return "no owning test yet", nil
	}
	root := top
	testName := target.Test
	if repo, name, found := strings.Cut(target.Test, ":"); found {
		if repo != "server" {
			return "", fmt.Errorf("%s names a test in %q, which is neither this module nor server", target.Id, repo)
		}
		root = filepath.Join(filepath.Dir(top), "server")
		testName = name
		if _, statErr := os.Stat(root); statErr != nil {
			return "server is not beside this checkout to resolve " + testName, nil
		}
	}
	if !strings.HasPrefix(testName, "Test") {
		return "", fmt.Errorf("%s names %q, which is no test", target.Id, testName)
	}
	declared, err := testDeclaredUnder(root, testName)
	if err != nil {
		return "", err
	}
	if !declared {
		return "", fmt.Errorf("%s names %s, which no test file declares", target.Id, target.Test)
	}
	return "", nil
}

// Each row's own fields.
func loadTargetFindings(ledger *loadTargetLedger) []string {
	findings := []string{}
	ids := map[string]bool{}
	for _, target := range ledger.Targets {
		if !loadTargetIdPattern.MatchString(target.Id) || ids[target.Id] {
			findings = append(findings, fmt.Sprintf("%q: an id malformed or held twice", target.Id))
		}
		ids[target.Id] = true
		if !slices.Contains(loadTargetSections, target.Section) {
			findings = append(findings, fmt.Sprintf("%s: section %q is not one R-TEST-7 names", target.Id, target.Section))
		}
		if target.Path == "" || target.Target == "" || target.Metric == "" {
			findings = append(findings, fmt.Sprintf("%s: no path, target or metric", target.Id))
		}
		if !slices.Contains(loadTargetTiers, target.Tier) {
			findings = append(findings, fmt.Sprintf("%s: tier %q", target.Id, target.Tier))
		}
		if len(target.Owners) == 0 {
			findings = append(findings, fmt.Sprintf("%s: no owner", target.Id))
		}
		for _, owner := range target.Owners {
			if !loadTargetOwnerPattern.MatchString(owner) {
				findings = append(findings, fmt.Sprintf("%s: owner %q is no task id", target.Id, owner))
			}
		}
		if target.Open != "" && !slices.Contains([]string{"production", "hardware", "people"}, target.Open) {
			findings = append(findings, fmt.Sprintf("%s: open %q is not production, hardware or people", target.Id, target.Open))
		}
	}
	return findings
}

// Every row of the ledger is well formed, every section R-TEST-7 names has a row, and each row
// resolves to a test that exists or reads open: an unverified number shows as open, never as met.
func TestTargetLedgerRowsResolveOrReadOpen(t *testing.T) {
	top := loadTargetTop(t)
	data, err := os.ReadFile(filepath.Join(top, "testdata", "targets.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := parseLoadTargetLedger(data)
	if err != nil {
		t.Fatalf("testdata/targets.yml: %v", err)
	}
	for _, finding := range loadTargetFindings(ledger) {
		t.Error(finding)
	}
	for _, section := range loadTargetSections {
		if !slices.ContainsFunc(ledger.Targets, func(target *loadTarget) bool { return target.Section == section }) {
			t.Errorf("no target of %s", section)
		}
	}
	openCount := 0
	for _, target := range ledger.Targets {
		open, err := resolveLoadTarget(top, target)
		if err != nil {
			t.Error(err)
			continue
		}
		if open != "" {
			openCount += 1
			t.Logf("open: %s (%s, %s): %s", target.Id, target.Section, strings.Join(target.Owners, ", "), open)
		}
	}
	t.Logf("%d of %d targets read open", openCount, len(ledger.Targets))
}

// A row naming a test that does not exist fails, one naming none reads open, and one naming a test
// that exists resolves.
func TestTargetLedgerResolvesTestsByName(t *testing.T) {
	top := loadTargetTop(t)
	cases := []struct {
		test    string
		open    bool
		failure string
	}{
		{test: "", open: true},
		{test: "TestTargetLedgerResolvesTestsByName"},
		{test: "TestNoSuchLoadRunAnywhere", failure: "no test file declares"},
		{test: "LoadRun", failure: "is no test"},
		{test: "mmm:TestLoadRun", failure: "neither this module nor server"},
	}
	for _, testCase := range cases {
		open, err := resolveLoadTarget(top, &loadTarget{Id: "planted", Test: testCase.test})
		switch {
		case testCase.failure != "":
			if err == nil || !strings.Contains(err.Error(), testCase.failure) {
				t.Errorf("%q: %v, want %q", testCase.test, err, testCase.failure)
			}
		case err != nil:
			t.Errorf("%q: %v", testCase.test, err)
		case testCase.open != (open != ""):
			t.Errorf("%q: open %q", testCase.test, open)
		}
	}
}

// The ledger's strict reader and row checks refuse what a typo would let through.
func TestTargetLedgerRefusesMalformedRows(t *testing.T) {
	if _, err := parseLoadTargetLedger([]byte("targets:\n  - {id: a, sction: \"§8.9\"}\n")); err == nil {
		t.Error("an unknown field was accepted")
	}
	ledger, err := parseLoadTargetLedger([]byte("targets:\n" +
		"  - {id: a, section: \"§8.9\", path: p, target: t, metric: m, tier: T9, owners: [ACL-M2-13]}\n" +
		"  - {id: a, section: \"§99\", path: p, target: t, metric: m, tier: T3, owners: [acl], open: soon}\n"))
	if err != nil {
		t.Fatal(err)
	}
	findings := strings.Join(loadTargetFindings(ledger), "\n")
	for _, want := range []string{`tier "T9"`, "held twice", `section "§99"`, `owner "acl"`, `open "soon"`} {
		if !strings.Contains(findings, want) {
			t.Errorf("no finding %q in:\n%s", want, findings)
		}
	}
}
