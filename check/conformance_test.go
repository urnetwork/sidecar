//go:build sidecar_check

// §22.9's conformance ledger (D-TEST-7: "conformance peers are pinned and rerun per pin change";
// R-TEST-7; TEST-M2-17): testdata/conformance/peers.yml lists each §22.9 row's peers with the version
// each is pinned at and every run recorded. The rule reads it against §22.9's own text and fails on a
// row the design holds and the ledger does not, a row the ledger holds and the design does not, a
// peer list the design has changed since the ledger was read against it, a pin that is no version,
// and a pin that changed with no run recorded at it since. What has not run, or has no pin yet, is
// reported open, never passed: the ledger records evidence, and a missing run is no evidence.

package check

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The ledger moves with the root module on a release branch; design/ stays at the top (§4.9).
const (
	conformanceLedgerPath  = "testdata/conformance/peers.yml"
	conformanceSectionPath = "design/source/sections/22-TEST.md"
)

// What a run may report. open: the host lacked the peer, which is never a pass.
const (
	conformancePass = "pass"
	conformanceFail = "fail"
	conformanceOpen = "open"
)

// A task id, as the plans write them.
var conformanceOwnerPattern = regexp.MustCompile(`^[A-Z0-9]+-M[0-9]+-[0-9]{2}$`)

var conformanceMilestonePattern = regexp.MustCompile(`^M([0-9]|10)$`)

var conformanceDayPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// A pin or what a latest peer got: something with a digit in it, so "latest", "stable" and an empty
// string are refused.
var conformanceVersionPattern = regexp.MustCompile(`[0-9]`)

// A host names a machine by its name, never an address (I-13, CODESTYLE's test data rule).
var conformanceAddressPattern = regexp.MustCompile(`^[0-9.]+$|:`)

// The ledger as peers.yml holds it.
type conformanceLedger struct {
	Rows []*conformanceRow `yaml:"rows"`
}

// One §22.9 row: its peers, who runs them, and the design text the ledger was read against.
type conformanceRow struct {
	Row       string             `yaml:"row"`
	Design    string             `yaml:"design"`
	Owners    []string           `yaml:"owners"`
	Milestone string             `yaml:"milestone"`
	Tests     []string           `yaml:"tests"`
	Peers     []*conformancePeer `yaml:"peers"`
}

// One peer of a row, pinned, latest, or not yet pinned, with its runs, newest last.
type conformancePeer struct {
	Peer     string            `yaml:"peer"`
	Pin      string            `yaml:"pin"`
	Latest   bool              `yaml:"latest"`
	Source   string            `yaml:"source"`
	Unpinned string            `yaml:"unpinned"`
	Runs     []*conformanceRun `yaml:"runs"`
}

// One recorded run of a peer.
type conformanceRun struct {
	At     string `yaml:"at"`
	Host   string `yaml:"host"`
	Pin    string `yaml:"pin"`
	Got    string `yaml:"got"`
	Result string `yaml:"result"`
	Test   string `yaml:"test"`
	Commit string `yaml:"commit"`
}

// Parses the ledger strictly: a field no entry has, a duplicate key, a tab or a second document fails.
func parseConformanceLedger(data []byte) (*conformanceLedger, error) {
	if index := bytes.IndexByte(data, '\t'); 0 <= index {
		return nil, fmt.Errorf("line %d holds a tab", 1+bytes.Count(data[:index], []byte("\n")))
	}
	ledger := &conformanceLedger{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(ledger); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("it holds no document")
		}
		return nil, err
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("it holds a second document: %v", err)
	}
	return ledger, nil
}

// §22.9's rows, by bold name, each with its parenthesized peer list.
type conformanceDesignRow struct {
	name  string
	peers string
}

// The bullets of §22.9, each "- **name** (peers): ...". The peer list closes at its matching
// parenthesis, since it holds parentheses of its own ("Postfix (may, dane)").
func conformanceDesignRows(section []byte) ([]conformanceDesignRow, error) {
	rows := []conformanceDesignRow{}
	inSection := false
	for _, line := range strings.Split(string(section), "\n") {
		if strings.HasPrefix(line, "### ") {
			inSection = strings.HasPrefix(line, "### 22.9 ")
			continue
		}
		if !inSection || !strings.HasPrefix(line, "- **") {
			continue
		}
		rest := strings.TrimPrefix(line, "- **")
		name, rest, found := strings.Cut(rest, "**")
		if !found {
			return nil, fmt.Errorf("§22.9's bullet %q has no closing bold", line)
		}
		rest = strings.TrimPrefix(rest, " ")
		if !strings.HasPrefix(rest, "(") {
			return nil, fmt.Errorf("§22.9's row %s names no peers in parentheses", name)
		}
		depth := 0
		end := -1
		for index, character := range rest {
			switch character {
			case '(':
				depth += 1
			case ')':
				depth -= 1
			}
			if depth == 0 {
				end = index
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("§22.9's row %s never closes its peer list", name)
		}
		rows = append(rows, conformanceDesignRow{name: name, peers: rest[1:end]})
	}
	if len(rows) == 0 {
		return nil, errors.New("§22.9 holds no row")
	}
	return rows, nil
}

// What the rule found that fails, and what it reports open.
type conformanceVerdict struct {
	findings []string
	open     []string
}

// Holds the ledger at moduleDirectory against §22.9 at topDirectory.
func conformanceLedgerFindings(topDirectory string, moduleDirectory string) *conformanceVerdict {
	verdict := &conformanceVerdict{}
	section, err := os.ReadFile(filepath.Join(topDirectory, conformanceSectionPath))
	if err != nil {
		verdict.findings = append(verdict.findings, findingf("reading §22.9: %v", err))
		return verdict
	}
	designRows, err := conformanceDesignRows(section)
	if err != nil {
		verdict.findings = append(verdict.findings, findingf("%v", err))
		return verdict
	}
	data, err := os.ReadFile(filepath.Join(moduleDirectory, conformanceLedgerPath))
	if err != nil {
		verdict.findings = append(verdict.findings, findingf("reading the ledger: %v", err))
		return verdict
	}
	ledger, err := parseConformanceLedger(data)
	if err != nil {
		verdict.findings = append(verdict.findings, findingf("%s does not parse: %v", conformanceLedgerPath, err))
		return verdict
	}

	ledgerRows := map[string]*conformanceRow{}
	for _, row := range ledger.Rows {
		if _, seen := ledgerRows[row.Row]; seen {
			verdict.findings = append(verdict.findings, findingf("%s holds row %q twice", conformanceLedgerPath, row.Row))
			continue
		}
		ledgerRows[row.Row] = row
	}
	designNames := map[string]bool{}
	for _, designRow := range designRows {
		designNames[designRow.name] = true
		row, found := ledgerRows[designRow.name]
		if !found {
			verdict.findings = append(verdict.findings, findingf("§22.9's row %s has no entry in %s", designRow.name, conformanceLedgerPath))
			continue
		}
		if row.Design != designRow.peers {
			verdict.findings = append(verdict.findings, findingf(
				"%s: §22.9 now names its peers as %q, and the ledger was read against %q: read the change and update its peers",
				row.Row, designRow.peers, row.Design))
		}
	}
	for _, row := range ledger.Rows {
		if !designNames[row.Row] {
			verdict.findings = append(verdict.findings, findingf("%s holds row %q, which §22.9 does not", conformanceLedgerPath, row.Row))
		}
		rowFindings, rowOpen := row.check()
		verdict.findings = append(verdict.findings, rowFindings...)
		verdict.open = append(verdict.open, rowOpen...)
	}
	return verdict
}

// One row's own fields and its peers.
func (self *conformanceRow) check() ([]string, []string) {
	findings := []string{}
	open := []string{}
	if len(self.Owners) == 0 {
		findings = append(findings, findingf("%s names no owning task", self.Row))
	}
	for _, owner := range self.Owners {
		if !conformanceOwnerPattern.MatchString(owner) {
			findings = append(findings, findingf("%s's owner %q is no task id", self.Row, owner))
		}
	}
	if !conformanceMilestonePattern.MatchString(self.Milestone) {
		findings = append(findings, findingf("%s's milestone %q is no milestone", self.Row, self.Milestone))
	}
	if len(self.Tests) == 0 {
		open = append(open, findingf("%s: no owning test yet (%s), so a gate reads it missing", self.Row, strings.Join(self.Owners, ", ")))
	}
	if len(self.Peers) == 0 {
		findings = append(findings, findingf("%s lists no peer", self.Row))
	}
	peerNames := map[string]bool{}
	for _, peer := range self.Peers {
		name := self.Row + ": " + peer.Peer
		if peer.Peer == "" {
			findings = append(findings, findingf("%s has a peer with no name", self.Row))
		}
		if peerNames[peer.Peer] {
			findings = append(findings, findingf("%s is listed twice", name))
		}
		peerNames[peer.Peer] = true
		peerFindings, peerOpen := peer.check(name, self.Tests)
		findings = append(findings, peerFindings...)
		open = append(open, peerOpen...)
	}
	return findings, open
}

// One peer: its pin, its runs, and whether its newest run is at its pin.
func (self *conformancePeer) check(name string, tests []string) ([]string, []string) {
	findings := []string{}
	open := []string{}
	switch {
	case self.Latest && (self.Pin != "" || self.Unpinned != ""):
		findings = append(findings, findingf("%s is pinned at each run (latest), so it takes no pin and no unpinned", name))
	case self.Latest:
	case self.Pin != "" && self.Unpinned != "":
		findings = append(findings, findingf("%s has a pin and says it is unpinned", name))
	case self.Pin != "":
		if !conformanceVersionPattern.MatchString(self.Pin) || strings.EqualFold(strings.TrimSpace(self.Pin), "latest") {
			findings = append(findings, findingf("%s is pinned at %q, which is no version: a pin is a version, and the newest release is latest: true", name, self.Pin))
		}
		if self.Source == "" {
			findings = append(findings, findingf("%s's pin %s names no source", name, self.Pin))
		}
	case self.Unpinned != "":
		open = append(open, findingf("%s: unpinned (%s)", name, self.Unpinned))
	default:
		findings = append(findings, findingf("%s has no pin, is not latest and says nothing of why", name))
	}

	for index, run := range self.Runs {
		at := findingf("%s's run %d", name, index+1)
		if !conformanceDayPattern.MatchString(run.At) {
			findings = append(findings, findingf("%s records no day (at %q)", at, run.At))
		}
		if run.Host == "" {
			findings = append(findings, findingf("%s records no host", at))
		} else if conformanceAddressPattern.MatchString(run.Host) {
			findings = append(findings, findingf("%s names its host by an address (%q): name the host", at, run.Host))
		}
		if !slices.Contains([]string{conformancePass, conformanceFail, conformanceOpen}, run.Result) {
			findings = append(findings, findingf("%s records result %q, not pass, fail or open", at, run.Result))
		}
		if run.Test == "" {
			findings = append(findings, findingf("%s names no test", at))
		} else if !slices.Contains(tests, run.Test) {
			findings = append(findings, findingf("%s names test %s, which its row does not list", at, run.Test))
		}
		if self.Latest {
			if run.Pin != "" {
				findings = append(findings, findingf("%s records a pin for a latest peer: record what it got", at))
			}
			if !conformanceVersionPattern.MatchString(run.Got) {
				findings = append(findings, findingf("%s records no version it got (got %q)", at, run.Got))
			}
		} else if run.Pin == "" {
			findings = append(findings, findingf("%s records no pin", at))
		}
	}

	if len(self.Runs) == 0 {
		if self.Pin != "" || self.Latest {
			open = append(open, findingf("%s: never run", name))
		}
		return findings, open
	}
	newest := self.Runs[len(self.Runs)-1]
	if !self.Latest && self.Pin != "" && newest.Pin != self.Pin {
		findings = append(findings, findingf("%s is pinned at %s and its newest run (%s) ran at %s: rerun it at the new pin and record the run", name, self.Pin, newest.At, newest.Pin))
	}
	if newest.Result != conformancePass {
		open = append(open, findingf("%s: newest run (%s on %s) reads %s", name, newest.At, newest.Host, newest.Result))
	}
	return findings, open
}

// The ledger in this checkout. Open peers are reported, each on the run's last lines.
func TestConformanceLedger(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	verdict := conformanceLedgerFindings(repository.topDirectory, repository.moduleDirectory)
	failFindings(t, "conformance", verdict.findings)
	for _, line := range verdict.open {
		t.Logf("open: %s", line)
	}
	runReportLock.Lock()
	defer runReportLock.Unlock()
	runReportLines[findingf("conformance: %d peers or rows read open in %s, which no gate counts as passed", len(verdict.open), conformanceLedgerPath)] = true
}

// A top directory holding §22.9 and a ledger, both given, for the planted cases. The section is this
// checkout's unless one is given.
func conformanceFixture(t *testing.T, section string, ledger string) string {
	t.Helper()
	directory := t.TempDir()
	if section == "" {
		repository, err := thisCheckout()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(repository.topDirectory, conformanceSectionPath))
		if err != nil {
			t.Fatal(err)
		}
		section = string(data)
	}
	for name, content := range map[string]string{conformanceSectionPath: section, conformanceLedgerPath: ledger} {
		path := filepath.Join(directory, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

// A one-row §22.9, so a planted ledger is small.
const conformancePlantedSection = "### 22.9 Conformance and platform budgets\n\n" +
	"- **git** (2.34, Ubuntu 22.04's; latest; go-git): oids equal a reference.\n\n" +
	"### 22.10 Internal review gates\n"

// The ledger for it, with a pinned peer run once at its pin, a latest peer run once, and $PIN and
// $RUNPIN to plant a change.
const conformancePlantedLedger = `rows:
  - row: git
    design: "2.34, Ubuntu 22.04's; latest; go-git"
    owners: [EVS1-M2-43]
    milestone: M2
    tests: [TestGitConformance]
    peers:
      - peer: git 2.34
        pin: "$PIN"
        source: "jammy's package"
        runs:
          - {at: 2026-11-09, host: builder-mac, pin: "$RUNPIN", result: pass, test: TestGitConformance, commit: abc123}
      - peer: git, the latest release
        latest: true
        runs:
          - {at: 2026-11-09, host: builder-mac, got: "2.52.0", result: pass, test: TestGitConformance, commit: abc123}
      - peer: go-git
        unpinned: "pinned when its test lands"
        runs: []
`

// The planted ledger with the 2.34 peer pinned at pin and its run recorded at runPin.
func plantedConformanceLedger(pin string, runPin string) string {
	return strings.NewReplacer("$PIN", pin, "$RUNPIN", runPin).Replace(conformancePlantedLedger)
}

func TestConformanceLedgerPassesAPlantedCleanLedger(t *testing.T) {
	directory := conformanceFixture(t, conformancePlantedSection, plantedConformanceLedger("2.34.1", "2.34.1"))
	verdict := conformanceLedgerFindings(directory, directory)
	wantFindings(t, verdict.findings)
	wantFindings(t, verdict.open, "git: go-git: unpinned")
}

// D-TEST-7's rerun per pin change: a pin moved after its newest run fails until a run at it is recorded.
func TestConformanceLedgerFailsOnAChangedPinWithNoRun(t *testing.T) {
	directory := conformanceFixture(t, conformancePlantedSection, plantedConformanceLedger("2.34.2", "2.34.1"))
	wantFindings(t, conformanceLedgerFindings(directory, directory).findings,
		"git: git 2.34 is pinned at 2.34.2 and its newest run (2026-11-09) ran at 2.34.1")
}

// Every §22.9 row of this checkout's design needs an entry: one dropped from the real ledger fails,
// naming the row.
func TestConformanceLedgerFailsOnASection229RowWithNoEntry(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(repository.moduleDirectory, conformanceLedgerPath))
	if err != nil {
		t.Fatal(err)
	}
	ledger := string(data)
	start := strings.Index(ledger, "  - row: ACME\n")
	end := strings.Index(ledger, "  - row: DNS\n")
	if start < 0 || end < start {
		t.Fatal("the ledger has no ACME entry before its DNS entry to drop")
	}
	directory := conformanceFixture(t, "", ledger[:start]+ledger[end:])
	wantFindings(t, conformanceLedgerFindings(directory, directory).findings, "§22.9's row ACME has no entry")
}

// A design that names its peers differently fails until the ledger is read against it again.
func TestConformanceLedgerFailsOnAChangedPeerList(t *testing.T) {
	section := strings.Replace(conformancePlantedSection, "latest; go-git", "latest; go-git, JGit", 1)
	directory := conformanceFixture(t, section, plantedConformanceLedger("2.34.1", "2.34.1"))
	wantFindings(t, conformanceLedgerFindings(directory, directory).findings,
		`git: §22.9 now names its peers as "2.34, Ubuntu 22.04's; latest; go-git, JGit"`)
}

func TestConformanceLedgerFailsOnARowTheDesignDoesNotHold(t *testing.T) {
	ledger := plantedConformanceLedger("2.34.1", "2.34.1") + `  - row: telnet
    design: "every telnet"
    owners: [EVS1-M2-43]
    milestone: M2
    tests: []
    peers:
      - peer: telnet
        unpinned: "never"
        runs: []
`
	directory := conformanceFixture(t, conformancePlantedSection, ledger)
	wantFindings(t, conformanceLedgerFindings(directory, directory).findings, `holds row "telnet", which §22.9 does not`)
}

// §22.9's "the latest" is pinned at each run, so "latest" as a pin is refused.
func TestConformanceLedgerFailsOnLatestAsAPin(t *testing.T) {
	directory := conformanceFixture(t, conformancePlantedSection, plantedConformanceLedger("latest", "latest"))
	wantFindings(t, conformanceLedgerFindings(directory, directory).findings,
		`git: git 2.34 is pinned at "latest", which is no version`)
}

// A run of a latest peer records what it got, and any run records its host and a known result.
func TestConformanceLedgerFailsOnARunMissingWhatItMustRecord(t *testing.T) {
	ledger := strings.Replace(plantedConformanceLedger("2.34.1", "2.34.1"), `got: "2.52.0", `, "", 1)
	ledger = strings.Replace(ledger, "host: builder-mac, pin:", "host: 192.0.2.7, pin:", 1)
	ledger = strings.Replace(ledger, "result: pass, test: TestGitConformance, commit: abc123}\n      - peer: git, the latest", "result: passed, test: TestGitConformance, commit: abc123}\n      - peer: git, the latest", 1)
	directory := conformanceFixture(t, conformancePlantedSection, ledger)
	wantFindings(t, conformanceLedgerFindings(directory, directory).findings,
		`git: git 2.34's run 1 names its host by an address`,
		`git: git 2.34's run 1 records result "passed", not pass, fail or open`,
		`git: git, the latest release's run 1 records no version it got`,
	)
}

// A peer this host lacks reads open, never passed, as does one never run.
func TestConformanceLedgerReadsAnOpenRunAsOpen(t *testing.T) {
	ledger := strings.Replace(plantedConformanceLedger("2.34.1", "2.34.1"), "result: pass, test: TestGitConformance, commit: abc123}\n      - peer: git, the latest", "result: open, test: TestGitConformance, commit: abc123}\n      - peer: git, the latest", 1)
	directory := conformanceFixture(t, conformancePlantedSection, ledger)
	verdict := conformanceLedgerFindings(directory, directory)
	wantFindings(t, verdict.findings)
	wantFindings(t, verdict.open, "git: git 2.34: newest run (2026-11-09 on builder-mac) reads open", "git: go-git: unpinned")
}

// The real §22.9 parses into its eleven rows, Postfix's own parentheses inside MTAs' list.
func TestConformanceDesignRowsParseSection229(t *testing.T) {
	repository, err := thisCheckout()
	if err != nil {
		t.Fatal(err)
	}
	section, err := os.ReadFile(filepath.Join(repository.topDirectory, conformanceSectionPath))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := conformanceDesignRows(section)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, row := range rows {
		names = append(names, row.name)
		if row.name == "MTAs" && !strings.HasPrefix(row.peers, "Postfix (may, dane), Exim;") {
			t.Errorf("MTAs' peers read as %q", row.peers)
		}
	}
	want := []string{"git", "git-lfs", "Restore", "File clusters", "MTAs", "ZK preamble", "ACME", "DNS", "Browsers", "Memory, size", "Index determinism"}
	if !slices.Equal(names, want) {
		t.Errorf("§22.9's rows read as %v, want %v", names, want)
	}
}
