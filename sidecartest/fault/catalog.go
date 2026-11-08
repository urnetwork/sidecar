// §22.8's fault schedule catalog and §23.6's gate map, as catalog.yml holds them (D-TEST-10). Every
// registration, every gate sweep and OPS-M1-07's gates.yml read this one copy, so a row's checks,
// tiers and cases are written once. The file's header says what each field means.
//
// The parser is strict: a field no row has, a duplicate key, a tab, a second document, an id out of
// sequence, a duplicate case, an invariant §22.8 does not hold and a tier or gate this file does not
// know each fail the parse, and the embedded file failing it panics at first use, since nothing that
// reads the catalog can go on without it.
//
// A parsed Catalog is read-only, so safe for concurrent use.

package fault

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed catalog.yml
var catalogYaml []byte

// §22.8's counts: FS-1 to FS-125 and FI-1 to FI-30, numbered without gaps.
const (
	catalogRowCount       = 125
	catalogInvariantCount = 30
)

// Where a case must pass, beside Mn-out and Mn-in.
const (
	// Each milestone's exit review (FS-55).
	GateEveryOut = "every-out"
	// Before place_new names a new metadata cluster (§23.6's last row, §19.9).
	GateNextCluster = "next-cluster"
)

var catalogGatePattern = regexp.MustCompile(`^M([0-9]|10)-(out|in)$`)

// A check a row names that is an FI, with its clause letter if any: FI-13c is FI-13's clause c.
var catalogInvariantCheckPattern = regexp.MustCompile(`^FI-([0-9]+)([a-d]?)$`)

// A case name: lower case words joined by hyphens, or empty for a row's main part.
var catalogCaseNamePattern = regexp.MustCompile(`^([a-z0-9]+(-[a-z0-9]+)*)?$`)

// What an oracle's owner is: a task, or the running base sidecartest was built on.
var catalogOraclePattern = regexp.MustCompile(`^([A-Z0-9]+-M[0-9]+-[0-9]{2}|base)$`)

// What a case waits on outside the build.
var catalogOpens = []string{"production", "hardware", "people"}

// The tiers a row may name (§22.4). T1 runs no schedule.
var catalogTiers = []Tier{TierT2, TierT3, TierT4}

// FI-n: §22.8's name, and the task whose oracle answers it.
type CatalogInvariant struct {
	Id     string `yaml:"id"`
	Name   string `yaml:"name"`
	Oracle string `yaml:"oracle"`
	Note   string `yaml:"note"`
	Number int    `yaml:"-"`
}

// One FS row.
type Row struct {
	Id string `yaml:"id"`
	// §22.8's § column: 11 for §11.
	Sections []int `yaml:"sections"`
	// FI ids with their clause letter, invariants and named checks, as §22.8 writes them.
	Checks []string `yaml:"checks"`
	Tiers  []Tier   `yaml:"tiers"`
	// Every write the row issues also runs with ApplyThenDrop (§22.8's unknown rule).
	Unknown bool `yaml:"unknown"`
	// The row's peers run on the fake contract issuer or ControlId sink (§22.8's cadence rule).
	FakeIssuer bool `yaml:"fake_issuer"`
	// Every case of the row is forged: see Case.Forged.
	Forged bool    `yaml:"forged"`
	Cases  []*Case `yaml:"cases"`
	Number int     `yaml:"-"`
}

// A part of a row a gate reports by itself.
type Case struct {
	// Empty for the row's main part.
	Name string `yaml:"name"`
	// Mn-out, Mn-in, every-out or next-cluster.
	Gates []string `yaml:"gates"`
	// The case passes at the later of its gates.
	LaterOf bool `yaml:"later_of"`
	// Empty takes the row's.
	CaseTiers []Tier `yaml:"tiers"`
	// The server forges, withholds or forks state here: it runs on T2 alone, and its twin also on T3.
	CaseForged bool `yaml:"forged"`
	// production, hardware or people: what the case waits on outside the build.
	Open string `yaml:"open"`
	// A T3 clause whose time a wrapper translates (plan-TEST-clock-seam #2).
	StoreClock bool `yaml:"store_clock"`
	Row        *Row `yaml:"-"`
}

// The row and case, as a gate report names it: FS-19 or FS-19's config-read.
func (self *Case) String() string {
	if self.Name == "" {
		return self.Row.Id
	}
	return self.Row.Id + "'s " + self.Name
}

// The tiers this case runs on.
func (self *Case) Tiers() []Tier {
	if 0 < len(self.CaseTiers) {
		return self.CaseTiers
	}
	return self.Row.Tiers
}

// Whether the server forges, withholds or forks state in this case.
func (self *Case) Forged() bool {
	return self.CaseForged || self.Row.Forged
}

// The tiers a forged case's twin runs on: the case's, and T3 (§22.8's cadence rule). For any other
// case, the case's own.
func (self *Case) TwinTiers() []Tier {
	tiers := slices.Clone(self.Tiers())
	if self.Forged() && !slices.Contains(tiers, TierT3) {
		tiers = append(tiers, TierT3)
	}
	return tiers
}

// Whether the case must pass at gate.
func (self *Case) AtGate(gate string) bool {
	return slices.Contains(self.Gates, gate)
}

type Catalog struct {
	Invariants []*CatalogInvariant `yaml:"invariants"`
	Rows       []*Row              `yaml:"rows"`
}

var (
	defaultCatalogOnce sync.Once
	defaultCatalog     *Catalog
)

// The catalog this package embeds, parsed once. Panics if catalog.yml does not parse, which
// TestCatalogMatchesSection22 reports first.
func DefaultCatalog() *Catalog {
	defaultCatalogOnce.Do(func() {
		catalog, err := ParseCatalog(catalogYaml)
		if err != nil {
			panic(fmt.Sprintf("catalog.yml: %v", err))
		}
		defaultCatalog = catalog
	})
	return defaultCatalog
}

// Parses a catalog's bytes. Any error is a catalog no gate may read.
func ParseCatalog(data []byte) (*Catalog, error) {
	if index := bytes.IndexByte(data, '\t'); 0 <= index {
		return nil, fmt.Errorf("line %d holds a tab", 1+bytes.Count(data[:index], []byte("\n")))
	}
	catalog := &Catalog{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(catalog); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("it holds no document")
		}
		return nil, err
	}
	if err := decoder.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("it holds a second document: %v", err)
	}
	findings := []error{}
	findings = append(findings, catalog.invariantErrors()...)
	findings = append(findings, catalog.rowErrors()...)
	if err := errors.Join(findings...); err != nil {
		return nil, err
	}
	return catalog, nil
}

func (self *Catalog) invariantErrors() []error {
	findings := []error{}
	if len(self.Invariants) != catalogInvariantCount {
		findings = append(findings, fmt.Errorf("%d invariants, and §22.8 holds %d", len(self.Invariants), catalogInvariantCount))
	}
	for index, invariant := range self.Invariants {
		want := fmt.Sprintf("FI-%d", index+1)
		if invariant.Id != want {
			findings = append(findings, fmt.Errorf("invariant %d is %q, want %s", index+1, invariant.Id, want))
			continue
		}
		invariant.Number = index + 1
		if invariant.Name == "" {
			findings = append(findings, fmt.Errorf("%s has no name", invariant.Id))
		}
		if !catalogOraclePattern.MatchString(invariant.Oracle) {
			findings = append(findings, fmt.Errorf("%s's oracle %q names no task", invariant.Id, invariant.Oracle))
		}
	}
	return findings
}

func (self *Catalog) rowErrors() []error {
	findings := []error{}
	if len(self.Rows) != catalogRowCount {
		findings = append(findings, fmt.Errorf("%d rows, and §22.8 holds %d", len(self.Rows), catalogRowCount))
	}
	for index, row := range self.Rows {
		want := fmt.Sprintf("FS-%d", index+1)
		if row.Id != want {
			// a duplicate or a missing row both shift every id after it
			findings = append(findings, fmt.Errorf("row %d is %q, want %s", index+1, row.Id, want))
			continue
		}
		row.Number = index + 1
		findings = append(findings, row.fieldErrors(self)...)
	}
	return findings
}

func (self *Row) fieldErrors(catalog *Catalog) []error {
	findings := []error{}
	if len(self.Sections) == 0 {
		findings = append(findings, fmt.Errorf("%s names no section", self.Id))
	}
	for _, section := range self.Sections {
		if section < 1 || 23 < section {
			findings = append(findings, fmt.Errorf("%s names §%d", self.Id, section))
		}
	}
	if len(self.Checks) == 0 {
		findings = append(findings, fmt.Errorf("%s names no check", self.Id))
	}
	for _, check := range self.Checks {
		match := catalogInvariantCheckPattern.FindStringSubmatch(check)
		if match == nil {
			if strings.HasPrefix(check, "FI") {
				findings = append(findings, fmt.Errorf("%s names %q, which is no FI", self.Id, check))
			}
			continue
		}
		number, _ := strconv.Atoi(match[1])
		if catalog.Invariant(number) == nil {
			findings = append(findings, fmt.Errorf("%s names %s, which §22.8 does not hold", self.Id, check))
		}
	}
	findings = append(findings, tierErrors(self.Id, self.Tiers)...)
	if len(self.Tiers) == 0 {
		findings = append(findings, fmt.Errorf("%s names no tier", self.Id))
	}
	if self.FakeIssuer && !slices.Contains(self.Tiers, TierT3) {
		findings = append(findings, fmt.Errorf("%s runs on the fake issuer and names no T3", self.Id))
	}
	if self.Forged && !slices.Equal(self.Tiers, []Tier{TierT2}) {
		findings = append(findings, fmt.Errorf("%s is forged and names tiers %v, not T2 alone", self.Id, self.Tiers))
	}
	if len(self.Cases) == 0 {
		findings = append(findings, fmt.Errorf("%s has no case", self.Id))
	}
	caseNames := map[string]bool{}
	caseTiers := map[Tier]bool{}
	for _, testCase := range self.Cases {
		testCase.Row = self
		if caseNames[testCase.Name] {
			findings = append(findings, fmt.Errorf("%s has two cases named %q", self.Id, testCase.Name))
		}
		caseNames[testCase.Name] = true
		findings = append(findings, testCase.fieldErrors()...)
		for _, tier := range testCase.Tiers() {
			caseTiers[tier] = true
		}
	}
	for _, tier := range self.Tiers {
		if !caseTiers[tier] {
			findings = append(findings, fmt.Errorf("%s names %s and no case runs on it", self.Id, tier))
		}
	}
	return findings
}

func tierErrors(owner string, tiers []Tier) []error {
	findings := []error{}
	seen := map[Tier]bool{}
	for _, tier := range tiers {
		if !slices.Contains(catalogTiers, tier) {
			findings = append(findings, fmt.Errorf("%s names tier %q", owner, tier))
		}
		if seen[tier] {
			findings = append(findings, fmt.Errorf("%s names %s twice", owner, tier))
		}
		seen[tier] = true
	}
	return findings
}

func (self *Case) fieldErrors() []error {
	findings := []error{}
	owner := self.String()
	if !catalogCaseNamePattern.MatchString(self.Name) {
		findings = append(findings, fmt.Errorf("%s: %q is no case name", self.Row.Id, self.Name))
	}
	if len(self.Gates) == 0 {
		findings = append(findings, fmt.Errorf("%s names no gate", owner))
	}
	for _, gate := range self.Gates {
		if !catalogGatePattern.MatchString(gate) && gate != GateEveryOut && gate != GateNextCluster {
			findings = append(findings, fmt.Errorf("%s names gate %q", owner, gate))
		}
	}
	if self.LaterOf != (1 < len(self.Gates)) {
		findings = append(findings, fmt.Errorf("%s: later_of goes with two gates and only then", owner))
	}
	findings = append(findings, tierErrors(owner, self.CaseTiers)...)
	for _, tier := range self.CaseTiers {
		if !slices.Contains(self.Row.Tiers, tier) {
			findings = append(findings, fmt.Errorf("%s runs on %s, which its row does not name", owner, tier))
		}
	}
	if self.CaseForged && !slices.Equal(self.CaseTiers, []Tier{TierT2}) {
		findings = append(findings, fmt.Errorf("%s is forged and does not run on T2 alone", owner))
	}
	if self.Open != "" && !slices.Contains(catalogOpens, self.Open) {
		findings = append(findings, fmt.Errorf("%s waits on %q", owner, self.Open))
	}
	return findings
}

// FI-n, or nil.
func (self *Catalog) Invariant(n int) *CatalogInvariant {
	if n < 1 || len(self.Invariants) < n {
		return nil
	}
	return self.Invariants[n-1]
}

// The row with id, or nil.
func (self *Catalog) Row(rowId string) *Row {
	number, ok := strings.CutPrefix(rowId, "FS-")
	if !ok {
		return nil
	}
	n, err := strconv.Atoi(number)
	if err != nil || n < 1 || len(self.Rows) < n || strconv.Itoa(n) != number {
		return nil
	}
	return self.Rows[n-1]
}

// A row's case, or nil. caseName is empty for the row's main part.
func (self *Catalog) Case(rowId string, caseName string) *Case {
	row := self.Row(rowId)
	if row == nil {
		return nil
	}
	for _, testCase := range row.Cases {
		if testCase.Name == caseName {
			return testCase
		}
	}
	return nil
}

// Every case that must pass at gate, in row order.
func (self *Catalog) GateCases(gate string) []*Case {
	cases := []*Case{}
	for _, row := range self.Rows {
		for _, testCase := range row.Cases {
			if testCase.AtGate(gate) {
				cases = append(cases, testCase)
			}
		}
	}
	return cases
}

// Every gate a case names, in milestone order: M1-out before M2-out, Mn-in before Mn-out, then
// every-out and next-cluster.
func (self *Catalog) Gates() []string {
	seen := map[string]bool{}
	for _, row := range self.Rows {
		for _, testCase := range row.Cases {
			for _, gate := range testCase.Gates {
				seen[gate] = true
			}
		}
	}
	gates := []string{}
	for gate := range seen {
		gates = append(gates, gate)
	}
	slices.SortFunc(gates, func(a string, b string) int {
		return gateOrder(a) - gateOrder(b)
	})
	return gates
}

func gateOrder(gate string) int {
	if match := catalogGatePattern.FindStringSubmatch(gate); match != nil {
		n, _ := strconv.Atoi(match[1])
		if match[2] == "in" {
			return 2 * n
		}
		return 2*n + 1
	}
	if gate == GateEveryOut {
		return 100
	}
	return 101
}

// The rows on §22.8's unknown list.
func (self *Catalog) UnknownRows() []*Row {
	rows := []*Row{}
	for _, row := range self.Rows {
		if row.Unknown {
			rows = append(rows, row)
		}
	}
	return rows
}
