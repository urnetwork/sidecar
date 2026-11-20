// Ties each clause of a case to its row and case (QD-1084; TEST.md's contract for schedule authors, rule 7), beside
// the case registry (register.go). A clause is a further schedule of a case beside the case's registered builder: an
// exported Builder in a non-test file of this package, run under every rule its row takes (CheckClause), which a gate
// counts with its case, so the case reads pass only when its registered builder's tests and every clause's tests pass.
// A clause registers from a package-level var in a non-test file, since server's gate tool links this package's
// non-test files alone and server's T3 test runs the same builder:
//
//	var Fs1ConcurrentRetriesClause = RegisterClause("FS-1", "", "concurrent retries", Fs1ConcurrentRetries, ClauseOnT3("./evshost"))
//
// A clause's name is its schedule's after the row, "FS-1 concurrent retries", which names its explorer's traces, so a
// registration never renames a schedule. Its tests are named from it by convention (gate.go): TestFs<n><Case><Clause>
// in this package under sidecar_testhooks, the thin test that calls RunRegisteredClause, and TestFs<n><Case><Clause>OnT3
// in the server package its T3 run is in, where it has one, <Case> being the case's name in camel case as for the case's
// own tests and <Clause> the clause's: each run of letters and digits a word, its first letter upper case and the rest
// lower, so "concurrent retries" is ConcurrentRetries, "a --now shred under a hold" ANowShredUnderAHold and "migration
// killed before the head CAS" MigrationKilledBeforeTheHeadCas.
//
// A clause runs on T2 when its case does, and on T3 when it names the server package its T3 test is in (ClauseOnT3),
// which needs a case that runs there or a forged case, whose twin carries T3. On T3 a forged case's clause runs its
// twin, which must succeed (§22.8's cadence rule), under the name "<row> <clause> twin", as CheckClause names a twin.
//
// Safe for concurrent use.

package fault

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/sidecartest"
)

// One clause of one case, on the tiers its tests run on.
type ClauseRegistration struct {
	Row string
	// Empty for the row's main part.
	Case string
	// What follows the row in its schedule's id: "concurrent retries" in "FS-1 concurrent retries".
	Name  string
	Build Builder
	Tiers []Tier
	// The server package its T3 test is in, from server's root, "./evshost" or "." for the root package; empty when it
	// runs on T2 alone.
	T3Package string
}

// "FS-1's clause concurrent retries on T2+T3", or with its case, "FS-72's migration clause migration killed after step 6
// on T2+T3".
func (self *ClauseRegistration) String() string {
	tiers := []string{}
	for _, tier := range self.Tiers {
		tiers = append(tiers, string(tier))
	}
	owner := self.Row + "'s"
	if self.Case != "" {
		owner += " " + self.Case
	}
	return owner + " clause " + self.Name + " on " + strings.Join(tiers, "+")
}

// The id its schedule runs under, which its traces are named by: the row and the clause's name.
func (self *ClauseRegistration) Id() string {
	return self.Row + " " + self.Name
}

// A choice a registration makes beyond its row, case, name and builder.
type ClauseOption func(registration *ClauseRegistration)

// The clause runs on T3 too, its test TestFs<n><Case><Clause>OnT3 in server's packagePath, from server's root:
// "./sidecart3", which runs T3's rows by convention, or the package whose block the clause drives, "./evshost" say.
func ClauseOnT3(packagePath string) ClauseOption {
	return func(registration *ClauseRegistration) {
		registration.T3Package = packagePath
	}
}

// A server package as a gate entry names it, from server's root.
var clauseT3PackagePattern = regexp.MustCompile(`^\.(/[A-Za-z0-9_][A-Za-z0-9_.-]*)*$`)

// A clause's name in camel case, for its tests' names: each run of letters and digits a word, its first letter upper
// case and the rest lower. Empty when the name holds no letter or digit.
func clauseCamel(clause string) string {
	var camel strings.Builder
	words := strings.FieldsFunc(clause, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, word := range words {
		first, size := utf8.DecodeRuneInString(word)
		camel.WriteRune(unicode.ToUpper(first))
		camel.WriteString(strings.ToLower(word[size:]))
	}
	return camel.String()
}

// The thin T2 test a clause's registration names, in this package under sidecar_testhooks, which calls
// RunRegisteredClause.
func GateClauseT2TestName(registration *ClauseRegistration) string {
	number := strings.TrimPrefix(registration.Row, "FS-")
	return "TestFs" + number + gateCaseCamel(registration.Case) + clauseCamel(registration.Name)
}

// The T3 test of a clause that runs on T3, in the server package its registration names.
func GateClauseT3TestName(registration *ClauseRegistration) string {
	return GateClauseT2TestName(registration) + "OnT3"
}

type clauseRegistry struct {
	catalog *Catalog

	stateLock     sync.Mutex
	registrations []*ClauseRegistration
}

func newClauseRegistry(catalog *Catalog) *clauseRegistry {
	return &clauseRegistry{catalog: catalog}
}

var (
	defaultClauseRegistryOnce sync.Once
	defaultClauseRegistry     *clauseRegistry
)

func theClauseRegistry() *clauseRegistry {
	defaultClauseRegistryOnce.Do(func() {
		defaultClauseRegistry = newClauseRegistry(DefaultCatalog())
	})
	return defaultClauseRegistry
}

// Ties builder to caseName of rowId as the clause named clause, on T2 when the case runs there and on T3 when an option
// names its T3 package. caseName is empty for the row's main part. A row or case the catalog does not hold, a nil
// builder, a name that makes no test name, a name the row already registered, a test name another of the row's cases or
// clauses holds, a T3 package for a case that never runs on T3, and a clause on no tier each panic, since a
// registration runs from a package-level var and a test binary that cannot link its clauses must not pass.
func RegisterClause(rowId string, caseName string, clause string, builder Builder, options ...ClauseOption) *ClauseRegistration {
	registration, err := theClauseRegistry().register(rowId, caseName, clause, builder, options...)
	if err != nil {
		panic(err)
	}
	return registration
}

func (self *clauseRegistry) register(rowId string, caseName string, clause string, builder Builder, options ...ClauseOption) (*ClauseRegistration, error) {
	row := self.catalog.Row(rowId)
	if row == nil {
		return nil, fmt.Errorf("register clause %q of %s: no such row in §22.8", clause, rowId)
	}
	testCase := self.catalog.Case(rowId, caseName)
	if testCase == nil {
		return nil, fmt.Errorf("register clause %q of %s: no case %q", clause, rowId, caseName)
	}
	registration := &ClauseRegistration{Row: rowId, Case: caseName, Name: clause, Build: builder}
	for _, option := range options {
		option(registration)
	}
	switch {
	case builder == nil:
		return nil, fmt.Errorf("register clause %q of %s: no builder", clause, testCase)
	case clause != strings.TrimSpace(clause) || clauseCamel(clause) == "":
		return nil, fmt.Errorf("register clause %q of %s: a name with no letter or digit, or with space around it, names no test", clause, testCase)
	case strings.HasSuffix(clause, " twin") || clause == "twin":
		return nil, fmt.Errorf("register clause %q of %s: a name ending in twin is the name a clause's twin runs under", clause, testCase)
	}
	if slices.Contains(testCase.TwinTiers(), TierT2) {
		registration.Tiers = append(registration.Tiers, TierT2)
	}
	if registration.T3Package != "" {
		if !clauseT3PackagePattern.MatchString(registration.T3Package) || strings.Contains(registration.T3Package, "/../") || strings.HasSuffix(registration.T3Package, "/..") {
			return nil, fmt.Errorf("register clause %q of %s: %q is no package from server's root", clause, testCase, registration.T3Package)
		}
		if !slices.Contains(testCase.TwinTiers(), TierT3) {
			return nil, fmt.Errorf("register clause %q of %s on T3: the case runs on %v, and is not forged", clause, testCase, testCase.Tiers())
		}
		registration.Tiers = append(registration.Tiers, TierT3)
	}
	if len(registration.Tiers) == 0 {
		return nil, fmt.Errorf("register clause %q of %s: the case runs on %v, and the clause names no T3 package", clause, testCase, testCase.Tiers())
	}

	testName := GateClauseT2TestName(registration)
	// the row's own cases' tests by convention, which no clause may take
	for _, sibling := range row.Cases {
		if GateT2TestName(sibling) == testName {
			return nil, fmt.Errorf("register clause %q of %s: its test %s is the test of the case %s", clause, testCase, testName, sibling)
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, other := range self.registrations {
		if other.Row != rowId {
			continue
		}
		if other.Name == clause {
			return nil, fmt.Errorf("register clause %q of %s: %s is registered already", clause, testCase, other)
		}
		if GateClauseT2TestName(other) == testName {
			return nil, fmt.Errorf("register clause %q of %s: its test %s is the test of %s", clause, testCase, testName, other)
		}
	}
	self.registrations = append(self.registrations, registration)
	return registration, nil
}

// Every clause this binary links, in row and case order, each case's by name.
func RegisteredClauses() []*ClauseRegistration {
	return theClauseRegistry().registered()
}

func (self *clauseRegistry) registered() []*ClauseRegistration {
	self.stateLock.Lock()
	registrations := slices.Clone(self.registrations)
	self.stateLock.Unlock()
	order := func(registration *ClauseRegistration) (int, int) {
		row := self.catalog.Row(registration.Row)
		return row.Number, slices.IndexFunc(row.Cases, func(testCase *Case) bool { return testCase.Name == registration.Case })
	}
	slices.SortStableFunc(registrations, func(a *ClauseRegistration, b *ClauseRegistration) int {
		rowA, caseA := order(a)
		rowB, caseB := order(b)
		switch {
		case rowA != rowB:
			return rowA - rowB
		case caseA != caseB:
			return caseA - caseB
		}
		return strings.Compare(a.Name, b.Name)
	})
	return registrations
}

// A case's clauses, by name. caseName is empty for the row's main part.
func Clauses(rowId string, caseName string) []*ClauseRegistration {
	return theClauseRegistry().clauses(rowId, caseName)
}

func (self *clauseRegistry) clauses(rowId string, caseName string) []*ClauseRegistration {
	clauses := []*ClauseRegistration{}
	for _, registration := range self.registered() {
		if registration.Row == rowId && registration.Case == caseName {
			clauses = append(clauses, registration)
		}
	}
	return clauses
}

// The clause of rowId named clause, whichever case it is of, or nil.
func LookupClause(rowId string, clause string) *ClauseRegistration {
	return theClauseRegistry().lookup(rowId, clause)
}

func (self *clauseRegistry) lookup(rowId string, clause string) *ClauseRegistration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, registration := range self.registrations {
		if registration.Row == rowId && registration.Name == clause {
			return registration
		}
	}
	return nil
}

// The builder a forged case's clause runs on T3: its schedule's twin, read from a schedule built on T2's fakes, so
// reading it touches no T3 store.
func clauseTwinBuilder(ctx context.Context, registration *ClauseRegistration) (Builder, error) {
	net := sidecartest.NewNet(ctx, sidecartest.DefaultNetSettings())
	defer net.Close()
	schedule := registration.Build(net)
	if schedule == nil || schedule.Twin == nil {
		return nil, fmt.Errorf("%s is of a forged case, and its schedule names no twin, which carries T3 (§22.8's cadence rule)", registration)
	}
	return schedule.Twin, nil
}

// Runs registration's clause under every rule its row takes, on T2, or on the tier settings name (server's sidecart3
// runs T3's): CheckClause on its builder, or on T3 for a forged case's clause on its twin, which must succeed, under
// the clause's name and twin. A clause not registered on the tier fails as missing. settings nil takes the defaults.
func CheckRegisteredClause(ctx context.Context, registration *ClauseRegistration, settings *RuleSettings) *RowReport {
	if settings == nil {
		settings = DefaultRuleSettings()
	}
	tier := settings.Tier
	if tier == "" {
		tier = TierT2
	}
	testCase := DefaultCatalog().Case(registration.Row, registration.Case)
	if testCase == nil || !slices.Contains(registration.Tiers, tier) {
		report := &RowReport{Case: &Case{Name: registration.Name, Row: &Row{Id: registration.Row}}, Tier: settings.Tier}
		if testCase != nil {
			report.Case = &Case{Name: registration.Name, Row: testCase.Row}
		}
		report.Errors = append(report.Errors, fmt.Errorf("%s is not registered on %s: missing", registration, tier))
		return report
	}
	if tier == TierT3 && testCase.Forged() {
		twin, err := clauseTwinBuilder(ctx, registration)
		if err != nil {
			return &RowReport{Case: &Case{Name: registration.Name, Row: testCase.Row}, Tier: settings.Tier, Errors: []error{err}}
		}
		return CheckClause(ctx, registration.Row, registration.Name+" twin", twin, settings)
	}
	return CheckClause(ctx, registration.Row, registration.Name, registration.Build, settings)
}

// CheckRegisteredClause for the clause of rowId named clause, failing t with each failure and logging what ran. A
// clause nobody registered, or one not registered on the tier settings name, fails as missing. settings nil takes the
// defaults.
func RunRegisteredClause(t testing.TB, rowId string, clause string, settings *RuleSettings) *RowReport {
	t.Helper()
	registration := LookupClause(rowId, clause)
	if registration == nil {
		t.Fatalf("%s has no clause %q registered: missing", rowId, clause)
	}
	report := CheckRegisteredClause(t.Context(), registration, settings)
	t.Log(report.String())
	for _, failure := range report.Failures {
		t.Errorf("%s", failure)
	}
	for _, err := range report.Errors {
		t.Errorf("%v", err)
	}
	return report
}

// The tests a registered clause's convention names (gate.go), each in one entry: its T2 test in this package, and its
// T3 test in the server package it names.
func GateClauseTests(registration *ClauseRegistration) []*GateTest {
	tests := []*GateTest{}
	if slices.Contains(registration.Tiers, TierT2) {
		tests = append(tests, &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateClauseT2TestName(registration)}})
	}
	if slices.Contains(registration.Tiers, TierT3) {
		tests = append(tests, &GateTest{Repo: "server", Package: registration.T3Package, Tags: gateT3Tags, Stores: true, Names: []string{GateClauseT3TestName(registration)}})
	}
	return tests
}

// One error for each test a clause's convention names that is not declared where it names it, under its tags. declared
// is GateTestDeclared over the checkout of each test's repo, but in a fixture; tiers limits the check to those tiers'
// tests, all of them when empty.
func ClauseTestsDeclared(registration *ClauseRegistration, declared func(test *GateTest) []error, tiers ...Tier) []error {
	errs := []error{}
	for _, test := range GateClauseTests(registration) {
		tier := TierT2
		if test.Repo == "server" {
			tier = TierT3
		}
		if 0 < len(tiers) && !slices.Contains(tiers, tier) {
			continue
		}
		for _, err := range declared(test) {
			errs = append(errs, fmt.Errorf("%s: %w", registration, err))
		}
	}
	return errs
}
