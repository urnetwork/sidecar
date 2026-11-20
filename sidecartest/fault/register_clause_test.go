package fault

// The clause registry (register_clause.go; QD-1084): what a registration refuses and what it takes, the names its tests
// take, a clause registered without its named test failing the check that every registered clause's tests exist, every
// RunClause call in this package's tests naming a registered clause, and every gate's row of a case naming each of its
// clauses' tests, so that the gate reads the case failed when one clause fails.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// What register refuses, each on a fresh registry so the package's own is left alone, and what it takes.
func TestClauseRegistrationRefusesWhatTheCatalogDoesNotHold(t *testing.T) {
	registry := newClauseRegistry(DefaultCatalog())
	build := func(net *Net) *Schedule { return &Schedule{Id: "toy"} }
	onEvshost := []ClauseOption{ClauseOnT3("./evshost")}
	for _, planted := range []struct {
		rowId    string
		caseName string
		clause   string
		builder  Builder
		options  []ClauseOption
		want     string
	}{
		{rowId: "FS-127", clause: "x", builder: build, want: "no such row"},
		{rowId: "FS-19", clause: "x", builder: build, want: `no case ""`},
		{rowId: "FS-9", clause: "x", want: "no builder"},
		{rowId: "FS-9", clause: "", builder: build, want: "names no test"},
		{rowId: "FS-9", clause: " x", builder: build, want: "names no test"},
		{rowId: "FS-9", clause: "--", builder: build, want: "names no test"},
		{rowId: "FS-9", clause: "x twin", builder: build, want: "ending in twin"},
		{rowId: "FS-9", clause: "twin", builder: build, want: "ending in twin"},
		// FS-9 runs on T2 alone and is not forged
		{rowId: "FS-9", clause: "x", builder: build, options: onEvshost, want: "is not forged"},
		{rowId: "FS-1", clause: "x", builder: build, options: []ClauseOption{ClauseOnT3("evshost")}, want: "no package from server's root"},
		{rowId: "FS-1", clause: "x", builder: build, options: []ClauseOption{ClauseOnT3("./../evshost")}, want: "no package from server's root"},
		{rowId: "FS-1", clause: "x", builder: build, options: []ClauseOption{ClauseOnT3("./evshost/")}, want: "no package from server's root"},
		// FS-40 runs on T3 alone, so a clause of it names where its T3 test is
		{rowId: "FS-40", clause: "x", builder: build, want: "names no T3 package"},
		// the main case's clause "wakes" would take the wakes case's own test, TestFs85Wakes
		{rowId: "FS-85", clause: "wakes", builder: build, want: "is the test of the case FS-85's wakes"},
	} {
		if _, err := registry.register(planted.rowId, planted.caseName, planted.clause, planted.builder, planted.options...); err == nil || !strings.Contains(err.Error(), planted.want) {
			t.Errorf("%s %q clause %q: want %q, got %v", planted.rowId, planted.caseName, planted.clause, planted.want, err)
		}
	}
	if 0 < len(registry.registered()) {
		t.Fatalf("a refused registration stayed: %v", registry.registered())
	}

	fs1, err := registry.register("FS-1", "", "x", build, onEvshost...)
	if err != nil || !slices.Equal(fs1.Tiers, []Tier{TierT2, TierT3}) || fs1.T3Package != "./evshost" || fs1.Id() != "FS-1 x" {
		t.Fatalf("FS-1's clause x: %+v %v", fs1, err)
	}
	if _, err := registry.register("FS-1", "", "x", build); err == nil || !strings.Contains(err.Error(), "registered already") {
		t.Errorf("a second clause x of FS-1: %v", err)
	}
	// "X" is no other name, but its test is x's
	if _, err := registry.register("FS-1", "", "X", build); err == nil || !strings.Contains(err.Error(), "is the test of FS-1's clause x") {
		t.Errorf("a clause whose test is x's: %v", err)
	}
	// the same name in another row is that row's own
	if _, err := registry.register("FS-2", "", "x", build); err != nil {
		t.Errorf("FS-2's clause x: %v", err)
	}
	// a forged case's clause runs its twin on T3
	if forged, err := registry.register("FS-10", "", "x", build, onEvshost...); err != nil || !slices.Equal(forged.Tiers, []Tier{TierT2, TierT3}) {
		t.Errorf("a forged case's clause on T3: %+v %v", forged, err)
	}
	// a case on T3 alone takes a clause on T3 alone
	if t3Alone, err := registry.register("FS-40", "", "x", build, ClauseOnT3("./sidecart3")); err != nil || !slices.Equal(t3Alone.Tiers, []Tier{TierT3}) {
		t.Errorf("FS-40's clause on T3 alone: %+v %v", t3Alone, err)
	}
	// a named case's clause, in its row's order beside the main case's
	if _, err := registry.register("FS-72", "migration", "killed", build, onEvshost...); err != nil {
		t.Errorf("FS-72's migration clause: %v", err)
	}
	names := []string{}
	for _, registration := range registry.registered() {
		names = append(names, registration.String())
	}
	want := []string{
		"FS-1's clause x on T2+T3", "FS-2's clause x on T2", "FS-10's clause x on T2+T3", "FS-40's clause x on T3",
		"FS-72's migration clause killed on T2+T3",
	}
	if !slices.Equal(names, want) {
		t.Errorf("the registry holds %v, want %v", names, want)
	}
	if registration := registry.lookup("FS-72", "killed"); registration == nil || registration.Case != "migration" {
		t.Errorf("lookup: %v", registration)
	}
	if clauses := registry.clauses("FS-72", "rollback"); len(clauses) != 0 {
		t.Errorf("FS-72's rollback case holds %v", clauses)
	}

	// RegisterClause panics where register errs, since it runs from a package-level var
	func() {
		defer func() {
			if recover() == nil {
				t.Error("RegisterClause of no row passed")
			}
		}()
		RegisterClause("FS-0", "", "x", build)
	}()
}

// A clause's tests are named from its row, case and name: each run of letters and digits a word in camel case.
func TestClauseTestNamesAreDerived(t *testing.T) {
	for clause, want := range map[string]string{
		"concurrent retries":                   "ConcurrentRetries",
		"step 7 past 5 s":                      "Step7Past5S",
		"a --now shred under a hold":           "ANowShredUnderAHold",
		"migration killed before the head CAS": "MigrationKilledBeforeTheHeadCas",
		"owner-bound":                          "OwnerBound",
		"re-created after a collection":        "ReCreatedAfterACollection",
		"acl gate":                             "AclGate",
	} {
		if got := clauseCamel(clause); got != want {
			t.Errorf("%q camel %q, want %q", clause, got, want)
		}
	}
	for _, want := range []struct {
		rowId  string
		clause string
		t2     string
		t3     string
	}{
		{rowId: "FS-1", clause: "concurrent retries", t2: "TestFs1ConcurrentRetries", t3: "TestFs1ConcurrentRetriesOnT3"},
		{rowId: "FS-72", clause: "migration killed after step 6", t2: "TestFs72MigrationMigrationKilledAfterStep6", t3: "TestFs72MigrationMigrationKilledAfterStep6OnT3"},
		{rowId: "FS-99", clause: "evs scope", t2: "TestFs99EntriesEvsScope", t3: "TestFs99EntriesEvsScopeOnT3"},
		{rowId: "FS-85", clause: "acl wakes", t2: "TestFs85WakesAclWakes"},
	} {
		registration := LookupClause(want.rowId, want.clause)
		if registration == nil {
			t.Errorf("%s's clause %q is not registered", want.rowId, want.clause)
			continue
		}
		if got := GateClauseT2TestName(registration); got != want.t2 {
			t.Errorf("%s: T2 test %s, want %s", registration, got, want.t2)
		}
		tests := GateClauseTests(registration)
		if want.t3 == "" {
			if len(tests) != 1 {
				t.Errorf("%s names %s, and runs on T2 alone", registration, gateTestsStringForTest(tests))
			}
			continue
		}
		if got := GateClauseT3TestName(registration); got != want.t3 || len(tests) != 2 || !slices.Equal(tests[1].Names, []string{want.t3}) || tests[1].Package != registration.T3Package || !tests[1].Stores || tests[1].Tags != gateT3Tags {
			t.Errorf("%s: T3 test %s in %s, want %s", registration, got, gateTestsStringForTest(tests), want.t3)
		}
	}
}

// A fixture monoroot: sidecar's fault package declaring two clause tests, one behind a tag the convention's entry lacks,
// and server's evshost declaring one T3 test. Returns its root and a check over it.
func clauseFixtureForTest(t *testing.T) func(test *GateTest) []error {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"sidecar/sidecartest/fault/clause_fixture_test.go": "//go:build sidecar_testhooks\n\npackage fault\n\nimport \"testing\"\n\n" +
			"func TestFs9Written(t *testing.T) {\n}\n\nfunc TestFs1Written(t *testing.T) {\n}\n",
		"sidecar/sidecartest/fault/clause_fixture_leak_test.go": "//go:build sidecar_leaktest\n\npackage fault\n\nimport \"testing\"\n\n" +
			"func TestFs9Tagged(t *testing.T) {\n}\n",
		"server/evshost/clause_fixture_test.go": "//go:build sidecar_localstack && sidecar_testhooks\n\npackage evshost_test\n\nimport \"testing\"\n\n" +
			"func TestFs1WrittenOnT3(t *testing.T) {\n}\n",
	}
	for path, content := range files {
		path = filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return func(test *GateTest) []error {
		return GateTestDeclared(filepath.Join(root, test.Repo), test)
	}
}

// A clause registered without its named test fails the check, on each tier its test is missing from: a test nobody
// wrote, and one declared behind a tag the convention's entry lacks, which go test would build out at the gate. A
// clause whose tests are written passes it.
func TestAClauseRegisteredWithoutItsTestFails(t *testing.T) {
	declared := clauseFixtureForTest(t)
	registry := newClauseRegistry(DefaultCatalog())
	build := func(net *Net) *Schedule { return &Schedule{Id: "toy"} }
	register := func(rowId string, clause string, options ...ClauseOption) *ClauseRegistration {
		registration, err := registry.register(rowId, "", clause, build, options...)
		if err != nil {
			t.Fatal(err)
		}
		return registration
	}
	for _, planted := range []struct {
		registration *ClauseRegistration
		tiers        []Tier
		want         []string
	}{
		{registration: register("FS-9", "written")},
		{registration: register("FS-9", "unwritten"), want: []string{"TestFs9Unwritten, which no test file there declares"}},
		{registration: register("FS-9", "tagged"), want: []string{"TestFs9Tagged, declared in [clause_fixture_leak_test.go], which go test does not build here"}},
		{registration: register("FS-1", "written", ClauseOnT3("./evshost"))},
		{
			registration: register("FS-1", "unwritten", ClauseOnT3("./evshost")),
			want:         []string{"TestFs1Unwritten, which no test file there declares", "TestFs1UnwrittenOnT3, which no test file there declares"},
		},
		// limited to a tier, the check reads that tier's test alone
		{registration: registry.lookup("FS-1", "unwritten"), tiers: []Tier{TierT3}, want: []string{"TestFs1UnwrittenOnT3, which no test file there declares"}},
	} {
		errs := ClauseTestsDeclared(planted.registration, declared, planted.tiers...)
		got := []string{}
		for _, err := range errs {
			got = append(got, err.Error())
		}
		if len(got) != len(planted.want) {
			t.Errorf("%s on %v: %q, want %q", planted.registration, planted.tiers, got, planted.want)
			continue
		}
		for index, want := range planted.want {
			if !strings.Contains(got[index], want) || !strings.HasPrefix(got[index], planted.registration.String()) {
				t.Errorf("%s: %q, want %q", planted.registration, got[index], want)
			}
		}
	}
}

// Every clause this package registers has its T2 test, TestFs<n><Case><Clause>, declared here under the convention's
// tags, so its gate rows find it. Its T3 test is server's to hold, in server's checkout, where
// TestGateSweepsNameServerTestsDeclaredUnderTheirTags fails a registered clause's T3 test that is not declared under
// its tags; here it is reported, so a rename in server never fails sidecar's tip.
func TestEveryRegisteredClauseHasItsTests(t *testing.T) {
	declared := gateDeclaredBesideThisCheckout(t)
	registrations := RegisteredClauses()
	if len(registrations) < 50 {
		t.Fatalf("%d clauses registered: the registry lost clauses.go's", len(registrations))
	}
	t3Count := 0
	for _, registration := range registrations {
		for _, err := range ClauseTestsDeclared(registration, declared, TierT2) {
			t.Error(err)
		}
		if slices.Contains(registration.Tiers, TierT3) {
			t3Count += 1
			for _, err := range ClauseTestsDeclared(registration, declared, TierT3) {
				t.Logf("server's to hold: %v", err)
			}
		}
	}
	t.Logf("%d clauses registered, %d of them on T3", len(registrations), t3Count)
}

// What fs91_test.go runs through RunClause and nobody has registered: its file is fi27-cached-head-clause's (QD-1146),
// so QD-1084's sweep left the registration to its owner. A clause here that is registered fails, to come off.
var clauseUnregisteredRuns = map[string]string{
	"FS-91 within the window": "fs91_test.go is fi27-cached-head-clause's, in the ops lane",
}

// Every RunClause or CheckClause call this package's tests make with a literal row and clause names a registered
// clause, but the twin a forged case's clause runs and what clauseUnregisteredRuns names: a clause run outside the
// registry is one no gate names, so a new one fails here until it registers.
func TestEveryRunClauseCallIsRegistered(t *testing.T) {
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	literal := func(expression ast.Expr) (string, bool) {
		basic, ok := expression.(*ast.BasicLit)
		if !ok || basic.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(basic.Value)
		return value, err == nil
	}
	runs := []string{}
	for _, path := range paths {
		file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if (name != "RunClause" && name != "CheckClause") || len(call.Args) < 3 {
				return true
			}
			rowId, rowOk := literal(call.Args[1])
			clause, clauseOk := literal(call.Args[2])
			if !rowOk || !clauseOk {
				return true
			}
			runs = append(runs, rowId+" "+clause)
			_, unregistered := clauseUnregisteredRuns[rowId+" "+clause]
			switch registration := LookupClause(rowId, clause); {
			case clause == "twin" || strings.HasSuffix(clause, " twin"):
			case registration != nil && unregistered:
				t.Errorf("%s: %s is registered: take it off clauseUnregisteredRuns, and run it through RunRegisteredClause", fileSet.Position(call.Pos()), registration)
			case registration == nil && !unregistered:
				t.Errorf("%s: %s %q runs through %s and is not registered (RegisterClause in clauses.go), so no gate names it", fileSet.Position(call.Pos()), rowId, clause, name)
			}
			return true
		})
	}
	for run := range clauseUnregisteredRuns {
		if !slices.Contains(runs, run) {
			t.Errorf("clauseUnregisteredRuns names %s, which no test runs any more", run)
		}
	}
}

// Every gate's row of a case names each of the case's registered clauses' tests, on each tier the clause runs on, where
// the clause says, so the gate tool, which reads a row pass only when every test it names passes, reads the case failed
// when one clause fails (TEST.md's rule 7): FS-1's at M2 among them, in evshost on T3, and the hold cases' at M5, M10
// and the held gate.
func TestEveryGateRowNamesItsCasesClauses(t *testing.T) {
	catalog := DefaultCatalog()
	checked := 0
	for _, gate := range GateNames() {
		for _, row := range GateRows(catalog, gate) {
			if row.Row == "" {
				continue
			}
			testCase := catalog.Case(row.Row, row.Case)
			for _, registration := range Clauses(testCase.Row.Id, testCase.Name) {
				for _, test := range GateClauseTests(registration) {
					named := slices.ContainsFunc(row.Tests, func(entry *GateTest) bool {
						return entry.Repo == test.Repo && entry.Dir == test.Dir && entry.Package == test.Package && slices.Contains(entry.Names, test.Names[0])
					})
					if !named {
						t.Errorf("%s's row of %s does not name %s's %s %s", gate, testCase, registration, test.Package, test.Names[0])
					}
					checked += 1
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no gate row names a clause")
	}
	rows := GateRows(catalog, "M2")
	index := slices.IndexFunc(rows, func(row *GateRow) bool { return row.Row == "FS-1" && row.Case == "" })
	if index < 0 {
		t.Fatal("M2 holds no FS-1")
	}
	want := []string{"TestFs1", "TestFs1OnT3", "TestFs1ConcurrentRetries", "TestFs1UnknownDeletesNothing", "TestFs1ConcurrentRetriesOnT3", "TestFs1UnknownDeletesNothingOnT3"}
	if got := gateRowNamesForTest(rows[index]); !slices.Equal(got, want) {
		t.Errorf("FS-1 at M2 names %v, want %v", got, want)
	}
}
