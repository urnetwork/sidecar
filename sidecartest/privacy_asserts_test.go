package sidecartest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// §22.7's assert block from design/source/sections/22-TEST.md, above the working directory: each clause
// with its continuation lines joined by one space. A clause opens at the block's column, 7, and its
// continuation lines sit two further in; the block ends at the first line that is neither.
func designPrivacyAssertClauses(t *testing.T) []string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var section []byte
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		section, err = os.ReadFile(filepath.Join(directory, "design", "source", "sections", "22-TEST.md"))
		if err == nil {
			break
		}
		if directory == filepath.Dir(directory) {
			t.Fatalf("no design/source/sections/22-TEST.md above %s", workingDirectory)
		}
	}
	const clauseIndent = "       "
	const continuationIndent = clauseIndent + "  "
	clauses := []string{}
	inBlock := false
	for _, line := range strings.Split(string(section), "\n") {
		switch {
		case !inBlock && strings.HasPrefix(line, "assert "):
			inBlock = true
			clauses = append(clauses, strings.TrimPrefix(line, "assert "))
		case !inBlock:
		case strings.HasPrefix(line, continuationIndent):
			clauses[len(clauses)-1] += " " + strings.TrimSpace(line)
		case strings.HasPrefix(line, clauseIndent) && line[len(clauseIndent)] != ' ':
			clauses = append(clauses, strings.TrimSpace(line))
		default:
			return clauses
		}
	}
	if !inBlock {
		t.Fatal("§22.7 holds no assert block")
	}
	return clauses
}

// Every clause of §22.7's block is one row, by its opening words, and every row opens one clause, in
// the design's order: a clause added to the design, dropped from it, or reworded at its start fails.
func TestEveryPrivacyAssertClauseIsARow(t *testing.T) {
	clauses := designPrivacyAssertClauses(t)
	rows := NewPrivacyAsserts().Rows()
	if len(clauses) != len(rows) {
		t.Errorf("§22.7's assert block holds %d clauses and the registry %d rows", len(clauses), len(rows))
	}
	for index, clause := range clauses {
		matches := []string{}
		for _, row := range rows {
			if strings.HasPrefix(clause, row.Opening) {
				matches = append(matches, row.Id)
			}
		}
		if len(matches) != 1 {
			t.Errorf("clause %d (%q) opens %d rows: %v", index+1, clause, len(matches), matches)
			continue
		}
		if index < len(rows) && rows[index].Id != matches[0] {
			t.Errorf("clause %d is row %s, and the registry holds %s at that place", index+1, matches[0], rows[index].Id)
		}
	}
	t.Logf("§22.7's assert block: %d clauses, each a row", len(clauses))
}

// A row names a gate the catalog's form allows, an owner, and an id no other row holds.
func TestPrivacyAssertRowsAreWellFormed(t *testing.T) {
	assertIds := map[string]bool{}
	for _, row := range NewPrivacyAsserts().Rows() {
		if row.Id == "" || assertIds[row.Id] {
			t.Errorf("row %q: an id empty or held twice", row.Id)
		}
		assertIds[row.Id] = true
		if len(row.Gates) == 0 || len(row.Owners) == 0 {
			t.Errorf("%s: no gate or no owner", row.Id)
		}
		for _, gate := range row.Gates {
			number, found := strings.CutPrefix(gate, "M")
			number, outGate := strings.CutSuffix(number, "-out")
			if !found || !outGate || !slices.Contains([]string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}, number) {
				t.Errorf("%s: gate %q is no Mn-out", row.Id, gate)
			}
		}
	}
}

// A row no test is registered to reads missing at each of its gates, and only there; one registration
// covers its row at every gate it names, and leaves its siblings missing.
func TestUnregisteredPrivacyAssertReadsMissing(t *testing.T) {
	asserts := NewPrivacyAsserts()
	ids := func(rows []*PrivacyAssert) []string {
		out := []string{}
		for _, row := range rows {
			out = append(out, row.Id)
		}
		return out
	}
	if got := ids(asserts.Missing("M2-out")); !slices.Equal(got, []string{"stored-commits", "store-writes"}) {
		t.Errorf("missing at M2-out before any registration: %v", got)
	}
	if got := ids(asserts.Missing("M1-out")); len(got) != 0 {
		t.Errorf("missing at M1-out, which no row names: %v", got)
	}
	err := asserts.Register("stored-commits", &PrivacyAssertTest{
		Repo: "server", Package: "github.com/urnetwork/server/sidecart3", Name: "TestStoredCommitsArePrivateMessages",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(asserts.Missing("M2-out")); !slices.Equal(got, []string{"store-writes"}) {
		t.Errorf("missing at M2-out after one registration: %v", got)
	}
	err = asserts.Register("certificates", &PrivacyAssertTest{
		Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestS5Certificates",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, gate := range []string{"M5-out", "M6-out"} {
		if slices.Contains(ids(asserts.Missing(gate)), "certificates") {
			t.Errorf("certificates is registered and still missing at %s", gate)
		}
	}
	if got := ids(asserts.Missing("M10-out")); !slices.Equal(got, []string{"query-canaries", "shards-dbreach", "request-traces"}) {
		t.Errorf("missing at M10-out: %v", got)
	}
}

// A registration naming no row fails, as do one with no test and the same test twice.
func TestPrivacyAssertRegistrationNamingNoRowFails(t *testing.T) {
	asserts := NewPrivacyAsserts()
	test := &PrivacyAssertTest{Repo: "sidecar", Package: "github.com/urnetwork/sidecar/sidecartest", Name: "TestPlanted"}
	if err := asserts.Register("no-such-clause", test); err == nil || !strings.Contains(err.Error(), `no row "no-such-clause"`) {
		t.Errorf("a registration naming no row: %v", err)
	}
	if err := asserts.Register("splices", &PrivacyAssertTest{Repo: "sidecar", Name: "TestPlanted"}); err == nil {
		t.Error("a registration with no package passed")
	}
	if err := asserts.Register("splices", nil); err == nil {
		t.Error("a registration with no test passed")
	}
	if err := asserts.Register("splices", test); err != nil {
		t.Fatal(err)
	}
	if err := asserts.Register("splices", test); err == nil {
		t.Error("the same test registered twice to one row passed")
	}
	if tests := asserts.Tests("splices"); len(tests) != 1 || tests[0].Name != "TestPlanted" {
		t.Errorf("splices' tests: %v", tests)
	}
	if len(asserts.Missing("M7-out")) != 3 {
		t.Errorf("M7-out's missing rows after registering splices: %d", len(asserts.Missing("M7-out")))
	}
}

// The package-level form panics on a row the registry does not hold, so a binary whose registrations
// do not link cannot pass. The default registry is left as it was.
func TestRegisterPrivacyAssertPanicsOnAnUnknownRow(t *testing.T) {
	panicked := func() (panicked bool) {
		defer func() {
			panicked = recover() != nil
		}()
		RegisterPrivacyAssert("no-such-clause", &PrivacyAssertTest{Repo: "sidecar", Package: "p", Name: "TestPlanted"})
		return false
	}()
	if !panicked {
		t.Error("RegisterPrivacyAssert of an unknown row did not panic")
	}
	if 0 < len(DefaultPrivacyAsserts().Tests("no-such-clause")) {
		t.Error("the refused registration was kept")
	}
}

// What the default registry reads at each gate today, so the run's log shows what a sweep would.
func TestDefaultPrivacyAssertsReportMissingByGate(t *testing.T) {
	for _, gate := range []string{"M2-out", "M3-out", "M4-out", "M5-out", "M6-out", "M7-out", "M8-out", "M10-out"} {
		for _, row := range DefaultPrivacyAsserts().Missing(gate) {
			t.Logf("%s: %s missing (owners %s)", gate, row.Id, strings.Join(row.Owners, ", "))
		}
	}
}
