package fault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The design's sources, from the top of the repository, which in this repository is an ancestor of
// every package. Finding none fails, since a check that cannot read the design checks nothing.
func designSection(t *testing.T, fileName string) []string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for directory := workingDirectory; ; directory = filepath.Dir(directory) {
		data, err := os.ReadFile(filepath.Join(directory, "design", "source", "sections", fileName))
		if err == nil {
			return strings.Split(string(data), "\n")
		}
		if directory == filepath.Dir(directory) {
			t.Fatalf("no design/source/sections/%s above %s", fileName, workingDirectory)
		}
	}
}

// The runes of line from one column to another, trimmed: the design's tables align by character, and
// a § before a column is two bytes.
func designColumn(line []rune, from int, to int) string {
	if len(line) <= from {
		return ""
	}
	return strings.TrimSpace(string(line[from:min(to, len(line))]))
}

var designRowIdPattern = regexp.MustCompile(`FS-([0-9]+)(?: to FS-([0-9]+))?`)

// Every FS id text names, ranges written "FS-1 to FS-12" included.
func designRowIds(text string) map[string]bool {
	rowIds := map[string]bool{}
	for _, match := range designRowIdPattern.FindAllStringSubmatch(text, -1) {
		from, _ := strconv.Atoi(match[1])
		to := from
		if match[2] != "" {
			to, _ = strconv.Atoi(match[2])
		}
		for n := from; n <= to; n += 1 {
			rowIds[fmt.Sprintf("FS-%d", n)] = true
		}
	}
	return rowIds
}

func sortedRowIds(rowIds map[string]bool) []string {
	sorted := []string{}
	for rowId := range rowIds {
		sorted = append(sorted, rowId)
	}
	slices.SortFunc(sorted, func(a string, b string) int {
		numberA, _ := strconv.Atoi(strings.TrimPrefix(a, "FS-"))
		numberB, _ := strconv.Atoi(strings.TrimPrefix(b, "FS-"))
		return numberA - numberB
	})
	return sorted
}

// One row of §22.8's table as the design writes it.
type designRow struct {
	id       string
	sections []int
	checks   []string
	tiers    []Tier
	gateText string
}

var designCheckPattern = regexp.MustCompile(`^((?:FI|I)-)([0-9]+[a-d]?)$`)
var designBareCheckPattern = regexp.MustCompile(`^[0-9]+[a-d]?$`)

// "FI-1,2,9" is FI-1, FI-2 and FI-9; "I-4,15,FI-2" is I-4, I-15 and FI-2; "hint SLO" is itself.
func designChecks(text string) []string {
	checks := []string{}
	prefix := ""
	for _, token := range strings.Split(text, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if match := designCheckPattern.FindStringSubmatch(token); match != nil {
			prefix = match[1]
			checks = append(checks, token)
		} else if designBareCheckPattern.MatchString(token) && prefix != "" {
			checks = append(checks, prefix+token)
		} else {
			checks = append(checks, token)
		}
	}
	return checks
}

// §22.8's table, read by its header's columns, each column joined across a row's wrapped lines: the
// tier and gate columns wrap, so FS-83's +T4 and FS-96's fifth check sit on later lines.
func section22Rows(t *testing.T) []*designRow {
	t.Helper()
	lines := designSection(t, "22-TEST.md")
	headerIndex := slices.IndexFunc(lines, func(line string) bool { return strings.HasPrefix(line, "id     §      schedule") })
	if headerIndex < 0 {
		t.Fatal("§22.8's table is not where it was")
	}
	header := []rune(lines[headerIndex])
	column := func(name string) int {
		index := slices.Index(header, []rune(name)[0])
		for ; index < len(header); index += 1 {
			if strings.HasPrefix(string(header[index:]), name) {
				return index
			}
		}
		t.Fatalf("§22.8's header has no %q", name)
		return 0
	}
	sectionColumn, scheduleColumn := column("§"), column("schedule")
	checksColumn, tierColumn, gateColumn := column("checks"), column("tier"), column("gate")

	rows := []*designRow{}
	sectionTexts := []string{}
	checkTexts := []string{}
	tierTexts := []string{}
	gateTexts := []string{}
	finish := func() {
		if len(rows) == 0 {
			return
		}
		row := rows[len(rows)-1]
		for _, section := range strings.Split(strings.TrimPrefix(strings.Join(sectionTexts, ""), "§"), ",") {
			if section == "" {
				continue
			}
			n, err := strconv.Atoi(section)
			if err != nil {
				t.Fatalf("%s's section %q", row.id, section)
			}
			row.sections = append(row.sections, n)
		}
		row.checks = designChecks(strings.Join(checkTexts, ""))
		for _, tier := range strings.Split(strings.Join(tierTexts, ""), "+") {
			row.tiers = append(row.tiers, Tier(tier))
		}
		row.gateText = strings.Join(gateTexts, " ")
	}
	for _, line := range lines[headerIndex+1:] {
		if strings.HasPrefix(line, "```") {
			break
		}
		runes := []rune(line)
		if strings.HasPrefix(line, "FS-") {
			finish()
			rows = append(rows, &designRow{id: strings.Fields(line)[0]})
			sectionTexts, checkTexts, tierTexts, gateTexts = nil, nil, nil, nil
		}
		if len(rows) == 0 {
			t.Fatalf("§22.8's table starts with %q", line)
		}
		for _, part := range []struct {
			texts *[]string
			from  int
			to    int
		}{
			{texts: &sectionTexts, from: sectionColumn, to: scheduleColumn},
			{texts: &checkTexts, from: checksColumn, to: tierColumn},
			{texts: &tierTexts, from: tierColumn, to: gateColumn},
			{texts: &gateTexts, from: gateColumn, to: len(runes)},
		} {
			if text := designColumn(runes, part.from, part.to); text != "" {
				*part.texts = append(*part.texts, text)
			}
		}
	}
	finish()
	return rows
}

var designGateRangePattern = regexp.MustCompile(`M([0-9]+) to M([0-9]+)`)
var designGatePattern = regexp.MustCompile(`M([0-9]+)(-in|-out)?`)

// The gates a §22.8 gate column names: "M5 to M8 per step" is M5-out to M8-out, "M3 on production" is
// M3-out, "each Gn-out" every-out and "each next cluster" next-cluster.
func designGates(text string) map[string]bool {
	gates := map[string]bool{}
	for _, match := range designGateRangePattern.FindAllStringSubmatch(text, -1) {
		from, _ := strconv.Atoi(match[1])
		to, _ := strconv.Atoi(match[2])
		for n := from; n <= to; n += 1 {
			gates[fmt.Sprintf("M%d-out", n)] = true
		}
	}
	for _, match := range designGatePattern.FindAllStringSubmatch(text, -1) {
		kind := "-out"
		if match[2] == "-in" {
			kind = "-in"
		}
		gates["M"+match[1]+kind] = true
	}
	if strings.Contains(text, "each Gn-out") {
		gates[GateEveryOut] = true
	}
	if strings.Contains(text, "each next cluster") {
		gates[GateNextCluster] = true
	}
	return gates
}

// The catalog holds §22.8's rows as the design writes them: ids in order, sections, checks and tiers,
// and the gates of every case are those the row's gate column names.
func TestCatalogMatchesSection22(t *testing.T) {
	catalog := DefaultCatalog()
	designRows := section22Rows(t)
	if len(designRows) != catalogRowCount {
		t.Fatalf("§22.8 reads as %d rows", len(designRows))
	}
	for index, designRow := range designRows {
		row := catalog.Rows[index]
		if row.Id != designRow.id {
			t.Errorf("row %d: catalog %s, §22.8 %s", index+1, row.Id, designRow.id)
			continue
		}
		if !slices.Equal(row.Sections, designRow.sections) {
			t.Errorf("%s: sections %v, §22.8 %v", row.Id, row.Sections, designRow.sections)
		}
		if !slices.Equal(row.Checks, designRow.checks) {
			t.Errorf("%s: checks %q, §22.8 %q", row.Id, row.Checks, designRow.checks)
		}
		if !slices.Equal(row.Tiers, designRow.tiers) {
			t.Errorf("%s: tiers %v, §22.8 %v", row.Id, row.Tiers, designRow.tiers)
		}
		caseGates := map[string]bool{}
		for _, testCase := range row.Cases {
			for _, gate := range testCase.Gates {
				caseGates[gate] = true
			}
		}
		if want := designGates(designRow.gateText); !mapsEqual(caseGates, want) {
			t.Errorf("%s: cases at %v, and §22.8's %q names %v", row.Id, sortedKeys(caseGates), designRow.gateText, sortedKeys(want))
		}
	}
	// the traps the plan names, read where the design wraps them
	for rowId, tier := range map[string]Tier{"FS-83": TierT4, "FS-98": TierT4, "FS-100": TierT4, "FS-124": TierT4, "FS-125": TierT4} {
		if !slices.Contains(catalog.Row(rowId).Tiers, tier) {
			t.Errorf("%s lost its wrapped %s", rowId, tier)
		}
	}
	if checks := catalog.Row("FS-96").Checks; len(checks) != 5 || checks[4] != "FI-27" {
		t.Errorf("FS-96's wrapped fifth check: %q", checks)
	}
}

func mapsEqual(a map[string]bool, b map[string]bool) bool {
	return slices.Equal(sortedKeys(a), sortedKeys(b))
}

func sortedKeys(set map[string]bool) []string {
	keys := []string{}
	for key := range set {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// "FI-15  file-mode CAS (I-EVS-8): ...", the name without the id in parentheses.
var designInvariantPattern = regexp.MustCompile(`^FI-([0-9]+)\s+([^:(]+?)\s*(?:\([^)]*\))?:`)

// FI-1 to FI-30 with §22.8's names, and §22.8's unknown list.
func TestCatalogInvariantsAndUnknownListMatchSection22(t *testing.T) {
	catalog := DefaultCatalog()
	lines := designSection(t, "22-TEST.md")
	names := map[int]string{}
	unknownText := ""
	for index, line := range lines {
		if match := designInvariantPattern.FindStringSubmatch(line); match != nil {
			n, _ := strconv.Atoi(match[1])
			names[n] = strings.TrimSpace(match[2])
		}
		if strings.HasPrefix(line, "unknown     ApplyThenDrop") {
			for _, next := range lines[index:] {
				unknownText += " " + next
				if strings.Contains(next, "also runs with it") {
					break
				}
			}
		}
	}
	if len(names) != catalogInvariantCount || len(catalog.Invariants) != catalogInvariantCount {
		t.Fatalf("§22.8 names %d invariants, the catalog %d", len(names), len(catalog.Invariants))
	}
	for n, name := range names {
		if invariant := catalog.Invariant(n); invariant == nil || invariant.Name != name {
			t.Errorf("FI-%d: catalog %v, §22.8 %q", n, invariant, name)
		}
	}
	unknownRowIds := []string{}
	for _, row := range catalog.UnknownRows() {
		unknownRowIds = append(unknownRowIds, row.Id)
	}
	want := sortedRowIds(designRowIds(unknownText))
	if len(want) != 12 || !slices.Equal(unknownRowIds, want) {
		t.Errorf("unknown rows %v, §22.8 %v", unknownRowIds, want)
	}
}

// §23.6's table: per gate, the FS ids its schedules column names, and the rows its design-closure
// column says must pass at Gn-in.
func section236Gates(t *testing.T) (outRows map[string]map[string]bool, inRows map[string]map[string]bool) {
	t.Helper()
	lines := designSection(t, "23-PHASE.md")
	headerIndex := slices.IndexFunc(lines, func(line string) bool { return strings.HasPrefix(line, "gate     design closure at Gn-in") })
	if headerIndex < 0 {
		t.Fatal("§23.6's table is not where it was")
	}
	header := lines[headerIndex]
	rightColumn := len([]rune(header[:strings.Index(header, "schedules passing at Gn-out")]))
	labels := map[string]string{
		"G0": "", "M0": "", "every": GateEveryOut, "Gn-out": GateEveryOut,
		"next": GateNextCluster, "metadata": GateNextCluster, "cluster": GateNextCluster,
	}
	lefts := map[string]string{}
	rights := map[string]string{}
	current := ""
	for _, line := range lines[headerIndex+1:] {
		if strings.HasPrefix(line, "```") {
			break
		}
		runes := []rune(line)
		if label := designColumn(runes, 0, 9); label != "" {
			gate, ok := labels[label]
			if !ok {
				gate = label + "-out"
			}
			current = gate
		}
		if current == "" {
			continue
		}
		lefts[current] += " " + designColumn(runes, 9, rightColumn)
		rights[current] += " " + designColumn(runes, rightColumn, len(runes))
	}
	outRows = map[string]map[string]bool{}
	for gate, right := range rights {
		outRows[gate] = designRowIds(right)
	}
	inRows = map[string]map[string]bool{}
	for gate, left := range lefts {
		// a design-closure item that freezes once a schedule passes: FS-46's escrow run on M4's build
		for _, part := range strings.Split(left, ";") {
			if strings.Contains(part, "pass") {
				inGate := strings.TrimSuffix(gate, "-out") + "-in"
				if inRows[inGate] == nil {
					inRows[inGate] = map[string]bool{}
				}
				for rowId := range designRowIds(part) {
					inRows[inGate][rowId] = true
				}
			}
		}
	}
	return outRows, inRows
}

func catalogGateRowIds(catalog *Catalog, gate string) map[string]bool {
	rowIds := map[string]bool{}
	for _, testCase := range catalog.GateCases(gate) {
		rowIds[testCase.Row.Id] = true
	}
	return rowIds
}

// Each gate's rows are §23.6's, the M2 list is §22.10's too, and a gate holds a row's case list, never
// a row as one milestone: FS-19's runs, FS-47's §21 and mail cases and the later-of cases each sit at
// the gates §23.6 names.
func TestCatalogMatchesGateMap(t *testing.T) {
	catalog := DefaultCatalog()
	outRows, inRows := section236Gates(t)
	if len(outRows["M2-out"]) < 40 || !outRows["M1-out"]["FS-54"] || !outRows[GateEveryOut]["FS-55"] {
		t.Fatalf("§23.6 read wrong: %v", outRows)
	}
	for _, gate := range catalog.Gates() {
		want := outRows[gate]
		if strings.HasSuffix(gate, "-in") {
			want = inRows[gate]
		}
		if got := catalogGateRowIds(catalog, gate); !mapsEqual(got, want) {
			t.Errorf("%s: catalog %v, §23.6 %v", gate, sortedRowIds(got), sortedRowIds(want))
		}
	}
	for gate, want := range outRows {
		if 0 < len(want) && !slices.Contains(catalog.Gates(), gate) {
			t.Errorf("§23.6 names %v at %s, and the catalog has no such gate", sortedRowIds(want), gate)
		}
	}

	// §22.10's M2 freeze: the same rows, less the cases it keeps at M7
	lines := designSection(t, "22-TEST.md")
	headerIndex := slices.IndexFunc(lines, func(line string) bool { return strings.HasPrefix(line, "format                        spec freeze") })
	if headerIndex < 0 {
		t.Fatal("§22.10's table is not where it was")
	}
	finalColumn := len([]rune(lines[headerIndex][:strings.Index(lines[headerIndex], "final freeze (Gn-out)")]))
	cells := map[string]string{}
	current := ""
	for _, line := range lines[headerIndex+1:] {
		if strings.HasPrefix(line, "```") {
			break
		}
		switch {
		case strings.HasPrefix(line, "§7.9's records"):
			current = "M2"
		case strings.HasPrefix(line, "record.proto (M3)"):
			current = "M3"
		case strings.HasPrefix(line, "directory.proto (M6)"):
			current = "M6"
		case strings.HasPrefix(line, "smtpproof/SPEC.md"), strings.HasPrefix(line, "escrow order"), strings.HasPrefix(line, "format 2 (M10)"), strings.HasPrefix(line, "data rule"):
			current = ""
		}
		if current != "" {
			cells[current] += " " + designColumn([]rune(line), finalColumn, len([]rune(line)))
		}
	}
	m2Parts := []string{}
	for _, part := range strings.Split(cells["M2"], ";") {
		if !strings.Contains(part, "keeping their M7 gates") {
			m2Parts = append(m2Parts, part)
		}
	}
	if got, want := catalogGateRowIds(catalog, "M2-out"), designRowIds(strings.Join(m2Parts, ";")); !mapsEqual(got, want) {
		t.Errorf("M2-out: catalog %v, §22.10 %v", sortedRowIds(got), sortedRowIds(want))
	}
	for rowId := range designRowIds(cells["M3"]) {
		if !catalogGateRowIds(catalog, "M3-out")[rowId] {
			t.Errorf("§22.10 freezes record.proto on %s, which has no M3-out case", rowId)
		}
	}
	for rowId := range designRowIds(cells["M6"]) {
		if !catalogGateRowIds(catalog, "M6-out")[rowId] {
			t.Errorf("§22.10 freezes directory.proto on %s, which has no M6-out case", rowId)
		}
	}

	// cases the plan names, each at its own gate
	for _, want := range []struct {
		rowId    string
		caseName string
		gates    []string
	}{
		{rowId: "FS-19", caseName: "config-read", gates: []string{"M2-out"}},
		{rowId: "FS-19", caseName: "grant", gates: []string{"M4-out"}},
		{rowId: "FS-19", caseName: "share", gates: []string{"M4-out"}},
		{rowId: "FS-19", caseName: "team", gates: []string{"M6-out"}},
		{rowId: "FS-19", caseName: "invite", gates: []string{"M6-out"}},
		{rowId: "FS-19", caseName: "quick-burner", gates: []string{"M8-out"}},
		{rowId: "FS-47", caseName: "section-21", gates: []string{"M5-out"}},
		{rowId: "FS-47", caseName: "mail", gates: []string{"M7-out"}},
		{rowId: "FS-69", caseName: "", gates: []string{"M5-out", "M10-out"}},
		{rowId: "FS-92", caseName: "", gates: []string{"M5-out", "M10-out"}},
	} {
		testCase := catalog.Case(want.rowId, want.caseName)
		if testCase == nil || !slices.Equal(testCase.Gates, want.gates) {
			t.Errorf("%s %q: %v", want.rowId, want.caseName, testCase)
		}
	}
	for _, testCase := range catalog.GateCases("M10-out") {
		if 1 < len(testCase.Gates) && !testCase.LaterOf {
			t.Errorf("%s keeps two gates and is not later-of", testCase)
		}
	}
}

func TestCatalogHolds125RowsAnd30Invariants(t *testing.T) {
	catalog := DefaultCatalog()
	if len(catalog.Rows) != 125 || len(catalog.Invariants) != 30 {
		t.Fatalf("%d rows, %d invariants", len(catalog.Rows), len(catalog.Invariants))
	}
	for n := 1; n <= 125; n += 1 {
		if row := catalog.Row(fmt.Sprintf("FS-%d", n)); row == nil || row.Number != n {
			t.Errorf("FS-%d: %v", n, row)
		}
	}
	for _, rowId := range []string{"FS-0", "FS-126", "FS-01", "FS-x", "fs-1"} {
		if catalog.Row(rowId) != nil {
			t.Errorf("%s resolved", rowId)
		}
	}
}

// One planted fault per kind: each is a catalog no gate may read.
func TestCatalogRefusesWhatItCannotHold(t *testing.T) {
	plant := func(old string, new string) []byte {
		if !bytes.Contains(catalogYaml, []byte(old)) {
			t.Fatalf("catalog.yml no longer holds %q", old)
		}
		return bytes.Replace(catalogYaml, []byte(old), []byte(new), 1)
	}
	for _, planted := range []struct {
		data []byte
		want string
	}{
		{data: plant("checks: [FI-9], tiers: [T3]", "checks: [FI-31], tiers: [T3]"), want: "FI-31, which §22.8 does not hold"},
		{data: plant("checks: [FI-9], tiers: [T3]", "checks: [FI-9x], tiers: [T3]"), want: "which is no FI"},
		{data: plant("{name: share, gates: [M4-out]}", "{name: grant, gates: [M4-out]}"), want: "two cases named \"grant\""},
		{data: plant("  - {id: FS-2,", "  - {id: FS-1,"), want: "row 2 is \"FS-1\""},
		{data: plant("{id: FI-2, name:", "{id: FI-1, name:"), want: "invariant 2 is \"FI-1\""},
		{data: plant("tiers: [T3], cases: [{gates: [M2-out]}]", "tiers: [T3], cases: [{gates: [M2-out], flavor: x}]"), want: "field flavor not found"},
		{data: plant("tiers: [T3], cases: [{gates: [M2-out]}]", "tiers: [T3], cases: [{gates: [M11-out]}]"), want: "names gate \"M11-out\""},
		{data: plant("tiers: [T3], cases: [{gates: [M2-out]}]", "tiers: [T5], cases: [{gates: [M2-out]}]"), want: "names tier \"T5\""},
		{data: plant("tiers: [T3], cases: [{gates: [M2-out]}]", "tiers: [T3], cases: [{gates: [M2-out], tiers: [T2]}]"), want: "which its row does not name"},
		{data: plant("tiers: [T3], cases: [{gates: [M2-out]}]", "tiers: [T3], cases: [{gates: [M2-out, M3-out]}]"), want: "later_of goes with two gates"},
		{data: plant("oracle: TEST-M2-03}", "oracle: somebody}"), want: "names no task"},
		{data: plant("{name: production, gates: [M3-out], open: production}", "{name: production, gates: [M3-out], open: hope}"), want: "waits on \"hope\""},
		{data: plant("rows:\n", "rows:\n\t"), want: "holds a tab"},
		{data: append(bytes.Clone(catalogYaml), []byte("---\nrows: []\n")...), want: "second document"},
	} {
		if _, err := ParseCatalog(planted.data); err == nil || !strings.Contains(err.Error(), planted.want) {
			t.Errorf("want %q: %v", planted.want, err)
		}
	}
}

// What register refuses, each on a fresh registry so the package's own is left alone.
func TestRegistrationRefusesWhatTheCatalogDoesNotHold(t *testing.T) {
	registry := newRegistry(DefaultCatalog())
	build := func(net *Net) *Schedule { return &Schedule{Id: "toy"} }
	both := []Tier{TierT2, TierT3}
	for _, planted := range []struct {
		rowId    string
		caseName string
		tiers    []Tier
		builder  Builder
		want     string
	}{
		{rowId: "FS-126", tiers: both, builder: build, want: "no such row"},
		{rowId: "FS-19", caseName: "", tiers: both, builder: build, want: "no case \"\""},
		{rowId: "FS-19", caseName: "grnat", tiers: both, builder: build, want: "no case \"grnat\""},
		{rowId: "FS-5", tiers: []Tier{TierT2}, builder: build, want: "the case runs on [T3]"},
		{rowId: "FS-2", tiers: nil, builder: build, want: "no tier"},
		{rowId: "FS-2", tiers: both, builder: nil, want: "no builder"},
	} {
		if _, err := registry.register(planted.rowId, planted.caseName, planted.tiers, planted.builder); err == nil || !strings.Contains(err.Error(), planted.want) {
			t.Errorf("%s %q: want %q, got %v", planted.rowId, planted.caseName, planted.want, err)
		}
	}
	if _, err := registry.register("FS-2", "", []Tier{TierT2}, build); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.register("FS-2", "", []Tier{TierT3, TierT2}, build); err == nil || !strings.Contains(err.Error(), "registered already") {
		t.Errorf("a duplicate case: %v", err)
	}
	if _, err := registry.register("FS-2", "", []Tier{TierT3}, build); err != nil {
		t.Errorf("T3 beside T2: %v", err)
	}
	// a forged case's twin runs on T3 too, so its builder may register there
	if _, err := registry.register("FS-102", "forged", []Tier{TierT2, TierT3}, build); err != nil {
		t.Errorf("forged twin on T3: %v", err)
	}
	// Register panics where register errs, since it runs from a package-level var
	func() {
		defer func() {
			if recover() == nil {
				t.Error("Register of no row passed")
			}
		}()
		Register("FS-0", "", both, build)
	}()
}

// Missing is never pass: an empty registry lists every case of every row, and one registered case
// leaves its siblings, and its own other tiers, missing.
func TestMissingListsWhatNoBuilderCovers(t *testing.T) {
	catalog := DefaultCatalog()
	registry := newRegistry(catalog)
	seen := map[*Case]bool{}
	for _, gate := range catalog.Gates() {
		for _, tier := range catalogTiers {
			for _, testCase := range registry.missing(gate, tier) {
				seen[testCase] = true
			}
		}
	}
	for _, row := range catalog.Rows {
		for _, testCase := range row.Cases {
			if !seen[testCase] && testCase.Open == "" {
				t.Errorf("%s is not missing on an empty registry", testCase)
			}
			if seen[testCase] && testCase.Open != "" {
				t.Errorf("%s waits on %s and reads missing", testCase, testCase.Open)
			}
		}
		if !slices.ContainsFunc(row.Cases, func(testCase *Case) bool { return seen[testCase] }) {
			t.Errorf("%s is not missing on an empty registry", row.Id)
		}
	}

	build := func(net *Net) *Schedule { return &Schedule{Id: "FS-19"} }
	if _, err := registry.register("FS-19", "config-read", []Tier{TierT2}, build); err != nil {
		t.Fatal(err)
	}
	names := func(cases []*Case) []string {
		texts := []string{}
		for _, testCase := range cases {
			texts = append(texts, testCase.String())
		}
		return texts
	}
	if missing := names(registry.missing("M2-out", TierT2)); slices.Contains(missing, "FS-19's config-read") || !slices.Contains(missing, "FS-1") {
		t.Errorf("M2-out on T2: %v", missing)
	}
	if missing := names(registry.missing("M2-out", TierT3)); !slices.Contains(missing, "FS-19's config-read") {
		t.Errorf("config-read's T3 is not missing: %v", missing)
	}
	for _, sibling := range []string{"FS-19's grant", "FS-19's share"} {
		if missing := names(registry.missing("M4-out", TierT2)); !slices.Contains(missing, sibling) {
			t.Errorf("%s is not missing: %v", sibling, missing)
		}
	}
	// a later-of case is missing at both its gates
	for _, gate := range []string{"M5-out", "M10-out"} {
		if missing := names(registry.missing(gate, TierT2)); !slices.Contains(missing, "FS-69") {
			t.Errorf("FS-69 at %s: %v", gate, missing)
		}
	}
	if registration := registry.lookup("FS-19", "config-read", TierT2); registration == nil || registration.String() != "FS-19's config-read on T2" {
		t.Errorf("lookup: %v", registration)
	}
}

// An FI the catalog does not hold is a schedule written wrong: it panics where it is named.
func TestAnUnknownFiPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("FI(31) passed")
		}
	}()
	FI(31)
}

// What a forged case's twin runs on, and what a case reports as.
func TestCaseTiersAndNames(t *testing.T) {
	catalog := DefaultCatalog()
	forged := catalog.Case("FS-124", "forged")
	if !forged.Forged() || !slices.Equal(forged.Tiers(), []Tier{TierT2}) || !slices.Equal(forged.TwinTiers(), []Tier{TierT2, TierT3}) {
		t.Errorf("FS-124's forged: %v %v", forged.Tiers(), forged.TwinTiers())
	}
	appHost := catalog.Case("FS-124", "app-host")
	if !slices.Equal(appHost.Tiers(), []Tier{TierT2, TierT3, TierT4}) || appHost.String() != "FS-124's app-host" {
		t.Errorf("FS-124's app-host: %v %s", appHost.Tiers(), appHost)
	}
	if row := catalog.Row("FS-17"); !row.Forged || !slices.Equal(row.Cases[0].TwinTiers(), []Tier{TierT2, TierT3}) {
		t.Errorf("FS-17: %v", row.Cases[0].TwinTiers())
	}
	if production := catalog.Case("FS-40", "production"); production.Open != "production" {
		t.Errorf("FS-40's production case waits on %q", production.Open)
	}
	if gates := catalog.Gates(); gates[0] != "M1-out" || gates[len(gates)-1] != GateNextCluster || !slices.Contains(gates, "M6-in") {
		t.Errorf("gates %v", gates)
	}
}
