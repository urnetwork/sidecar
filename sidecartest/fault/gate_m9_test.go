package fault

// M9's sweeps (gate_m9.go; TEST-M9-01): FS-31 in smtpproof's two legs and on T3, FS-123 where each of its owners ran it,
// FS-42's M9 step on server's rows; §22.10's mutated witnesses one item a check, each listing its breaks with what
// refused them, and the command holding that listing to smtpproof's evidence table; S6 and S10 part by part from the
// scenario registry; and the items that read open on the world or missing on a test nobody wrote.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The flag only sidecar-gate M9's witness-listing command passes (gate_m9.go).
var gateM9WitnessesFlagValue = flag.Bool(gateM9WitnessesFlag, false, "report M9's witness-listing item for sidecar-gate M9")

// M9's rows: FS-31 in smtpproof's plain leg, where the circuits are solved, and its engine leg, and on T3 in server's
// smtpedgehost; FS-123 in sidecartest, the root and the sdk and on T3; FS-42's M9 step on server's model alone. Each
// case of M9's exit is one the sweep names, so none keeps the convention's entries, which nothing has written.
func TestGateM9NamesEachRowsTestsWhereTheyRun(t *testing.T) {
	catalog := DefaultCatalog()
	data, err := GateFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	file := parseGateFileForTest(t, data)
	type where struct {
		repo        string
		dir         string
		packagePath string
		tags        string
		stores      bool
		names       []string
	}
	for _, want := range []struct {
		rowId    string
		caseName string
		wheres   []where
	}{
		{rowId: "FS-31", wheres: []where{
			{repo: "sidecar", dir: "smtpproof", packagePath: ".", names: []string{"TestFs31HonestControls", "TestFs31MaliciousSender", "TestFs31MatrixTable", "FuzzSmtpTranscript"}},
			{repo: "sidecar", dir: "smtpproof", packagePath: ".", tags: "sidecar_testhooks", names: []string{"TestFs31ScriptedMxs", "TestFs31TheSenderKeepsAMessageTheEdgeForgedSent"}},
			{repo: "server", packagePath: "./smtpedgehost", tags: "sidecar_pending,sidecar_testhooks", stores: true, names: []string{"TestT3Fs31AnHonestSend", "TestT3Fs31A451", "TestT3Fs31AMessageRecordBeforeTheEnvelopesReplies"}},
		}},
		{rowId: "FS-123", wheres: []where{
			{repo: "sidecar", packagePath: "./sidecartest", names: []string{"TestFs123SentFromADesktop", "TestFs123QueuedFromAPhone", "TestFs123OtherOutcomesReachTheResult"}},
			{repo: "sidecar", packagePath: "./sidecartest", tags: "sidecar_testhooks", names: []string{"TestFs123MailOutcomesStandInTheSendingMailbox", "TestFs123CoverageCopySaysNothingOfSending"}},
			{repo: "sidecar", packagePath: ".", names: []string{"TestMailSendResultReadsASendByItsId", "TestMailSendWatchRaisesOncePerChangedOutcome"}},
			{repo: "sdk", packagePath: ".", names: []string{"TestCheckSendPredictsPerDomain", "TestSendResultsReachGetSendResultAndMailSend"}},
			{repo: "server", packagePath: "./smtpedgehost", tags: "sidecar_pending,sidecar_testhooks", stores: true, names: []string{"TestT3Fs123SentFromADesktop", "TestT3Fs123OtherOutcomesReachTheResult"}},
		}},
		{rowId: "FS-42", caseName: "m9", wheres: []where{
			{repo: "server", packagePath: "./model", tags: "sidecar_pending", stores: true, names: []string{"TestSmtpDkimRevokedAfterTheDumpHasNoSelectorOnceTheReplayEnds", "TestDnsDkimDeleteInTheCallersTransaction"}},
		}},
	} {
		row := gateFileRow(file, "M9", want.rowId, want.caseName)
		if row == nil {
			t.Errorf("M9 has no %s %q", want.rowId, want.caseName)
			continue
		}
		for _, w := range want.wheres {
			found := false
			for _, test := range row.Tests {
				if test.Repo != w.repo || test.Dir != w.dir || test.Package != w.packagePath || test.Tags != w.tags || test.Stores != w.stores {
					continue
				}
				found = true
				for _, name := range w.names {
					if !slices.Contains(test.Names, name) {
						t.Errorf("%s %q at M9 runs %v in %s/%s, which lacks %s", want.rowId, want.caseName, test.Names, w.repo, w.packagePath, name)
					}
				}
			}
			if !found {
				t.Errorf("%s %q at M9 names nothing in %+v: %s", want.rowId, want.caseName, w, gateTestsStringForTest(row.Tests))
			}
		}
		// the convention's entries, which nothing has written, are not among them
		testCase := catalog.Case(want.rowId, want.caseName)
		for _, test := range row.Tests {
			for _, name := range test.Names {
				if name == GateT2TestName(testCase) || name == GateT3TestName(testCase) {
					t.Errorf("%s at M9 keeps the convention's %s, which nothing has written", testCase, name)
				}
			}
		}
		if row.External != "" {
			t.Errorf("%s at M9 waits on %q", testCase, row.External)
		}
	}
	cases := []string{}
	for _, testCase := range catalog.GateCases(gateM9OutGate) {
		cases = append(cases, testCase.String())
	}
	if !slices.Equal(cases, []string{"FS-31", "FS-42's m9", "FS-123"}) {
		t.Errorf("M9's exit holds %v, §23.6's M9 row FS-31, FS-123 and FS-42's M9 step", cases)
	}
}

// The clause-rows item names exactly the cases the sweep names, so a row that gains a builder leaves both together,
// and it runs nothing, reading missing until each has a builder.
func TestGateM9ClauseRowsAreTheSweptCases(t *testing.T) {
	catalog := DefaultCatalog()
	swept := []string{}
	for _, testCase := range catalog.GateCases(gateM9OutGate) {
		if _, ok := gateM9Cases(catalog)[testCase.String()]; ok {
			swept = append(swept, testCase.String())
		}
	}
	if !slices.Equal(swept, gateM9ClauseRows) {
		t.Errorf("the clause rows are %v, the swept cases %v", gateM9ClauseRows, swept)
	}
	_, find := gateItemsForTest(t, "M9")
	clauses := find("the rows that pass on their owners' tests alone")
	for _, name := range gateM9ClauseRows {
		if !strings.Contains(clauses.Item, name) {
			t.Errorf("the clause-rows item does not name %s", name)
		}
	}
	if 0 < len(clauses.Tests) || 0 < len(clauses.Commands) || clauses.External != "" {
		t.Errorf("the clause-rows item, which reads missing until each row has a builder: %+v", clauses)
	}
}

// One item a check, in SPEC.md's order, each listing every witness of its check with what refused it and where it
// runs, an E break at the gate and a Z break at a part, the excused cells said, and each running its check's test in
// smtpproof's plain leg, where a Z break's circuit is solved, beside the table's and the honest twins'.
func TestGateM9WitnessItemsListEachWitnessWithWhatRefusedIt(t *testing.T) {
	items, _ := gateItemsForTest(t, "M9")
	witnessItems := []*GateRow{}
	for _, item := range items {
		if strings.HasPrefix(item.Item, "§22.10's mutated witnesses for ") {
			witnessItems = append(witnessItems, item)
		}
	}
	if len(witnessItems) != len(gateWitnessChecks) {
		t.Fatalf("M9 lists %d checks' witnesses, §22.10 asks for %d", len(witnessItems), len(gateWitnessChecks))
	}
	listed := 0
	for index, check := range gateWitnessChecks {
		item := witnessItems[index]
		if !strings.HasPrefix(item.Item, "§22.10's mutated witnesses for "+check+",") {
			t.Errorf("item %d is %q, not %s's", index, item.Item, check)
			continue
		}
		witnesses := 0
		for _, witness := range gateM9Witnesses() {
			if witness.check != check {
				continue
			}
			witnesses += 1
			listed += 1
			if !strings.Contains(item.Item, witness.mutation) {
				t.Errorf("%s's item does not list %q", check, witness.mutation)
			}
			switch {
			case strings.HasPrefix(check, "E") && witness.refusedAt != gateWitnessRefusedAtGate:
				t.Errorf("%s's %q is refused at %s; an E break is the gate's own", check, witness.mutation, witness.refusedAt)
			case strings.HasPrefix(check, "Z") && !strings.HasPrefix(witness.refusedAt, "part "):
				t.Errorf("%s's %q is refused at %s; a Z break is a part's circuit's", check, witness.mutation, witness.refusedAt)
			case strings.HasPrefix(check, "Z") && !strings.Contains(item.Item, "refused at "+witness.refusedAt+", in "+gateWitnessCellsText(witness)):
				t.Errorf("%s's item does not say %q is refused at %s in %s", check, witness.mutation, witness.refusedAt, gateWitnessCellsText(witness))
			}
		}
		if witnesses == 0 {
			t.Errorf("%s lists no witness", check)
		}
		if strings.HasPrefix(check, "E") && !strings.Contains(item.Item, "refused at the gate, by edgeSession on its own") {
			t.Errorf("%s's item does not say the gate refuses it: %q", check, item.Item)
		}
		for _, cell := range gateM9WitnessExcusedCells() {
			if cell.check == check && !strings.Contains(item.Item, "no witness can break "+check+" alone") {
				t.Errorf("%s's item does not say which cells no witness can break", check)
			}
		}
		want := []*GateTest{
			{Repo: "sidecar", Dir: "smtpproof", Package: ".", Names: []string{"TestMutatedWitness" + check}},
			{Repo: "sidecar", Dir: "smtpproof", Package: ".", Names: []string{"TestMutatedWitnessHonestTwins", "TestMutatedWitnessTable"}},
		}
		if !slices.EqualFunc(item.Tests, want, func(a *GateTest, b *GateTest) bool { return fmt.Sprintf("%+v", *a) == fmt.Sprintf("%+v", *b) }) {
			t.Errorf("%s's item runs %s, want %s", check, gateTestsStringForTest(item.Tests), gateTestsStringForTest(want))
		}
		if item.External != "" || 0 < len(item.Commands) {
			t.Errorf("%s's item: %+v", check, item)
		}
	}
	if listed != len(gateM9Witnesses()) {
		t.Errorf("the items list %d witnesses of %d", listed, len(gateM9Witnesses()))
	}
	// the listing item runs this package's check under the flag only its command passes
	_, find := gateItemsForTest(t, "M9")
	listing := find("the mutated witnesses M9's items list are smtpproof/testdata/mutations/table.md's")
	if len(listing.Commands) != 1 || listing.Commands[0].Repo != "sidecar" || !slices.Equal(listing.Commands[0].Command, gateM9WitnessesCommand()) || 0 < len(listing.Tests) {
		t.Errorf("the listing item: %+v", listing)
	}
	command := strings.Join(gateM9WitnessesCommand(), " ")
	for _, part := range []string{"-run ^TestGateM9WitnessesAreTheTablesRows$", "./sidecartest/fault", "-" + gateM9WitnessesFlag} {
		if !strings.Contains(command, part) {
			t.Errorf("the listing command %q lacks %q", command, part)
		}
	}
}

// The witness-listing item's check, as M9's command runs it: the reason and the outcome on the last two lines, failing
// the run on a fail. Without the flag it reads the table as it stands and logs what the gate would report, failing
// nothing: the table is SMTP-M9-29's to change, and a listing left behind it is the gate's to report.
func TestGateM9WitnessesAreTheTablesRows(t *testing.T) {
	table, err := os.ReadFile(filepath.Join(gateM9WitnessTablePath...))
	if err != nil {
		if *gateM9WitnessesFlagValue {
			fmt.Printf("%v\n%s%s\n", err, GateOutcomeLinePrefix, GateOutcomeFail)
			t.Fatal(err)
		}
		t.Logf("no evidence table to read here: %v", err)
		return
	}
	outcome, reason := gateM9WitnessesListed(table, gateM9Witnesses(), gateM9WitnessExcusedCells())
	if !*gateM9WitnessesFlagValue {
		t.Logf("%s: %s", outcome, reason)
		return
	}
	// the tool reads the last outcome line and the line before it, so they are printed last
	fmt.Printf("%s\n%s%s\n", reason, GateOutcomeLinePrefix, outcome)
	if outcome == GateOutcomeFail {
		t.Error(reason)
	}
}

// An evidence table in smtpproof's layout: its witness rows, one a cell in the order given, a section of
// DESIGN-DETAILS 3.6's cells, which the listing passes over, and its excused cells.
func gateM9WitnessTableForTest(witnesses []*gateMutatedWitness, excusedCells []*gateWitnessExcusedCell) []byte {
	var table strings.Builder
	table.WriteString("# Mutated witnesses (SMTP-M9-29)\n\nA paragraph that reads like the table's own: Parts are bound to one key part.\n\n")
	table.WriteString("| Check | TLS | Mode | Refused at | Mutation | Test |\n|---|---|---|---|---|---|\n")
	for _, witness := range witnesses {
		for _, leg := range witness.legs {
			for _, mode := range witness.modes {
				fmt.Fprintf(&table, "| %s | %s | %s | %s | %s | TestMutatedWitness%s |\n", witness.check, leg, mode, witness.refusedAt, witness.mutation, witness.check)
			}
		}
	}
	table.WriteString("\nDESIGN-DETAILS 3.6's cells:\n\n| Check | Cell | Mutation | Modes |\n|---|---|---|---|\n")
	table.WriteString("| Z1 | a later part opens other keys than the key part committed | a break | BDAT and DATA, every leg |\n")
	table.WriteString("\nCells no witness can break alone:\n\n| Check | TLS | Mode | Why |\n|---|---|---|---|\n")
	for _, cell := range excusedCells {
		fmt.Fprintf(&table, "| %s | %s | %s | a reason |\n", cell.check, cell.version, cell.mode)
	}
	return []byte(table.String())
}

// The listing reads pass on a table of exactly its witnesses and excused cells, and fail naming each difference: a
// row the table has and the listing lacks, a witness the table lacks, a witness in other cells, a row run by another
// check's test, other excused cells, and a table with no witness rows.
func TestGateM9WitnessesListedReadsEachDifference(t *testing.T) {
	witnesses := gateM9Witnesses()
	excused := gateM9WitnessExcusedCells()
	if outcome, reason := gateM9WitnessesListed(gateM9WitnessTableForTest(witnesses, excused), witnesses, excused); outcome != GateOutcomePass ||
		!strings.Contains(reason, fmt.Sprintf("%d witnesses", len(witnesses))) {
		t.Errorf("the listing's own table: %s, %s", outcome, reason)
	}
	added := &gateMutatedWitness{check: "Z2", mutation: "a break nobody listed", refusedAt: "part 2 (env)", legs: []string{gateWitnessLegAes}, modes: []string{gateWitnessModeBdat}}
	moved := *witnesses[0]
	moved.legs = []string{gateWitnessLegAes}
	retold := *witnesses[1]
	retold.refusedAt = "part 3 (msg)"
	for _, c := range []struct {
		name    string
		table   []byte
		listing []*gateMutatedWitness
		excused []*gateWitnessExcusedCell
		want    string
	}{
		{name: "a row the listing lacks", table: gateM9WitnessTableForTest(append(slices.Clone(witnesses), added), excused), listing: witnesses, excused: excused, want: `Z2's "a break nobody listed" refused at part 2 (env) is in the table and not listed here`},
		{name: "a witness the table lacks", table: gateM9WitnessTableForTest(witnesses[1:], excused), listing: witnesses, excused: excused, want: `E1's "a client record of another type after the handshake" refused at gate is listed here and not in the table`},
		{name: "a witness in other cells", table: gateM9WitnessTableForTest(append([]*gateMutatedWitness{&moved}, witnesses[1:]...), excused), listing: witnesses, excused: excused, want: "runs in [1.3 AES-128-GCM BDAT 1.3 AES-128-GCM DATA] in the table"},
		{name: "a witness refused elsewhere", table: gateM9WitnessTableForTest(append([]*gateMutatedWitness{witnesses[0], &retold}, witnesses[2:]...), excused), listing: witnesses, excused: excused, want: "refused at part 3 (msg) is in the table and not listed here"},
		{name: "other excused cells", table: gateM9WitnessTableForTest(witnesses, excused[1:]), listing: witnesses, excused: excused, want: "the table excuses"},
		{name: "no witness rows", table: gateM9WitnessTableForTest(nil, excused), listing: witnesses, excused: excused, want: "holds no witness row"},
	} {
		outcome, reason := gateM9WitnessesListed(c.table, c.listing, c.excused)
		if outcome != GateOutcomeFail || !strings.Contains(reason, c.want) {
			t.Errorf("%s: %s, %s; want fail naming %q", c.name, outcome, reason, c.want)
		}
	}
	// a row run by another check's test
	table := strings.Replace(string(gateM9WitnessTableForTest(witnesses, excused)), "| TestMutatedWitnessE2 |", "| TestMutatedWitnessE1 |", 1)
	if outcome, reason := gateM9WitnessesListed([]byte(table), witnesses, excused); outcome != GateOutcomeFail || !strings.Contains(reason, "runs in TestMutatedWitnessE1, not TestMutatedWitnessE2") {
		t.Errorf("a row run by another check's test: %s, %s", outcome, reason)
	}
}

// S6 and S10 at M9's exit, part by part and tier by tier as the default registry ties tests to them: every part of
// S10 runs a test on T2 and on T3, its server ones on the private stores; S6, whose tests run outside RunScenario, runs
// none on either, so both read missing; and each part's T6 reads open.
func TestGateM9ReadsS6AndS10PartByPart(t *testing.T) {
	items := []*GateRow{}
	for _, row := range GateRows(DefaultCatalog(), "M9") {
		if strings.HasPrefix(row.Item, "§22.7's S6 on ") || strings.HasPrefix(row.Item, "§22.7's S10's ") {
			items = append(items, row)
		}
	}
	// S6, one part, on T2, T3 and T6, and S10's four parts on each
	if len(items) != 3+4*3 {
		t.Errorf("M9 reads %d scenario parts", len(items))
	}
	byName := map[string]*GateRow{}
	for _, item := range items {
		name, _, _ := strings.Cut(item.Item, " (")
		byName[name] = item
	}
	for _, tier := range []string{"T2", "T3"} {
		if item := byName["§22.7's S6 on "+tier]; item == nil || 0 < len(item.Tests) || item.External != "" {
			t.Errorf("S6 on %s, whose tests run outside RunScenario: %+v", tier, item)
		}
	}
	for _, clause := range sidecartest.DefaultScenarioRegistry().Row("S10").Parts() {
		for _, tier := range []string{"T2", "T3"} {
			item := byName["§22.7's S10's "+clause+" on "+tier]
			if item == nil || len(item.Tests) == 0 || item.External != "" {
				t.Errorf("S10's %s on %s: %+v", clause, tier, item)
				continue
			}
			for _, test := range item.Tests {
				if (tier == "T3") != (test.Repo == "server" && test.Stores && test.Package == "./sidecart3") {
					t.Errorf("S10's %s on %s runs %s", clause, tier, gateTestsStringForTest(item.Tests))
				}
			}
		}
		if item := byName["§22.7's S10's "+clause+" on T6"]; item == nil || !strings.HasPrefix(item.External, "T6:") || 0 < len(item.Tests) {
			t.Errorf("S10's %s on T6: %+v", clause, item)
		}
	}
	if item := byName["§22.7's S6 on T6"]; item == nil || !strings.HasPrefix(item.External, "T6:") {
		t.Errorf("S6 on T6: %+v", item)
	}
	for _, tier := range []string{sidecartest.ScenarioTierT2, sidecartest.ScenarioTierT3} {
		missing := []string{}
		for _, part := range sidecartest.DefaultScenarioRegistry().Missing(gateM9OutGate, tier) {
			missing = append(missing, part.String())
		}
		if !slices.Equal(missing, []string{"S6"}) {
			t.Errorf("the registry reads %v missing on %s at M9, S6 alone until SMTP-M9-31 registers it", missing, tier)
		}
	}
}

// M9's items: the rules and FI bindings, the oracles M9's rows do not feed, the SPEC.md evidence with what people and
// hardware owe, S6 and S10, §23.4's exit criteria, the privacy and schema rows, the inline path, the load harness and
// HE's port 25, each reading open where the world owes it and missing where nobody wrote the test, never pass.
func TestGateM9ItemsSayWhatTheWorldOwes(t *testing.T) {
	items, find := gateItemsForTest(t, "M9")
	find("§22.8's rules on every row")
	find("every FI the rows check")
	missing := []string{
		"FS-31's FI-11 and FS-42's M9 step's FI-12 through their oracles",
		"S6's §15.10 forwarding rows on T3",
		"§14's report canary rows on T3",
		"the preamble gate on server's host through InlinePath",
	}
	for _, prefix := range missing {
		if row := find(prefix); 0 < len(row.Tests) || 0 < len(row.Commands) || row.External != "" {
			t.Errorf("%q runs something or waits on the world, and nothing shows it: %+v", prefix, row)
		}
	}
	for prefix, external := range map[string]string{
		"the checker of the public relation written apart":              "people",
		"two engineers who did not write the circuits":                  "people",
		"§22.9's ZK row and D-SMTP-16's speed":                          "hardware",
		"D-SMTP-16's coverage":                                          "production",
		"D-SMTP-16's interop and §22.9's MTA row":                       "production",
		"D-SMTP-16's gate whole, or burner email launches receive-only": "people",
		"DANE-only MXs reached and unauthenticated ones refused":        "production",
		"smtpedge's load harness":                                       "hardware",
		"HE's TCP 25 egress":                                            "people",
	} {
		if row := find(prefix); !strings.HasPrefix(row.External, external) {
			t.Errorf("%q waits on %q, want %s", prefix, row.External, external)
		}
	}
	// the trap: a miss is reported for the owner, and a smoke run stands for none of D-SMTP-16's rows
	trap := find("D-SMTP-16's gate whole, or burner email launches receive-only")
	if 0 < len(trap.Tests) || !strings.Contains(trap.Item, "never hidden by a smoke run") || !strings.Contains(trap.External, "BS1 stays receive-only") {
		t.Errorf("the trap: %+v", trap)
	}
	speed := find("§22.9's ZK row and D-SMTP-16's speed")
	if !strings.Contains(speed.External, "M1 MacBook Air") || !strings.Contains(speed.External, "m5.large") || !strings.Contains(speed.External, "no evidence") {
		t.Errorf("the speed row: %+v", speed)
	}
	checker := gateRowNamesForTest(find("the checker of the public relation written apart"))
	for _, name := range []string{"TestTheCheckerImportsNothingFromTheProverTree", "TestKeyScheduleReproducesRfc8448", "TestCheckerAndTheGateNameTheSameChecks", "TestHeaderCircuitTheGateAndTheCheckerRefuseAlike"} {
		if !slices.Contains(checker, name) {
			t.Errorf("the checker's item lacks %s", name)
		}
	}
	scripted := find("FS-31's scripted MXs as §22.10's M9 evidence")
	if !slices.EqualFunc(scripted.Tests, []*GateTest{gateFs31PlainTests, gateFs31EngineTests, gateFs31T3Tests}, func(a *GateTest, b *GateTest) bool { return a == b }) {
		t.Errorf("FS-31's scripted MXs run %s, not the row's own entries, which the tool runs once", gateTestsStringForTest(scripted.Tests))
	}
	if names := gateRowNamesForTest(find("the bytes M9's exit freezes reproduce")); !slices.Equal(names, []string{"TestSpecVectorsReproduce", "TestSpecVectorsCoverEveryShape", "TestSpecPi1ProofVectorVerifies"}) {
		t.Errorf("the vectors' item runs %v", names)
	}
	s6 := gateRowNamesForTest(find("S6, send mail, as its owners' tests run it"))
	for _, name := range []string{"TestS6NoRecordReachesTheMxBeforeItsPart", "TestS6ForwardAndRelayThroughMailsCode", "TestT3S6TooLargeForTheNonChunkingDomainAlone"} {
		if !slices.Contains(s6, name) {
			t.Errorf("S6's item lacks %s", name)
		}
	}
	dane := gateRowNamesForTest(find("DANE-only MXs reached and unauthenticated ones refused"))
	for _, name := range []string{"TestSmtpDaneOnlyMxIsReached", "TestSmtpTlsReachesTl1ByDane", "TestS6NoUnauthenticatedMx", "TestT3S6NoUnauthenticatedMx"} {
		if !slices.Contains(dane, name) {
			t.Errorf("the DANE item lacks %s", name)
		}
	}
	joins := gateRowNamesForTest(find("halt, ARF and RUA joins"))
	for _, name := range []string{"TestAttributionHighJoin", "TestReportIntakeArfFromAnAllowlistedLoopIsAComplaint", "TestSmtpSenderHaltReachesTheNextSendWithinAReload", "TestAbuseMailRuaOpensACaseWithNoHalt", "TestSmtpReconcileOpensACaseOverTwentyOnePercentAndFive"} {
		if !slices.Contains(joins, name) {
			t.Errorf("the joins item lacks %s", name)
		}
	}
	find("§14's privacy rows")
	find("the schema guard at M9")
	find("the preamble on its inline path and the CROSSSLOT lint")
	find("S10's records")
	if count := len(gateSweep("M9").Items); count != len(items) {
		t.Errorf("M9's sweeps add %d items, the file %d", count, len(items))
	}
}

// M9's entry review reads the assembly check, its design closure, SPEC.md's specification with the review that freezes
// it, and HE's lead time, and runs no row.
func TestGateM9InReadsItsClosureAndSpecFreeze(t *testing.T) {
	rows := GateRows(DefaultCatalog(), "M9-in")
	if len(rows) != 4 {
		t.Fatalf("M9-in holds %d rows", len(rows))
	}
	if rows[0].Item != gateAssemblyItem.Item {
		t.Errorf("M9-in's first row: %+v", rows[0])
	}
	closure := rows[1]
	if !strings.HasPrefix(closure.Item, "§23.6's M9 design closure") || !strings.HasPrefix(closure.External, "people") || 0 < len(closure.Tests) {
		t.Errorf("M9-in's closure: %+v", closure)
	}
	for _, part := range []string{"SMTP server-state relation", "22.10's M9 evidence", "send-capability and result model"} {
		if !strings.Contains(closure.Item, part) {
			t.Errorf("M9-in's closure lacks %q, which §23.6's M9 row names", part)
		}
	}
	spec := rows[2]
	if !strings.HasPrefix(spec.Item, "smtpproof/SPEC.md's specification freeze") || !strings.HasPrefix(spec.External, "people") ||
		!slices.Equal(gateRowNamesForTest(spec), []string{"TestSpecNamesEveryCheck", "TestSpecHeaderRecordsOutlastEveryLiteral"}) {
		t.Errorf("M9-in's specification: %+v", spec)
	}
	if he := rows[3]; !strings.HasPrefix(he.Item, "HE's TCP 25 egress") || !strings.HasPrefix(he.External, "people") || 0 < len(he.Tests) {
		t.Errorf("M9-in's lead time: %+v", he)
	}
}

// Every test M9's entry and exit name in this repo, smtpproof's module among them, is declared in its package in a
// file that builds under the entry's tags, and so is each the sdk names, in the sdk's checkout beside this one, so a
// rename or a tag an owner adds fails here rather than only reading missing at the gate.
func TestGateM9SweepsNameSidecarAndSdkTestsDeclaredUnderTheirTags(t *testing.T) {
	catalog := DefaultCatalog()
	declared := gateDeclaredBesideThisCheckout(t)
	checked := 0
	sdkNames := 0
	for _, gate := range []string{"M9-in", "M9"} {
		rows := GateRows(catalog, gate)
		for _, name := range gateUndeclaredSidecarTestsForTest(t, catalog, rows) {
			t.Errorf("%s names %s, which is not declared so", gate, name)
		}
		for _, row := range rows {
			for _, test := range row.Tests {
				switch test.Repo {
				case "sidecar":
					checked += len(test.Names)
				case "sdk":
					for _, err := range declared(test) {
						t.Error(err)
					}
					sdkNames += len(test.Names)
				}
			}
		}
	}
	if checked < 100 || sdkNames < 3 {
		t.Errorf("M9's sweeps name %d tests in this repo and %d in the sdk", checked, sdkNames)
	}
}
