// M2's entry review (TEST-M2-18; §22.10's left column for M2, §23.8's Gn-in, §23.6's M2 row; D-TEST-9, D-PHASE-7,
// R-TEST-6): what freezes the specifications of §7.9's records, format 1, credential 0xF552, suite 0x0010 and
// D-KEYS-10's delivery wire, each item with what shows it, so `sidecar-gate M2-in` reports each pass, fail, missing
// or open:
//
//   - EvsCommit.tla and StoreSettle.tla passing TLC at their bounds: TEST-M2-08's tests in gate mode, which let a
//     model's recorded runs stand while nothing it keeps has changed. The report runs no TLC itself, since a model at
//     its bounds takes hours; test.sh's gate cadence runs the model phase first. Where the runs do not stand the item
//     reads open and says TLC has not run, never pass: the specifications freeze here, and a model TLC has not checked
//     holds nothing.
//   - the FS rows written as tests against the fakes: one item per case §23.6 holds at M2's exit. A case counts as
//     written only if it is registered and its builder builds a schedule that has steps and checks something, its
//     twin too where it refuses or is forged. An empty builder fails, and a case no builder covers reads missing,
//     whatever tests of it exist outside the registry, since no gate can find those.
//   - the vector schemas fixed: each M2 format's vector files and the tests that hold the code to them.
//   - format 2's reserved numbers and format 1's refusal vectors, D-PHASE-9's list, which gains acl.proto's
//     RepoPrefixRules (SignedType 0x1111) and AclRepo.prefix_rules (DESIGN-DETAILS 16.8's line for D-PHASE-9;
//     QD-212). The client-checked prefix rules moved to Later (QD-1032), so the numbers stay reserved and launch holds
//     the rules dark: every log refuses a RepoPrefixRules at its position and folds no set, which the item's tests
//     show, and the rules' own tests, run with the switch on, are no longer what the gate expects.
//   - people's work: peer review of the schemas and state machines, RECORD.md's review (owner decision 25), §23.6's
//     design closure and §23.8's review of the changes since G0 and of §22's exit-test plan. Each reads open.
//
// No item here is an external audit: none gates a freeze or the claim (R-TEST-6; owner decisions 99, 119).
//
// An item that is no go test is a command whose last line says its outcome, as server's gate tool reads it
// (GateOutcomeLinePrefix): the written check and the TLC check run as tests of this package, under a flag of
// gate_m2_in_test.go that only the command passes.

package fault

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The outcomes server's gate tool reports, and what a command prints on its last line to report one other than its
// exit status gives (server/local/sidecar-gate's gateOutcomeLinePrefix).
const (
	GateOutcomePass    = "pass"
	GateOutcomeFail    = "fail"
	GateOutcomeMissing = "missing"
	GateOutcomeOpen    = "open"

	GateOutcomeLinePrefix = "sidecar-gate outcome: "
)

// The catalog's gate whose cases M2's entry review must find written: M2's exit (§22.10's right column names the
// same schedules as 23.6's).
const gateM2InRowsGate = "M2-out"

// The flags gate_m2_in_test.go reads, which only a gate's command passes: a case's written check, and the TLC check.
const (
	GateWrittenFlag = "fault.gate-written"
	GateTlcFlag     = "fault.gate-tlc"
)

// TEST-M2-08's tests of the two M2 models, each mode a gate needs passing at a model's sources (model, mutants,
// live), which M2's entry runs in gate mode with no TLC, so each passes only on runs modelled.yml records.
var gateM2InTlcTests = []string{
	"TestEvsCommitPassesTlcAtItsBounds",
	"TestEvsCommitMutantsFailTlc",
	"TestEvsCommitLivenessHolds",
	"TestStoreSettlePassesTlcAtItsBounds",
	"TestStoreSettleMutantsFailTlc",
	"TestStoreSettleLivenessHolds",
}

// What TEST-M2-08's gate mode says when a model's runs do not stand and no TLC is there to run them.
const gateTlcNotRunText = "TLC has not run"

// The command a case's written check runs in the sidecar repo: this package's test under the hooks, as T2 runs it.
func gateWrittenCommand(testCase *Case) []string {
	argument := testCase.Row.Id
	if testCase.Name != "" {
		argument += "/" + testCase.Name
	}
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateM2InRowWritten$", "./sidecartest/fault", "-" + GateWrittenFlag + "=" + argument}
}

// The command M2-in's TLC item runs in the sidecar repo.
func gateTlcCommand() []string {
	return []string{"go", "test", "-count=1", "-v", "-tags", "sidecar_testhooks", "-run", "^TestGateM2InModelsPassTlc$", "./sidecartest/fault", "-" + GateTlcFlag}
}

// The case a written check's flag names, <row> or <row>/<case>, which must be one M2's exit holds.
func GateWrittenCase(catalog *Catalog, argument string) (*Case, error) {
	rowId, caseName, _ := strings.Cut(argument, "/")
	testCase := catalog.Case(rowId, caseName)
	if testCase == nil {
		return nil, fmt.Errorf("%q names no case catalog.yml holds", argument)
	}
	if !testCase.AtGate(gateM2InRowsGate) {
		return nil, fmt.Errorf("%s is not a case M2's exit holds, so M2's entry does not look for it", testCase)
	}
	return testCase, nil
}

// The items people sign at M2's entry, none of which a test shows.
func gateM2InPeopleItems() []*GateItem {
	return []*GateItem{
		{
			Item:     "peer review of the schemas and state machines of §7.9's records, format 1 (§11.5 to §11.8 included), credential 0xF552, suite 0x0010 and D-KEYS-10's delivery wire, by their owning sections (§22.10's M2 entry)",
			External: "people: the owning sections' reviewers read and sign the schemas and state machines (owner decision 99: no external review stands in)",
		},
		{
			Item:     "RECORD.md reviewed (§22.10's M2 entry; owner decision 25; §23.8's G0 row: here or by M2's entry)",
			External: "people: a reviewer reads RECORD.md and signs it",
		},
		{
			Item: "§23.6's M2 design closure: the head object and its pins; generation serialization; the delta-prefix commitment; the recovery veto; ref witnesses; path epochs; the git model with git-mode tip CAS; placement; the config leaf rule; IndexerSet; the ephemeral ceiling; deposit-only principals and the depositor rule; shred and restore; staged versions; orphans; the path-directory bound; " +
				"format 2's reserved numbers and format 1's refusal of them; the directory kind, autogroup:dst-owner and EvsShare.expires; refusal records; the write budget's accounts, wallet and P0 reports; the store's deadline and settle rules; Delegation key drops and ends; key deliveries' identity and authority, ReaderKey validity and gkm's route scopes; the presence countersignature; usage batches, relayed reservations, quota maintenance; Q-CTX-4, Q-KEYS-11, Q-EVS-6, Q-OPS-2, Q-EVS-24",
			External: "people: the Gn-in review reads and signs the closure (§23.8)",
		},
		{
			Item:     "the changes since G0 and §22's exit-test plan for M2 reviewed (§23.8's Gn-in)",
			External: "people: the Gn-in review reads them",
		},
	}
}

// Every item of M2's entry review in §22.10's order, the people's first, each FS case of M2's exit its own item.
func gateM2InItems(catalog *Catalog) []*GateItem {
	people := gateM2InPeopleItems()
	items := []*GateItem{people[0]}
	items = append(items, &GateItem{
		Item:     "EvsCommit.tla and StoreSettle.tla passing TLC at their bounds, their mutants refused and their liveness held, by the runs sidecartest/model/modelled.yml records at these sources (§22.10's M2 entry; D-PHASE-7; TEST-M2-08, EVS1-M2-02); where none stands, open: this report runs no TLC itself",
		Commands: []*GateCommand{{Repo: "sidecar", Command: gateTlcCommand()}},
	})
	for _, testCase := range catalog.GateCases(gateM2InRowsGate) {
		items = append(items, &GateItem{
			Item:     testCase.String() + " written as a test against the fakes (§22.10's M2 entry)",
			Commands: []*GateCommand{{Repo: "sidecar", Command: gateWrittenCommand(testCase)}},
		})
	}
	items = append(items,
		&GateItem{
			Item: "the vector schemas fixed: the vector files of §7.9's records, format 1, credential 0xF552, suite 0x0010 and the delivery wire, with the tests that hold the code to them byte for byte (§22.10's M2 entry)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestEvsChainVectors", "TestEvsDigestVectors", "TestEvsTokenVectors", "TestEvsBatchVectors", "TestEvsWindowVectors",
					"TestEvsPushVectors", "TestEvsRecordVectors", "TestEvsSegmentVectors", "TestGkmLadderVectors", "TestGkmWrapAadVectors",
					"TestGkmWrapPathVectors", "TestAuthChainVectors", "TestMlsCryptoBasicsVectors", "TestMlsInteropTranscripts",
				}},
				{Repo: "sidecar", Package: "./protocol/bridge", Names: []string{"TestSignedVectorsAreByteEqual", "TestAuthEntryVectorsAreByteEqual", "TestAuthChainDigestFollowsTheVectors"}},
			},
		},
		people[1],
		&GateItem{
			Item: "format 2's reserved numbers and format 1's refusal vectors (§22.10's M2 entry; D-PHASE-9; owner decision 163): EvsPush's flags 256 and 512 and fields 33 and 34, EvsHead's index_epoch, window bit 5, the read states drop_pending and dropped, and every number testdata/evs/reserved_numbers.yml holds; " +
				"the directory's kind, acl.proto's autogroup:dst-owner atom, EvsShare.expires and config.proto's ServiceSettings.directory",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./protocol", Names: []string{"TestEvsReservesOnlyTheListedNumbers", "TestEvsDeclaresTheListedFields", "TestEvsDeclaresTheListedValues", "TestEvsListHoldsTheDecidedReservations", "TestPhaseReservations"}},
				{Repo: "sidecar", Package: "./sidecartest", Names: []string{
					"TestEvsFormat2ConstructsRefusedAtAFormat1Evs", "TestEvsFormat2ConstructsAtAFormat1Reader", "TestEvsFormat1EvsServesAFormat2RepoAndTakesNoPush",
					"TestEvsFormat2WritesRefusedAtAFormat1Writer", "TestEvsFormat2BatchLeftByAFormat1Evacuator", "TestEvsSlotRuleRefusedAtAFormat1Evs",
					"TestEvsFormat2RefusalVectorsCoverTheReservations",
				}},
			},
		},
		&GateItem{
			Item: "acl.proto's RepoPrefixRules (SignedType 0x1111) and AclRepo.prefix_rules reserved, their numbers kept while the client-checked prefix rules wait for Later (QD-1032): at launch every log refuses a RepoPrefixRules at its position and folds no set, a base's tail included (DESIGN-DETAILS 16.8's line for D-PHASE-9; QD-212; ACL-M2-18)",
			Tests: []*GateTest{
				{Repo: "sidecar", Package: "./protocol", Names: []string{"TestPhaseReservations"}},
				{Repo: "sidecar", Package: "./protocol/bridge", Names: []string{"TestSignedTypeNumbersStable"}},
				{Repo: "sidecar", Package: ".", Names: []string{
					"TestAclPrefixRulesAreDarkInTheLaunchSettings", "TestConfigLogRefusesRepoPrefixRulesAtLaunch", "TestConfigLogFoldsNoSetFromABasesTailAtLaunch",
				}},
			},
		},
	)
	return append(items, people[2], people[3])
}

var gateM2InSweep = RegisterGateSweep(&GateSweep{Gate: "M2-in", Items: gateM2InItems(DefaultCatalog())})

// What a case's written check found: its outcome as the gate tool reads it, and why, in a line that names no secret.
type GateWrittenResult struct {
	Case *Case
	// The tier the case was looked up on: T2, or T3 for a case that runs on T3 alone.
	Tier    Tier
	Outcome string
	Reason  string
}

// The lines a written check's command prints last: the reason, then the outcome, as the gate tool reads them.
func (self *GateWrittenResult) Lines() string {
	return self.Reason + "\n" + GateOutcomeLinePrefix + self.Outcome + "\n"
}

// What the written check builds a case's schedule on.
type GateWrittenSettings struct {
	// The Net each builder and twin is built on, a fresh one each: T2's, as a case's T2 test runs it.
	Net *sidecartest.NetSettings
}

func DefaultGateWrittenSettings() *GateWrittenSettings {
	return &GateWrittenSettings{Net: DefaultRuleSettings().Net}
}

// Whether testCase is written as a test against the fakes (§22.10's M2 entry): registered on T2, or on T3 for a case
// that runs on T3 alone, and its builder building a schedule that has steps and names an invariant to check, a
// refusing or forged schedule's twin too. Each builder is built on a fresh Net and none is run: whether it passes is
// M2's exit sweep's, and a builder that panics fails here. A case that waits on production, hardware or people reads
// open, as fault.Missing leaves it out. lookup is fault.Lookup but in a fixture; settings nil takes the defaults.
func GateWritten(ctx context.Context, testCase *Case, lookup func(rowId string, caseName string, tier Tier) *Registration, settings *GateWrittenSettings) *GateWrittenResult {
	if settings == nil {
		settings = DefaultGateWrittenSettings()
	}
	result := &GateWrittenResult{Case: testCase, Tier: TierT2}
	if testCase.Open != "" {
		result.Outcome = GateOutcomeOpen
		result.Reason = fmt.Sprintf("%s waits on %s, as catalog.yml marks it: no builder shows it", testCase, testCase.Open)
		return result
	}
	if !slices.Contains(testCase.Tiers(), TierT2) {
		result.Tier = testCase.Tiers()[0]
	}
	registration := lookup(testCase.Row.Id, testCase.Name, result.Tier)
	if registration == nil {
		result.Outcome = GateOutcomeMissing
		result.Reason = fmt.Sprintf("%s: no %s builder is registered (fault.Register), so no gate can find a schedule of it; a test of it the registry does not hold is no written row", testCase, result.Tier)
		if result.Tier != TierT2 {
			result.Reason += fmt.Sprintf(", and the case runs on %s alone", result.Tier)
		}
		return result
	}

	schedule, err := gateBuildSchedule(ctx, registration.Build, settings)
	if err == nil {
		err = gateScheduleWritten(schedule)
	}
	if err == nil && testCase.Forged() && schedule.Twin == nil {
		err = errors.New("the case is forged, and its schedule names no twin, which carries T3 (§22.8's cadence rule)")
	}
	var twin *Schedule
	if err == nil && schedule.Twin != nil {
		twin, err = gateBuildSchedule(ctx, twinBuilder(schedule), settings)
		if err == nil && twin.Refuses != "" {
			err = fmt.Errorf("it expects %s refused, and a twin is what must succeed", twin.Refuses)
		}
		if err == nil {
			err = gateScheduleWritten(twin)
		}
		if err != nil {
			err = fmt.Errorf("its twin: %w", err)
		}
	}
	if err != nil {
		result.Outcome = GateOutcomeFail
		result.Reason = fmt.Sprintf("%s's %s builder: %v", testCase, result.Tier, err)
		return result
	}

	checked := []string{}
	for _, invariant := range schedule.Check {
		checked = append(checked, invariant.Id())
	}
	result.Outcome = GateOutcomePass
	result.Reason = fmt.Sprintf("%s: written on %s, its schedule %d steps checking %s", testCase, result.Tier, len(schedule.Steps), strings.Join(checked, ", "))
	if twin != nil {
		result.Reason += fmt.Sprintf(", its twin %d steps", len(twin.Steps))
	}
	// what the row's checks name that the schedule's Check does not, by id: the exit sweep's to answer, said here
	unnamed := []string{}
	for _, check := range testCase.Row.Checks {
		id := check
		if match := catalogInvariantCheckPattern.FindStringSubmatch(check); match != nil {
			id = "FI-" + match[1]
		}
		if !slices.Contains(checked, id) && !slices.Contains(unnamed, id) {
			unnamed = append(unnamed, id)
		}
	}
	if 0 < len(unnamed) {
		result.Reason += fmt.Sprintf("; of the row's checks it names no %s by id, which M2's exit sweep reads", strings.Join(unnamed, ", "))
	}
	return result
}

// Builds a schedule on a fresh Net, which it closes: a builder's panic is its error.
func gateBuildSchedule(ctx context.Context, builder Builder, settings *GateWrittenSettings) (schedule *Schedule, err error) {
	net := sidecartest.NewNet(ctx, settings.Net)
	defer net.Close()
	defer func() {
		if recovered := recover(); recovered != nil {
			schedule = nil
			err = fmt.Errorf("it panicked building on T2's Net: %v", recovered)
		}
	}()
	schedule = builder(net)
	if schedule == nil {
		return nil, errors.New("it built no schedule")
	}
	return schedule, nil
}

// Whether a built schedule is written: it steps, every step does something, it checks something, and a refusal
// names the twin that must succeed beside it.
func gateScheduleWritten(schedule *Schedule) error {
	if len(schedule.Steps) == 0 {
		return errors.New("an empty builder: its schedule has no step")
	}
	for index, step := range schedule.Steps {
		if step == nil {
			return fmt.Errorf("its step %d is nil", index)
		}
	}
	if len(schedule.Check) == 0 {
		return errors.New("its schedule checks nothing: it names no invariant (the contract's rule 4)")
	}
	for index, invariant := range schedule.Check {
		if invariant == nil {
			return fmt.Errorf("its check %d is nil", index)
		}
	}
	if schedule.Refuses != "" && schedule.Twin == nil {
		return fmt.Errorf("it expects %s refused and names no twin that must succeed (§22.8's twins)", schedule.Refuses)
	}
	return nil
}

// go test -v's verdict line for a test, and the line that starts a test's output.
var (
	gateTestVerdictPattern = regexp.MustCompile(`(?m)^\s*--- (PASS|FAIL|SKIP): (\S+)`)
	gateTestRunPattern     = regexp.MustCompile(`^=== (?:RUN|CONT|NAME)\s+(\S+)`)
)

// What M2-in's TLC item reports from TEST-M2-08's tests, named in names and run in gate mode with no TLC, by their go
// test -v output and whether that run failed: pass when each passed, its recorded runs standing; open, saying so, when
// any failed only because TLC has not run at the model's sources, since this report runs none; fail for any other
// failure, or for a test that gave no verdict.
func GateTlcOutcome(output []byte, runErr error, names []string) (string, string) {
	text := string(output)
	verdicts := map[string]string{}
	for _, match := range gateTestVerdictPattern.FindAllStringSubmatch(text, -1) {
		verdicts[match[2]] = match[1]
	}
	// each top-level test's own lines, so a failure's reason is read from its own output
	testLines := map[string][]string{}
	current := ""
	for _, line := range strings.Split(text, "\n") {
		if match := gateTestRunPattern.FindStringSubmatch(line); match != nil {
			current, _, _ = strings.Cut(match[1], "/")
			continue
		}
		if current != "" {
			testLines[current] = append(testLines[current], strings.TrimSpace(line))
		}
	}
	failed := []string{}
	notRun := []string{}
	skipped := []string{}
	passed := []string{}
	for _, name := range names {
		switch verdicts[name] {
		case "PASS":
			passed = append(passed, name)
		case "SKIP":
			skipped = append(skipped, name)
		case "FAIL":
			ownText := strings.Join(testLines[name], " ")
			if strings.Contains(ownText, gateTlcNotRunText) {
				notRun = append(notRun, name)
			} else {
				failed = append(failed, name)
			}
		default:
			failed = append(failed, name)
		}
	}
	switch {
	case 0 < len(failed):
		reason := fmt.Sprintf("TLC's check failed or gave no verdict: %s", strings.Join(failed, ", "))
		if runErr != nil && len(verdicts) == 0 {
			reason = fmt.Sprintf("the model tests did not build or run (%v): %s", runErr, gateLastLines(text, 3))
		}
		return GateOutcomeFail, reason
	case 0 < len(notRun) || 0 < len(skipped):
		reason := fmt.Sprintf("TLC has not run at these sources for %s: no passing runs of every mode stand in modelled.yml, and this report runs no TLC itself; test.sh's gate cadence runs the model phase, whose passing runs, once recorded, stand here", strings.Join(append(notRun, skipped...), ", "))
		return GateOutcomeOpen, reason
	}
	return GateOutcomePass, fmt.Sprintf("the recorded runs stand at these sources: %s", strings.Join(passed, ", "))
}

// The last lines of a command's output, joined, for a reason.
func gateLastLines(output string, count int) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if count < len(lines) {
		lines = lines[len(lines)-count:]
	}
	return strings.Join(lines, " / ")
}
