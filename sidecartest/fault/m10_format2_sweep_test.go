//go:build sidecar_testhooks

// M10's format-2 schedules swept on their tiers (EVS2-M10-35; §23.6's M10 row for §11's format 2, §22.10's final
// freeze of format 2, §22.8's rules; D-OPS-21, D-TEST-13, R-TEST-11): every case catalog.yml holds at M10's exit for
// FS-64 to FS-73, FS-89 to FS-96 and FS-114's purge and drop cases, each run on T2 under its row's rules or said to be
// missing or open, in one report, and the list of what M10's Gn-out runs for them. Like EVS1-M2-39 for format 1, this
// is the area's last task: each row is split across tasks (EVS2.md's table of which task closes which clause), so a
// clause nobody finished surfaces here, and a clause that fails is fixed in the code of the task that owns it, never
// by editing a schedule.
//
//	cases       m10Format2SweepCases: each case with the clauses its tests run beside its registered schedule, the
//	            T3 tests of a case that is no builder, the tests that hold parts of it without being a schedule run
//	            under its row's rules, what the registered schedules leave out, and what it waits on outside this
//	            build. TestM10Format2SweepNamesEveryCase holds the list to the catalog, and the tests it names to
//	            what is declared
//	T2          TestM10Format2SweepOnT2 runs every case registered on T2, and each clause the list names, under
//	            every rule §22.8 gives its row (CheckRow, CheckClause): the fixed schedule, its twin, the explorer's
//	            10 seeds over both, every write's lost answer for a row on the unknown list and each committed
//	            trace. It logs the report, each case run, missing or open on each tier its row names. Missing is no
//	            builder registered: a gate reads such a case missing, never pass, whatever clause tests of it exist
//	invariants  TestM10Format2SweepSchedulesCheckTheirRowsInvariants: every schedule the sweep runs, and each twin,
//	            checks each FI its row names after every step, where that FI's oracle is bound. An unbound one fails
//	            closed in any schedule that names it (FI-13's, QUOTA-M2-13's), so the report names it instead
//	gate list   TestM10Format2SweepGateList: what M10's Gn-out runs for each case, where each of its tests is
//	            declared in sidecar and in server's checkout beside this one, beside what gates.yml names today, and
//	            the gate's items for format 2 (§22.10's right column) with their tests. A sidecar test the list
//	            names that nothing declares fails here; a server one is reported, so a rename in server never fails
//	            sidecar's tip
//
// Which case is registered is read from the registry when the sweep runs, so a schedule registered later turns its
// case from missing to run with no edit here, as ABUSE-M10-01's hold cases of FS-66, FS-69 and FS-92 did, and a case's
// lines for when nothing is registered print only while that holds. server's evshost/m10_format2_sweep_test.go
// is the T3 half: the registered cases and the clauses beside them on T3's Nets, at a merge's seeds.
//
// The registry and the gate's rows are this package's, so this is an internal test of it.

package fault

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The catalog's name for M10's exit, and the gate tool's.
const (
	m10Format2CatalogGate = "M10-out"
	m10Format2ToolGate    = "M10"
)

// The rows of §23.6's M10 row that are format 2's evs: FS-64 to FS-73, FS-89 to FS-96, and FS-114, whose purge and
// drop cases are M10's. The index's rows (FS-74 to FS-81, FS-83, FS-107 to FS-112) are SEARCH's.
func m10Format2RowIds() []string {
	return []string{
		"FS-64", "FS-65", "FS-66", "FS-67", "FS-68", "FS-69", "FS-70", "FS-71", "FS-72", "FS-73",
		"FS-89", "FS-90", "FS-91", "FS-92", "FS-93", "FS-94", "FS-95", "FS-96", "FS-114",
	}
}

// Every case catalog.yml holds at M10's exit for the sweep's rows, in row order: the cases the sweep must name.
func m10Format2CatalogCases(catalog *Catalog) []*Case {
	cases := []*Case{}
	for _, testCase := range catalog.GateCases(m10Format2CatalogGate) {
		if slices.Contains(m10Format2RowIds(), testCase.Row.Id) {
			cases = append(cases, testCase)
		}
	}
	return cases
}

// A clause beside a row's registered case, run under the row's rules by the name the row's own tests give it, so its
// explorer's traces are the ones those tests write and replay.
type m10Format2Clause struct {
	name  string
	build Builder
}

// One case of the sweep: a case catalog.yml holds at M10's exit, what runs it, and what it waits on.
type m10Format2Case struct {
	rowId    string
	caseName string
	// Run beside the registered case, on each tier it is registered on.
	clauses []*m10Format2Clause
	// The T3 tests of a case that is no builder, where they run.
	t3Tests []*GateTest
	// Tests of the sidecar repo that hold parts of the case without being a schedule run under its row's rules.
	heldByTests []*GateTest
	// What holds the case while no builder is registered for it, and who owns its schedule: printed only then.
	unscheduledNote string
	// The row's clauses its registered schedules leave out, each with the task that owns it, as that task's report
	// states them.
	missingClauses []string
	// What outside this build the case waits on.
	openNotes []string
}

// A sidecar package's tests that hold part of a case, built as the sweep is, with the hooks.
func m10Format2Held(packagePath string, names ...string) *GateTest {
	return &GateTest{Repo: "sidecar", Package: packagePath, Tags: "sidecar_testhooks", Names: names}
}

// What the later of M5-out and M10-out runs on: the hold cases (§23.6).
const m10Format2HoldOpen = "a hold case, due at the later of M5-out and M10-out (§23.6): on T2 it runs on fixture holds " +
	"(sidecartest.PlaceHold, and ABUSE-M10-01's FixtureHoldApi, which writes api's bytes on api's deadlines), on T3 against " +
	"api's real hold/ writes (server's model), and holds in production wait on counsel's confirmation of owner decision 133"

// What every drop and purge clause waits on at T3 while T3's clusters have not declared settle.
const m10Format2SettleNote = "on T3 the local stack's clusters name no settle_passed_build, so a drop job holds at its " +
	"wait for settle and a purge sweep deletes nothing (fsDropSettled): the deletes, and what readers see after them, run " +
	"on T2 alone until T3's tier declares its clusters settled (FS-114)"

// Every case of the sweep, in the catalog's order. The text is what the owning tasks' reports state at this commit.
func m10Format2SweepCases() []*m10Format2Case {
	fs114T3 := &GateTest{Repo: "server", Package: ".", Tags: "sidecar_filecluster_t3", Names: []string{"TestFileClusterSuitePassesOnT3"}}
	return []*m10Format2Case{
		{
			rowId: "FS-64",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestPurgerDeletesAfterTheAllowance", "TestReadAnswersCollectedFromTheMinuteRule", "TestCheckCitationOverStep4sReads"),
				m10Format2Held(".", "TestEvsReadHeadRereadsAVersionlessFileReplacedMidRead", "TestEvsReadHeadChecksContentSha256"),
				m10Format2Held("./sidecartest", "TestEvsWriteVersioningOffAndOnEndToEnd"),
				m10Format2Held("./sidecartest/fault", "TestFi16TakesAPurgeAfterTheAllowance"),
			},
			unscheduledNote: "EVSB-M10-01's schedule (sidecartest/fault/fs64_test.go), deferred while EVS2-M10-06's versionless " +
				"commit path was unbuilt; that path has landed and the schedule has not, so the row's readers paused across the " +
				"purge, the cached head a failed cache write left, the re-upload refused 409 VERSIONING and the slot-keyed clauses " +
				"checked at the seal run as the tests below, never as one schedule under FI-1, FI-16 and FI-17 after every step",
		},
		{
			rowId: "FS-65",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestPushPurgeHandsACertainCommitsListOnce", "TestPurgerUnsureClockDeletesNothing", "TestPurgerObserveCountsItsKeptIds", "TestPurgerDrainsDueItems"),
				m10Format2Held("./sidecartest/fault", "TestFi16CatchesAPurgeOnAnUnknownOutcome", "TestFi16CatchesAPurgeOfARefusedPushsCandidate"),
			},
			unscheduledNote: "EVSB-M10-01's schedule (sidecartest/fault/fs65_test.go), deferred with FS-64's: the row is on " +
				"§22.8's unknown list, and no run of it loses every write's answer; evs1 killed at the certainty and after half " +
				"its DELETEs, and a DELETE delayed to the request deadline, run only as the purger's own tests",
		},
		{
			rowId: "FS-66",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestEvacuationWritesAStagedSegmentStillNewest", "TestEvacuationDropsAStagedSegmentReplacedEarlier", "TestReadServesAStagedSegmentFromItsPushRecord", "TestReadFindsAStagedSegmentAtSegAfterEvacuation", "TestReadServesNoStagedContentOfACollectedVersion"),
			},
			unscheduledNote: "EVSB-M10-02's schedule (sidecartest/fault/fs66_test.go), deferred while EVS2-M10-06's path was " +
				"unbuilt; evacuation killed between the seg/ PUT and the batch DELETE, a dead push's staged record and a " +
				"replacing push pending at evacuation run as no schedule",
		},
		{
			rowId:    "FS-66",
			caseName: "hold",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestEvacuationWritesStagedContentAHoldKeeps"),
			},
			unscheduledNote: "ABUSE-M10-01's schedule, against api's hold/ writes; with none registered, evacuation's hold keep " +
				"runs as the test below",
			openNotes: []string{m10Format2HoldOpen},
		},
		{
			rowId: "FS-67",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestFormat2RemovalFoldCarriesAnUnlistedVersionlessFilesIds", "TestFormat2RefDeleteCarriesAnUnlistedVersionlessFilesIds", "TestFormat2PathWrittenBelowTheRemovedDirectoryKeepsItsOwnContent"),
				m10Format2Held("./sidecartest", "TestEvsWriteRemovalListsVersionlessFilesBelowEndToEnd"),
			},
			unscheduledNote: "no task names its schedule: EVSB-M10-01 lists its listed clauses and EVSB-M10-02 its marker " +
				"clauses, each as tests, and neither a file; the orphan markers under _o/ killed after their PUT and rerun, and " +
				"a removal racing a write of a listed file, run as no schedule",
		},
		{
			rowId: "FS-68",
			clauses: []*m10Format2Clause{
				{name: "rules", build: Fs68Rules},
				{name: "platform rule", build: Fs68PlatformRule},
				{name: "config", build: Fs68Kind(protocol.RepoKind_REPO_KIND_CONFIG)},
				{name: "mailcfg", build: Fs68Kind(protocol.RepoKind_REPO_KIND_MAILCFG)},
				{name: "lock", build: Fs68LockedPastTheWindow},
			},
			missingClauses: []string{
				"git-mode and creates-only refs never taking versioning off (EVS2-M10-31)",
				"the index's own files committing under a lock, owner decision 168, whose root no world names yet (EVS2-M10-31)",
				"the lock's signer rule, §8.8's, which the world files as a row (EVS2-M10-31)",
				"an admin's VersioningRules edit reaching every repo of a network: a world holds one repo (EVS2-M10-31)",
				"the platform rule at 64 MiB: the world runs it at 64 KiB, and sidecar's TestVersioningRulesFirstMatchAndThePlatformRule holds the 64 MiB (EVS2-M10-31)",
			},
		},
		{
			rowId: "FS-69",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestPurgerHoldKeepsWhatExistedAtItsPlacement", "TestPurgerHoldPlacedAfterTheCertaintyStopsLaterDeletes", "TestSweepKeepsWhatAHoldKeeps", "TestEvsSweepHoldEndDeletesWhatTheHoldKept"),
				m10Format2Held(".", "TestHoldCoverKeepsWhatExistedAtPlacement"),
			},
			unscheduledNote: "ABUSE-M10-01's schedule, against api's hold/ writes (EVSB-M10-01 deferred its fs69_test.go); with " +
				"none registered, the purge's, the sweep's and the hold-end pass's hold rules run as the tests below",
			openNotes: []string{m10Format2HoldOpen},
		},
		{
			rowId: "FS-70",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestReseedFormat2FromAMirrorOfNewestVersionsOnly", "TestReseedFormat2RefusesAStaleMirrorsReplacedContent", "TestReseedFormat2MirrorEndingBeforeTheReplacement", "TestReseedFormat2StagedHeadsReuploadAsSegments"),
				m10Format2Held("./sidecartest", "TestEvsMirrorSyncingAsAPurgeLandsHoldsTheReplacementEndToEnd"),
			},
			unscheduledNote: "EVSB-M10-02's schedule (sidecartest/fault/fs70_test.go), deferred; the re-seed runs on evsservice's " +
				"in-process engine with the real client walk (EVS2-M10-13), never through a world after a site loss",
		},
		{
			rowId: "FS-71",
			heldByTests: []*GateTest{
				m10Format2Held("./evsservice", "TestPushPurgeAtTheStorageLimit"),
				m10Format2Held("./sidecartest/fault", "TestFs71QuotaFreesMoveTheStoredCountOnce", "TestFs71QuotaObserveCountsReplacedContentUntilDeletesTurnOn"),
			},
			unscheduledNote: "EVSB-M10-01's schedule (sidecartest/fault/fs71_test.go), deferred; QUOTA-M10-01's accounting " +
				"clauses run as the T2 tests below and server's quotahost on T3, and FI-13's oracle (QUOTA-M2-13) is unbound, so " +
				"no schedule could check FI-13c after every step",
		},
		{
			rowId:    "FS-72",
			caseName: "migration",
			clauses: []*m10Format2Clause{
				{name: "migration killed after step 6", build: Fs72MigrationKilledAt(evsservice.BarrierPushStep6After)},
				{name: "migration killed before the raise", build: Fs72MigrationKilledAt(evsservice.BarrierMigrateRaiseBefore)},
				{name: "migration killed after the raise", build: Fs72MigrationKilledAt(evsservice.BarrierMigrateRaiseAfter)},
				{name: "migration killed before the head CAS", build: Fs72MigrationKilledAt(evsservice.BarrierHeadCasBefore)},
				{name: "migration killed after the head CAS", build: Fs72MigrationKilledAt(evsservice.BarrierHeadCasAfter)},
			},
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFi16AndFi27ReadFs72sSchedulesClean"),
			},
			missingClauses: []string{
				"a repo set: each world holds one repo, so the migration of a format-1 repo set is one repo's (EVS2-M10-30)",
				"kill points past the five swept (EVS2-M10-30)",
			},
		},
		{
			rowId:    "FS-72",
			caseName: "rollback",
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFi16AndFi27ReadFs72sSchedulesClean"),
			},
			missingClauses: []string{
				"taskworker's own process: its evacuation runs stand in with the settings its loader reads (EVS2-M10-30)",
			},
		},
		{
			rowId: "FS-73",
			t3Tests: []*GateTest{
				{Repo: "server", Package: "./evshost", Tags: gateT3Tags, Stores: true, Names: []string{"TestFs73OnT3"}},
			},
			missingClauses: []string{
				"the purge following a prune, which needs T3's store clock through evacuation (EVS2-M10-29)",
				"git-remote-ur as cli's own binary: the world's helper is a test binary (EVS2-M10-29)",
				"the explorer's seeds: stock git's world needs a testing.TB, so FS-73 is no builder (QD-995)",
			},
			openNotes: []string{
				"§22.9's git-lfs rows beyond this host: git-lfs 3.0.2 and 3.4.1 with git 2.34 and 2.43, as Ubuntu 22.04 and 24.04 ship them, over ssh from a machine with no local ur",
			},
		},
		{
			rowId:   "FS-89",
			clauses: []*m10Format2Clause{{name: "now", build: Fs89Now}},
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFs89NowWaitsForTheHorizon", "TestFs89WindowPendingAndCancel"),
				m10Format2Held("./evsservice", "TestDropJobWaitsForTheStartDelay", "TestDropJobWaitsForTheHorizon", "TestDropJobRunsADropToDone"),
			},
			unscheduledNote: "no task names its schedule: EVSB-M10-03's job-side clauses (window, pending, cancel, --now at 25 h, " +
				"25 h 12 min and 26 h 12 min) are T2 tests over the drop table, and the row's push, read and export clauses (EVS2-M10-19 " +
				"to -23) each wait on the others; the path of 30 versions dropped end to end, export's stubs through git fsck, diff " +
				"and restore reporting dropped, and the twin whose hand-deleted live segment alarms run as no schedule",
			missingClauses: []string{
				"export's stubs through git fsck, and diff and restore reporting dropped: the world drives no export, diff or restore (EVS2-M10-19, -23)",
				"the head written again keeping its oid and mode: the schedule reads its content, and no world read gives a mode",
				"the twin whose live version's segment, deleted by hand, alarms as a missing segment",
				"--now's bounds to the minute (evacuation's horizon past seen_ms by 12 min, not_before_ms + 25 min) and a version uploaded 1 h before a --now drop kept until the horizon passes its upload by 24 h 2 min: fs89_test.go's TestFs89NowWaitsForTheHorizon holds them on the drop table, not through a world (EVSB-M10-03)",
			},
			openNotes: []string{m10Format2SettleNote},
		},
		{
			rowId: "FS-90",
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFs90KilledAndResumedByAnotherInstance", "TestFs90TwoInstancesRacingTheTake", "TestFs90AnUnsureClockStartsAndDeletesNothing", "TestFi27ReadsAHealthyDropJobClean"),
				m10Format2Held("./evsservice", "TestDropDeleteStaleDeleteIsRefusedPastItsDeadline", "TestDropJobRestartsAtTheHorizonAfterAKill"),
			},
			unscheduledNote: "EVSB-M10-06's clauses run as T2 tests over the real resolve, mark, verify and deletes, not under " +
				"§22.8's rules; the job killed at every barrier through the schedule harness and a stale DELETE held at a drive " +
				"barrier are deferred to the review phase (EVSB-M10-06), and FI-13's oracle is unbound",
		},
		{
			rowId: "FS-91",
			clauses: []*m10Format2Clause{
				{name: "within the window", build: Fs91ReleasedWithinTheWindow},
			},
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFs91WithinTheWindowIsHeldToTheWindow", "TestFs91WithinTheWindowIsHeldToAPushValidatedBeforeTheFence"),
			},
			missingClauses: []string{
				"(c) a cached head a failed cache write left before the DROP, and a creating head write held past 26 h (EVS2-M10-31, EVSB-M10-04)",
				"(d) a push in parts sealed after the drop: evsservice's TestPushDroppedRefusesASealAfterTheDrop holds the seal's refusal on the engine (EVS2-M10-31)",
				"(e) a re-upload adopting a young candidate's receipt, and past 23 h SEGMENT_STALE (EVS2-M10-31, EVSB-M10-05)",
				"(f) a git-mode push carrying a young candidate's bytes as a history segment (EVS2-M10-31, EVSB-M10-04)",
			},
			openNotes: []string{m10Format2SettleNote},
		},
		{
			rowId: "FS-92",
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFs92AHoldKeepsWhatTheDropWouldDeleteUntilItEnds", "TestFs92ASealedHoldsAnswersEqualANoHoldTwin"),
				m10Format2Held("./evsservice", "TestDropDeleteMovesTheRestToHeldUnderAHold", "TestDropJobWaitsOnAHold", "TestDropStateHeldReadsDone"),
			},
			unscheduledNote: "ABUSE-M10-01's schedule, against api's hold/ writes; with none registered, EVSB-M10-06's " +
				"job-side clauses run as T2 tests on fixture holds, and FI-13's oracle is unbound",
			openNotes: []string{m10Format2HoldOpen},
		},
		{
			rowId: "FS-93",
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFs93DroppingXKeepsWhatTheChainAndACopyName", "TestFs93FollowFreesWhatOnlyTheChainNames", "TestFs93ALineageThroughThreeEpochs", "TestFs93ARemovalBeforeACutOverMakesTwoLineages"),
			},
			unscheduledNote: "EVSB-M10-04's clauses run as T2 tests over the real job, not under §22.8's rules; no task names " +
				"the row's schedule",
		},
		{
			rowId:   "FS-94",
			clauses: []*m10Format2Clause{{name: "record class", build: Fs94RecordClass}},
			missingClauses: []string{
				"x.txt's marker collected and its epoch drained after its path's removal (EVS2-M10-31)",
				"its inline bytes unserved by push id, which no route of the world's client asks for (EVS2-M10-31)",
			},
			openNotes: []string{
				"compaction's stub runs in the registered case (Fs94CompactionKeeps), as RESOLUTIONS' plan-EVSB-fs94-compaction-clause #1 reads it (QD-296): a pure function that deletes nothing, compaction being Later (owner decision 247)",
				m10Format2SettleNote,
			},
		},
		{
			rowId: "FS-95",
			clauses: []*m10Format2Clause{
				{name: "locked", build: Fs95Locked},
				{name: "config", build: Fs95Kind(protocol.RepoKind_REPO_KIND_CONFIG)},
				{name: "mailcfg", build: Fs95Kind(protocol.RepoKind_REPO_KIND_MAILCFG)},
				{name: "owner-bound", build: Fs95OwnerBound},
				{name: "list missing a version", build: Fs95ListMismatch(false)},
				{name: "list adding a version", build: Fs95ListMismatch(true)},
			},
			missingClauses: []string{
				"git-mode and creates-only refs, 409 REF_MODE (EVS2-M10-31)",
				"ur/lfs's objects and the reserved names beyond .ur-index/, and a modified client's DROP there raising history_drop at readers (EVS2-M10-31)",
				"a written version whose oid differs, readers raising history_drop in state invalid (EVS2-M10-31)",
				"the owner's page Worker refused, and no MCP tool able to drop (EVS2-M10-31)",
				"a DROP past its 256 KiB body (400 INVALID) or its 1,048,576 listed values (409 DROP_LIST), and one in parts whose body is not whole in part 1 (EVS2-M10-31)",
				"a head-mode device's drop of a path with 5,000 versions refused locally (EVS2-M10-31)",
			},
			openNotes: []string{m10Format2SettleNote},
		},
		{
			rowId: "FS-96",
			heldByTests: []*GateTest{
				m10Format2Held("./sidecartest/fault", "TestFs96GitHistorySegmentsStayThroughADrop", "TestFs96StoredBytesFallByEachDeletedSegmentAndSlotsReportNothing", "TestFs96ObserveDeletesNothingAndRecordsItsDeleteSet", "TestFs96ResolveRunAgainWritesEqualListFiles"),
				m10Format2Held("./evsservice/dropverify", "TestVerifyAgreesWithAnHonestMark"),
			},
			unscheduledNote: "EVSB-M10-04's and -06's clauses run as T2 tests, not under §22.8's rules; the DROP's index " +
				"rewrites (SEARCH), mirrors applying and deleting local copies, a re-seed from a stale mirror, a drive's heal, an " +
				"ERASE meeting a slot the drop deleted, a versionless era inside the range and a kind-5-headed segment adopted as " +
				"kind 1 are no task's finished clause (EVSB-M10-06 defers them), and FI-13's oracle is unbound",
		},
		{
			rowId:    "FS-114",
			caseName: "purge",
			t3Tests:  []*GateTest{fs114T3},
			missingClauses: []string{
				"the purge DELETE with its coordinator killed and restarted, and a full heal after each case (EVSB-M10-08)",
			},
			openNotes: []string{
				"server's file-cluster suite runs fs114-purge-delete-one-host-held and fs114-purge-delete-two-hosts-held on local/file-cluster-t3's three clusters (EVSB-M10-08); the case on each real cluster, build and upgrade is §23.7's, before any purge deletes there (D-OPS-20)",
			},
		},
		{
			rowId:    "FS-114",
			caseName: "drop",
			t3Tests:  []*GateTest{fs114T3},
			missingClauses: []string{
				"the drop job's DELETE with its coordinator killed and restarted, and a full heal after each case (EVSB-M10-08)",
			},
			openNotes: []string{
				"server's file-cluster suite runs fs114-drop-delete-one-host-held and fs114-drop-delete-two-hosts-held on local/file-cluster-t3's three clusters (EVSB-M10-08); the case on each real cluster, build and upgrade is §23.7's, before any drop deletes there (D-OPS-20)",
			},
		},
	}
}

// FS-89's T2 tests by the gate's convention, for the schedule this task closes (fs89.go): the registered case and its
// --now clause under every rule §22.8 gives the row.
func TestFs89(t *testing.T) {
	RunRow(t, "FS-89", "", nil)
}

func TestFs89Now(t *testing.T) {
	RunClause(t, "FS-89", "now", Fs89Now, nil)
}

// The case catalog.yml holds for sweepCase, or nil.
func (self *m10Format2Case) catalogCase(catalog *Catalog) *Case {
	return catalog.Case(self.rowId, self.caseName)
}

// The case's report header: "FS-66's hold (§11; FI-6, FI-16; T2+T3; the later of M5-out and M10-out)".
func m10Format2Header(testCase *Case) string {
	sections := []string{}
	for _, section := range testCase.Row.Sections {
		sections = append(sections, "§"+strconv.Itoa(section))
	}
	tiers := []string{}
	for _, tier := range testCase.Tiers() {
		tiers = append(tiers, string(tier))
	}
	gates := strings.Join(testCase.Gates, " and ")
	if testCase.LaterOf {
		gates = "the later of " + gates
	}
	header := fmt.Sprintf("%s (%s; %s; %s; %s", testCase, strings.Join(sections, ", "), strings.Join(testCase.Row.Checks, ", "), strings.Join(tiers, "+"), gates)
	if testCase.StoreClock {
		header += "; store clock on T3"
	}
	if testCase.Row.Unknown {
		header += "; §22.8's unknown list"
	}
	return header + ")"
}

// The FI a row names, by id, split into those whose oracle is bound, which a schedule must check, and those that are
// not, which fail closed in any schedule naming them. A clause letter names part of its FI: FI-13c is FI-13.
func m10Format2RowInvariants(row *Row, built []int) (required []string, unbound []string) {
	for _, check := range row.Checks {
		match := catalogInvariantCheckPattern.FindStringSubmatch(check)
		if match == nil {
			continue
		}
		n, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		id := "FI-" + match[1]
		switch {
		case slices.Contains(required, id) || slices.Contains(unbound, id):
		case slices.Contains(built, n):
			required = append(required, id)
		default:
			unbound = append(unbound, id)
		}
	}
	return required, unbound
}

// The sweep names every case the catalog holds at M10's exit for its rows, in the catalog's order, each once; every
// case with no builder on a tier it runs on says why, or names its T3 tests; each clause names a builder and a name of
// its own; and every test the list names as holding part of a case is declared where it says, so the report never
// names a test that is not there.
func TestM10Format2SweepNamesEveryCase(t *testing.T) {
	catalog := DefaultCatalog()
	want := []string{}
	for _, testCase := range m10Format2CatalogCases(catalog) {
		want = append(want, testCase.String())
	}
	have := []string{}
	repoDirectory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, sweepCase := range m10Format2SweepCases() {
		testCase := sweepCase.catalogCase(catalog)
		if testCase == nil {
			t.Errorf("the sweep names %s %q, which the catalog does not hold", sweepCase.rowId, sweepCase.caseName)
			continue
		}
		have = append(have, testCase.String())
		for _, tier := range testCase.Tiers() {
			if Lookup(testCase.Row.Id, testCase.Name, tier) != nil {
				continue
			}
			if tier == TierT3 && 0 < len(sweepCase.t3Tests) {
				continue
			}
			if sweepCase.unscheduledNote == "" {
				t.Errorf("%s has no builder on %s, and the sweep does not say what holds it", testCase, tier)
			}
		}
		clauseNames := []string{}
		for _, clause := range sweepCase.clauses {
			if clause.name == "" || clause.build == nil || slices.Contains(clauseNames, clause.name) {
				t.Errorf("%s's clause %q is unnamed, unbuilt or named twice", testCase, clause.name)
			}
			clauseNames = append(clauseNames, clause.name)
		}
		for _, test := range sweepCase.heldByTests {
			for _, err := range GateTestDeclared(repoDirectory, test) {
				t.Errorf("%s: %v", testCase, err)
			}
		}
	}
	if !slices.Equal(have, want) {
		t.Errorf("the sweep names %v, and the catalog holds %v at %s for its rows", have, want, m10Format2CatalogGate)
	}
	// the rows are format 2's, each with a case at M10's exit
	for _, rowId := range m10Format2RowIds() {
		if !slices.ContainsFunc(m10Format2CatalogCases(catalog), func(testCase *Case) bool { return testCase.Row.Id == rowId }) {
			t.Errorf("%s has no case at %s", rowId, m10Format2CatalogGate)
		}
	}
}

// Each schedule the sweep builds, on a Net of its own closed before the next: a builder's schedule and its twin.
func m10Format2Schedules(t *testing.T, builder Builder) []*Schedule {
	schedules := []*Schedule{}
	var schedule *Schedule
	func() {
		net := sidecartest.NewNet(t.Context(), nil)
		defer net.Close()
		schedule = builder(net)
	}()
	schedules = append(schedules, schedule)
	if schedule.Twin != nil {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			schedules = append(schedules, schedule.Twin(net))
		}()
	}
	return schedules
}

// The oracle checks each FI a row names after every step (§22.8): every schedule the sweep runs, the registered case's
// on each of its tiers and each clause's, and each one's twin, names every such FI whose oracle is bound in its Check,
// which Run reads after every step and at the end.
func TestM10Format2SweepSchedulesCheckTheirRowsInvariants(t *testing.T) {
	catalog := DefaultCatalog()
	built := BuiltInvariants()
	checked := 0
	for _, sweepCase := range m10Format2SweepCases() {
		testCase := sweepCase.catalogCase(catalog)
		if testCase == nil {
			continue
		}
		required, unbound := m10Format2RowInvariants(testCase.Row, built)
		names := []string{}
		builders := []Builder{}
		for _, tier := range testCase.Tiers() {
			registration := Lookup(testCase.Row.Id, testCase.Name, tier)
			if registration == nil || slices.Contains(names, registration.String()) {
				continue
			}
			names = append(names, registration.String())
			builders = append(builders, registration.Build)
		}
		for _, clause := range sweepCase.clauses {
			names = append(names, testCase.Row.Id+" "+clause.name)
			builders = append(builders, clause.build)
		}
		for index, builder := range builders {
			for _, schedule := range m10Format2Schedules(t, builder) {
				ids := []string{}
				for _, invariant := range schedule.Check {
					ids = append(ids, invariant.Id())
				}
				for _, id := range required {
					if !slices.Contains(ids, id) {
						t.Errorf("%s's schedule %q checks %v, without its row's %s", names[index], schedule.Id, ids, id)
					}
				}
				checked += 1
			}
		}
		if 0 < len(unbound) && 0 < len(builders) {
			t.Logf("%s: %s, which its row names, has no oracle bound, so no schedule of it checks that", testCase, strings.Join(unbound, " and "))
		}
	}
	if checked == 0 {
		t.Error("no schedule was checked")
	}
}

// Writes what one run under a row's rules did: its seeds, twin, lost writes and replays, and each failure.
func m10Format2WriteRun(report *strings.Builder, label string, rowReport *RowReport) {
	outcome := "passed"
	if rowReport.Failed() {
		outcome = fmt.Sprintf("FAILED, %d runs", len(rowReport.Failures)+len(rowReport.Errors))
	}
	fmt.Fprintf(report, "    %s: %s: %s\n", label, outcome, strings.ReplaceAll(rowReport.String(), "\n", "\n      "))
}

// §23.6's M10 rows for format 2 on T2, under every rule §22.8 gives each row, and the report: each case run, missing
// or open on each tier its row names. A case or clause that fails fails this test; a missing case is reported, since
// the gate reads it missing on its own, and what fills it is the owning task's.
func TestM10Format2SweepOnT2(t *testing.T) {
	catalog := DefaultCatalog()
	var report strings.Builder
	runCount, missingCount, t3AloneCount, openCount, clauseCount := 0, 0, 0, 0, 0
	for _, sweepCase := range m10Format2SweepCases() {
		testCase := sweepCase.catalogCase(catalog)
		if testCase == nil {
			t.Errorf("the sweep names %s %q, which the catalog does not hold", sweepCase.rowId, sweepCase.caseName)
			continue
		}
		fmt.Fprintf(&report, "\n%s\n", m10Format2Header(testCase))
		registration := Lookup(testCase.Row.Id, testCase.Name, TierT2)
		switch {
		case !slices.Contains(testCase.Tiers(), TierT2):
			t3AloneCount += 1
			fmt.Fprintf(&report, "  T2: not one of its tiers\n")
		case registration == nil:
			missingCount += 1
			fmt.Fprintf(&report, "  T2: missing, no builder registered: %s\n", sweepCase.unscheduledNote)
		default:
			runCount += 1
			fmt.Fprintf(&report, "  T2: run, %s and its clauses under §22.8's rules:\n", registration)
			rowReport := CheckRow(t.Context(), registration, nil)
			m10Format2WriteRun(&report, "registered case", rowReport)
			for _, failure := range rowReport.Failures {
				t.Errorf("%s on T2: %s", testCase, failure)
			}
			for _, err := range rowReport.Errors {
				t.Errorf("%s on T2: %v", testCase, err)
			}
			for _, clause := range sweepCase.clauses {
				clauseCount += 1
				clauseReport := CheckClause(t.Context(), testCase.Row.Id, clause.name, clause.build, nil)
				m10Format2WriteRun(&report, "clause "+clause.name, clauseReport)
				for _, failure := range clauseReport.Failures {
					t.Errorf("%s %s on T2: %s", testCase.Row.Id, clause.name, failure)
				}
				for _, err := range clauseReport.Errors {
					t.Errorf("%s %s on T2: %v", testCase.Row.Id, clause.name, err)
				}
			}
		}
		if slices.Contains(testCase.Tiers(), TierT3) {
			switch t3Registration := Lookup(testCase.Row.Id, testCase.Name, TierT3); {
			case t3Registration != nil:
				fmt.Fprintf(&report, "  T3: %s, by its T3 tests where the gate list says; the T3 half (server's evshost/m10_format2_sweep_test.go) runs evshost's at a merge's seeds\n", t3Registration)
			case 0 < len(sweepCase.t3Tests):
				for _, test := range sweepCase.t3Tests {
					fmt.Fprintf(&report, "  T3: no builder; %s's %s %v under %s\n", test.Repo, test.Package, test.Names, test.Tags)
				}
			default:
				fmt.Fprintf(&report, "  T3: missing, no builder registered\n")
			}
		}
		for _, test := range sweepCase.heldByTests {
			fmt.Fprintf(&report, "  held in part by %s's %s: %s\n", test.Repo, test.Package, strings.Join(test.Names, ", "))
		}
		for _, missing := range sweepCase.missingClauses {
			fmt.Fprintf(&report, "  missing: %s\n", missing)
		}
		for _, open := range sweepCase.openNotes {
			openCount += 1
			fmt.Fprintf(&report, "  open: %s\n", open)
		}
	}
	required, unbound := []string{}, []string{}
	for _, testCase := range m10Format2CatalogCases(catalog) {
		rowRequired, rowUnbound := m10Format2RowInvariants(testCase.Row, BuiltInvariants())
		for _, id := range rowRequired {
			if !slices.Contains(required, id) {
				required = append(required, id)
			}
		}
		for _, id := range rowUnbound {
			if !slices.Contains(unbound, id) {
				unbound = append(unbound, id)
			}
		}
	}
	slices.SortFunc(required, m10Format2CompareInvariantIds)
	slices.SortFunc(unbound, m10Format2CompareInvariantIds)
	t.Logf("§23.6's M10 rows for format 2 on T2 (EVS2-M10-35): %d cases run under §22.8's rules with %d clauses beside them, %d missing on T2, %d on T3 alone, %d open notes; the FI the rows name whose oracle is bound, which each run schedule checks after every step: %s; unbound, failing closed where a schedule names one: %s\n%s",
		runCount, clauseCount, missingCount, t3AloneCount, openCount, strings.Join(required, ", "), strings.Join(unbound, ", "), report.String())
}

// FI-2 before FI-13.
func m10Format2CompareInvariantIds(a string, b string) int {
	numberA, _ := strconv.Atoi(strings.TrimPrefix(a, "FI-"))
	numberB, _ := strconv.Atoi(strings.TrimPrefix(b, "FI-"))
	return numberA - numberB
}

// One item M10's Gn-out shows for format 2 beside its rows (§22.10's right column for format 2), with the tests that
// show it in either repo, what no task finished, and what outside this build it waits on.
type m10Format2Item struct {
	item           string
	tests          []*GateTest
	missingClauses []string
	external       string
}

// §22.10's right column for format 2, as the gate list gives TEST-M10-05 its items: what each shows, by its tests.
func m10Format2GateItems() []*m10Format2Item {
	return []*m10Format2Item{
		{
			item: "EvsCommit.tla's purger and drop extension pass TLC (§22.10; EVSB-M10-07): its M10 stories, each at its bounds, its M10 twins each refused with its invariant violated, which hold I-EVS-9, I-EVS-10, I-EVS-15, FI-16, FI-17 and FI-27 where the stories reach, and F2DropsEnd under weak fairness on each drop story, the purger's and the drop extension's each modes of their own that M10's exit needs (QD-1116, QD-1119)",
			tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/model", Tags: "sidecar_tlc", Names: []string{"TestEvsCommitPurgerStoriesPassTlc", "TestEvsCommitPurgerMutantsFailTlc", "TestEvsCommitDropStoriesPassTlc", "TestEvsCommitDropMutantsFailTlc", "TestEvsCommitDropLivenessHolds"}},
			},
			missingClauses: []string{
				"EVSB-M10-07's report lists what the stories leave out (locks voiding drops, observe modes, the 2,048-id mark, several drops a repo, index rewrites, FI-16's sweep-period liveness)",
				"F2DropsEnd runs on one instance; on two it is the review phase's (QD-1119)",
			},
		},
		{
			item: "D-TEST-13's projection of format 2's drive writes, computed from M2's price table and T3's index counts and never measured (R-TEST-11; EVSB-M10-08)",
			tests: []*GateTest{
				{Repo: "server", Package: "./cli/filecluster-bench", Names: []string{"TestProjectionOnT3CountsThatFitPasses", "TestProjectionMissFailsTheGate", "TestProjectionReadsOpenOnInferredRows", "TestProjectionReadsOpenWithoutM2sChoice"}},
			},
			missingClauses: []string{
				"the index mode runs no load until SEARCH-M10-40's writers' load driver is named, so the projection reads open on inferred index operations (EVSB-M10-08)",
			},
			external: "M2's nvme run (D-TEST-11) on the PM9A3 set, whose measured price table the projection multiplies; production's measured over priced bytes within 10% while §19.11's format2 gate holds percent at 0",
		},
		{
			item: "D-TEST-12's observe evidence: under purge: observe every candidate is kept and checked against every retained version that could name it (EVS2-M10-33)",
			tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestPurgeObserveCleanOnAnHonestHistory", "TestPurgeObserveCatchesACandidateALaterVersionNames", "TestSweepUnderObserveRunsTheCheckAndKeepsEverything"}},
				{Repo: "server", Package: "./taskworker/work", Names: []string{"TestEvsObserveSoaksMet", "TestEvsObserveSoaksStateEachUnmetThreshold"}},
			},
			missingClauses: []string{
				"the observe check's T3 run (EVS2-M10-33)",
			},
			external: "D-TEST-12's production soak after the final freeze: at least 14 days and 10,000 candidates, none a retained version names, before purge: on",
		},
		{
			item: "D-TEST-18's drop soak: at least 30 days and 200 jobs, half on repos with renames and cross-ref copies, no delete-set member a retained version names, with FS-89 to FS-96 and TLC passing first",
			tests: []*GateTest{
				{Repo: "server", Package: "./taskworker/work", Names: []string{"TestEvsObserveDropSoakSharesJobsWithBothARenameAndACopy"}},
			},
			external: "production, after the final freeze and before drop: on",
		},
		{
			item: "purge and drops stay in observe by default: deletes on is a production soak's, then the owner's (§19.11; D-TEST-12, D-TEST-18)",
			tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestFormat2GateTable", "TestFormat2GateFollowsTheHostAndFailsClosed"}},
				{Repo: "server", Package: "./evshost", Names: []string{"TestHostFormat2GateReadsServersSidecarYml", "TestHostFormat2GateWithoutGatesIsClosed"}},
			},
		},
		{
			item: "a migration of a format-1 repo set and a rollback to format-1 binaries (§22.10; FS-72's M10 cases; EVS2-M10-30, QD-854)",
			tests: []*GateTest{
				{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{"TestFs72Migration", "TestFs72Rollback"}},
				{Repo: "server", Package: "./evshost", Tags: gateT3Tags, Stores: true, Names: []string{"TestFs72MigrationOnT3", "TestFs72RollbackOnT3", "TestFs72RollbackThroughTheBlockConfigOnT3", "TestFs72RollbackOnThePinnedBuildOnT3"}},
			},
			missingClauses: []string{
				"a repo set: each world holds one repo (EVS2-M10-30)",
			},
		},
		{
			item: "format 2's fuzz seeds, run as tests (§22.6; EVS2-M10-32)",
			tests: []*GateTest{
				{Repo: "sidecar", Package: ".", Names: []string{"FuzzEvsKind5Segment", "FuzzEvsFormat2Batch", "FuzzEvsDrop", "FuzzEvsPurgeList", "FuzzEvsStaged", "FuzzEvsDropStatus"}},
			},
			missingClauses: []string{
				"long fuzz campaigns (EVS2-M10-32, review phase)",
			},
		},
		{
			item: "D-OPS-21's drop job bounds: one job a segment cluster, at most 32 MB/s of reads and 10 DELETEs a second, paused past half the HDD drives' measured capacity or while none is known (EVSB-M10-03, -06)",
			tests: []*GateTest{
				{Repo: "sidecar", Package: "./evsservice", Names: []string{"TestDropJobTakeIsOneInstances", "TestDropJobGatesStartNothing"}},
			},
			missingClauses: []string{
				"no test holds a job's reads to DropSettings.ReadBytesPerSecond or its DELETEs to DeletesPerSecond: the pace runs, unmeasured (EVSB-M10-03, -06)",
			},
		},
	}
}

// The server checkout beside this one, resolved through a track's symlink, or "" where there is none.
func m10Format2ServerDirectory(t *testing.T) string {
	directory, err := filepath.Abs(filepath.Join("..", "..", "..", "server"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err = filepath.EvalSymlinks(directory)
	if err != nil {
		return ""
	}
	if info, err := os.Stat(filepath.Join(directory, "go.mod")); err != nil || info.IsDir() {
		return ""
	}
	return directory
}

// Where server's test files declare each top-level test or fuzz target, by name: the packages as gates.yml names them,
// from server's root ("." for the root package). Read once from the sources, building nothing; the vendored modules
// under third_party and directories go ignores are left out.
func m10Format2ServerTestPackages(t *testing.T, serverDirectory string) map[string][]string {
	declaration := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]*)\(`)
	namePackages := map[string][]string{}
	err := filepath.WalkDir(serverDirectory, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != serverDirectory && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" || name == "node_modules" || name == "third_party") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(serverDirectory, filepath.Dir(path))
		if err != nil {
			return err
		}
		packagePath := "."
		if relative != "." {
			packagePath = "./" + filepath.ToSlash(relative)
		}
		for _, match := range declaration.FindAllSubmatch(data, -1) {
			name := string(match[1])
			if !slices.Contains(namePackages[name], packagePath) {
				namePackages[name] = append(namePackages[name], packagePath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return namePackages
}

// The packages where server declares name in a file go test builds with tags, as the gate would run it there.
func m10Format2ServerPlaces(serverDirectory string, namePackages map[string][]string, name string, tags string) []string {
	places := []string{}
	for _, packagePath := range namePackages[name] {
		if len(GateTestDeclared(serverDirectory, &GateTest{Repo: "server", Package: packagePath, Tags: tags, Names: []string{name}})) == 0 {
			places = append(places, packagePath)
		}
	}
	return places
}

// A gate test as one line of the list.
func m10Format2TestLine(test *GateTest) string {
	line := fmt.Sprintf("%s %s %s", test.Repo, test.Package, strings.Join(test.Names, ", "))
	if test.Tags != "" {
		line += " [" + test.Tags + "]"
	}
	if test.Stores {
		line += " on the private stores"
	}
	return line
}

// The names of tests server declares for testCase's T3 run beyond the convention's own, by their convention prefix:
// TestFs92HoldsPlacedByApiOnT3 is FS-92's, and TestFs66HoldPlacedByApiOnT3 FS-66's hold case's, never FS-66's main
// part's, since a longer case's prefix takes it.
func m10Format2T3NamesOfCase(namePackages map[string][]string, testCase *Case) []string {
	prefix := GateT2TestName(testCase)
	otherPrefixes := []string{}
	for _, other := range testCase.Row.Cases {
		if otherPrefix := GateT2TestName(other); other != testCase && strings.HasPrefix(otherPrefix, prefix) && len(prefix) < len(otherPrefix) {
			otherPrefixes = append(otherPrefixes, otherPrefix)
		}
	}
	names := []string{}
	for name := range namePackages {
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok || !strings.HasSuffix(name, "OnT3") || rest == "" || !('A' <= rest[0] && rest[0] <= 'Z') {
			continue
		}
		if slices.ContainsFunc(otherPrefixes, func(otherPrefix string) bool { return strings.HasPrefix(name, otherPrefix) }) {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Whether the gate's row names test at place, so the gate runs it there.
func m10Format2GateNames(gateRow *GateRow, repo string, place string, name string) bool {
	return slices.ContainsFunc(gateRow.Tests, func(test *GateTest) bool {
		return test.Repo == repo && test.Package == place && slices.Contains(test.Names, name)
	})
}

// The gate list for M10's Gn-out (EVS2-M10-35's provides): for each case of the sweep, the tests M10's exit runs where
// they are declared, sidecar's T2 test by the convention and each T3 test wherever server declares it under T3's
// tags, beside what gates.yml's M10 rows name today; then format 2's items with their tests. A sidecar test an item
// names that is not declared fails here: the list is this task's to keep true. A server test the list names that is
// not where it says is reported, never failed, so a rename in server cannot break sidecar's tip: server's own
// TestGateSweepsNameServerTestsDeclaredUnderTheirTags holds each test a gate sweep names once it is there. A case
// that reads missing at the gate, or whose T3 tests run outside the convention's ./sidecart3 or under other names, is
// listed as such and fails nothing here: the gate's own sweep, gate_m10_out.go, is TEST-M10-05's to extend (QD-1081),
// and it names such tests where they run from this list.
func TestM10Format2SweepGateList(t *testing.T) {
	catalog := DefaultCatalog()
	sidecarDirectory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	serverDirectory := m10Format2ServerDirectory(t)
	var namePackages map[string][]string
	if serverDirectory != "" {
		namePackages = m10Format2ServerTestPackages(t, serverDirectory)
	}
	gateRows := GateRows(catalog, m10Format2ToolGate)
	var list strings.Builder
	unnamedCount, missingCount, undeclaredCount := 0, 0, 0
	for _, sweepCase := range m10Format2SweepCases() {
		testCase := sweepCase.catalogCase(catalog)
		if testCase == nil {
			continue
		}
		index := slices.IndexFunc(gateRows, func(row *GateRow) bool { return row.Row == testCase.Row.Id && row.Case == testCase.Name })
		if index < 0 {
			t.Errorf("gates.yml's M10 holds no row for %s", testCase)
			continue
		}
		gateRow := gateRows[index]
		fmt.Fprintf(&list, "\n%s\n", testCase)
		for _, tier := range testCase.Tiers() {
			registered := Lookup(testCase.Row.Id, testCase.Name, tier) != nil
			switch tier {
			case TierT2:
				test := &GateTest{Repo: "sidecar", Package: "./sidecartest/fault", Tags: "sidecar_testhooks", Names: []string{GateT2TestName(testCase)}}
				switch declared := len(GateTestDeclared(sidecarDirectory, test)) == 0; {
				case declared:
					fmt.Fprintf(&list, "  T2: %s\n", m10Format2TestLine(test))
				case registered:
					missingCount += 1
					fmt.Fprintf(&list, "  T2: missing at the gate: a builder is registered, and nothing declares %s\n", test.Names[0])
				default:
					missingCount += 1
					fmt.Fprintf(&list, "  T2: missing: no builder is registered, and nothing declares %s\n", test.Names[0])
				}
			case TierT3:
				if serverDirectory == "" {
					fmt.Fprintf(&list, "  T3: unchecked: no server checkout beside this one\n")
					continue
				}
				tests := sweepCase.t3Tests
				if len(tests) == 0 {
					names := []string{GateT3TestName(testCase)}
					if len(m10Format2ServerPlaces(serverDirectory, namePackages, names[0], gateT3Tags)) == 0 {
						names = m10Format2T3NamesOfCase(namePackages, testCase)
					}
					for _, name := range names {
						tests = append(tests, &GateTest{Repo: "server", Package: "./sidecart3", Tags: gateT3Tags, Stores: true, Names: []string{name}})
					}
				}
				if len(tests) == 0 {
					missingCount += 1
					if registered {
						fmt.Fprintf(&list, "  T3: missing at the gate: a builder is registered, and server declares no %s or other test of it\n", GateT3TestName(testCase))
					} else {
						fmt.Fprintf(&list, "  T3: missing: no builder is registered, and server declares no %s\n", GateT3TestName(testCase))
					}
				}
				for _, test := range tests {
					for _, name := range test.Names {
						places := m10Format2ServerPlaces(serverDirectory, namePackages, name, test.Tags)
						if 0 < len(sweepCase.t3Tests) && !slices.Contains(places, test.Package) {
							undeclaredCount += 1
							fmt.Fprintf(&list, "  T3: NOT DECLARED where the list says: server's %s declares no %s under %s (declared in %v)\n", test.Package, name, test.Tags, places)
							continue
						}
						if len(places) == 0 {
							continue
						}
						place := test.Package
						if !slices.Contains(places, place) {
							place = places[0]
						}
						line := m10Format2TestLine(&GateTest{Repo: "server", Package: place, Tags: test.Tags, Stores: test.Stores, Names: []string{name}})
						if m10Format2GateNames(gateRow, "server", place, name) {
							fmt.Fprintf(&list, "  T3: %s, as the gate names it\n", line)
						} else {
							unnamedCount += 1
							fmt.Fprintf(&list, "  T3: %s, which the gate does not name, so it reads the case's T3 run missing until its sweep names it there (QD-1081)\n", line)
						}
					}
				}
			}
		}
		gateLines := []string{}
		for _, test := range gateRow.Tests {
			gateLines = append(gateLines, m10Format2TestLine(test))
		}
		fmt.Fprintf(&list, "  gates.yml's M10 runs today: %s\n", strings.Join(gateLines, "; "))
		if gateRow.External != "" {
			fmt.Fprintf(&list, "  gates.yml's external: %s\n", gateRow.External)
		}
		for _, open := range sweepCase.openNotes {
			fmt.Fprintf(&list, "  open: %s\n", open)
		}
	}
	fmt.Fprintf(&list, "\nitems for format 2 (§22.10's right column):\n")
	for _, item := range m10Format2GateItems() {
		fmt.Fprintf(&list, "  %s\n", item.item)
		for _, test := range item.tests {
			directory := sidecarDirectory
			if test.Repo == "server" {
				directory = serverDirectory
			}
			if directory == "" {
				fmt.Fprintf(&list, "    %s, unchecked: no server checkout beside this one\n", m10Format2TestLine(test))
				continue
			}
			errs := GateTestDeclared(directory, test)
			// a sidecar test is this repo's to keep where the list says; a server one is the T3 half's and server's own
			// gate test's, so a rename in server never fails sidecar's tip, and is reported here
			for _, err := range errs {
				if test.Repo == "sidecar" {
					t.Errorf("format 2's item %q: %v", item.item, err)
				} else {
					undeclaredCount += 1
					fmt.Fprintf(&list, "    NOT DECLARED where the list says: %v\n", err)
				}
			}
			fmt.Fprintf(&list, "    %s\n", m10Format2TestLine(test))
		}
		for _, missing := range item.missingClauses {
			fmt.Fprintf(&list, "    missing: %s\n", missing)
		}
		if item.external != "" {
			fmt.Fprintf(&list, "    external: %s\n", item.external)
		}
	}
	t.Logf("M10's Gn-out for format 2's rows (EVS2-M10-35's gate list; gate_m10_out.go is TEST-M10-05's, QD-1081): %d T3 tests run where the gate does not name them, so it reads them missing until its sweep does; %d tests missing; %d server tests not declared where the list says\n%s",
		unnamedCount, missingCount, undeclaredCount, list.String())
}
