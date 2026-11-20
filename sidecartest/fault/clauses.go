// Every clause the areas' fs<n>_test.go files run beside a registered case, registered against its row and case
// (register_clause.go; QD-1084), so a gate counts each with its case and names its tests by convention. Each builder
// stays where its owner wrote it, an exported Builder in a non-test file here, and each name is the one its owner's
// tests ran it under, which names its traces: a registration renames no schedule. A clause that runs on T3 names the
// server package its T3 test is in. FS-99's evs scope registers in clauses_directory.go, beside the build its builder
// is in.
//
// Not here: FS-91's within-the-window clause, whose test file another track holds, runs through RunClause unregistered
// until it registers (TestEveryRunClauseCallIsRegistered names it).

package fault

import (
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// The clauses, in row order. EVS1-M2-40's and EVS1-M2-41's T3 runs are server's evshost's, ABUSE-M10-01's hold clauses'
// server's model's against api's real hold/ writes, and ACL-M6-05's request legs' server's api's.
var registeredClauses = []*ClauseRegistration{
	RegisterClause("FS-1", "", "concurrent retries", Fs1ConcurrentRetries, ClauseOnT3("./evshost")),
	RegisterClause("FS-1", "", "unknown deletes nothing", Fs1UnknownDeletesNothing, ClauseOnT3("./evshost")),

	RegisterClause("FS-3", "", "step 7 past 5 s", Fs3StepSevenPastFiveSeconds),

	RegisterClause("FS-4", "", "two sources", Fs4TwoSources, ClauseOnT3("./evshost")),
	RegisterClause("FS-4", "", "batched epoch", Fs4BatchedEpoch, ClauseOnT3("./evshost")),
	RegisterClause("FS-4", "", "batched epoch read before copy", Fs4BatchedEpochReadBeforeCopy),

	RegisterClause("FS-6", "", "seven-day start", Fs6SevenDayStart, ClauseOnT3("./evshost")),
	RegisterClause("FS-6", "", "killed at each phase", Fs6KilledAtEachPhase, ClauseOnT3("./evshost")),
	RegisterClause("FS-6", "", "stale job", Fs6StaleJob, ClauseOnT3("./evshost")),
	RegisterClause("FS-6", "", "reads refused while deleted", Fs6ReadsRefusedWhileDeleted),
	// §22.8's FS-6 names it, and FS-69 says it keeps ciphertext as FS-6 states: the held gate names it beside FS-69 too
	RegisterClause("FS-6", "", "a --now shred under a hold", Fs6NowShredUnderAHold, ClauseOnT3("./model")),

	RegisterClause("FS-7", "", "evacuated window after a restart", Fs7EvacuatedWindowAfterRestart),
	RegisterClause("FS-7", "", "fold lost with its instance", Fs7FoldLostWithItsInstance),

	RegisterClause("FS-9", "", "unfolded listing", Fs9UnfoldedListing),

	// a forged case: on T3 its twin runs, which must succeed
	RegisterClause("FS-10", "", "rollback refused", Fs10RollbackRefused, ClauseOnT3("./evshost")),

	// the ledger's named gaps in FS-14 among them (ACL-M2-16): the repo revoke, the owner confirm, the two removals
	RegisterClause("FS-14", "", "acl suspend orders", Fs14AclSuspendOrders),
	RegisterClause("FS-14", "", "acl repo revoke", Fs14AclRepoRevoke),
	RegisterClause("FS-14", "", "acl owner confirm", Fs14AclOwnerConfirm),
	RegisterClause("FS-14", "", "acl two removals", Fs14AclTwoRemovals),
	RegisterClause("FS-14", "", "acl forked readers", Fs14AclForkedReaders),

	RegisterClause("FS-57", "", "store unreachable", Fs57StoreUnreachable, ClauseOnT3("./evshost")),

	RegisterClause("FS-58", "", "folds killed and raced", Fs58FoldKilledAndRaced, ClauseOnT3("./evshost")),
	RegisterClause("FS-58", "", "re-created after a collection", Fs58RecreatedAfterCollection),

	RegisterClause("FS-62", "", "lease holder resync", Fs62LeaseHolderResync, ClauseOnT3("./evshost")),
	RegisterClause("FS-62", "", "acl gate", Fs62AclGate, ClauseOnT3("./sidecart3")),

	RegisterClause("FS-68", "", "rules", Fs68Rules, ClauseOnT3("./evshost")),
	RegisterClause("FS-68", "", "platform rule", Fs68PlatformRule, ClauseOnT3("./evshost")),
	RegisterClause("FS-68", "", "config", Fs68Kind(protocol.RepoKind_REPO_KIND_CONFIG), ClauseOnT3("./evshost")),
	RegisterClause("FS-68", "", "mailcfg", Fs68Kind(protocol.RepoKind_REPO_KIND_MAILCFG), ClauseOnT3("./evshost")),
	RegisterClause("FS-68", "", "lock", Fs68LockedPastTheWindow, ClauseOnT3("./evshost")),

	RegisterClause("FS-69", "", "between sweep deletes", Fs69HoldBetweenSweepDeletes, ClauseOnT3("./model")),
	RegisterClause("FS-69", "", "an erase under the hold", Fs69EraseUnderTheHold, ClauseOnT3("./model")),

	RegisterClause("FS-72", "migration", "migration killed after step 6", Fs72MigrationKilledAt(evsservice.BarrierPushStep6After), ClauseOnT3("./evshost")),
	RegisterClause("FS-72", "migration", "migration killed before the raise", Fs72MigrationKilledAt(evsservice.BarrierMigrateRaiseBefore), ClauseOnT3("./evshost")),
	RegisterClause("FS-72", "migration", "migration killed after the raise", Fs72MigrationKilledAt(evsservice.BarrierMigrateRaiseAfter), ClauseOnT3("./evshost")),
	RegisterClause("FS-72", "migration", "migration killed before the head CAS", Fs72MigrationKilledAt(evsservice.BarrierHeadCasBefore), ClauseOnT3("./evshost")),
	RegisterClause("FS-72", "migration", "migration killed after the head CAS", Fs72MigrationKilledAt(evsservice.BarrierHeadCasAfter), ClauseOnT3("./evshost")),

	RegisterClause("FS-85", "", "acl repo request", Fs85AclRepoRequest, ClauseOnT3("./api")),
	RegisterClause("FS-85", "", "acl owner-bound request", Fs85AclOwnerBoundRequest, ClauseOnT3("./api")),
	RegisterClause("FS-85", "", "acl worker request", Fs85AclWorkerRequest, ClauseOnT3("./api")),
	RegisterClause("FS-85", "", "acl copied decision", Fs85AclCopiedDecision, ClauseOnT3("./api")),
	// ACL-M8-01's, beside RECORD-M8-01's registered wakes case
	RegisterClause("FS-85", "wakes", "acl wakes", Fs85AclWakes),

	RegisterClause("FS-89", "", "now", Fs89Now, ClauseOnT3("./evshost")),

	RegisterClause("FS-92", "", "between verify and delete", Fs92HoldBetweenVerifyAndDelete, ClauseOnT3("./model")),
	RegisterClause("FS-92", "", "between deletes", Fs92HoldBetweenDeletes, ClauseOnT3("./model")),
	RegisterClause("FS-92", "", "a delete in flight", Fs92DeleteInFlight, ClauseOnT3("./model")),
	RegisterClause("FS-92", "", "a hold that outlasts the drop table", Fs92HoldOutlastsTheDropTable),
	RegisterClause("FS-92", "", "a second drop during the hold", Fs92SecondDropDuringTheHold),

	RegisterClause("FS-94", "", "record class", Fs94RecordClass, ClauseOnT3("./evshost")),

	RegisterClause("FS-95", "", "locked", Fs95Locked, ClauseOnT3("./evshost")),
	RegisterClause("FS-95", "", "config", Fs95Kind(protocol.RepoKind_REPO_KIND_CONFIG), ClauseOnT3("./evshost")),
	RegisterClause("FS-95", "", "mailcfg", Fs95Kind(protocol.RepoKind_REPO_KIND_MAILCFG), ClauseOnT3("./evshost")),
	RegisterClause("FS-95", "", "owner-bound", Fs95OwnerBound, ClauseOnT3("./evshost")),
	RegisterClause("FS-95", "", "list missing a version", Fs95ListMismatch(false), ClauseOnT3("./evshost")),
	RegisterClause("FS-95", "", "list adding a version", Fs95ListMismatch(true), ClauseOnT3("./evshost")),
}
