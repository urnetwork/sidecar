package gkmschedule

// T2 of the schedules in delivery.go, each on a fresh world on the fake host (FsKeysT2); server/gkm's T3 runs FS-103's
// builders on the local stack. FS-104 is T2 alone (§22.8's row).

import (
	"testing"
)

func TestFsKeysDeliveryAuthorityIsJudgedAlikeByEveryMemberAndTheOracle(t *testing.T) {
	FsKeysScheduleDeliveryAuthority(t, FsKeysT2(t))
}

func TestFsKeysDeliveryByAClockFiftySecondsBehindTheClaimIsValid(t *testing.T) {
	FsKeysScheduleDeliveryByATrailingClock(t, FsKeysT2(t))
}

func TestFsKeysDeliveryAnInjectedCommitIsRefusedByMembersAndTheOracle(t *testing.T) {
	FsKeysScheduleInjectedCommitJudged(t, FsKeysT2(t))
}

func TestFsKeysDeliveryALateDeliveryKeepsItsIdentityAcrossKeyReplacement(t *testing.T) {
	FsKeysScheduleLateDeliveryIdentity(t, FsKeysT2(t))
}

func TestFsKeysDeliveryASameGenerationRebindLeavesBothBindingsAtAKill(t *testing.T) {
	FsKeysScheduleSameGenerationRebind(t, FsKeysT2(t))
}

func TestFsKeysDeliveryTheOracleSeesMutantsOfTheMembersCheck(t *testing.T) {
	FsKeysScheduleOracleSeesCheckMutants(t, FsKeysT2(t))
}

func TestFsKeysDeliveryAnOlderKeysObjectAgesOutThirtyDaysPastTheNewerOnes(t *testing.T) {
	FsKeysScheduleOlderKeyDeliveryAgesOut(t, FsKeysT2(t))
}
