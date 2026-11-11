package gkmschedule

// T2 of the schedules in claims.go, each on a fresh world on the fake host (FsKeysT2); server/gkm's T3 runs the
// same builders on the local stack.

import (
	"testing"
)

func TestFsKeysClaimsAWrappedRotationLeavesTheRemovedLeafNothing(t *testing.T) {
	FsKeysScheduleWrappedRotation(t, FsKeysT2(t))
}

func TestFsKeysClaimsALeafAndAWrappedRotationRaceForOneGeneration(t *testing.T) {
	FsKeysScheduleRotationRace(t, FsKeysT2(t))
}

func TestFsKeysClaimsALostAnswerAndAKilledClaimEachEndInOneGeneration(t *testing.T) {
	FsKeysScheduleLostAndKilledClaims(t, FsKeysT2(t))
}

func TestFsKeysClaimsACommitBelowItsPredecessorsGenerationIsRefused(t *testing.T) {
	FsKeysScheduleCommitBelowItsPredecessor(t, FsKeysT2(t))
}
