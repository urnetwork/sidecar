package gkmschedule

// T2 of the schedules in hints.go, each on a fresh world on the fake host (FsKeysT2); server/gkm's T3 runs the
// same builders on the local stack.

import (
	"testing"
)

func TestFsKeysHintsAnIdleWriterIsToldPendingAtAnUnchangedEpoch(t *testing.T) {
	FsKeysScheduleIdleWriterHint(t, FsKeysT2(t))
}

func TestFsKeysHintsARotationWithoutACommitRaisesTheGroupTopic(t *testing.T) {
	FsKeysScheduleRotationGroupHint(t, FsKeysT2(t))
}

func TestFsKeysHintsALateAskIsToldWrapPendingAndAnswered(t *testing.T) {
	FsKeysScheduleLateAsk(t, FsKeysT2(t))
}

func TestFsKeysHintsLostAcksDeleteNoEpochForThirtyDays(t *testing.T) {
	FsKeysScheduleLostAcks(t, FsKeysT2(t))
}

func TestFsKeysHintsPendingRepeatsWhileADroppedLeafStandsAndStopsPastIt(t *testing.T) {
	FsKeysScheduleDroppedHolderHint(t, FsKeysT2(t))
}

func TestFsKeysHintsAWaitingLeafsWantRaisesWrapPending(t *testing.T) {
	FsKeysScheduleWaitingLeafWant(t, FsKeysT2(t))
}
