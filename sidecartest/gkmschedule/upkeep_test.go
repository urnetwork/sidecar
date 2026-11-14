package gkmschedule

// T2 of the schedules in upkeep.go, each on a fresh world on the fake host (FsKeysT2); server/gkm's T3 runs the same
// builders on the local stack.

import (
	"testing"
)

func TestFsKeysUpkeepUnderRHoldsThroughTheRetentionHorizon(t *testing.T) {
	FsKeysScheduleKeyUpkeepUnderR(t, FsKeysT2(t))
}

func TestFsKeysUpkeepAParkedDevicesReaderKeyWaitsForItsLift(t *testing.T) {
	FsKeysScheduleParkedReaderKeyWaits(t, FsKeysT2(t))
}
