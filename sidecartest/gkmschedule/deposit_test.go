package gkmschedule

// T2 of the schedules in deposit.go, each on a fresh world on the fake host (FsKeysT2); server/gkm's T3 runs the
// same builders on the local stack.

import (
	"testing"
)

func TestFsKeysDepositADepositOnlyPrincipalFollowsTheDropKeyAndReadsNothing(t *testing.T) {
	FsKeysScheduleDepositor(t, FsKeysT2(t))
}

func TestFsKeysDepositADepositorRefusesAnOlderGenRotateAfterARemoval(t *testing.T) {
	FsKeysScheduleDepositorReplay(t, FsKeysT2(t))
}
