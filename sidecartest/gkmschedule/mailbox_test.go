package gkmschedule

// T2 of the schedules in mailbox.go, each on a fresh world on the fake host (FsKeysT2); server/gkm's T3 runs the
// same builders on the local stack.

import (
	"testing"
)

func TestFsKeysMailboxTheReceiverFollowsTheDropKeyAndReadsNothing(t *testing.T) {
	FsKeysScheduleMailboxReceiver(t, FsKeysT2(t))
}

func TestFsKeysMailboxTheReceiverRefusesAnUncoveredDropKeyAfterARemoval(t *testing.T) {
	FsKeysScheduleMailboxReceiverAfterARemoval(t, FsKeysT2(t))
}

func TestFsKeysMailboxAWriterBackRenewsTheDropKeyBeforeItLapses(t *testing.T) {
	FsKeysScheduleMailboxRenewal(t, FsKeysT2(t))
}

func TestFsKeysMailboxReadersOfflinePastTheDropKeysLife(t *testing.T) {
	FsKeysScheduleMailboxReadersOffline(t, FsKeysT2(t))
}
