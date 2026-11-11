package gkmschedule

// T2 of the schedules in copy.go, each on a fresh world on the fake host (FsKeysT2).

import (
	"testing"
)

func TestFsKeysCopyACopiedAgentKeychainOpensNothingPastItsBound(t *testing.T) {
	FsKeysScheduleCopiedAgentKeychain(t, FsKeysT2(t))
}

func TestFsKeysCopyAnAdvertisementValidPastSevenDaysIsRefused(t *testing.T) {
	FsKeysScheduleLongAdvertisement(t, FsKeysT2(t))
}
