package gkmschedule

// KEYS-M6-03's Team-scale schedules on T2: FS-87's key legs and S4b's, S3b's key part, and §22.7's seats row at
// reduced scale in every run and at 5,000 admissions behind -fs-keys-team-full.

import (
	"flag"
	"testing"
)

var fsKeysTeamFull = flag.Bool("fs-keys-team-full", false, "run §22.7's seats row at 5,000 admissions")

func TestFsKeysTeamAMemberRevokeReachesLeavesAndWraps(t *testing.T) {
	FsKeysScheduleDirectoryMemberRemoval(t, FsKeysT2(t))
}

func TestFsKeysTeamAMemberAdmitAddsAndWrapsOnlyReaders(t *testing.T) {
	FsKeysScheduleDirectoryMemberAdd(t, FsKeysT2(t))
}

func TestFsKeysTeamSeatsPastTheFirstThousand(t *testing.T) {
	settings := ReducedFsKeysTeamSettings()
	if *fsKeysTeamFull {
		settings = DefaultFsKeysTeamSettings()
	}
	FsKeysScheduleTeamSeats(t, FsKeysT2(t), settings)
}
