//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package fault

// FS-86's M6 case on T2 (§22.8, D-TEST-17; §16.11's cost table, D-MCP-31; RECORD-M6-24): the directory's scale row on
// announce entries, as a schedule over sidecartest's directory load. A small team's day runs on the fake clock, its
// announcing daemons' entries sealed and signed for real and its following daemons on the real client, and each step
// is one run of that same day:
//
//	day       the client as it is: every measured reader-day and the team-day within 1.25 times the golden schedule's
//	          (sidecartest.DirectoryCostOracle), streams read 64 to a request, the stream pushes' p99 within the
//	          table's ceiling, a cold desktop within the oracle's bytes, and a cold phone, whose state passes its
//	          metered cap, showing partial coverage that names what is left and completing once allowed
//	mutants   one at a time, a client that reads one moved stream to a request, one that reads unmoved streams again,
//	          and one that fetches unchanged notices again: each fails the oracle's check
//	delays    200 ms injected on every head PUT: the run fails the p99 ceiling
//
// Each refusal's twin is the day step, which passes the same check on the same plan. After every step, FI-14 as this
// case can hold it without evs's governor: the NVMe bytes each run's pushes cost one metadata drive, priced by
// §11.13's directory rows, stay within the table's M6 row for the team's size.
//
// Not here: the table's own columns, a day at 500 members and the Team limit's and the stress case's days, which are
// sidecartest's own tests (directory_cost_oracle_test.go) because a row's schedule runs under every explorer seed;
// the 26 h physical run, the physical peak hours with 3x bursts and the governor's FI-14 on T3's stores (server's
// sidecar_directory_load_t3_test.go); 400 days of retention; and the card case at the later of M6-out and M10-out.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs86M6 = Register("FS-86", "announce-entries", []Tier{TierT2}, Fs86DirectoryScale)

// What the steps of one schedule share: every run so far.
type fs86State struct {
	settings  *sidecartest.DirectoryLoadSettings
	directory *sidecar.SidecarDirectorySettings
	ceilings  *sidecartest.DirectoryLoadCeilings
	results   []*sidecartest.DirectoryLoadResult
}

// One run of the day: store nil is the store model with no fault.
func (self *fs86State) run(ctx context.Context, store *sidecartest.DirectoryLoadStoreSettings, options *sidecartest.DirectoryLoadOptions) (*sidecartest.DirectoryLoad, *sidecartest.DirectoryLoadResult, error) {
	plan, err := sidecartest.NewDirectoryLoadPlan(self.settings, sidecartest.DefaultClockStart().UnixMilli())
	if err != nil {
		return nil, nil, err
	}
	fakes, err := sidecartest.NewDirectoryLoadFakes(ctx, plan, nil, nil, store)
	if err != nil {
		return nil, nil, err
	}
	load, err := sidecartest.NewDirectoryLoad(plan, fakes.Seams(), options)
	if err != nil {
		return nil, nil, err
	}
	result, err := load.Run(ctx)
	if err != nil {
		return nil, nil, err
	}
	if violations := fakes.Streams.Violations(); 0 < len(violations) {
		return nil, nil, fmt.Errorf("the streams' store was violated: %v", violations)
	}
	self.results = append(self.results, result)
	return load, result, nil
}

// FS-86's M6 case: see the file header.
func Fs86DirectoryScale(net *Net) *Schedule {
	state := &fs86State{ceilings: sidecartest.DefaultDirectoryLoadCeilings()}
	state.settings = sidecartest.DefaultDirectoryLoadSettings()
	state.settings.MemberCount = 16
	state.settings.SampledReaderCount = 2
	// a cap a small team's day passes
	state.directory = sidecar.DefaultSidecarSettings().Directory
	state.directory.PhoneMeteredByteCount = 128 * 1024
	state.settings.Directory = state.directory

	mutant := func(mutant sidecartest.DirectoryLoadMutant) *Step {
		return &Step{Actor: "daemons", Action: func(ctx context.Context, net *Net) error {
			load, result, err := state.run(ctx, nil, &sidecartest.DirectoryLoadOptions{NoCold: true, Mutant: mutant})
			if err != nil {
				return err
			}
			if errs := result.CheckOracle(load.Oracle()); len(errs) == 0 {
				return fmt.Errorf("%s passed the golden schedule: a reader-day %s", mutant, result.MeanReaderDay())
			}
			// it costs more and reads nothing wrong
			if 0 < len(result.Alarms) {
				return fmt.Errorf("%s raised %d alarms", mutant, len(result.Alarms))
			}
			return nil
		}}
	}
	return &Schedule{
		Steps: []*Step{
			{Actor: "daemons", Action: func(ctx context.Context, net *Net) error {
				load, result, err := state.run(ctx, nil, nil)
				if err != nil {
					return err
				}
				if errs := result.CheckOracle(load.Oracle()); 0 < len(errs) {
					return fmt.Errorf("the golden schedule: %w", errors.Join(errs...))
				}
				if errs := result.CheckCeilings(state.ceilings); 0 < len(errs) {
					return fmt.Errorf("the ceilings: %w", errors.Join(errs...))
				}
				if errs := result.CheckPhone(load.Oracle(), state.directory); 0 < len(errs) {
					return fmt.Errorf("the cold phone: %w", errors.Join(errs...))
				}
				if len(result.ReaderIds) != state.settings.SampledReaderCount || len(result.Measured.ReaderDays) != len(result.ReaderIds) {
					return fmt.Errorf("%d readers measured over %d reader-days", len(result.ReaderIds), len(result.Measured.ReaderDays))
				}
				if result.Phone.Metered.Complete || result.Phone.Metered.Waiting != sidecar.DirectoryCoverageWaitingMetered {
					return fmt.Errorf("a phone whose state is %d bytes shows %+v", result.StreamByteCount, result.Phone.Metered)
				}
				if result.ColdDesktopMeasured == nil || result.ColdDesktopMeasured.ByteCount < result.StreamByteCount {
					return fmt.Errorf("a cold desktop read %v of a state of %d bytes", result.ColdDesktopMeasured, result.StreamByteCount)
				}
				return nil
			}},
			mutant(sidecartest.DirectoryLoadMutantOneReadPerStream),
			mutant(sidecartest.DirectoryLoadMutantRereadUnmovedStreams),
			mutant(sidecartest.DirectoryLoadMutantRefetchUnchangedNotices),
			{Actor: "store", Action: func(ctx context.Context, net *Net) error {
				store := sidecartest.DefaultDirectoryLoadStoreSettings()
				store.HeadPutDelay = 200 * time.Millisecond
				_, result, err := state.run(ctx, store, &sidecartest.DirectoryLoadOptions{NoCold: true})
				if err != nil {
					return err
				}
				errs := result.CheckCeilings(state.ceilings)
				if len(errs) == 0 || !strings.Contains(errs[0].Error(), "p99") {
					return fmt.Errorf("200 ms on every head PUT passed the ceilings: p99 %s", sidecartest.DirectoryLoadP99(result.StreamPushLatencies))
				}
				return nil
			}},
		},
		Check: []Invariant{NewInvariant("FI-14/directory-drive-bytes", func(ctx context.Context, oracle *Oracle) error {
			// the table's NVMe row is 3 MiB a member a day in each of its columns; the first stands for a team of any size
			row := sidecartest.DefaultDirectoryCostTableM6()[0]
			for i, result := range state.results {
				allowed := state.ceilings.Tolerance * float64(row.DriveDayByteCount) * float64(state.settings.MemberCount) / float64(row.MemberCount) * float64(state.settings.DayCount)
				if priced := result.DriveByteCount(state.ceilings); allowed < float64(priced) {
					return fmt.Errorf("run %d's pushes cost a drive %d bytes, past the table's %.0f for %d members", i, priced, allowed, state.settings.MemberCount)
				}
			}
			return nil
		})},
		Tiers: []Tier{TierT2},
	}
}

func TestFs86M6(t *testing.T) {
	RunRow(t, "FS-86", "announce-entries", nil)
}
