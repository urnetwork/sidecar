//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

package fault

// FS-86's card case on T2 (§22.8, D-TEST-17; §16.11's cost table and sync row, D-MCP-31; RECORD-M10-07): the
// directory's scale row in M10's form, as a schedule over sidecartest's directory load. A small team's day runs on the
// fake clock at format 2, each announcing daemon's run starts, ends and renewals written as its signed card on the one
// cards ref and its following daemons on the real client, and each step is one run of that same day:
//
//	day       the client as it is: every measured reader-day and the team-day within 1.25 times the golden schedule's
//	          (sidecartest.DirectoryCostOracle: the cards ref's statements after the pin, each changed card's newest
//	          version, 64 paths to a read, no index head fetched), the cards ref's commits within the table's
//	          ceilings at the peak rate and at 3x bursts, and a cold desktop within the oracle's bytes
//	mutants   one at a time, a client that fetches every changed version of a card and not its newest alone, one that
//	          fetches the index heads its cards reproduce, and one that fetches unchanged cards again: each fails the
//	          oracle's check. Coalescing saves where a card changed more than once between a reader's syncs, so its
//	          mutant and its twin run with readers that sync every four hours
//	delays    200 ms injected on every head PUT: the run fails the cards ref's p99 ceiling
//
// Each refusal's twin is a day step, which passes the same check on the same plan. After every step, FI-14 as this
// case can hold it without evs's governor: the NVMe bytes each run's pushes cost one metadata drive, priced by
// §11.13's team directory push rows, stay within the table's M10 row for the team's size. Those rows and their
// counts (DirectoryLoadResult.DrivePushes) are what the directory's pushes bring to format 2's computed write gate.
//
// Not here: the table's own columns, a day at 500 members and the Team limit's and the stress case's days, which are
// sidecartest's own tests (directory_cost_cards_test.go); the index itself, whose heads the load prices and does not
// store, so a forged head's fetch and alarm is directory_index_test.go's; the physical peak hour with 3x bursts,
// FOLD_BEHIND and the governor's FI-14 on T3's stores (server's sidecar_directory_load_t3_test.go); and the cold phone,
// which is the M6 case's.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs86Cards = Register("FS-86", "cards", []Tier{TierT2}, Fs86DirectoryCards)

// What the steps of one schedule share: every run so far.
type fs86CardsState struct {
	ceilings *sidecartest.DirectoryLoadCeilings
	results  []*sidecartest.DirectoryLoadResult
}

// A small team's day in M10's form: sparse true is its readers syncing every four hours and at no view.
func fs86CardsSettings(sparse bool) *sidecartest.DirectoryLoadSettings {
	settings := sidecartest.DefaultDirectoryLoadSettings()
	settings.Cards = true
	settings.MemberCount = 16
	settings.SampledReaderCount = 2
	if sparse {
		settings.SessionSyncInterval = 4 * time.Hour
		settings.IdleSyncInterval = 4 * time.Hour
		settings.ViewSyncsPerDaemonDay = 0
	}
	return settings
}

// One run of the day by settings: store nil is the store model with no fault.
func (self *fs86CardsState) run(ctx context.Context, settings *sidecartest.DirectoryLoadSettings, store *sidecartest.DirectoryLoadStoreSettings, options *sidecartest.DirectoryLoadOptions) (*sidecartest.DirectoryLoad, *sidecartest.DirectoryLoadResult, error) {
	plan, err := sidecartest.NewDirectoryLoadPlan(settings, sidecartest.DefaultClockStart().UnixMilli())
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

// FS-86's card case: see the file header.
func Fs86DirectoryCards(net *Net) *Schedule {
	state := &fs86CardsState{ceilings: sidecartest.DefaultDirectoryLoadCeilings()}

	// the client as it is on sparse's plan, held to the golden schedule
	day := func(ctx context.Context, sparse bool, options *sidecartest.DirectoryLoadOptions) (*sidecartest.DirectoryLoad, *sidecartest.DirectoryLoadResult, error) {
		load, result, err := state.run(ctx, fs86CardsSettings(sparse), nil, options)
		if err != nil {
			return nil, nil, err
		}
		if errs := result.CheckOracle(load.Oracle()); 0 < len(errs) {
			return nil, nil, fmt.Errorf("the golden schedule: %w", errors.Join(errs...))
		}
		if 0 < len(result.Alarms) {
			return nil, nil, fmt.Errorf("the client as it is raised %d alarms", len(result.Alarms))
		}
		return load, result, nil
	}
	mutant := func(mutant sidecartest.DirectoryLoadMutant, sparse bool) *Step {
		return &Step{Actor: "daemons", Action: func(ctx context.Context, net *Net) error {
			if sparse {
				// the twin on the same plan
				if _, _, err := day(ctx, true, &sidecartest.DirectoryLoadOptions{NoCold: true}); err != nil {
					return err
				}
			}
			load, result, err := state.run(ctx, fs86CardsSettings(sparse), nil, &sidecartest.DirectoryLoadOptions{NoCold: true, Mutant: mutant})
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
				load, result, err := day(ctx, false, &sidecartest.DirectoryLoadOptions{NoPhone: true})
				if err != nil {
					return err
				}
				if errs := append(result.CheckCeilings(state.ceilings), result.CheckCardCeilings(state.ceilings)...); 0 < len(errs) {
					return fmt.Errorf("the ceilings: %w", errors.Join(errs...))
				}
				if len(result.ReaderIds) != 2 || len(result.Measured.ReaderDays) != len(result.ReaderIds) {
					return fmt.Errorf("%d readers measured over %d reader-days", len(result.ReaderIds), len(result.Measured.ReaderDays))
				}
				cards, changes := 0, 0
				for _, event := range result.Schedule.Events {
					if event.Kind == sidecartest.DirectoryCostEventCard {
						cards += 1
						if event.IndexEntry {
							changes += 1
						}
					}
				}
				if changes == 0 || cards <= changes {
					return fmt.Errorf("%d card pushes, %d of them content changes: the day holds no renewal or no change", cards, changes)
				}
				if result.ColdDesktopMeasured == nil || result.ColdDesktopMeasured.ByteCount == 0 || float64(result.ColdDesktopExpected.ByteCount)*load.Oracle().Settings().Tolerance < float64(result.ColdDesktopMeasured.ByteCount) {
					return fmt.Errorf("a cold desktop read %v where the golden schedule has %v", result.ColdDesktopMeasured, result.ColdDesktopExpected)
				}
				return nil
			}},
			mutant(sidecartest.DirectoryLoadMutantNoCardCoalescing, true),
			mutant(sidecartest.DirectoryLoadMutantNoHeadReproduction, false),
			mutant(sidecartest.DirectoryLoadMutantRefetchUnchangedCards, false),
			{Actor: "store", Action: func(ctx context.Context, net *Net) error {
				store := sidecartest.DefaultDirectoryLoadStoreSettings()
				store.HeadPutDelay = 200 * time.Millisecond
				_, result, err := state.run(ctx, fs86CardsSettings(false), store, &sidecartest.DirectoryLoadOptions{NoCold: true})
				if err != nil {
					return err
				}
				errs := result.CheckCardCeilings(state.ceilings)
				if len(errs) == 0 || !strings.Contains(errs[0].Error(), "p99") {
					return fmt.Errorf("200 ms on every head PUT passed the cards ref's ceilings: p99 %s", sidecartest.DirectoryLoadP99(result.CardCommits(1).Latencies))
				}
				return nil
			}},
		},
		Check: []Invariant{NewInvariant("FI-14/directory-card-drive-bytes", func(ctx context.Context, oracle *Oracle) error {
			// the table's NVMe row is 1.8 MiB a member a day in each of its columns; the first stands for a team of any size
			row := sidecartest.DefaultDirectoryCostTableM10()[0]
			for i, result := range state.results {
				settings := result.Plan.Settings
				allowed := state.ceilings.Tolerance * float64(row.DriveDayByteCount) * float64(settings.MemberCount) / float64(row.MemberCount) * float64(settings.DayCount)
				if priced := result.DriveByteCount(state.ceilings); priced == 0 || allowed < float64(priced) {
					return fmt.Errorf("run %d's pushes cost a drive %d bytes, where the table has %.0f for %d members", i, priced, allowed, settings.MemberCount)
				}
			}
			return nil
		})},
		Tiers: []Tier{TierT2},
	}
}

func TestFs86Cards(t *testing.T) {
	RunRow(t, "FS-86", "cards", nil)
}
