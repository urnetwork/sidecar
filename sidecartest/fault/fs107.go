//go:build sidecar_testhooks

// FS-107 on real engines (§11.14's dependency and reads rows; owner decision 584; FI-18; SEARCH-M10-36): full entries on
// the evs world at format 2 (fs74.go's settings), each writer's in-ref IndexWriter (SEARCH-M10-13) planning its head
// beside its content push, through evsservice's engine on T2's fakes and, through server's evshost, on T3's stores;
// the index read back through EvsRepo's verifying reader, as every index builder reads it.
//
//	Fs107FullEntriesOnEvs  writerA's note D is created and edited twice, each push's full entry replacing the last in
//	                       writerA's head, so one file holds D, at its newest version, live; the purge is turned on
//	                       and evacuation's sweep runs a day on, and the index reads the same; writerB edits D, its full
//	                       entry in writerB's own head, and the newest version is the one live, writerA's older entry
//	                       standing beside it and masked by version; the sweep runs again and the index reads the same
//
// The rest of FS-107 (seals, large entries, merges, slot reuse, backfills, DROPs, the reserved kind and a fresh device's
// search) runs on the search world (fs107_test.go), whose store stands in for evs, until merges, backfills and a
// device's sync run over EvsRepo (SEARCH-M10-19's source). The index's seams here are the root's under
// sidecar_testhooks alone, so the case is registered only on that build.

package fault

import (
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

var Fs107 = Register("FS-107", "", []Tier{TierT2, TierT3}, Fs107FullEntriesOnEvs)

// D's path on the evs world.
const fs107EvsPath = "notes/field-log.md"

// What a reader holds of D on the evs world: its live version, and each file holding an entry of it.
type fs107EvsHeld struct {
	live  uint64
	files []sidecar.SearchTestHeld
}

// See the file header.
func Fs107FullEntriesOnEvs(net *Net) *Schedule {
	world := NewEvsWorld(net, fs74EvsWorldSettings())
	read := func(ctx context.Context) (*fs107EvsHeld, error) {
		reader := world.Device("reader").Repo
		index, err := sidecar.ReadSearchTestEvsIndex(ctx, reader, nil, fs74NoAdmin)
		if err != nil {
			return nil, err
		}
		key, err := sidecar.SearchTestEvsDocKey(ctx, reader, world.RefId(), fs107EvsPath)
		if err != nil {
			return nil, err
		}
		files, err := sidecar.SearchTestEvsFilesHolding(ctx, reader, nil, fs107EvsPath)
		if err != nil {
			return nil, err
		}
		return &fs107EvsHeld{live: index.Live[key], files: files}, nil
	}
	var afterA, afterB *fs107EvsHeld
	// the index as it read before the sweep, which it must read the same after
	same := func(label string, want **fs107EvsHeld) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			held, err := read(ctx)
			if err != nil {
				return err
			}
			if held.live != (*want).live || fmt.Sprint(held.files) != fmt.Sprint((*want).files) {
				return fmt.Errorf("%s the index holds D live at %d in %v, before it %d in %v", label, held.live, held.files, (*want).live, (*want).files)
			}
			return nil
		}
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: fs74InstallIndexWriters(world, "writerA", "writerB")},
		{Actor: "writerA", Action: world.Write("writerA", fs107EvsPath, []byte("Field log\nkestrel osprey\n"))},
		{Actor: "writerA", Action: world.Write("writerA", fs107EvsPath, []byte("Field log\nkestrel plover\n"))},
		{Actor: "writerA", Action: world.Write("writerA", fs107EvsPath, []byte("Field log\nkestrel quail\n"))},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			held, err := read(ctx)
			if err != nil {
				return err
			}
			if held.live == 0 || len(held.files) != 1 || held.files[0].Version != held.live || !held.files[0].Live {
				return fmt.Errorf("after three edits in one head the index holds D live at %d in %v", held.live, held.files)
			}
			afterA = held
			return nil
		}},
		// the purge on, and evacuation's sweep a day on, so no replaced version of D's head is left to read
		{Actor: "admin", Action: world.SetFormat2Modes(&EvsWorldFormat2Settings{Purge: "on", Drop: "observe"})},
		{Advance: 26 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "reader", Action: same("after the sweep", &afterA)},
		{Actor: "writerB", Action: world.Write("writerB", fs107EvsPath, []byte("Field log\nkestrel vireo\n"))},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			held, err := read(ctx)
			if err != nil {
				return err
			}
			if held.live <= afterA.live {
				return fmt.Errorf("after writerB's edit the index holds D live at %d, not above writerA's %d", held.live, afterA.live)
			}
			newest, older := 0, 0
			for _, file := range held.files {
				switch file.Version {
				case held.live:
					newest += 1
				case afterA.live:
					older += 1
				default:
					return fmt.Errorf("after writerB's edit %s holds D at %d", file.Path, file.Version)
				}
			}
			if newest != 1 || older != 1 {
				return fmt.Errorf("after writerB's edit the index holds D in %v", held.files)
			}
			afterB = held
			return nil
		}},
		{Advance: 26 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "reader", Action: same("after the second sweep", &afterB)},
	}
	return &Schedule{Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
