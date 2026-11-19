//go:build sidecar_testhooks

// FS-108 on real engines (§11.14's tombstones and roll-up rows; FI-18, FI-20; SEARCH-M10-36): a removal's tombstone and
// two roll-ups on the evs world at format 2 (fs74.go's settings), each writer's in-ref IndexWriter (SEARCH-M10-13)
// writing its head beside its content push and SEARCH-M10-11's roller reaching evs through EvsRepo, through evsservice's
// engine on T2's fakes and, through server's evshost, on T3's stores; the index read back through EvsRepo's verifying
// reader, as every index builder reads it.
//
//	Fs108RemovalOnEvs  writerA's notes D and E fill a bucket that, 100 days on, writerA rolls into all; writerA removes
//	                   D, its push writing a tombstone into writerA's head in a new bucket, which masks all's row: D is
//	                   live nowhere; the purge on and evacuation's sweep a day on leave that as it was; 100 days on
//	                   writerB rolls the new bucket up, dropping all's row and then the tombstone, so nothing of D is
//	                   left in the index while E stays live in all
//
// The rest of FS-108 (the variants, sealing, merging and slot reuse under a tombstone, the skewed writers' promotion,
// the decoder's refusals and a fresh device's search) runs on the search world (fs108_test.go) until merges and a
// device's sync run over EvsRepo (SEARCH-M10-19's source). The index's seams here are the root's under
// sidecar_testhooks alone, so the case is registered only on that build.

package fault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

var Fs108 = Register("FS-108", "", []Tier{TierT2, TierT3}, Fs108RemovalOnEvs)

// See the file header.
func Fs108RemovalOnEvs(net *Net) *Schedule {
	world := NewEvsWorld(net, fs74EvsWorldSettings())
	const removed, kept = "notes/marten.md", "notes/heron.md"
	read := func(ctx context.Context, path string) (uint64, []sidecar.SearchTestHeld, *sidecar.SearchTestEvsIndex, error) {
		reader := world.Device("reader").Repo
		index, err := sidecar.ReadSearchTestEvsIndex(ctx, reader, nil, fs74NoAdmin)
		if err != nil {
			return 0, nil, nil, err
		}
		key, err := sidecar.SearchTestEvsDocKey(ctx, reader, world.RefId(), path)
		if err != nil {
			return 0, nil, nil, err
		}
		held, err := sidecar.SearchTestEvsFilesHolding(ctx, reader, nil, path)
		if err != nil {
			return 0, nil, nil, err
		}
		return index.Live[key], held, index, nil
	}
	var masked []sidecar.SearchTestHeld
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: fs74InstallIndexWriters(world, "writerA", "writerB")},
		{Actor: "writerA", Action: world.Write("writerA", removed, []byte("Marten\nmarten martenold\n"))},
		{Actor: "writerA", Action: world.Write("writerA", kept, []byte("Heron\nheron at the tideline\n"))},
		// past the bucket's window and the next one, so it is expired, and rolled into all
		{Advance: 100 * 24 * time.Hour},
		{Actor: "writerA", Action: fs75RollUpOnEvs(world, "writerA")},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			live, held, index, err := read(ctx, removed)
			if err != nil {
				return err
			}
			if live == 0 || len(held) != 1 || !strings.Contains(held[0].Path, "/a/") || len(index.Buckets) != 0 {
				return fmt.Errorf("after the roll-up D is live at %d in %v, buckets %v", live, held, index.Buckets)
			}
			return nil
		}},
		// D removed in a new bucket: the tombstone in writerA's head masks all's row
		{Actor: "writerA", Action: world.Remove("writerA", removed)},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			live, held, _, err := read(ctx, removed)
			if err != nil {
				return err
			}
			tombstone := false
			for _, file := range held {
				tombstone = tombstone || !file.Live && strings.Contains(file.Path, "/w/")
			}
			if live != 0 || !tombstone {
				return fmt.Errorf("after the removal D is live at %d, held in %v", live, held)
			}
			masked = held
			return nil
		}},
		// the purge on, and evacuation's sweep a day on: the index reads the same
		{Actor: "admin", Action: world.SetFormat2Modes(&EvsWorldFormat2Settings{Purge: "on", Drop: "observe"})},
		{Advance: 26 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			live, held, _, err := read(ctx, removed)
			if err != nil {
				return err
			}
			if live != 0 || fmt.Sprint(held) != fmt.Sprint(masked) {
				return fmt.Errorf("after the sweep D is live at %d, held in %v, before it %v", live, held, masked)
			}
			return nil
		}},
		// the new bucket rolled: all's row and then the tombstone go
		{Advance: 100 * 24 * time.Hour},
		{Actor: "writerB", Action: fs75RollUpOnEvs(world, "writerB")},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			live, held, _, err := read(ctx, removed)
			if err != nil {
				return err
			}
			if live != 0 || 0 < len(held) {
				return fmt.Errorf("after the new bucket's roll-up D is live at %d, held in %v", live, held)
			}
			keptLive, _, _, err := read(ctx, kept)
			if err != nil {
				return err
			}
			if keptLive == 0 {
				return fmt.Errorf("the roll-ups left E out of the index")
			}
			return nil
		}},
	}
	return &Schedule{Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
