//go:build sidecar_testhooks

// FS-75 on real engines (§11.14's roll-up, lock, crash and idempotent rows; I-EVS-11, FI-20; SEARCH-M10-35): the
// roll-up of an expired bucket on the evs world at format 2 (fs74.go's settings), SEARCH-M10-11's roller reaching
// evs through EvsRepo as every index builder does (evs_index_store_evs.go), through evsservice's engine on T2's fakes
// and, through server's evshost, on T3's stores.
//
//	Fs75RollUpKilledOnEvs  writerA's and writerB's in-ref pushes fill a bucket; 100 days on, writerA rolls it up and
//	                       is killed at its built barrier, holding the lock; past the lock's term and grace writerB
//	                       rolls the bucket, and one roll-up stands: the bucket gone from the ref, all rolled past it
//	                       and holding every document live, and another roll-up finding nothing to roll
//
// FS-75 is on §22.8's unknown list, so RunRow also runs the case with each of its writes' answers lost; a roll-up
// whose answer was lost is run again, as the schedule's next tick would run it, a runner retaking its own lock. The
// index's seams here are the root's under sidecar_testhooks alone (search_evs_testhooks.go), so the case is registered
// only on that build. The rest of FS-75 runs on the search world (fs75_test.go).

package fault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

var Fs75 = Register("FS-75", "", []Tier{TierT2, TierT3}, Fs75RollUpKilledOnEvs)

// A step action: device rolls the ref's oldest expired bucket up, running again after an error, as the schedule's
// next tick would, until a roll-up commits or finds the bucket rolled; a runner beside another's held lock fails.
func fs75RollUpOnEvs(world *EvsWorld, device string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		evsDevice := world.Device(device)
		if evsDevice == nil || evsDevice.Repo == nil {
			return fmt.Errorf("device %s is not started", device)
		}
		errs := []error{}
		for range 8 {
			result, err := sidecar.RollUpSearchTestEvs(ctx, evsDevice.Repo, nil, evsDevice.Signer.SidecarId, fs74NoAdmin)
			switch {
			case err == nil && result.Skipped == "locked":
				return fmt.Errorf("%s's roll-up found another runner's lock held", device)
			case err == nil:
				return nil
			case ctx.Err() != nil:
				return ctx.Err()
			}
			errs = append(errs, err)
		}
		return fmt.Errorf("%s's roll-up: %w", device, errors.Join(errs...))
	}
}

// See the file header.
func Fs75RollUpKilledOnEvs(net *Net) *Schedule {
	world := NewEvsWorld(net, fs74EvsWorldSettings())
	notes := []struct {
		device string
		path   string
		text   string
	}{
		{device: "writerA", path: "notes/harbor.md", text: "the harbor at noon\n"},
		{device: "writerB", path: "notes/lighthouse.md", text: "a lighthouse keeper's log\n"},
		{device: "writerA", path: "notes/cormorant.md", text: "a cormorant on the pier\n"},
	}
	read := func(ctx context.Context) (*sidecar.SearchTestEvsIndex, error) {
		return sidecar.ReadSearchTestEvsIndex(ctx, world.Device("reader").Repo, nil, fs74NoAdmin)
	}
	var rolled uint32
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: fs74InstallIndexWriters(world, "writerA", "writerB")},
	}
	for _, note := range notes {
		steps = append(steps, &Step{Actor: note.device, Action: world.Write(note.device, note.path, []byte(note.text))})
	}
	steps = append(steps, []*Step{
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			index, err := read(ctx)
			if err != nil {
				return err
			}
			if len(index.Buckets) != 1 {
				return fmt.Errorf("the writers' pushes made buckets %v", index.Buckets)
			}
			rolled = index.Buckets[0]
			return nil
		}},
		// past the bucket's window and the next one, so it is expired
		{Advance: 100 * 24 * time.Hour},
		{Actor: "writerA", Action: fs75RollUpOnEvs(world, "writerA"), Background: true},
		{Actor: "writerA", Await: "evs.index.rollup.built"},
		{Actor: "writerA", Kill: true},
		// the dead holder's lock lapses at its term and grace
		{Advance: 45 * time.Minute},
		{Actor: "writerB", Action: fs75RollUpOnEvs(world, "writerB")},
		{Actor: "reader", Action: func(ctx context.Context, net *Net) error {
			index, err := read(ctx)
			if err != nil {
				return err
			}
			if 0 < len(index.Buckets) || index.RolledThroughDay < rolled || index.AllShardCount == 0 {
				return fmt.Errorf("after the roll-up: buckets %v, rolled through %d of %d, %d all shards", index.Buckets, index.RolledThroughDay, rolled, index.AllShardCount)
			}
			reader := world.Device("reader").Repo
			for _, note := range notes {
				key, err := sidecar.SearchTestEvsDocKey(ctx, reader, world.RefId(), note.path)
				if err != nil {
					return err
				}
				if index.Live[key] == 0 {
					return fmt.Errorf("the roll-up left %s out of all: %v", note.path, index.Files)
				}
			}
			return nil
		}},
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			evsDevice := world.Device("writerB")
			again, err := sidecar.RollUpSearchTestEvs(ctx, evsDevice.Repo, nil, evsDevice.Signer.SidecarId, fs74NoAdmin)
			if err != nil || again.Version != 0 {
				return fmt.Errorf("a second roll-up committed %+v: %v", again, err)
			}
			return nil
		}},
	}...)
	return &Schedule{Steps: steps, Tiers: []Tier{TierT2, TierT3}}
}
