// FS-92 (a) with a hold that outlasts the drop table's 30 days (Fs92HoldOutlastsTheDropTable; owner decision 643,
// QD-1113; §11.13's table row, §21.9's expiry row, FI-13c, D-TRUST-7): a 90-day §2703(f) order, as every §2703(f) or
// §2258A hold outlasts the 30 days an ended drop's entry is kept. The schedule's steps from the job's move to held are
// fs92OutlastingSteps; the rest is fs92Schedule's (a).

package fault

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

// Steps after the job moved x.txt's drop to held under the 90-day order. 32 days on, the held job's wake writes the
// table, which keeps the held entry for its deletions, while the admin's listing has let the drop go, as its done
// twin's entry would have gone, and the reader still reads its versions dropped, nothing deleted. At the order's
// deadline api's pass ends it and the job's next round deletes every held candidate after an incremental mark and
// verify: the drop moves to done and leaves the table at that write, its 30 days from the move to held long past, so
// it reads executed, with no entry, void record or listing, and the stored count does not move again.
func fs92OutlastingSteps(history *fs92History, stored *EvsWorldStoredMark, job func(background bool) *Step) []*Step {
	world, holds := history.world, history.holds
	return []*Step{
		{Actor: "check", Action: history.expectDeleted(0)},
		// past the 30 days an ended drop's entry is kept, counted from the end of the day it moved to held, and inside
		// the order's 90
		{Advance: 32 * 24 * time.Hour},
		job(false),
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateHeld)},
		{Actor: "admin", Action: world.ListingOmits("admin", "x.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "check", Action: history.expectDeleted(0)},
		{Actor: "check", Action: world.StoredFell(stored, true)},
		// api's expiry ends the order at its 90 days
		{Actor: "abuse", Action: holds.ToExpiry("order")},
		{Actor: "abuse", Action: holds.Pass("order")},
		{Actor: "check", Action: holds.Swept()},
		{Advance: time.Hour},
		job(false),
		// no entry and no void record: executed, its entry gone at the job's end
		{Actor: "check", Action: world.ExpectDropState("x.txt", 0)},
		{Actor: "admin", Action: world.ListingOmits("admin", "x.txt")},
		{Actor: "check", Action: history.expectDeleted(3)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		// once, at move-to-held: the later DELETEs report nothing
		{Actor: "check", Action: world.StoredFell(stored, true)},
	}
}

// A step action: device lists the repo's drops, and none is path's: its drop has left the listing, as an executed
// drop's does once the 30 days its entry is kept have passed (owner decision 643).
func (self *EvsWorld) ListingOmits(device string, path string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		drop := self.DropOf(path)
		if drop == nil {
			return fmt.Errorf("the world holds no drop of %q", path)
		}
		drops, err := self.Device(device).Repo.Drops(ctx, &sidecar.EvsDropsArgs{KnownPaths: []string{path}})
		if err != nil {
			return fmt.Errorf("%s's listing of the drops: %w", device, err)
		}
		for _, listed := range drops {
			if bytes.Equal(listed.Status.GetDropId(), drop.Push.DropId.Bytes()) {
				return fmt.Errorf("%s's listing still names %q's drop, %s", device, path, listed.Status.GetState())
			}
		}
		return nil
	}
}
