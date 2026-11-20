// FS-92 (a) with a second DROP made while the hold stands (QD-1127; §11.13's table, holds and delete rows, owner
// decisions 93 and 184, FI-13c): a 90-day §2703(f) order covers the network, x.txt's drop moves to held, and y.txt's
// drop, committed after that, runs as its no-hold twin's does. A held job gives up the drop table's one job slot, so
// y.txt's job starts at once: the admin's listing reads y.txt's drop pending, then executing while its job waits for
// evacuation's horizon, then done once its deletes meet the hold and move its candidates to held, the stored count
// falling by their stored sizes once, as the twin's falls when it deletes them. At the order's deadline api's pass ends
// it, and each held job takes the slot back in turn, x.txt's first, deleting what it held after an incremental mark
// and verify, the stored count not moving again; both drops leave the table at their jobs' ends, their 30 days from
// the move to held long past. The twin, Fs92SecondDropNoHold, places no hold and deletes each drop's candidates at
// once. Fs92SecondDropTwins runs both and compares the admin's listings and the bill, step by step, while the hold
// stands.

package fault

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One path's versions as its writes committed them: the segments a drop of its history lists.
type fs92PathVersions struct {
	world *EvsWorld
	path  string

	stateLock sync.Mutex
	versions  []*EvsWorldCommittedEntry
}

// Steps: path written count times by admin, each version an uploaded segment of its own, kept.
func (self *fs92PathVersions) writes(count int) []*Step {
	steps := []*Step{}
	for ordinal := 1; ordinal <= count; ordinal += 1 {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: self.world.Write("admin", self.path, fsDropWritten(self.path, ordinal, fsDropUploadContent))},
			{Actor: "check", Action: func(ctx context.Context, net *Net) error {
				entry, err := self.world.CommittedEntry("admin", self.path)
				if err != nil {
					return err
				}
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.versions = append(self.versions, entry)
				return nil
			}},
		}...)
	}
	return steps
}

// The segments the path's versions name.
func (self *fs92PathVersions) listed() ([][]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.versions) == 0 {
		return nil, fmt.Errorf("no write of %q committed", self.path)
	}
	ids := [][]byte{}
	for _, version := range self.versions {
		ids = append(ids, version.SegmentIds()...)
	}
	return ids, nil
}

// A step action: of the path's listed segments, exactly deletedCount are gone and the rest stored.
func (self *fs92PathVersions) expectDeleted(deletedCount int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		ids, err := self.listed()
		if err != nil {
			return err
		}
		cluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		goneCount := 0
		for _, id := range ids {
			_, err := cluster.Head(sidecartest.InspectContext(ctx), evsservice.SegmentKey(self.world.RepoId, [32]byte(id)))
			switch {
			case errors.Is(err, sidecar.ErrBlobNotFound):
				goneCount += 1
			case err != nil:
				return err
			}
		}
		if goneCount != deletedCount {
			return fmt.Errorf("%d of %q's drop's %d candidates are deleted, not %d", goneCount, self.path, len(ids), deletedCount)
		}
		return nil
	}
}

// The segments both paths' versions name.
func fs92BothListed(paths ...*fs92PathVersions) func() ([][]byte, error) {
	return func() ([][]byte, error) {
		ids := [][]byte{}
		for _, path := range paths {
			listed, err := path.listed()
			if err != nil {
				return nil, err
			}
			ids = append(ids, listed...)
		}
		return ids, nil
	}
}

// See the file header.
func Fs92SecondDropDuringTheHold(net *Net) *Schedule {
	schedule := fs92SecondDropSchedule(net, true, nil)
	schedule.Twin = Fs92SecondDropNoHold
	return schedule
}

// See the file header.
func Fs92SecondDropNoHold(net *Net) *Schedule {
	return fs92SecondDropSchedule(net, false, nil)
}

// The schedule, held under the order or its twin, each listing and bill while the order stands kept in answers when
// answers is not nil.
func fs92SecondDropSchedule(net *Net, held bool, answers *HoldAnswers) *Schedule {
	history := newFs92History(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	world, holds := history.world, history.holds
	x := &fs92PathVersions{world: world, path: "x.txt"}
	y := &fs92PathVersions{world: world, path: "y.txt"}
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	steps = append(steps, x.writes(3)...)
	steps = append(steps, y.writes(3)...)
	if held {
		steps = append(steps, &Step{Actor: "abuse", Action: holds.Place("order", fs92Order)})
	}
	// both worlds' clocks alike: the order binds the deleters once this has passed
	steps = append(steps, &Step{Advance: holds.settings.BindTimeout})
	storedX, storedY, storedBoth := &EvsWorldStoredMark{}, &EvsWorldStoredMark{}, &EvsWorldStoredMark{}
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Advance: 50 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "check", Action: world.MarkStored(storedX, x.listed)},
		{Actor: "check", Action: world.MarkStored(storedBoth, fs92BothListed(x, y))},
	}...)
	if !fsDropSettled(net) {
		// the job waits on settle, deleting nothing (fsDropExecute's reading of such a Net)
		steps = append(steps, fsDropExecute(net, world)[2:]...)
		return &Schedule{Id: "FS-92", Steps: steps, Check: fs92Checks(world), Tiers: []Tier{TierT2, TierT3}}
	}
	job := &Step{Actor: "taskworker", Action: world.RunDropJob("taskworker", nil)}
	ended, deleted := evsservice.DropStateDone, 3
	if held {
		ended, deleted = evsservice.DropStateHeld, 0
	}
	steps = append(steps, []*Step{
		job,
		{Actor: "check", Action: world.ExpectDropState("x.txt", ended)},
		{Actor: "admin", Action: world.ListingReads("admin", "x.txt", protocol.EvsDropState_EVS_DROP_DONE, answers)},
		{Actor: "check", Action: x.expectDeleted(deleted)},
		{Actor: "check", Action: world.StoredFell(storedX, true)},

		// the second DROP, under the hold: taken, and pending until its start
		{Actor: "admin", Action: world.Drop("admin", "y.txt", true)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsDropped())},
		{Actor: "admin", Action: world.ListingReads("admin", "y.txt", protocol.EvsDropState_EVS_DROP_PENDING, answers)},
		// its job starts once its 25 min have passed, and waits for the horizon: executing, as the twin's
		{Advance: 26 * time.Minute},
		job,
		{Actor: "check", Action: world.ExpectDropState("y.txt", evsservice.DropStateExecuting)},
		{Actor: "admin", Action: world.ListingReads("admin", "y.txt", protocol.EvsDropState_EVS_DROP_EXECUTING, answers)},
		{Advance: 50 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "check", Action: world.MarkStored(storedY, y.listed)},
		// its round: done, its bytes off the count once, whether its deletes met the hold or not
		job,
		{Actor: "check", Action: world.ExpectDropState("y.txt", ended)},
		{Actor: "admin", Action: world.ListingReads("admin", "y.txt", protocol.EvsDropState_EVS_DROP_DONE, answers)},
		{Actor: "check", Action: y.expectDeleted(deleted)},
		{Actor: "check", Action: x.expectDeleted(deleted)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsDropped())},
		{Actor: "check", Action: world.StoredFell(storedY, true)},
		{Actor: "check", Action: world.StoredFell(storedBoth, true)},
	}...)
	if answers != nil {
		steps = append(steps, &Step{Actor: "check", Action: world.BillAnswers(storedBoth, answers)})
	}
	if held {
		steps = append(steps, []*Step{
			// api's expiry ends the order at its 90 days: each held job takes the slot back in turn, x.txt's first
			{Actor: "abuse", Action: holds.ToExpiry("order")},
			{Actor: "abuse", Action: holds.Pass("order")},
			{Actor: "check", Action: holds.Swept()},
			{Advance: time.Hour},
			job,
			{Actor: "check", Action: x.expectDeleted(3)},
			{Actor: "check", Action: y.expectDeleted(0)},
			{Actor: "check", Action: world.ExpectDropState("x.txt", 0)},
			{Actor: "check", Action: world.ExpectDropState("y.txt", evsservice.DropStateHeld)},
			job,
			{Actor: "check", Action: y.expectDeleted(3)},
			// no entry and no void record: executed, each entry gone at its job's end, its 30 days long past
			{Actor: "check", Action: world.ExpectDropState("y.txt", 0)},
			{Actor: "admin", Action: world.ListingOmits("admin", "x.txt")},
			{Actor: "admin", Action: world.ListingOmits("admin", "y.txt")},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsDropped())},
			// once, at move-to-held: the later DELETEs report nothing
			{Actor: "check", Action: world.StoredFell(storedBoth, true)},
		}...)
	}
	return &Schedule{Id: "FS-92", Steps: steps, Check: fs92Checks(world), Tiers: []Tier{TierT2, TierT3}}
}

// FS-92 (a) with a second DROP during the hold, run held and not, each on a Net newNet builds, closed before the next
// opens: the admin's listings and the bill while the order stands must equal the twin's. An error names a run that
// failed or the first answer that differs.
func Fs92SecondDropTwins(ctx context.Context, newNet func() *Net) (*Fs92Twins, error) {
	twins := &Fs92Twins{HeldAnswers: NewHoldAnswers(), TwinAnswers: NewHoldAnswers()}
	run := func(held bool, answers *HoldAnswers) *Result {
		net := newNet()
		defer net.Close()
		return Run(ctx, fs92SecondDropSchedule(net, held, answers), net)
	}
	twins.Held = run(true, twins.HeldAnswers)
	if twins.Held.Err != nil {
		return twins, fmt.Errorf("the held network's run: %s", twins.Held)
	}
	twins.Twin = run(false, twins.TwinAnswers)
	if twins.Twin.Err != nil {
		return twins, fmt.Errorf("the twin's run: %s", twins.Twin)
	}
	return twins, HoldAnswersEqual(twins.HeldAnswers, twins.TwinAnswers)
}
