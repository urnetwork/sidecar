// FS-89 (§22.8; §11.7's action, states and drop rows, §11.13's drop job, owner decisions 183, 204 and 397, FI-1, FI-27;
// EVS2-M10-35, which closes the row's schedule: EVSB-M10-03's fs89_test.go holds its job-side clauses on the drop table
// and no task named the row's schedule) on the evs world with its drop wiring (evs_world_drop.go): a path's history
// dropped with the window, the drop cancelled, and the history dropped again; and a drop with --now.
//
//	history   x.txt written 30 times: 20 versions of 40 KiB a few bytes apart, so its diff chain passes two checkpoints,
//	          the first write's and the one §11.7's 16-diff bound forces; two of 9 MiB, past 8 MiB, an era of chunks;
//	          and eight of 100 B, small enough that their records hold them inline. y.txt, written twice beside it with
//	          contents of its own, is no listed version's
//	window    Fs89, the registered case: the admin drops x.txt's history with the 7-day window. In the window every
//	          version the drop lists reads drop pending, and a diff, a chunked and an inline version each read whole. A
//	          cancel well before not_before is accepted, and past the window, evacuation's horizon and the job the
//	          versions read kept and no segment is deleted. Dropped again: past the window the listed versions read
//	          dropped, nothing of them shown, and once the job has run to done exactly the segments only the listed
//	          versions name are gone, y.txt keeping its own; the head the drop wrote again reads x.txt's newest content,
//	          and every path verifies, with no alarm (FI-1, the world's alarms and FI-27 after every step)
//	now       Fs89Now: x.txt's three versions dropped with --now read dropped at once, and the job, past not_before plus
//	          25 min but short of evacuation's horizon past the drop, deletes nothing; past the horizon it deletes the
//	          listed versions' segments
//
// On a Net whose clusters have not passed settle, T3's local stack's (fsDropSettled), each job holds at its wait on
// settle, nothing is deleted, and what follows the deletes is not run, as fs95.go's fsDropExecute says.
//
// Not here, each a missing clause in EVS2-M10-35's report: export's stubs through git fsck, and diff and restore
// reporting dropped (EVS2-M10-19, -23); the twin whose live segment, deleted by hand, alarms as a missing segment;
// --now's bounds to the minute (evacuation's horizon past seen_ms by 12 min, not_before_ms + 25 min) and a version
// uploaded 1 h before a --now drop keeping its segments until the horizon passes its upload by 24 h 2 min, which
// fs89_test.go's TestFs89NowWaitsForTheHorizon holds on the drop table with the real horizon, not through a world.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs89Case = Register("FS-89", "", []Tier{TierT2, TierT3}, Fs89)

// x.txt's writes in Fs89, by era: 20 diffed versions, then 2 chunked, then 8 inline, 30 in all as the row has them.
type fs89Eras struct {
	diffed  int
	chunked int
	inline  int
}

func newFs89Eras() *fs89Eras {
	return &fs89Eras{diffed: 20, chunked: 2, inline: 8}
}

// Every write of x.txt.
func (self *fs89Eras) count() int {
	return self.diffed + self.chunked + self.inline
}

// x.txt's ordinal-th write's content, from 1: 40 KiB a few bytes apart, then 9 MiB, then 100 B.
func (self *fs89Eras) content(ordinal int) []byte {
	switch {
	case ordinal <= self.diffed:
		content := EvsWorldContent("fs89 x", 40*1024)
		copy(content[1000:], fmt.Sprintf("x.txt's edit %02d", ordinal))
		return content
	case ordinal <= self.diffed+self.chunked:
		return EvsWorldContent(fmt.Sprintf("fs89 x chunked %02d", ordinal), 9*1024*1024)
	}
	return fsDropInlineContent(fmt.Sprintf("fs89 x inline %02d", ordinal))
}

// Each of x.txt's listed versions, its write's ordinal from 1 to count, read in state.
func fs89States(count int, state string) map[int]string {
	states := map[int]string{}
	for ordinal := 1; ordinal <= count; ordinal += 1 {
		states[ordinal] = state
	}
	return states
}

// A step action: x.txt's committed versions are the history the row names: among the diffed versions at least two
// checkpoints, a chain of one locator, each followed by diffs, chains of more; the chunked versions each several
// chunks; and the inline versions no segment.
func fs89ExpectHistory(world *EvsWorld, eras *fs89Eras) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		entries, err := world.CommittedEntries("x.txt")
		if err != nil {
			return err
		}
		if len(entries) != eras.count() {
			return fmt.Errorf("x.txt holds %d committed writes, not %d", len(entries), eras.count())
		}
		checkpoints, diffs := 0, 0
		for index, entry := range entries {
			chain := entry.Entry.GetChain()
			switch ordinal := index + 1; {
			case ordinal <= eras.diffed && len(chain) == 1:
				checkpoints += 1
			case ordinal <= eras.diffed:
				diffs += 1
			case ordinal <= eras.diffed+eras.chunked && len(entry.SegmentIds()) < 2:
				return fmt.Errorf("x.txt's write %d, 9 MiB, names %d segments, not chunks", ordinal, len(entry.SegmentIds()))
			case eras.diffed+eras.chunked < ordinal && len(entry.SegmentIds()) != 0:
				return fmt.Errorf("x.txt's write %d, 100 B, names %d segments, not held inline", ordinal, len(entry.SegmentIds()))
			}
		}
		if checkpoints < 2 || diffs < 2 {
			return fmt.Errorf("x.txt's diffed versions hold %d checkpoints and %d diffs: its chain passes no two checkpoints", checkpoints, diffs)
		}
		return nil
	}
}

// The segments path's committed writes name that no newer write of it does: what a drop of path's history, its head
// written again, lists, which the job deletes.
func fs89ListedSegments(world *EvsWorld, path string) func() ([][]byte, error) {
	return func() ([][]byte, error) {
		entries, err := world.CommittedEntries(path)
		if err != nil {
			return nil, err
		}
		ids := [][]byte{}
		for _, entry := range entries {
			for _, id := range entry.SegmentIds() {
				if !slices.ContainsFunc(ids, func(other []byte) bool { return bytes.Equal(other, id) }) {
					ids = append(ids, id)
				}
			}
		}
		return ids, nil
	}
}

// See the file header.
func Fs89(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	eras := newFs89Eras()
	historyCount := eras.count()
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	for ordinal := 1; ordinal <= historyCount; ordinal += 1 {
		steps = append(steps, &Step{Actor: "admin", Action: world.Write("admin", "x.txt", eras.content(ordinal))})
	}
	steps = append(steps, fsDropWrites(world, "admin", "y.txt", 2, fsDropUploadContent)...)
	cancelled := &EvsWorldStoreMark{}
	steps = append(steps, []*Step{
		{Actor: "check", Action: fs89ExpectHistory(world, eras)},
		{Actor: "check", Action: world.MarkStore(cancelled)},
		{Actor: "admin", Action: world.Drop("admin", "x.txt", false)},
		// in the window: pending, and read whole
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", fs89States(historyCount, sidecar.EvsVersionStateDropPending))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 5, EvsWorldReadsContent(eras.content(5)))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", eras.diffed+1, EvsWorldReadsContent(eras.content(eras.diffed+1)))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", historyCount-1, EvsWorldReadsContent(eras.content(historyCount-1)))},
		// cancelled a day in: nothing goes, past the window, the horizon and the job
		{Advance: 24 * time.Hour},
		{Actor: "admin", Action: world.CancelDrop("admin", "x.txt")},
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateCancelled)},
		{Advance: 7 * 24 * time.Hour},
	}...)
	steps = append(steps, fsDropExecute(net, world, []*Step{
		{Actor: "check", Action: world.NoSegmentDeletesSince(cancelled)},
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateCancelled)},
	}...)...)
	steps = append(steps, []*Step{
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", fs89States(historyCount, "kept"))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 5, EvsWorldReadsContent(eras.content(5)))},
		// dropped again, its rewrite of the head after the cancelled drop's among what it lists
		{Actor: "admin", Action: world.Drop("admin", "x.txt", false)},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", fs89States(historyCount+1, sidecar.EvsVersionStateDropPending))},
		{Advance: 7*24*time.Hour + time.Minute},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", fs89States(historyCount+1, sidecar.EvsVersionStateDropped))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 5, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", eras.diffed+1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
	}...)
	steps = append(steps, fsDropExecute(net, world, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		{Actor: "check", Action: world.ExpectSegments("x.txt's listed versions' segments", false, fs89ListedSegments(world, "x.txt"))},
		{Actor: "check", Action: world.ExpectSegments("y.txt's segments", true, fs89ListedSegments(world, "y.txt"))},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", fs89States(historyCount+1, sidecar.EvsVersionStateDropped))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", historyCount+2, EvsWorldReadsContent(eras.content(historyCount)))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
	}...)...)
	return &Schedule{Id: "FS-89", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs89Now(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	steps = append(steps, fsDropWrites(world, "admin", "x.txt", 3, fsDropUploadContent)...)
	mark := &EvsWorldStoreMark{}
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.MarkStore(mark)},
		{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", fs89States(3, sidecar.EvsVersionStateDropped))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		// past not_before plus 25 min, short of evacuation's horizon past the drop: nothing goes
		{Advance: time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "taskworker", Action: world.RunDropJob("taskworker", func(result *evsservice.DropJobResult) error {
			if result == nil || result.Ended {
				return errors.New("the job ended an hour after a --now drop, before evacuation's horizon passed it")
			}
			return nil
		})},
		{Actor: "check", Action: world.NoSegmentDeletesSince(mark)},
	}...)
	steps = append(steps, fsDropExecute(net, world, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		{Actor: "check", Action: world.ExpectSegments("x.txt's listed versions' segments", false, fs89ListedSegments(world, "x.txt"))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
	}...)...)
	return &Schedule{Id: "FS-89 now", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}
