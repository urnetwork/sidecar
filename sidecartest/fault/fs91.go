// FS-91's races (a) and (b) (§22.8; §11.7's fence row, §11.8's step 4 and 5h, §11.13's mark row, FI-2, FI-27;
// EVS2-M10-31) on the evs world with its drop wiring (evs_world_drop.go): a reuse copy racing the DROP that lists its
// source. x.txt has three versions on main, each its own segment; a writer's push on ref r2 creates a file as a copy
// of x.txt's first version, naming it as its reuse source and citing its segment, and is held on its instance after
// step 4 validated it (evs.push.step4.after), the DROP of x.txt's history going through the other instance.
//
//	(a)  Fs91ReleasedBeforeTheDrop: the copy is released before the DROP commits, and commits. The DROP then commits
//	     and its job runs: mark finds r2's version and keeps the segment it shares with x.txt's first version, while
//	     the segments only x.txt's second and third versions name go (the drop writes its kept head again)
//	(b)  Fs91ReleasedAfterTheDrop, the registered case: the DROP commits while the copy is held; released more than
//	     §11.8's 5 s after its validation, the copy's step 7 reruns 5h and is refused 409 DROPPED. Nothing names the
//	     listed versions' segments beyond the drop's list, and the job deletes both. Its twin is (a)
//
// The copy is a hand-built push (EvsWorld.PostPlan, ReuseFill): the client's planner writes a reuse list only from a
// git tier's publish. A copy released within 5 s of its validation after the DROP committed commits, which the design
// leaves to mark (§11.13's mark row waits evacuation's horizon past the DROP for it), and FI-27's fence clause reads
// any reuse of a listed version first found after its DROP as a violation, so no schedule here runs that order: a
// finding in EVS2-M10-31's report. Races (c) to (f) are not built: the cached head a failed cache write left and a
// creating head write held past 26 h, a push in parts sealed after the drop (evsservice's
// TestPushDroppedRefusesASealAfterTheDrop holds the seal's refusal on the engine), a re-upload adopting a young
// candidate's receipt, and a git-mode push carrying a candidate's bytes.

package fault

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs91Case = Register("FS-91", "", []Tier{TierT2, TierT3}, Fs91ReleasedAfterTheDrop)

// The ref the copy is pushed on.
var fs91CopyRef = []byte("r2")

// See the file header.
func Fs91ReleasedAfterTheDrop(net *Net) *Schedule {
	schedule := fs91Schedule(net, false)
	schedule.Refuses = "a reuse copy of a version a DROP lists, released past 5 s after the DROP committed"
	schedule.Twin = Fs91ReleasedBeforeTheDrop
	return schedule
}

// See the file header.
func Fs91ReleasedBeforeTheDrop(net *Net) *Schedule {
	return fs91Schedule(net, true)
}

func fs91Schedule(net *Net, before bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	posted := &EvsWorldPosted{}
	// x.txt's versions as each write committed them, kept for the segments they name
	versions := []*EvsWorldCommittedEntry{}
	keep := func(ctx context.Context, net *Net) error {
		entry, err := world.CommittedEntry("admin", "x.txt")
		if err != nil {
			return err
		}
		versions = append(versions, entry)
		return nil
	}
	version := func(ordinal int) func() (*EvsWorldCommittedEntry, error) {
		return func() (*EvsWorldCommittedEntry, error) {
			if len(versions) < ordinal {
				return nil, errors.New("x.txt's writes did not all commit")
			}
			return versions[ordinal-1], nil
		}
	}
	segments := func(ordinal int) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			entry, err := version(ordinal)()
			if err != nil {
				return nil, err
			}
			return entry.SegmentIds(), nil
		}
	}
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	for ordinal := 1; ordinal <= 3; ordinal += 1 {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.Write("admin", "x.txt", fsDropWritten("x.txt", ordinal, fsDropUploadContent))},
			{Actor: "check", Action: keep},
		}...)
	}
	release := &Step{Release: []string{sidecartest.ActorBarrierSite("evs2", evsservice.BarrierPushStep4After)}}
	join := &Step{Actor: "writer", Join: true}
	drop := &Step{Actor: "admin", Action: world.Drop("admin", "x.txt", true)}
	steps = append(steps, []*Step{
		// r2's first write passes evs2's step 4 first
		{Actor: "writer", Action: world.WriteRef("writer", fs91CopyRef, "seed.txt", fsDropUploadContent("fs91 seed"))},
		{Actor: "writer", Action: world.PostPlan("writer", fs91CopyRef, posted, world.ReuseFill("copy of x.txt", version(1))), Background: true},
		{Actor: "evs2", Await: evsservice.BarrierPushStep4After, AwaitSkip: 1},
	}...)
	if before {
		steps = append(steps, release, join,
			&Step{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusOK, 0)},
			drop)
	} else {
		steps = append(steps, drop, &Step{Advance: 6 * time.Second}, release, join,
			&Step{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED)})
	}
	steps = append(steps, &Step{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped, 2: sidecar.EvsVersionStateDropped})})
	steps = append(steps, fsDropExecute(net, world, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		// what r2's copy names stays; what only listed versions name goes
		{Actor: "check", Action: world.ExpectSegments("x.txt's first version, which r2's copy cites", before, segments(1))},
		{Actor: "check", Action: world.ExpectSegments("x.txt's second version", false, segments(2))},
		// the head the drop keeps is its own rewrite, uploaded again: the version it replaced is listed, and goes
		{Actor: "check", Action: world.ExpectSegments("x.txt's third version", false, segments(3))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		// the evacuation fenced r2's head for the refused copy's record: a push arriving within the fence's margin of
		// it ends unknown, so the ref's next write comes after it
		{Advance: time.Hour},
		{Actor: "writer", Action: world.WriteRef("writer", fs91CopyRef, "after.txt", fsDropUploadContent("fs91 after"))},
	}...)...)
	return &Schedule{Id: "FS-91", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}
