// FS-6 (§22.8; §11.12's delete, restore, start, phases and refused rows, D-EVS-19, I-1, FI-5; EVS1-M2-41) on the evs
// world (evs_world.go, evs_world_lifecycle.go): a repo's lifecycle at repo/'s If-Match, one winner, and a shred that
// leaves only the tombstone.
//
// The registered case, Fs6NowBeatsTheRestore, beside its twin: writerA deletes the repo, restorable; a day on, writerA files its RepoRestore and its restore holds at repo/'s CAS on evs1,
// having read the projection; writerB files RepoDelete{now}, the newest, and its DELETE holds at the CAS on evs3. The
// --now claim lands first: repo/ goes deleted -> shredding under writerB's deletion, and the restore, rereading,
// answers 409 SHREDDING. The twin, Fs6RestoreThenNow, releases the restore first: it lands, active, and the --now then
// shreds the active repo. Either way the shred runs: its first pass waits out step 1's 20 s, then deletes slots, the
// group's keys and every family; the final pass 10 min on finds nothing more and writes the tombstone, after which
// repo/ and place/ are all of the repo any store holds.
//
// The clause beside it, Fs6SevenDayStart: a restorable delete; a restore a minute past its 7 d, which api refuses;
// and 7 d 10 min on the shred's start claims repo/ and runs to the tombstone; its twin, Fs6RestoredBeforeTheStart, has writerA restore at 7 d less an hour, so the start's
// pass finds repo/ under no deletion and deletes nothing, every file reading as before. The clause Fs6KilledAtEachPhase
// kills the shred at each of the first pass's destructive steps and runs it again, and the repo still ends shredded
// with nothing left; Fs6StaleJob runs a pass of a deletion that a restore and a newer delete superseded, which
// deletes nothing.
//
// §11.12's refused row closes every route but restore and DELETE with now while a repo is deleted, and every route
// while it is shredding, the read, refs and log routes included (QD-665, answering evs1-m2-41-reads-of-deleted-repo).
// The schedules above read nothing between the delete and the end; the clause Fs6ReadsRefusedWhileDeleted holds the
// reader's reads to 409 REPO_DELETED while the repo is deleted, then SHREDDING once a --now delete claims it, and,
// past the tombstone, its GET .../refs to SHREDDING: the shred deleted the group's keys, so the reader can no longer
// name a path, and refs names none. Its twin is Fs6RestoredBeforeTheStart's, every file reading as before.
//
// FS-6's further clauses (a push validated just before the CAS removed by step 6's final pass; a fold, an evacuation,
// a gkm commit and a delayed ack held across a --now shred re-creating nothing; a --now shred under a hold, its
// records in 25 h-old batches packed, kept until the hold ends and then deleted; a device killed between filing
// RepoDelete and calling DELETE, the reconciler applying it; DELETE and restore without their projected statements
// 409 STATEMENT_MISSING; a re-seed refused for a repo deleted with now or over 7 d ago, and a soft-deleted one's
// re-seed then restore) are EVS1-M2-41's report's; FI-5's oracle is not bound (TEST-M2-06), so the schedules check
// repo/'s states, the shred's outcomes and what the stores keep in its place.

package fault

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs6 = Register("FS-6", "", []Tier{TierT2, TierT3}, Twin(Fs6NowBeatsTheRestore, Fs6RestoreThenNow))

// The files every FS-6 schedule writes first.
var fs6Files = []string{"a.txt", "d/b.txt"}

// Setup and the files, read once.
func fs6Prefix(world *EvsWorld) []*Step {
	return []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs6 a", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "d/b.txt", EvsWorldContent("fs6 b", 200))},
		{Actor: "reader", Action: world.Verify("reader", fs6Files...)},
	}
}

// The shred from its first pass to the tombstone.
func fs6ShredToTheEnd(world *EvsWorld) []*Step {
	return []*Step{
		// step 1: 20 s past shredding's state_ms
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredWaiting)},
		{Advance: 20 * time.Second},
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredFirstPassDone)},
		{Advance: 10 * time.Minute},
		{Actor: "shred", Action: world.Shred(true)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredShredded)},
		{Actor: "check", Action: world.ExpectShredded()},
	}
}

// See the file header.
func Fs6NowBeatsTheRestore(net *Net) *Schedule {
	schedule := fs6RaceSchedule(net, false)
	schedule.Refuses = "a restore whose CAS a --now delete's claim beat, 409 SHREDDING"
	return schedule
}

// See the file header.
func Fs6RestoreThenNow(net *Net) *Schedule {
	return fs6RaceSchedule(net, true)
}

func fs6RaceSchedule(net *Net, restoreFirst bool) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := fs6Prefix(world)
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.DeleteRepo("writerA", false)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_DELETED)},
		{Advance: 24 * time.Hour},
		// the restore reads the projection, its deletion restored, and holds at repo/'s CAS on evs1, past the delete's
		{Actor: "writerA", Action: world.RestoreRepoAny("writerA"), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierRepoCasBefore, AwaitSkip: 1},
		// RepoDelete{now} is the newest, and its DELETE holds at the CAS on evs3
		{Actor: "writerB", Action: world.DeleteRepoAny("writerB", true), Background: true},
		{Actor: "evs3", Await: evsservice.BarrierRepoCasBefore},
	}...)
	first, second := "evs3", "evs1"
	firstWriter, secondWriter := "writerB", "writerA"
	if restoreFirst {
		first, second = second, first
		firstWriter, secondWriter = secondWriter, firstWriter
	}
	steps = append(steps, []*Step{
		{Release: []string{sidecartest.ActorBarrierSite(first, evsservice.BarrierRepoCasBefore)}},
		{Actor: firstWriter, Join: true},
		{Release: []string{sidecartest.ActorBarrierSite(second, evsservice.BarrierRepoCasBefore)}},
		{Actor: secondWriter, Join: true},
		{Actor: "check", Action: world.ExpectLifecycle("writerB", protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED)},
	}...)
	if restoreFirst {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectLifecycle("writerA", protocol.EvsRefusalCode_EVS_REFUSAL_CODE_UNSPECIFIED)})
	} else {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectLifecycle("writerA", protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)})
	}
	steps = append(steps, &Step{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_SHREDDING)})
	steps = append(steps, fs6ShredToTheEnd(world)...)
	return &Schedule{Id: "FS-6", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs6SevenDayStart(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := fs6Prefix(world)
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.DeleteRepo("writerA", false)},
		// the start before its 7 d 10 min queues itself and changes nothing
		{Advance: 7*24*time.Hour - time.Hour},
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredWaiting)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_DELETED)},
		// a restore a minute past the 7 d: api takes no RepoRestore then, so nothing reaches evs
		{Advance: time.Hour + time.Minute},
		{Actor: "writerA", Action: world.RestoreRepoAny("writerA")},
		{Actor: "check", Action: world.ExpectLifecycleFailed("writerA")},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_DELETED)},
		{Advance: 9 * time.Minute},
		// the start claims repo/, then waits out step 1
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredWaiting)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_SHREDDING)},
	}...)
	steps = append(steps, fs6ShredToTheEnd(world)...)
	return &Schedule{
		Id: "FS-6 seven-day start", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3},
		Refuses: "a restore past the RepoDelete's 7 d, which api never takes, so the start claims repo/ and shreds it",
		Twin:    Fs6RestoredBeforeTheStart,
	}
}

// See the file header.
func Fs6RestoredBeforeTheStart(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := fs6Prefix(world)
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.DeleteRepo("writerA", false)},
		{Advance: 7*24*time.Hour - time.Hour},
		{Actor: "writerA", Action: world.RestoreRepo("writerA")},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_ACTIVE)},
		{Advance: time.Hour + 10*time.Minute},
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredStale)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_ACTIVE)},
		{Actor: "reader", Action: world.Verify("reader", fs6Files...)},
		{Actor: "writerB", Action: world.Write("writerB", "d/b.txt", EvsWorldContent("fs6 b 2", 200))},
		{Actor: "reader", Action: world.Verify("reader", fs6Files...)},
	}...)
	return &Schedule{Id: "FS-6 seven-day start twin", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs6KilledAtEachPhase(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := fs6Prefix(world)
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.DeleteRepo("writerA", true)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_SHREDDING)},
		{Advance: 20 * time.Second},
	}...)
	// the first pass's steps 2, 3 and 5 reach evs.shred.step.before once each: killed at each in turn, the job is run
	// again from repo/ alone. Each Await arms its own hold, which takes the arrivals after the one before it
	for skip := 0; skip < 3; skip += 1 {
		steps = append(steps,
			&Step{Actor: "shred", Action: world.Shred(false), Background: true},
			&Step{Actor: "shred", Await: evsservice.BarrierShredStepBefore, AwaitSkip: skip},
			&Step{Actor: "shred", Kill: true},
			&Step{Actor: "shred", Restart: "shred"},
		)
	}
	steps = append(steps, []*Step{
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredFirstPassDone)},
		{Advance: 10 * time.Minute},
		{Actor: "shred", Action: world.Shred(true), Background: true},
		// the final pass's step 7, the tombstone's CAS, past the whole first pass's three arrivals and the final pass's
		// steps 2, 3 and 5
		{Actor: "shred", Await: evsservice.BarrierShredStepBefore, AwaitSkip: 6},
		{Actor: "shred", Kill: true},
		{Actor: "shred", Restart: "shred"},
		{Actor: "shred", Action: world.Shred(true)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredShredded)},
		{Actor: "check", Action: world.ExpectShredded()},
	}...)
	return &Schedule{Id: "FS-6 killed at each phase", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs6StaleJob(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := fs6Prefix(world)
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.DeleteRepo("writerA", false)},
		{Actor: "writerA", Action: world.RestoreRepo("writerA")},
		{Actor: "writerA", Action: world.DeleteRepo("writerA", false)},
		{Advance: 7*24*time.Hour + 10*time.Minute},
		// the first deletion's job: repo/ names the second, so it ends deleting nothing
		{Actor: "shred", Action: world.ShredDeletion(0, false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredStale)},
		{Actor: "shred", Action: world.ShredDeletion(0, true)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredStale)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_DELETED)},
		{Actor: "writerA", Action: world.RestoreRepoAny("writerA")},
		// the second deletion is past its 7 d: api refuses its RepoRestore
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_DELETED)},
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_SHREDDING)},
	}...)
	steps = append(steps, fs6ShredToTheEnd(world)...)
	return &Schedule{Id: "FS-6 stale job", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs6ReadsRefusedWhileDeleted(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := fs6Prefix(world)
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.DeleteRepo("writerA", false)},
		{Actor: "reader", Action: world.ExpectReadRefused("reader", "a.txt", protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)},
		{Actor: "writerB", Action: world.DeleteRepo("writerB", true)},
		{Actor: "reader", Action: world.ExpectReadRefused("reader", "a.txt", protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)},
	}...)
	steps = append(steps, fs6ShredToTheEnd(world)...)
	steps = append(steps, &Step{Actor: "reader", Action: fs6ExpectRefsRefused(world, "reader", protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)})
	return &Schedule{
		Id: "FS-6 reads refused while deleted", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3},
		Refuses: "reads of a deleted repo, 409 REPO_DELETED, and of a shredding or shredded one, 409 SHREDDING",
		Twin:    Fs6RestoredBeforeTheStart,
	}
}

// A step action: device's GET .../refs through the lb under its own read token is refused with code. The route names
// no path, so it needs none of the repo's keys, which a shred deletes.
func fs6ExpectRefsRefused(world *EvsWorld, device string, code protocol.EvsRefusalCode) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		worldDevice := world.Device(device)
		token, err := world.issueToken(worldDevice, []string{"repo:" + world.RepoId.String() + ":r"})
		if err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://evs.example/evs/v1/repos/"+sidecar.EvsKeyId(world.RepoId)+"/refs", nil)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := worldDevice.transport.RoundTrip(request)
		if err != nil {
			return fmt.Errorf("%s's GET .../refs: %w", device, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		reply := &protocol.EvsRefusalReply{}
		status, _ := sidecar.EvsRefusalStatus(code)
		if response.StatusCode != status || proto.Unmarshal(body, reply) != nil || reply.GetCode() != code {
			return fmt.Errorf("%s's GET .../refs answered %d %s, not refused %s", device, response.StatusCode, reply.GetCode(), code)
		}
		return nil
	}
}
