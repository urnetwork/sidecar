// FS-63 (§22.8; §11.8's placement row, owner decision 145; EVS1-M2-41) on the evs world (evs_world.go), the repo
// unplaced until a schedule places it through PUT /evs/v1/repos/<id>, as a create resuming the RepoCreate the
// projection holds does. FS-63 is on §22.8's unknown list, so every write each clause issues also runs with its
// response lost.
//
// The registered case, Fs63CreatorsRace, beside its twin: writerA's and writerB's placements of one repo id both reach
// place/'s If-None-Match, each held before it; writerA's lands with its answer lost and its read-back continues on the
// cluster place/ names, making repo/; writerB's then meets writerA's placement and is refused 409; writerA's group and
// activation follow (by hand: sidecartest's FakeGkm writes no GroupForm for the route's activation to read), both
// write the repo there, and the reader reads it. The twin, Fs63OneCreator, has writerA place it alone.
//
// FS-63's place_new naming a second metadata cluster, restarts resolving every repo to its cluster with a cached 404
// clearing within 5 s, an unreachable place_new answering 503, the one-pool suite and the next-cluster case are
// EVS1-M2-41's report's; FI-2 and FI-4's oracles are not bound (TEST-M2-04, TEST-M2-05).

package fault

import (
	"context"
	"fmt"
	"net/http"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs63 = Register("FS-63", "", []Tier{TierT2, TierT3}, Twin(Fs63CreatorsRace, Fs63OneCreator))

// The default world, unplaced.
func fs63WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Unplaced = true
	return settings
}

// See the file header.
func Fs63CreatorsRace(net *Net) *Schedule {
	world := NewEvsWorld(net, fs63WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: sidecar.EvsPlaceKey(world.RepoId), Result: ApplyThenDrop, Actor: "evs1", WritesOnly: true}},
		{Actor: "writerA", Action: world.PlaceRepo("writerA"), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierPlacePutBefore},
		{Actor: "writerB", Action: world.PlaceRepoAny("writerB"), Background: true},
		{Actor: "evs3", Await: evsservice.BarrierPlacePutBefore},
		{Release: []string{sidecartest.ActorBarrierSite("evs1", evsservice.BarrierPlacePutBefore)}},
		{Actor: "writerA", Join: true},
		{Release: []string{sidecartest.ActorBarrierSite("evs3", evsservice.BarrierPlacePutBefore)}},
		{Actor: "writerB", Join: true},
		{Actor: "check", Action: world.Expect("writerB's placement was refused 409", func(ctx context.Context) error {
			if status := world.PlaceStatus("writerB"); status != http.StatusConflict {
				return fmt.Errorf("writerB's placement answered %d", status)
			}
			return nil
		})},
		{Actor: "writerA", Action: world.FinishCreate("writerA")},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs63 a", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "b.txt", EvsWorldContent("fs63 b", 200))},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.txt")},
	}
	return &Schedule{
		Id: "FS-63", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3},
		Refuses: "writerB's create of a repo writerA placed first, 409",
	}
}

// See the file header.
func Fs63OneCreator(net *Net) *Schedule {
	world := NewEvsWorld(net, fs63WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.PlaceRepo("writerA")},
		{Actor: "writerA", Action: world.FinishCreate("writerA")},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs63 a", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "b.txt", EvsWorldContent("fs63 b", 200))},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.txt")},
	}
	return &Schedule{Id: "FS-63", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
