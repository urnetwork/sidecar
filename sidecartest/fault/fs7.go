// FS-7 (§22.8; §11.8's 5g, FI-6; EVS1-M2-40) on the evs world (evs_world.go): five writers, each on an evs instance of
// its own, push one path from one committed base, each held at its head CAS with its record written; the first
// released commits, and each other's rerun on the new head refuses it 409 PATH_CONFLICT. The reader reads the
// committed version throughout: at every hold, once it is folded into its entry, after evacuation 26 h on has dropped
// the losers' records, and after the reader's instance is killed and started again from the stores. Its twin,
// Fs7FivePaths, has the five push five paths, and every one commits.
//
// The fold runs on evs1, whose next commit, w1's of a path outside the five 26 h on, raises folded_through over every
// version before it, since a commit carries its own process's folds (§11.7's horizon row): the one window version
// past folded_through is then that commit's, in a batch too young to evacuate. A fresh instance's newest rule reads the
// record of each window version past folded_through and past the entry's own newest version whose digest may touch the
// path (newest.go), and finds it through pidx/ once evacuation has moved its batch (QD-664); before that fallback such a
// read answered 503 on every try. Two clauses, on the twin's paths, read past a fold after the restart:
//
//	evacuated window  Fs7EvacuatedWindowAfterRestart: the commit outside the paths made before the 26 h, so its
//	                  creation's root delta touches every path and evacuation moves its batch before the reader's
//	                  instance first reads it; every run reads that moved record, then again after the restart
//	fold lost         Fs7FoldLostWithItsInstance, the twin as EVS1-M2-40 wrote it: the fold on the reader's own instance
//	                  and nothing committed after it, so folded_through stays below the fold and the restart loses its
//	                  horizon; each read takes its entry and every later window version whose digest may touch the path.
//	                  A digest matching by chance (64 bits, k = 2, over the run's own path keys) sends a read to a moved
//	                  record in about one run in 55, which failed tip-check at f2134f8 before the fallback
//
// Neither was ever the restart's readiness, which no route reads, and since the fold-lost failure turned on the keys a
// run drew, no replay of its trace repeats it.

package fault

import (
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs7 = Register("FS-7", "", []Tier{TierT2, TierT3}, Twin(Fs7OnePath, Fs7FivePaths))

// See the file header.
func Fs7OnePath(net *Net) *Schedule {
	schedule := fs7Schedule(net, true, fs7FoldCommitted)
	schedule.Refuses = "four of five pushes of one path from one base, 409 PATH_CONFLICT"
	return schedule
}

// See the file header.
func Fs7FivePaths(net *Net) *Schedule {
	return fs7Schedule(net, false, fs7FoldCommitted)
}

// See the file header.
func Fs7EvacuatedWindowAfterRestart(net *Net) *Schedule {
	schedule := fs7Schedule(net, false, fs7FoldCommittedEvacuated)
	schedule.Id = "FS-7 evacuated window after a restart"
	return schedule
}

// See the file header.
func Fs7FoldLostWithItsInstance(net *Net) *Schedule {
	schedule := fs7Schedule(net, false, fs7FoldLost)
	schedule.Id = "FS-7 fold lost with its instance"
	return schedule
}

// Writers w1 to w5 on evs1 to evs5, and the reader on evsr.
func fs7WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Instances = []string{"evs1", "evs2", "evs3", "evs4", "evs5", "evsr"}
	settings.Devices = nil
	for index := 1; index <= 5; index += 1 {
		settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{
			Name: fmt.Sprintf("w%d", index), Instances: []string{fmt.Sprintf("evs%d", index)}, Writer: true,
		})
	}
	settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: "reader", Instances: []string{"evsr"}})
	return settings
}

// Where the fold after the five pushes runs, and what commits after it.
type fs7Fold int

const (
	// on evs1, whose commit of keep.txt 26 h on raises folded_through over the five paths' versions
	fs7FoldCommitted fs7Fold = iota + 1
	// on evs1, keep.txt committed before the 26 h, so evacuation moves keep's batch too
	fs7FoldCommittedEvacuated
	// on evsr, the reader's own instance, with nothing committed after it, so folded_through stays below the fold
	// and the restart loses its horizon with the process
	fs7FoldLost
)

// See the file header.
func fs7Schedule(net *Net, onePath bool, fold fs7Fold) *Schedule {
	world := NewEvsWorld(net, fs7WorldSettings())
	path := func(index int) string {
		if onePath {
			return "x.txt"
		}
		return fmt.Sprintf("x%d.txt", index)
	}
	paths := []string{"x.txt"}
	if !onePath {
		paths = []string{"x1.txt", "x2.txt", "x3.txt", "x4.txt", "x5.txt"}
	}
	steps := []*Step{{Actor: "w1", Action: world.Setup}}
	// the one base: every path written once by w1, its first CAS on evs1
	for _, base := range paths {
		steps = append(steps, &Step{Actor: "w1", Action: world.Write("w1", base, EvsWorldContent("fs7 base "+base, 200))})
	}
	for index := 1; index <= 5; index += 1 {
		writer := fmt.Sprintf("w%d", index)
		instance := fmt.Sprintf("evs%d", index)
		skip := 0
		if index == 1 {
			skip = len(paths)
		}
		steps = append(steps,
			&Step{Actor: writer, Action: world.WriteAny(writer, path(index), EvsWorldContent(fmt.Sprintf("fs7 by %s", writer), 200)), Background: true},
			&Step{Actor: instance, Await: evsservice.BarrierHeadCasBefore, AwaitSkip: skip},
		)
	}
	steps = append(steps, &Step{Actor: "reader", Action: world.Verify("reader", paths...)})
	for index := 1; index <= 5; index += 1 {
		writer := fmt.Sprintf("w%d", index)
		instance := fmt.Sprintf("evs%d", index)
		steps = append(steps,
			&Step{Release: []string{sidecartest.ActorBarrierSite(instance, evsservice.BarrierHeadCasBefore)}},
			&Step{Actor: writer, Join: true},
			&Step{Actor: "reader", Action: world.Verify("reader", paths...)},
		)
		switch {
		case !onePath || index == 1:
			steps = append(steps, &Step{Actor: "check", Action: world.ExpectCommitted(writer, path(index))})
		default:
			steps = append(steps, &Step{Actor: "check", Action: world.ExpectRefused(writer, path(index), protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)})
		}
	}
	// w1's commit carries evs1's fold as folded_through
	keep := &Step{Actor: "w1", Action: world.Write("w1", "keep.txt", EvsWorldContent("fs7 keep", 16))}
	switch fold {
	case fs7FoldLost:
		steps = append(steps, []*Step{
			{Actor: "folder", Action: world.Fold("evsr")},
			{Actor: "reader", Action: world.Verify("reader", paths...)},
			{Advance: 26 * time.Hour},
		}...)
	case fs7FoldCommittedEvacuated:
		steps = append(steps, []*Step{
			{Actor: "folder", Action: world.Fold("evs1")},
			{Actor: "reader", Action: world.Verify("reader", paths...)},
			keep,
			{Advance: 26 * time.Hour},
		}...)
	default:
		steps = append(steps, []*Step{
			{Actor: "folder", Action: world.Fold("evs1")},
			{Actor: "reader", Action: world.Verify("reader", paths...)},
			{Advance: 26 * time.Hour},
			keep,
		}...)
	}
	steps = append(steps, []*Step{
		{Actor: "evacuator", Action: world.Evacuate()},
		{Actor: "reader", Action: world.Verify("reader", paths...)},
		{Actor: "evsr", Kill: true},
		{Actor: "evsr", Restart: "evsr"},
		{Actor: "reader", Action: world.Verify("reader", paths...)},
	}...)
	return &Schedule{Id: "FS-7", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
