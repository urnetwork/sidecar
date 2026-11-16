// FS-72's M10 cases (§22.8; §11.6's format row, D-EVS-39, D-PHASE-10, R-PHASE-13, FI-1, FI-2, FI-17; EVS2-M10-30) on
// the evs world (evs_world.go) with format 2's gate, instances and devices (evs_world_format2.go): a repo migrated
// while a format-1 client pushes and reads, a migration killed at each step, and evs and taskworker rolled back to
// format 1 after format-2 data exists. The format-1 client is this code's client held to format 1 by
// EvsSettings.MaxFormat, and a rolled-back binary this code at EvsSettings.InstanceFormat 1, since T2 runs one tree;
// server's T3 rollback runs real binaries built from testdata/evs/format1_build.txt's commits. FS-72 is on §22.8's
// unknown list, so every write each case issues also runs with its response lost.
//
//	migration  Fs72Migration: a format-1 repo on format-2 evs, its network in the format2 gate, written by a format-2
//	           writer and a format-1 client. The format-1 client commits a.txt; the format-2 writer's versionless
//	           write of v.bin, the repo's first format-2 value, raises repo/ by §11.6's If-Match between its step 6
//	           and step 7 (repo_format.go). While the raise is held before its write the format-1 client commits
//	           b.txt, and while it is held after, repo/ at format 2 and v.bin not yet committed, c.txt, format-1 data
//	           being valid format 2; v.bin then commits, its head CAS rerun past both. In the migrated repo the
//	           format-1 client commits d.txt, reads every file but v.bin, refuses v.bin as needing format 2 with no
//	           alarm, and refuses to write over it before it sends anything; a format-2 reader reads every newest
//	           version. The twin is Fs72MigrationRaceFree, the same writes with no hold
//	killed     Fs72MigrationKilledAt, one schedule per step of the migration's push from step 6's record to step 8
//	           (evs.push.step6.after, evs.migrate.raise.before, evs.migrate.raise.after, evs.head.cas.before and
//	           .after): the instance holding the format-2 push is killed there with its request, the lb sends it to
//	           the next instance, which resumes it, the raise finding repo/ as the killed one left it; the push
//	           commits once, repo/ stands at format 2, and every newest version reads, while no step leaves the repo
//	           half-migrated (FormatHolds after every step)
//	rollback   Fs72Rollback: format-2 data exists: a.txt versioned; u.bin versionless on a kind-5 segment, its record
//	           of format 1's layout; k.bin versionless, written twice, so its newest record lists the first version's
//	           segment as a purge candidate; v.bin versionless and staged, its record in a format-2 batch; the window
//	           folded on format 2. evs's instances and taskworker roll back to format 1 with the gate's purge on. A
//	           format-1 instance answers the format-2 writer's push 503 before step 4, writing nothing, and serves no
//	           record of format 2's layout, so the format-1 client, whose last read predates the migration, and a
//	           write over v.bin are refused as needing format 2 before any push; it serves the stored bytes of a.txt
//	           and u.bin to a format-2 reader, and k.bin and v.bin are refused as needing format 2. 26 h on, its
//	           evacuation leaves the format-2 batches, alarming evacuate_batch_format, settles no staged segment,
//	           sweeps nothing and deletes no segment, so v.bin's staged content stays and nothing is purged. Rolled
//	           forward, with purge back in observe, the format-2 evacuator takes every batch, v.bin's staged segment
//	           written to seg/, every newest version reads through evsr and evs1, and both writers commit again. The
//	           twin, Fs72RollbackForwardOnly, runs the same data on format 2 throughout and evacuates it alike
//
// The forward run keeps purge in observe because FI-1's oracle holds every committed version's segments to the
// closure and does not yet excuse a replaced versionless version's purged ones, which FI-16 governs (TEST-M10-01).
// FI-17 is TEST-M10-01's oracle (fault.FI(17)); the schedules name it once it is bound (fs72Checks) and meanwhile
// check its format clause through FormatHolds and the world's NoAlarms.

package fault

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs72MigrationCase = Register("FS-72", "migration", []Tier{TierT2, TierT3}, Fs72Migration)
	Fs72RollbackCase  = Register("FS-72", "rollback", []Tier{TierT2, TierT3}, Fs72Rollback)
)

// The steps of the migration's push a kill lands on, in order (Fs72MigrationKilledAt).
var Fs72MigrationSteps = []string{
	evsservice.BarrierPushStep6After,
	evsservice.BarrierMigrateRaiseBefore,
	evsservice.BarrierMigrateRaiseAfter,
	evsservice.BarrierHeadCasBefore,
	evsservice.BarrierHeadCasAfter,
}

// Content of label that a versionless write stages in its push's body: 200 B, under 16 KiB padded.
func fs72StagedContent(label string) []byte {
	return EvsWorldContent(label, 200)
}

// Content of label that a versionless write uploads as a kind-5 segment: 20 KiB, past 16 KiB.
func fs72Kind5Content(label string) []byte {
	return EvsWorldContent(label, 20*1024)
}

// The world: writer2, a format-2 device on evs1 then evs2; writer1, the format-1 client, this code's client at
// MaxFormat 1, on evs2 then evs1; reader2 and reader1, of format 2 and format 1, on evsr. Every instance runs format 2,
// and the network is in the format2 gate with both modes observe.
func fs72WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Instances = []string{"evs1", "evs2", "evsr"}
	settings.Devices = []*EvsWorldDeviceSettings{
		{Name: "writer2", Instances: []string{"evs1", "evs2"}, Writer: true, Format2: true},
		{Name: "writer1", Instances: []string{"evs2", "evs1"}, Writer: true, Format2: true},
		{Name: "reader2", Instances: []string{"evsr"}, Format2: true},
		{Name: "reader1", Instances: []string{"evsr"}, Format2: true},
	}
	settings.Format2 = DefaultEvsWorldFormat2Settings()
	settings.InstanceFormats = map[string]uint32{}
	for _, instance := range settings.Instances {
		settings.InstanceFormats[instance] = sidecar.EvsRepoFormat2
	}
	settings.AdjustClient = func(device string, clientSettings *sidecar.EvsSettings) {
		if device == "writer1" || device == "reader1" {
			clientSettings.MaxFormat = 1
		}
	}
	return settings
}

// The world's checks, FS-72's format clause among them, and FI-17 once its oracle is bound.
func fs72Checks(world *EvsWorld) []Invariant {
	checks := world.Checks(world.FormatHolds())
	if slices.Contains(BuiltInvariants(), 17) {
		checks = append(checks, FI(17))
	}
	return checks
}

// See the file header.
func Fs72Migration(net *Net) *Schedule {
	schedule := fs72MigrationSchedule(net, true)
	schedule.Twin = Fs72MigrationRaceFree
	return schedule
}

// See the file header.
func Fs72MigrationRaceFree(net *Net) *Schedule {
	return fs72MigrationSchedule(net, false)
}

func fs72MigrationSchedule(net *Net, held bool) *Schedule {
	world := NewEvsWorld(net, fs72WorldSettings())
	format1Paths := []string{"a.txt", "b.txt", "c.txt", "d.txt"}
	steps := []*Step{
		{Actor: "writer2", Action: world.Setup},
		{Actor: "writer1", Action: world.Write("writer1", "a.txt", EvsWorldContent("fs72 a", 100))},
		{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat1)},
	}
	if held {
		steps = append(steps, []*Step{
			{Actor: "writer2", Action: world.WriteVersioningAny("writer2", "v.bin", fs72Kind5Content("fs72 v"), sidecar.EvsVersioningOff), Background: true},
			{Actor: "evs1", Await: evsservice.BarrierMigrateRaiseBefore},
			{Actor: "writer1", Action: world.Write("writer1", "b.txt", EvsWorldContent("fs72 b", 100))},
			{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat1)},
			{Release: []string{sidecartest.ActorBarrierSite("evs1", evsservice.BarrierMigrateRaiseBefore)}},
			{Actor: "evs1", Await: evsservice.BarrierMigrateRaiseAfter},
			{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat2)},
			{Actor: "writer1", Action: world.Write("writer1", "c.txt", EvsWorldContent("fs72 c", 100))},
			{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "b.txt", "c.txt", "v.bin")},
			{Release: []string{sidecartest.ActorBarrierSite("evs1", evsservice.BarrierMigrateRaiseAfter)}},
			{Actor: "writer2", Join: true},
			{Actor: "check", Action: world.ExpectCommitted("writer2", "v.bin")},
		}...)
	} else {
		steps = append(steps, []*Step{
			{Actor: "writer1", Action: world.Write("writer1", "b.txt", EvsWorldContent("fs72 b", 100))},
			{Actor: "writer1", Action: world.Write("writer1", "c.txt", EvsWorldContent("fs72 c", 100))},
			{Actor: "writer2", Action: world.WriteVersioning("writer2", "v.bin", fs72Kind5Content("fs72 v"), sidecar.EvsVersioningOff)},
		}...)
	}
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat2)},
		{Actor: "writer1", Action: world.Write("writer1", "d.txt", EvsWorldContent("fs72 d", 100))},
		{Actor: "reader1", Action: world.Verify("reader1", format1Paths...)},
		{Actor: "reader1", Action: world.VerifyNeedsFormat2("reader1", "v.bin")},
		{Actor: "writer1", Action: world.Verify("writer1", format1Paths...)},
		{Actor: "writer1", Action: world.VerifyNeedsFormat2("writer1", "v.bin")},
		{Actor: "writer1", Action: world.WriteNeedsFormat2("writer1", "v.bin", EvsWorldContent("fs72 v by format 1", 100), "")},
		{Actor: "reader2", Action: world.Verify("reader2", append(slices.Clone(format1Paths), "v.bin")...)},
	}...)
	return &Schedule{Id: "FS-72 migration", Steps: steps, Check: fs72Checks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header. step is one of Fs72MigrationSteps.
func Fs72MigrationKilledAt(step string) Builder {
	return func(net *Net) *Schedule {
		world := NewEvsWorld(net, fs72WorldSettings())
		skip := 0
		if step == evsservice.BarrierHeadCasBefore || step == evsservice.BarrierHeadCasAfter || step == evsservice.BarrierPushStep6After {
			// a.txt's commit by writer2 on evs1 passes first
			skip = 1
		}
		steps := []*Step{
			{Actor: "writer2", Action: world.Setup},
			{Actor: "writer2", Action: world.Write("writer2", "a.txt", EvsWorldContent("fs72 a", 100))},
			{Actor: "writer2", Action: world.WriteVersioningAny("writer2", "v.bin", fs72Kind5Content("fs72 v"), sidecar.EvsVersioningOff), Background: true},
			{Actor: "evs1", Await: step, AwaitSkip: skip},
			{Actor: "evs1", Kill: true},
			{Actor: "writer2", Join: true},
			{Actor: "check", Action: world.ExpectCommitted("writer2", "v.bin")},
			{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat2)},
			{Actor: "check", Action: world.Expect("one commit of the push", func(ctx context.Context) error {
				return fs72CommittedOnce(world, "writer2")
			})},
			{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "v.bin")},
			{Actor: "evs1", Restart: "evs1"},
			{Actor: "writer1", Action: world.Write("writer1", "b.txt", EvsWorldContent("fs72 b", 100))},
			{Actor: "writer2", Action: world.WriteVersioning("writer2", "w.bin", fs72StagedContent("fs72 w"), sidecar.EvsVersioningOff)},
			{Actor: "reader1", Action: world.Verify("reader1", "a.txt", "b.txt")},
			{Actor: "reader1", Action: world.VerifyNeedsFormat2("reader1", "v.bin", "w.bin")},
			{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "b.txt", "v.bin", "w.bin")},
		}
		return &Schedule{Id: "FS-72 migration killed at " + step, Steps: steps, Check: fs72Checks(world), Tiers: []Tier{TierT2, TierT3}}
	}
}

// device's newest push committed at one version, which every instance that answered it 200 names.
func fs72CommittedOnce(world *EvsWorld, device string) error {
	answers, pushId, err := world.NewestAnswers(device)
	if err != nil {
		return err
	}
	version, committed := world.committedVersionOf(pushId)
	if !committed {
		return fmt.Errorf("%s's push %s did not commit: %v", device, pushId, answers)
	}
	for _, answer := range answers {
		if answer.Status == http.StatusOK && answer.Version != version {
			return fmt.Errorf("%s's push %s answered %s, committed at version %d", device, pushId, answer, version)
		}
	}
	return nil
}

// See the file header.
func Fs72Rollback(net *Net) *Schedule {
	schedule := fs72RollbackSchedule(net, true)
	schedule.Twin = Fs72RollbackForwardOnly
	return schedule
}

// See the file header.
func Fs72RollbackForwardOnly(net *Net) *Schedule {
	return fs72RollbackSchedule(net, false)
}

func fs72RollbackSchedule(net *Net, rollBack bool) *Schedule {
	world := NewEvsWorld(net, fs72WorldSettings())
	instances := []string{"evs1", "evs2", "evsr"}
	mark := &EvsWorldStoreMark{}
	steps := []*Step{
		{Actor: "writer2", Action: world.Setup},
		{Actor: "writer1", Action: world.Write("writer1", "a.txt", EvsWorldContent("fs72 a", 100))},
		{Actor: "writer2", Action: world.WriteVersioning("writer2", "u.bin", fs72Kind5Content("fs72 u"), sidecar.EvsVersioningOff)},
		{Actor: "writer2", Action: world.WriteVersioning("writer2", "k.bin", fs72Kind5Content("fs72 k 1"), sidecar.EvsVersioningOff)},
		{Actor: "writer2", Action: world.WriteVersioning("writer2", "k.bin", fs72Kind5Content("fs72 k 2"), "")},
		{Actor: "writer2", Action: world.WriteVersioning("writer2", "v.bin", fs72StagedContent("fs72 v"), sidecar.EvsVersioningOff)},
		// the window folded on format 2, and a commit of evs1's carrying it, so no read but v.bin's needs a record of
		// format 2's layout
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writer2", Action: world.Write("writer2", "a.txt", EvsWorldContent("fs72 a 2", 100))},
		{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat2)},
		{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "u.bin", "k.bin", "v.bin")},
		{Actor: "admin", Action: world.SetFormat2Modes(&EvsWorldFormat2Settings{Purge: "on", Drop: "observe"})},
		{Actor: "check", Action: world.MarkStore(mark)},
	}
	format := uint32(sidecar.EvsRepoFormat2)
	if rollBack {
		format = sidecar.EvsRepoFormat1
	}
	steps = append(steps, fs72Restart(world, instances, format)...)
	if rollBack {
		steps = append(steps, []*Step{
			// the format-1 client, whose last read predates the migration, cannot read the history it must build on
			// from a format-1 evs, which serves no record of format 2's layout, and posts nothing
			{Actor: "writer1", Action: world.WriteNeedsFormat2("writer1", "b.txt", EvsWorldContent("fs72 b", 100), "")},
			// the format-2 writer's push reaches evs and is answered 503 before step 4, writing nothing; its write
			// over v.bin, whose staged record the format-1 evs cannot serve, posts nothing
			{Actor: "writer2", Action: world.WriteUnavailable("writer2", "a.txt", EvsWorldContent("fs72 a 3", 100), "")},
			{Actor: "writer2", Action: world.WriteNeedsFormat2("writer2", "v.bin", fs72StagedContent("fs72 v 2"), "")},
			// it serves the stored bytes of records of format 1's layout, u.bin's versionless version among them, and
			// no record of format 2's: k.bin's newest lists a purge candidate and v.bin's stages its content
			{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "u.bin")},
			{Actor: "reader2", Action: world.VerifyNeedsFormat2("reader2", "k.bin", "v.bin")},
			{Actor: "reader1", Action: world.VerifyNeedsFormat2("reader1", "u.bin", "k.bin", "v.bin")},
			{Advance: 26 * time.Hour},
			{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat1, fs72LeftByFormat1)},
			{Actor: "check", Action: world.NoSegmentDeletesSince(mark)},
			{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat2)},
			{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "u.bin")},
			{Actor: "reader2", Action: world.VerifyNeedsFormat2("reader2", "k.bin", "v.bin")},
			// rolled forward, with the purge back in observe so the forward run is evacuation's alone
			{Actor: "admin", Action: world.SetFormat2Modes(DefaultEvsWorldFormat2Settings())},
		}...)
		steps = append(steps, fs72Restart(world, instances, sidecar.EvsRepoFormat2)...)
	} else {
		steps = append(steps, []*Step{
			{Advance: 26 * time.Hour},
			{Actor: "admin", Action: world.SetFormat2Modes(DefaultEvsWorldFormat2Settings())},
		}...)
	}
	steps = append(steps, []*Step{
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, fs72TakenByFormat2)},
		{Actor: "check", Action: world.Expect("every batch taken", func(ctx context.Context) error {
			return fs72NoBatches(ctx, world)
		})},
		{Actor: "check", Action: world.ExpectRepoFormat(sidecar.EvsRepoFormat2)},
		{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "u.bin", "k.bin", "v.bin")},
		{Actor: "writer2", Action: world.Verify("writer2", "a.txt", "u.bin", "k.bin", "v.bin")},
		{Actor: "reader1", Action: world.Verify("reader1", "a.txt")},
		{Actor: "reader1", Action: world.VerifyNeedsFormat2("reader1", "u.bin", "k.bin", "v.bin")},
		{Actor: "writer1", Action: world.Write("writer1", "b.txt", EvsWorldContent("fs72 b 2", 100))},
		{Actor: "writer2", Action: world.WriteVersioning("writer2", "v.bin", fs72StagedContent("fs72 v 3"), "")},
		{Actor: "reader2", Action: world.Verify("reader2", "a.txt", "b.txt", "u.bin", "k.bin", "v.bin")},
	}...)
	schedule := &Schedule{Id: "FS-72 rollback", Steps: steps, Check: fs72Checks(world), Tiers: []Tier{TierT2, TierT3}}
	if rollBack {
		schedule.Refuses = "every push to the format-2 repo at a format-1 evs, 503 writing nothing, and v.bin's read, as needing format 2"
	}
	return schedule
}

// Every instance killed and started again at format, over the same stores.
func fs72Restart(world *EvsWorld, instances []string, format uint32) []*Step {
	steps := []*Step{}
	for _, instance := range instances {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.SetInstanceFormat(instance, format)},
			{Actor: instance, Kill: true},
			{Actor: instance, Restart: instance},
		}...)
	}
	return steps
}

// A format-1 evacuation 26 h on: the format-2 batches stay, each alarmed evacuate_batch_format, their minute waiting,
// and nothing of the minute is deleted.
func fs72LeftByFormat1(result *evsservice.EvacuationResult, alarms []string) error {
	if !EvsWorldAlarmsName(alarms, "evacuate_batch_format") {
		return fmt.Errorf("no evacuate_batch_format alarm: %v", alarms)
	}
	if result.BatchDeletedCount != 0 || result.MinuteDeletedCount != 0 || result.MinuteWaitingCount == 0 {
		return fmt.Errorf("deleted %d batches in %d minutes, %d waiting", result.BatchDeletedCount, result.MinuteDeletedCount, result.MinuteWaitingCount)
	}
	if result.StagedWrittenCount != 0 || result.StagedDroppedCount != 0 || result.Swept.CandidateCount != 0 {
		return fmt.Errorf("settled %d staged segments, dropped %d and swept %d candidates", result.StagedWrittenCount, result.StagedDroppedCount, result.Swept.CandidateCount)
	}
	return nil
}

// A format-2 evacuation: nothing alarmed of a batch's format or checks, and the candidate k.bin's newest version lists
// logged and kept, purge being observe. The run that answers may be a rerun after a store fault (EvacuateAt), so what
// it moved and wrote is read from the store after it (fs72NoBatches) and from every newest version's read.
func fs72TakenByFormat2(result *evsservice.EvacuationResult, alarms []string) error {
	if EvsWorldAlarmsName(alarms, "evacuate_batch_format") || EvsWorldAlarmsName(alarms, "evacuate_batch_invalid") {
		return fmt.Errorf("alarmed: %v", alarms)
	}
	if result.Swept.DeletedCount != 0 {
		return fmt.Errorf("the sweep deleted %d candidates in observe", result.Swept.DeletedCount)
	}
	return nil
}

// No batch is left on the repo's cluster: evacuation took every one, its staged segments settled.
func fs72NoBatches(ctx context.Context, world *EvsWorld) error {
	view := NewStoreView(world.net, nil)
	clusterId, err := view.RepoClusterId(sidecartest.InspectContext(ctx), world.RepoId)
	if err != nil {
		return err
	}
	batches, err := view.Batches(sidecartest.InspectContext(ctx), clusterId)
	if err != nil {
		return err
	}
	if len(batches) != 0 {
		keys := []string{}
		for key := range batches {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		return fmt.Errorf("batches left: %v", keys)
	}
	return nil
}
