// FS-95's M10 case (§22.8; §11.7's rule, action, list and states rows, §8.8's lock, D-ACL-25, FI-17, FI-27;
// EVS2-M10-31) on the evs world with its drop wiring (evs_world_drop.go): the drops evs and an honest client refuse,
// each beside a twin that must succeed. An honest client refuses most of them itself before it sends anything
// (ErrEvsDropRefused, ErrEvsDropPath, ErrEvsDropVersionless), so each clause that evs holds too also sends the DROP a
// modified client would, built by hand over the same history (EvsWorld.DropFill) and posted through the lb.
//
//	refusals      Fs95Refusals, the registered case, in a general repo: a writer that is no admin refused by its own
//	              client and, sending the DROP anyway under the write scope it can get, 403 SCOPE; a path naming a
//	              directory and one under .ur-index/ (ErrEvsDropPath); a path whose head is versionless
//	              (ErrEvsDropVersionless); the network's evs_drops_per_day spent by two drops, its next drop 429 while a
//	              cancel of the first is accepted, at the storage limit too; at the storage limit a drop of a path whose
//	              head an inline record holds accepted and one whose head needs an upload refused; a cancel within 60 s
//	              of its drop's not_before refused (ErrEvsDropState), the drop then executing. The twin, Fs95Accepted,
//	              is the same history with the admin's drops accepted and executed
//	locked        Fs95Locked: a lock filed in a pending drop's window voids it at its start, the job moving it to
//	              refused {locked} and deleting nothing, its listed versions reading on; in the locked repo the admin's
//	              client refuses a drop, and the DROP sent anyway gets 409 VERSIONING. The twin, Fs95Unlocked, is the
//	              same drops with no lock, executed
//	kind          Fs95Kind(config or mailcfg): the admin's client refuses, and the DROP sent anyway gets 409 DROP_KIND.
//	              The twin is Fs95Accepted
//	owner-bound   Fs95OwnerBound, a secret repo: an admin that is not the owner's consented device refused by its
//	              client and, sending the DROP anyway, 409 DROP_CONSENT, while the owner's consented device's drop is
//	              accepted. The twin, Fs95OwnerBoundConsented, is the same admin consented, its drop accepted
//	list          Fs95ListMismatch(adding): a DROP whose list leaves out one version, or adds one, commits, as evs
//	              cannot read a list against a history it holds sealed, and the job's resolve refuses it {mismatch}:
//	              nothing is deleted and every listed version reads on. The twin is Fs95Accepted
//
// Not here, each a deferral in EVS2-M10-31's report: git-mode and creates-only refs (409 REF_MODE), ur/lfs's objects and
// the reserved names beyond .ur-index/, a modified client's DROP at a reserved name raising history_drop at readers, a
// written version whose oid differs, the owner's page Worker, the MCP surface, a DROP past its body or list bound or
// in parts, and a head-mode device's drop of 5,000 versions; the format-1 cases are EVS1-M2-39's.

package fault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs95Case = Register("FS-95", "", []Tier{TierT2, TierT3}, Fs95Refusals)

// What an FS-95 world's drops cost a day (EvsWorldDropSettings.DropsPerDay), which Fs95Refusals spends.
const fs95DropsPerDay = 2

// A file whose versions each need an upload: 40 KiB, past what a record holds inline.
func fsDropUploadContent(label string) []byte {
	return EvsWorldContent(label, 40*1024)
}

// A file a record holds inline: 100 B.
func fsDropInlineContent(label string) []byte {
	return EvsWorldContent(label, 100)
}

// The drop rows' world: admin, a repo admin on evs1 then evs2; writer, a writer that is no admin, on evs2 then evs1;
// reader on evsr; every device and instance of format 2, the network in the format2 gate with purge and drop on, and
// the drop limits a clause names. A repo of kind, owner-bound kinds getting owner, the owner's consented admin
// device, beside admin, which is consented only where consented says so.
func fsDropWorldSettings(kind protocol.RepoKind, consented bool) *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Kind = kind
	settings.Instances = []string{"evs1", "evs2", "evsr"}
	settings.Devices = []*EvsWorldDeviceSettings{
		{Name: "admin", Instances: []string{"evs1", "evs2"}, Writer: true, Admin: true, Format2: true, Consented: consented},
		{Name: "writer", Instances: []string{"evs2", "evs1"}, Writer: true, Format2: true},
		{Name: "reader", Instances: []string{"evsr"}, Format2: true},
	}
	if sidecar.EvsRepoKindOwnerBound(kind) {
		settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{
			Name: "owner", Instances: []string{"evs1", "evs2"}, Writer: true, Admin: true, Format2: true, Consented: true,
		})
	}
	settings.Format2 = &EvsWorldFormat2Settings{Purge: "on", Drop: "on"}
	settings.InstanceFormats = map[string]uint32{}
	for _, instance := range settings.Instances {
		settings.InstanceFormats[instance] = sidecar.EvsRepoFormat2
	}
	settings.Drops = DefaultEvsWorldDropSettings()
	return settings
}

// The world's checks with FS-72's format clause and the format-2 invariants FI-16, FI-17 and FI-27 after every step.
func fsDropChecks(world *EvsWorld) []Invariant {
	return world.Checks(world.FormatHolds(), FI(16), FI(17), FI(27))
}

// Steps: device writes path count times, each version's content of its own, by content.
func fsDropWrites(world *EvsWorld, device string, path string, count int, content func(label string) []byte) []*Step {
	steps := []*Step{}
	for version := 1; version <= count; version += 1 {
		steps = append(steps, &Step{Actor: device, Action: world.Write(device, path, content(fmt.Sprintf("%s %d", path, version)))})
	}
	return steps
}

// path's version-th write's content, as fsDropWrites wrote it.
func fsDropWritten(path string, version int, content func(label string) []byte) []byte {
	return content(fmt.Sprintf("%s %d", path, version))
}

// Steps: the hours a now drop's job waits for evacuation's horizon pass, an evacuation, and the drop job to its end.
func fsDropExecute(world *EvsWorld) []*Step {
	return []*Step{
		{Advance: 50 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, nil)},
		{Actor: "taskworker", Action: world.RunDropJob("taskworker", nil)},
	}
}

// A step action: the world's network stands at its storage limit, or with limited false below it again.
func fsDropStorageLimit(world *EvsWorld, limited bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		var refusal *sidecar.QuotaRefusal
		if limited {
			refusal = &sidecar.QuotaRefusal{LimitKey: "storage"}
		}
		net.Fakes().Quota.SetStorageRefusal(connect.Id(world.NetworkId), refusal)
		return nil
	}
}

// A check of a refused drop's error: any error at all, which a clause names where the limit's own answer reaches the
// client through more than one route.
func fsDropAnyRefusal() func(err error) error {
	return func(err error) error { return nil }
}

// The history every general-repo clause of FS-95 starts from: x.txt, three versions each needing an upload; s.txt,
// three inline; a.txt, b.txt and c.txt, two each; v.bin, versionless; d/f.txt, in a directory.
func fs95History(world *EvsWorld) []*Step {
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	steps = append(steps, fsDropWrites(world, "admin", "x.txt", 3, fsDropUploadContent)...)
	steps = append(steps, fsDropWrites(world, "admin", "s.txt", 3, fsDropInlineContent)...)
	for _, path := range []string{"a.txt", "b.txt", "c.txt"} {
		steps = append(steps, fsDropWrites(world, "admin", path, 2, fsDropUploadContent)...)
	}
	return append(steps, []*Step{
		{Actor: "admin", Action: world.WriteVersioning("admin", "v.bin", fs72Kind5Content("v.bin 1"), sidecar.EvsVersioningOff)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "v.bin", fs72Kind5Content("v.bin 2"), "")},
		{Actor: "admin", Action: world.Write("admin", "d/f.txt", fsDropInlineContent("d/f.txt 1"))},
	}...)
}

// Every path fs95History writes, for a reader's verify.
var fs95Paths = []string{"x.txt", "s.txt", "a.txt", "b.txt", "c.txt", "v.bin", "d/f.txt"}

func fs95Settings() *EvsWorldSettings {
	settings := fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false)
	settings.Drops.DropsPerDay = fs95DropsPerDay
	return settings
}

// See the file header.
func Fs95Refusals(net *Net) *Schedule {
	world := NewEvsWorld(net, fs95Settings())
	byWriter := &EvsWorldPosted{}
	mark := &EvsWorldStoreMark{}
	steps := fs95History(world)
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.MarkStore(mark)},
		// a non-admin: its own client, then the DROP it sends anyway
		{Actor: "writer", Action: world.DropRefused("writer", "x.txt", true, EvsWorldExpectError(sidecar.ErrEvsDropRefused))},
		{Actor: "writer", Action: world.PostPlan("writer", nil, byWriter, world.DropFill("s.txt", true))},
		{Actor: "check", Action: EvsWorldExpectPosted(byWriter, http.StatusForbidden, protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)},
		// paths a drop cannot name
		{Actor: "admin", Action: world.DropRefused("admin", "d", true, EvsWorldExpectError(sidecar.ErrEvsDropPath))},
		{Actor: "admin", Action: world.DropRefused("admin", ".ur-index/i1/postings", true, EvsWorldExpectError(sidecar.ErrEvsDropPath))},
		{Actor: "admin", Action: world.DropRefused("admin", "v.bin", true, EvsWorldExpectError(sidecar.ErrEvsDropVersionless))},
		// the day's drops spent: the next gets 429, a cancel is accepted, at the storage limit too
		{Actor: "admin", Action: world.Drop("admin", "a.txt", false)},
		{Actor: "admin", Action: world.Drop("admin", "b.txt", false)},
		{Actor: "admin", Action: world.DropRefused("admin", "c.txt", false, EvsWorldExpectRefusal(http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED))},
		{Actor: "owner", Action: fsDropStorageLimit(world, true)},
		{Actor: "admin", Action: world.CancelDrop("admin", "a.txt")},
		{Actor: "check", Action: world.ExpectDropState("a.txt", evsservice.DropStateCancelled)},
		// the next day, still at the storage limit: an inline head's drop is accepted, one needing an upload refused
		{Advance: 25 * time.Hour},
		{Actor: "admin", Action: world.Drop("admin", "s.txt", false)},
		{Actor: "admin", Action: world.DropRefused("admin", "x.txt", false, fsDropAnyRefusal())},
		{Actor: "owner", Action: fsDropStorageLimit(world, false)},
		// within 60 s of b.txt's not_before its cancel is refused, and the drop executes
		{Advance: 7*24*time.Hour - 25*time.Hour - 30*time.Second},
		{Actor: "admin", Action: world.CancelDropRefused("admin", "b.txt", EvsWorldExpectError(sidecar.ErrEvsDropState))},
		{Actor: "reader", Action: world.HistoryStates("reader", "b.txt", map[int]string{1: sidecar.EvsVersionStateDropPending})},
	}...)
	steps = append(steps, fsDropExecute(world)...)
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.ExpectDropState("b.txt", evsservice.DropStateDone)},
		{Actor: "check", Action: world.ExpectDropState("s.txt", evsservice.DropStateDone)},
		{Actor: "reader", Action: world.Verify("reader", fs95Paths...)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "b.txt", 1, EvsWorldReadsDropped())},
		// what was refused or cancelled kept every version
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "a.txt", 1, EvsWorldReadsContent(fsDropWritten("a.txt", 1, fsDropUploadContent)))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "c.txt", 1, EvsWorldReadsContent(fsDropWritten("c.txt", 1, fsDropUploadContent)))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsContent(fsDropWritten("x.txt", 1, fsDropUploadContent)))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 2, EvsWorldReadsContent(fsDropWritten("x.txt", 2, fsDropUploadContent)))},
	}...)
	return &Schedule{
		Id: "FS-95", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3},
		Refuses: "a non-admin's drop, a directory's, an index file's and a versionless head's, a drop past the day's limit, one needing an upload at the storage limit, and a cancel within 60 s of not_before",
		Twin:    Fs95Accepted,
	}
}

// See the file header.
func Fs95Accepted(net *Net) *Schedule {
	world := NewEvsWorld(net, fs95Settings())
	steps := fs95History(world)
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
		{Actor: "admin", Action: world.Drop("admin", "s.txt", true)},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped, 2: sidecar.EvsVersionStateDropped})},
	}...)
	steps = append(steps, fsDropExecute(world)...)
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		{Actor: "check", Action: world.ExpectDropState("s.txt", evsservice.DropStateDone)},
		{Actor: "reader", Action: world.Verify("reader", fs95Paths...)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "s.txt", 2, EvsWorldReadsDropped())},
	}...)
	return &Schedule{Id: "FS-95 accepted", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs95Locked(net *Net) *Schedule {
	schedule := fs95LockSchedule(net, true)
	schedule.Refuses = "a locked repo's drops, and a pending drop a lock filed in its window voids"
	schedule.Twin = Fs95Unlocked
	return schedule
}

// See the file header.
func Fs95Unlocked(net *Net) *Schedule {
	return fs95LockSchedule(net, false)
}

func fs95LockSchedule(net *Net, locked bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	posted := &EvsWorldPosted{}
	mark := &EvsWorldStoreMark{}
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	steps = append(steps, fsDropWrites(world, "admin", "w.txt", 2, fsDropUploadContent)...)
	steps = append(steps, fsDropWrites(world, "admin", "x.txt", 2, fsDropUploadContent)...)
	steps = append(steps, fsDropWrites(world, "admin", "z.txt", 2, fsDropInlineContent)...)
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.Drop("admin", "w.txt", false)},
		{Actor: "reader", Action: world.HistoryStates("reader", "w.txt", map[int]string{1: sidecar.EvsVersionStateDropPending})},
		{Actor: "check", Action: world.MarkStore(mark)},
	}...)
	firstOf := func(path string, content func(label string) []byte) func(read []byte, err error) error {
		return EvsWorldReadsContent(fsDropWritten(path, 1, content))
	}
	if locked {
		steps = append(steps, []*Step{
			{Actor: "owner", Action: world.LockRepo(true)},
			{Actor: "admin", Action: world.DropRefused("admin", "x.txt", true, EvsWorldExpectError(sidecar.ErrEvsDropRefused))},
			{Actor: "admin", Action: world.PostPlan("admin", nil, posted, world.DropFill("z.txt", true))},
			{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)},
			{Advance: 6 * 24 * time.Hour},
		}...)
		steps = append(steps, fsDropExecute(world)...)
		steps = append(steps, []*Step{
			{Actor: "check", Action: world.ExpectDropState("w.txt", evsservice.DropStateRefusedLocked)},
			{Actor: "check", Action: world.NoSegmentDeletesSince(mark)},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "w.txt", 1, firstOf("w.txt", fsDropUploadContent))},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, firstOf("x.txt", fsDropUploadContent))},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "z.txt", 1, firstOf("z.txt", fsDropInlineContent))},
		}...)
	} else {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
			{Actor: "admin", Action: world.Drop("admin", "z.txt", true)},
			{Advance: 6 * 24 * time.Hour},
		}...)
		steps = append(steps, fsDropExecute(world)...)
		steps = append(steps, []*Step{
			{Actor: "check", Action: world.ExpectDropState("w.txt", evsservice.DropStateDone)},
			{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "w.txt", 1, EvsWorldReadsDropped())},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "z.txt", 1, EvsWorldReadsDropped())},
		}...)
	}
	steps = append(steps, &Step{Actor: "reader", Action: world.Verify("reader", "w.txt", "x.txt", "z.txt")})
	return &Schedule{Id: "FS-95 lock", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header. kind is config or mailcfg.
func Fs95Kind(kind protocol.RepoKind) Builder {
	return func(net *Net) *Schedule {
		world := NewEvsWorld(net, fsDropWorldSettings(kind, false))
		posted := &EvsWorldPosted{}
		steps := []*Step{{Actor: "admin", Action: world.Setup}}
		steps = append(steps, fsDropWrites(world, "admin", "x.txt", 2, fsDropInlineContent)...)
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.DropRefused("admin", "x.txt", true, EvsWorldExpectError(sidecar.ErrEvsDropRefused))},
			{Actor: "admin", Action: world.PostPlan("admin", nil, posted, world.DropFill("x.txt", true))},
			{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_KIND)},
			{Actor: "reader", Action: world.Verify("reader", "x.txt")},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsContent(fsDropWritten("x.txt", 1, fsDropInlineContent)))},
		}...)
		return &Schedule{
			Id: "FS-95 " + kind.String(), Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3},
			Refuses: "a drop in a config or mailcfg repo", Twin: Fs95Accepted,
		}
	}
}

// See the file header.
func Fs95OwnerBound(net *Net) *Schedule {
	schedule := fs95OwnerBoundSchedule(net, false)
	schedule.Refuses = "an owner-bound repo's drop by an admin that is not its owner's consented device"
	schedule.Twin = Fs95OwnerBoundConsented
	return schedule
}

// See the file header.
func Fs95OwnerBoundConsented(net *Net) *Schedule {
	return fs95OwnerBoundSchedule(net, true)
}

// A secret repo's reads need the read receipt gate, which the evs world wires for no device, so these clauses hold
// each drop to evs's answer and the drop table's state, not to a reader's history.
func fs95OwnerBoundSchedule(net *Net, consented bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_SECRET, consented))
	posted := &EvsWorldPosted{}
	steps := []*Step{{Actor: "owner", Action: world.Setup}}
	steps = append(steps, fsDropWrites(world, "owner", "x.txt", 2, fsDropInlineContent)...)
	steps = append(steps, fsDropWrites(world, "owner", "z.txt", 2, fsDropInlineContent)...)
	if consented {
		steps = append(steps, &Step{Actor: "admin", Action: world.Drop("admin", "x.txt", true)})
	} else {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.DropRefused("admin", "x.txt", true, EvsWorldExpectError(sidecar.ErrEvsDropRefused))},
			{Actor: "admin", Action: world.PostPlan("admin", nil, posted, world.DropFill("x.txt", true))},
			{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_DROP_CONSENT)},
		}...)
	}
	// the owner's consented device is accepted either way
	steps = append(steps, &Step{Actor: "owner", Action: world.Drop("owner", "z.txt", true)})
	steps = append(steps, fsDropExecute(world)...)
	steps = append(steps, &Step{Actor: "check", Action: world.ExpectDropState("z.txt", evsservice.DropStateDone)})
	if consented {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)})
	}
	return &Schedule{Id: "FS-95 owner-bound", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header. adding lists one entry hash more; otherwise the list leaves one version out. The list with
// one more is a.txt's, a path created after others: evs itself refuses a list longer than the path versions below
// through_version (409 DROP_LIST), which x.txt, the ref's first path, would pass with any hash added.
func Fs95ListMismatch(adding bool) Builder {
	return func(net *Net) *Schedule {
		world := NewEvsWorld(net, fs95Settings())
		path, writeCount := "x.txt", 3
		if adding {
			path, writeCount = "a.txt", 2
		}
		steps := fs95History(world)
		steps = append(steps, &Step{Actor: "admin", Action: world.DropWithWrongList("admin", path, true, adding)})
		steps = append(steps, fsDropExecute(world)...)
		steps = append(steps, []*Step{
			{Actor: "check", Action: world.ExpectDropState(path, evsservice.DropStateRefusedMismatch)},
			{Actor: "reader", Action: world.Verify("reader", fs95Paths...)},
			{Actor: "check", Action: func(ctx context.Context, net *Net) error {
				entries, err := world.CommittedEntries(path)
				if err != nil {
					return err
				}
				if len(entries) != writeCount {
					return fmt.Errorf("%s has %d committed writes, not %d", path, len(entries), writeCount)
				}
				errs := []error{}
				for _, entry := range entries {
					errs = append(errs, world.ExpectSegments(fmt.Sprintf("%s version %d", path, entry.Entry.GetVersion()), true, func() ([][]byte, error) {
						return entry.SegmentIds(), nil
					})(ctx, net))
				}
				return errors.Join(errs...)
			}},
			{Actor: "reader", Action: world.ReadVersionEnds("reader", path, 1, EvsWorldReadsContent(fsDropWritten(path, 1, fsDropUploadContent)))},
		}...)
		return &Schedule{
			Id: "FS-95 list mismatch", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3},
			Refuses: "a drop whose list is not its path's versions", Twin: Fs95Accepted,
		}
	}
}
