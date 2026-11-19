// FS-68 (§22.8; §11.7's choose, refused, off, on and cite rows, §7.9's VersioningRules, §8.8's lock, owner decisions
// 167 and 168, FI-1, FI-17; EVS2-M10-31) on the evs world with format 2's gate and its rules and lock (evs_world_drop.go):
// a file's turns between versioning on and off, the rules that choose a new path's setting, the repos that never take
// versioning off, and the lock.
//
//	transitions   Fs68, the registered case, a general repo with purge on. c.bin, 9 MiB and chunked, turned off with
//	              its bytes unchanged: the new version is versionless, cites the versioned version's chunks as kind
//	              1, and uploads nothing. d.txt, small and diffed over three versions, turned off: one checkpoint,
//	              a single kind-5 locator. k.bin, written versionless as a kind-5 segment, turned on: the new version
//	              is versioned and names the uploaded segment as kind 1, uploading nothing. p.bin, versionless, is
//	              written twice. Each of c.bin, d.txt and k.bin is then written again and 30 h pass: the evacuation's
//	              sweep purges p.bin's replaced segment and nothing else, so no chunk a versioned version names, and no
//	              adopted chunk, is purged, and c.bin's versioned version reads whole
//	rules         Fs68Rules: under a VersioningRules record whose rule turns media/ off, a path created there is
//	              versionless and one created elsewhere versioned, while media/old.bin, created before the record,
//	              keeps its setting through a later write (owner decision 167); the repo's own rules, turning logs/
//	              off, then replace the network's: a new path under media/ is versioned and one under logs/ versionless
//	platform      Fs68PlatformRule: under no VersioningRules record the rule that holds is the platform's, off above
//	              a size, which the world gives at 64 KiB in place of the platform's 64 MiB
//	              (EvsWorldSettings.PlatformVersioning): an honest client writes 65 KiB versionless and 63 KiB
//	              versioned; under a present record that matches no rule a new 65 KiB file is versioned. The 64 MiB
//	              itself is sidecar's TestVersioningRulesFirstMatchAndThePlatformRule's: three steps of 63 MiB or
//	              more overran the driver's wait, 10 s then (60 s since QD-1101), on a loaded machine, and §22.8
//	              raises that wait for no row
//	kind          Fs68Kind(config or mailcfg): under a record turning every path off, an honest client's new path is
//	              versioned, and a writer that sends a file's turn to versioning off anyway (EvsWorld.VersioningFill)
//	              gets 409 VERSIONING. The twin, Fs68KindGeneral, is a general repo: the same record makes the new path
//	              versionless and the client's own turn to off commits
//	lock          Fs68LockedPastTheWindow: a versionless write is validated and held after its step 6 while the repo
//	              is locked; released 6 s on, past §11.8's 5 s window, its step 7 reruns the checks against the lock
//	              and it is refused 409 VERSIONING. Under the lock an honest client's write with versioning off commits
//	              versioned, and a writer sending the turn anyway gets 409 VERSIONING; an unlock restores versioning
//	              off. The twin, Fs68LockedWithinTheWindow, releases the held write within the window: it commits,
//	              versionless, its authorization pin the state before the lock (FI-17's lock clause)
//
// Not here, each a deferral in EVS2-M10-31's report: git-mode and creates-only refs; the index's own files committing
// under a lock (owner decision 168), whose root no world names yet; the lock's signer rule, which is §8.8's and the
// world files as a row; and an admin's edit reaching every repo of a network, the world holding one repo. The rules a
// device reads are the world's stand-in for ConfigState.VersioningFor's source order over the real
// sidecar.ConfigVersioningUnder and the platform rule (evs_world_drop.go's rules row).

package fault

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs68Case = Register("FS-68", "", []Tier{TierT2, TierT3}, Fs68)

const fs68MiB = 1024 * 1024

// A chunked file: 9 MiB, past the 8 MiB above which a file is stored in chunks.
func fs68ChunkedContent(label string) []byte {
	return EvsWorldContent(label, 9*fs68MiB)
}

// A small file a versioned repo stores as a checkpoint and diffs: 40 KiB, each version differing from base in a few
// bytes.
func fs68DiffedContent(edit string) []byte {
	content := EvsWorldContent("fs68 d", 40*1024)
	copy(content[1000:], []byte(edit))
	return content
}

// A step action: device's newest committed version of path names count locators, every one of kind.
func fs68ExpectChain(world *EvsWorld, device string, path string, kind protocol.EvsLocatorKind, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		entry, err := world.CommittedEntry(device, path)
		if err != nil {
			return err
		}
		chain := entry.Entry.GetChain()
		if count != 0 && len(chain) != count {
			return fmt.Errorf("%q's newest version names %d locators, not %d", path, len(chain), count)
		}
		if count == 0 && len(chain) < 2 {
			return fmt.Errorf("%q's newest version names %d locators, not several", path, len(chain))
		}
		for index, locator := range chain {
			if protocol.EvsLocatorKind(locator.GetKind()) != kind {
				return fmt.Errorf("%q's newest version's locator %d is of kind %d, not %d", path, index, locator.GetKind(), kind)
			}
		}
		return nil
	}
}

// A step action: no segment was uploaded since mark.
func fs68NoSegmentPutsSince(mark *EvsWorldStoreMark) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		index := mark.index
		mark.stateLock.Unlock()
		history := net.BlobHistory()
		for _, entry := range history[min(index, len(history)):] {
			switch entry.Op {
			case sidecartest.BlobHistoryPutIfNoneMatch, sidecartest.BlobHistoryPutIfMatch, sidecartest.BlobHistoryPutStream:
				if strings.HasPrefix(entry.Key, "seg/") {
					return fmt.Errorf("%s uploaded %s on %s", entry.Actor, entry.Key, entry.ClusterId)
				}
			}
		}
		return nil
	}
}

// See the file header.
func Fs68(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	chunked := fs68ChunkedContent("fs68 c")
	kind5 := fs72Kind5Content("fs68 k")
	offMark, onMark := &EvsWorldStoreMark{}, &EvsWorldStoreMark{}
	var versioned, adopted *EvsWorldCommittedEntry
	keep := func(into **EvsWorldCommittedEntry, path string) func(ctx context.Context, net *Net) error {
		return func(ctx context.Context, net *Net) error {
			entry, err := world.CommittedEntry("admin", path)
			*into = entry
			return err
		}
	}
	segmentsOf := func(entry **EvsWorldCommittedEntry) func() ([][]byte, error) {
		return func() ([][]byte, error) {
			if *entry == nil {
				return nil, fmt.Errorf("the version was not kept")
			}
			return (*entry).SegmentIds(), nil
		}
	}
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		// on to off on a chunked file
		{Actor: "admin", Action: world.Write("admin", "c.bin", chunked)},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "c.bin", 0)},
		{Actor: "check", Action: keep(&versioned, "c.bin")},
		{Actor: "check", Action: world.MarkStore(offMark)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "c.bin", chunked, sidecar.EvsVersioningOff)},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "c.bin", 1)},
		{Actor: "check", Action: fs68ExpectChain(world, "admin", "c.bin", protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, 0)},
		{Actor: "check", Action: fs68NoSegmentPutsSince(offMark)},
		// on to off on a small diffed file
		{Actor: "admin", Action: world.Write("admin", "d.txt", fs68DiffedContent("base"))},
		{Actor: "admin", Action: world.Write("admin", "d.txt", fs68DiffedContent("edit one"))},
		{Actor: "admin", Action: world.Write("admin", "d.txt", fs68DiffedContent("edit two"))},
		{Actor: "check", Action: fs68ExpectChain(world, "admin", "d.txt", protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, 0)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "d.txt", fs68DiffedContent("edit two"), sidecar.EvsVersioningOff)},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "d.txt", 1)},
		{Actor: "check", Action: fs68ExpectChain(world, "admin", "d.txt", protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, 1)},
		// off to on
		{Actor: "admin", Action: world.WriteVersioning("admin", "k.bin", kind5, sidecar.EvsVersioningOff)},
		{Actor: "check", Action: fs68ExpectChain(world, "admin", "k.bin", protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT, 1)},
		{Actor: "check", Action: world.MarkStore(onMark)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "k.bin", kind5, sidecar.EvsVersioningOn)},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "k.bin", 0)},
		{Actor: "check", Action: fs68ExpectChain(world, "admin", "k.bin", protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, 1)},
		{Actor: "check", Action: fs68NoSegmentPutsSince(onMark)},
		{Actor: "check", Action: keep(&adopted, "k.bin")},
		// each written again, and a versionless file replaced, which the sweep purges
		{Actor: "admin", Action: world.WriteVersioning("admin", "c.bin", fs68ChunkedContent("fs68 c again"), "")},
		{Actor: "admin", Action: world.WriteVersioning("admin", "d.txt", fs68DiffedContent("edit three"), "")},
		{Actor: "admin", Action: world.WriteVersioning("admin", "k.bin", fs72Kind5Content("fs68 k again"), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "k.bin", 0)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "p.bin", fs72Kind5Content("fs68 p"), sidecar.EvsVersioningOff)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "p.bin", fs72Kind5Content("fs68 p again"), "")},
		{Advance: 30 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, func(result *evsservice.EvacuationResult, alarms []string) error {
			if len(alarms) != 0 {
				return fmt.Errorf("it alarmed: %v", alarms)
			}
			switch {
			case !fsDropSettled(net):
				// the sweep's deletes wait on the clusters' settle flag, as a drop job's do (fsDropSettled)
				if result.Swept.DeletedCount != 0 {
					return fmt.Errorf("the sweep purged on clusters that have not passed settle: %+v", result.Swept)
				}
			case result.Swept.DeletedCount == 0:
				return fmt.Errorf("the sweep purged nothing, p.bin's replaced segment included: %+v", result.Swept)
			}
			return nil
		})},
		{Actor: "check", Action: world.ExpectSegments("c.bin's versioned version, whose chunks its versionless version cited", true, segmentsOf(&versioned))},
		{Actor: "check", Action: world.ExpectSegments("k.bin's adopted chunk", true, segmentsOf(&adopted))},
		{Actor: "reader", Action: world.Verify("reader", "c.bin", "d.txt", "k.bin", "p.bin")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "c.bin", 1, EvsWorldReadsContent(chunked))},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "k.bin", 2, EvsWorldReadsContent(kind5))},
	}
	return &Schedule{Id: "FS-68", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// A VersioningRules record of one rule: paths matching glob, of any size, turned off.
func fs68RulesOff(glob string) *protocol.VersioningRules {
	return &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{PathGlob: glob, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF}}}
}

// See the file header.
func Fs68Rules(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	content := func(label string) []byte { return fs72Kind5Content("fs68 " + label) }
	write := func(path string, versioning uint32) []*Step {
		return []*Step{
			{Actor: "admin", Action: world.WriteVersioning("admin", path, content(path), "")},
			{Actor: "admin", Action: world.ExpectVersioning("admin", path, versioning)},
		}
	}
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	steps = append(steps, write("media/old.bin", 0)...)
	steps = append(steps, &Step{Actor: "owner", Action: world.SetVersioningRules(fs68RulesOff("media/**"), nil)})
	steps = append(steps, write("media/new.bin", 1)...)
	steps = append(steps, write("docs/n.txt", 0)...)
	// an existing path keeps its setting
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.WriteVersioning("admin", "media/old.bin", content("media/old.bin again"), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "media/old.bin", 0)},
		{Actor: "owner", Action: world.SetVersioningRules(fs68RulesOff("media/**"), fs68RulesOff("logs/**"))},
	}...)
	steps = append(steps, write("media/newer.bin", 0)...)
	steps = append(steps, write("logs/l.bin", 1)...)
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.WriteVersioning("admin", "media/new.bin", content("media/new.bin again"), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "media/new.bin", 1)},
		{Actor: "reader", Action: world.Verify("reader", "media/old.bin", "media/new.bin", "docs/n.txt", "media/newer.bin", "logs/l.bin")},
	}...)
	return &Schedule{Id: "FS-68 rules", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// The size above which fs68's stand-in for the platform rule turns versioning off.
const fs68PlatformSizeAbove = 64 * 1024

// See the file header.
func Fs68PlatformRule(net *Net) *Schedule {
	settings := fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false)
	settings.PlatformVersioning = &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{SizeAboveBytes: fs68PlatformSizeAbove, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
	world := NewEvsWorld(net, settings)
	above := fs68PlatformSizeAbove + 1024
	below := fs68PlatformSizeAbove - 1024
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WriteVersioning("admin", "above.bin", EvsWorldContent("fs68 above", above), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "above.bin", 1)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "below.bin", EvsWorldContent("fs68 below", below), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "below.bin", 0)},
		// a present record that matches no rule here
		{Actor: "owner", Action: world.SetVersioningRules(fs68RulesOff("never/**"), nil)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "above-under-rules.bin", EvsWorldContent("fs68 above under rules", above), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "above-under-rules.bin", 0)},
		{Actor: "reader", Action: world.Verify("reader", "above.bin", "below.bin", "above-under-rules.bin")},
	}
	return &Schedule{Id: "FS-68 platform rule", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header. kind is config or mailcfg.
func Fs68Kind(kind protocol.RepoKind) Builder {
	return func(net *Net) *Schedule {
		schedule := fs68KindSchedule(net, kind)
		schedule.Refuses = "versioning off in a config or mailcfg repo"
		schedule.Twin = Fs68KindGeneral
		return schedule
	}
}

// See the file header.
func Fs68KindGeneral(net *Net) *Schedule {
	return fs68KindSchedule(net, protocol.RepoKind_REPO_KIND_GENERAL)
}

func fs68KindSchedule(net *Net, kind protocol.RepoKind) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(kind, false))
	posted := &EvsWorldPosted{}
	takes := kind == protocol.RepoKind_REPO_KIND_GENERAL
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.Write("admin", "c.bin", fsDropUploadContent("fs68 c"))},
		{Actor: "owner", Action: world.SetVersioningRules(fs68RulesOff(""), nil)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "n.bin", fs72Kind5Content("fs68 n"), "")},
	}
	if takes {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.ExpectVersioning("admin", "n.bin", 1)},
			{Actor: "admin", Action: world.WriteVersioning("admin", "c.bin", fsDropUploadContent("fs68 c"), sidecar.EvsVersioningOff)},
			{Actor: "admin", Action: world.ExpectVersioning("admin", "c.bin", 1)},
		}...)
	} else {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.ExpectVersioning("admin", "n.bin", 0)},
			{Actor: "admin", Action: world.PostPlan("admin", nil, posted, world.VersioningFill("c.bin", 1))},
			{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)},
			{Actor: "admin", Action: world.ExpectVersioning("admin", "c.bin", 0)},
		}...)
	}
	steps = append(steps, &Step{Actor: "reader", Action: world.Verify("reader", "c.bin", "n.bin")})
	return &Schedule{Id: "FS-68 " + kind.String(), Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs68LockedPastTheWindow(net *Net) *Schedule {
	schedule := fs68LockSchedule(net, true)
	schedule.Refuses = "versioning off under a lock, and a versionless write committing past 5 s after the lock"
	schedule.Twin = Fs68LockedWithinTheWindow
	return schedule
}

// See the file header.
func Fs68LockedWithinTheWindow(net *Net) *Schedule {
	return fs68LockSchedule(net, false)
}

func fs68LockSchedule(net *Net, late bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	posted := &EvsWorldPosted{}
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.Write("admin", "c.bin", fsDropUploadContent("fs68 c"))},
		// validated, its record written, and held: c.bin's commit passed evs1's step 6 first
		{Actor: "admin", Action: world.WriteVersioningAny("admin", "v.bin", fs72Kind5Content("fs68 v"), sidecar.EvsVersioningOff), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierPushStep6After, AwaitSkip: 1},
		{Actor: "owner", Action: world.LockRepo(true)},
	}
	if late {
		steps = append(steps, &Step{Advance: 6 * time.Second})
	}
	steps = append(steps, []*Step{
		{Release: []string{sidecartest.ActorBarrierSite("evs1", evsservice.BarrierPushStep6After)}},
		{Actor: "admin", Join: true},
	}...)
	if late {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectRefused("admin", "v.bin", protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)})
	} else {
		steps = append(steps, []*Step{
			{Actor: "check", Action: world.ExpectCommitted("admin", "v.bin")},
			{Actor: "admin", Action: world.ExpectVersioning("admin", "v.bin", 1)},
		}...)
	}
	steps = append(steps, []*Step{
		// under the lock: an honest client's off is a versioned write, and the turn sent anyway is refused
		{Advance: time.Minute},
		{Actor: "admin", Action: world.WriteVersioningAny("admin", "w.bin", fs72Kind5Content("fs68 w"), sidecar.EvsVersioningOff)},
		{Actor: "check", Action: world.ExpectCommitted("admin", "w.bin")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "w.bin", 0)},
		{Actor: "admin", Action: world.PostPlan("admin", nil, posted, world.VersioningFill("c.bin", 1))},
		{Actor: "check", Action: EvsWorldExpectPosted(posted, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING)},
		// an unlock restores it
		{Actor: "owner", Action: world.LockRepo(false)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "u.bin", fs72Kind5Content("fs68 u"), sidecar.EvsVersioningOff)},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "u.bin", 1)},
		{Actor: "reader", Action: world.Verify("reader", "c.bin", "w.bin", "u.bin")},
	}...)
	return &Schedule{Id: "FS-68 lock", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}
