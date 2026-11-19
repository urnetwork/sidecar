// FS-94 (§22.8; §11.7's states and inline rows, §11.13's delete row, FI-1, FI-27; EVS2-M10-31) on the evs world with
// its drop wiring (evs_world_drop.go): a shared inline record. One push writes small x.txt and y.txt with the same
// bytes, so one batch record holds both entry versions; x.txt is written again and its history dropped.
//
//	general       Fs94, the registered case, a general repo: in the drop's window x.txt's listed version reads on,
//	              shown drop pending; after not_before it is withheld (dropped, nothing fetched), while y.txt is served
//	              and verifies at its newest and at the version the shared record holds, and the record's other entry
//	              versions keep their hashes (FI-1 opens every committed version after every step). The job then
//	              executes: nothing of a general repo's inline bytes is deleted, x.txt's listed versions stay withheld
//	              and y.txt reads on, a later write of y.txt verifying over the shared record. x.txt's path is then
//	              removed: its listed versions still read dropped, with no alarm
//	record class  Fs94RecordClass, a record repo, where each path's versions name their own slots: x.txt's listed
//	              versions are unreadable from the DROP's commit, the job deletes their slots, and y.txt, whose slot
//	              no listed version names, is served and verifies at both versions
//
// Not here, each a deferral in EVS2-M10-31's report: compaction's stub test, which waits on
// plan-EVSB-fs94-compaction-clause (compaction is Later, owner decision 247); x.txt's marker collected and its epoch
// drained after its removal; and the inline bytes unserved by push id, which no route of the world's client asks for.

package fault

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs94Case = Register("FS-94", "", []Tier{TierT2, TierT3}, Fs94)

// The bytes x.txt and y.txt share: small enough that one record holds both versions inline.
var fs94SharedContent = []byte("fs94: the bytes x.txt and y.txt both hold")

// See the file header.
func Fs94(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	mark := &EvsWorldStoreMark{}
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WritePair("admin", "x.txt", "y.txt", fs94SharedContent)},
		{Actor: "admin", Action: world.Write("admin", "x.txt", fsDropInlineContent("fs94 x second"))},
		{Actor: "check", Action: world.MarkStore(mark)},
		{Actor: "admin", Action: world.Drop("admin", "x.txt", false)},
		// in the window: pending, and still read
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropPending})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		// after not_before: withheld, y.txt served and verifying
		{Advance: 7*24*time.Hour + time.Minute},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
	}
	steps = append(steps, fsDropExecute(world)...)
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		// a general repo's inline bytes are in its packs, which a drop never rewrites
		{Actor: "check", Action: world.NoSegmentDeletesSince(mark)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		{Actor: "admin", Action: world.Write("admin", "y.txt", fsDropInlineContent("fs94 y second"))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		// the path removed: its listed versions still read dropped
		{Actor: "admin", Action: world.Remove("admin", "x.txt")},
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
	}...)
	return &Schedule{Id: "FS-94", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs94RecordClass(net *Net) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_RECORD, false))
	mark := &EvsWorldStoreMark{}
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WritePair("admin", "x.txt", "y.txt", fs94SharedContent)},
		{Actor: "admin", Action: world.Write("admin", "x.txt", fsDropInlineContent("fs94 x second"))},
		{Actor: "check", Action: world.MarkStore(mark)},
		{Actor: "admin", Action: world.Drop("admin", "x.txt", true)},
		// unreadable at once, y.txt read on
		{Actor: "reader", Action: world.HistoryStates("reader", "x.txt", map[int]string{1: sidecar.EvsVersionStateDropped})},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
	}
	steps = append(steps, fsDropExecute(world)...)
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.ExpectDropState("x.txt", evsservice.DropStateDone)},
		{Actor: "check", Action: fs94SlotDeletes(mark, 2)},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "x.txt", 1, EvsWorldReadsDropped())},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
		{Actor: "admin", Action: world.Write("admin", "y.txt", fsDropInlineContent("fs94 y second"))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "y.txt", 1, EvsWorldReadsContent(fs94SharedContent))},
	}...)
	return &Schedule{Id: "FS-94 record class", Steps: steps, Check: fsDropChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: taskworker deleted count slots since mark, the listed versions' own: x.txt's two versions below the
// drop's rewrite of its head, and none of y.txt's, whose reads the steps beside this hold.
func fs94SlotDeletes(mark *EvsWorldStoreMark, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		mark.stateLock.Lock()
		index := mark.index
		mark.stateLock.Unlock()
		history := net.BlobHistory()
		deleted := map[string]bool{}
		for _, entry := range history[min(index, len(history)):] {
			if entry.Op == sidecartest.BlobHistoryDelete && entry.Outcome == sidecartest.BlobOutcomeOk && strings.HasPrefix(entry.Key, "slot/") {
				deleted[entry.Key] = true
			}
		}
		if len(deleted) != count {
			return fmt.Errorf("%d slots were deleted since the drop, not the %d its listed versions name", len(deleted), count)
		}
		return nil
	}
}
