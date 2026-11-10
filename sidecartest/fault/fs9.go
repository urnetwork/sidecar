// FS-9 (§22.8; §11.7's directory bound, §11.8's 5g; EVS1-M2-41) on the evs world (evs_world.go), T2 alone as the
// catalog has it.
//
// The registered case, Fs9DirectoryAtItsBound, beside its twin: one push, in parts, writes 3,584 children of a
// directory D under an existing top-level directory, each name under 64 B, so each sealed name with its nonce and tag frames to a 128-byte row and the 448
// KiB of name table binds exactly, before the 4,096-child count; D's table is folded; a child added by another writer
// is refused 409 DIRECTORY_FULL from 5g after the ref's fence, and so is a second a second later, once the first's
// refusal record is past §11.8's one a second, after the reader lists D whole. The twin, Fs9DirectoryBelowItsBound,
// writes 3,582, and both child adds commit, the second filling D to its bound, each listing taking them.
//
// The clause beside it, Fs9UnfoldedListing, lists D at its bound and adds a child before the fold, FS-9's unfolded
// half. On the landed engine the read reply's path frame, which carries the four parts' directory deltas and their
// proofs, passes the read frame's 1 MiB and 64 KiB bound, so evs notes stream_failed and the reply ends before its
// last frame, for the listing and for the creation's own read of D alike (question
// evs1-m2-40-unfolded-listing-frame); no test runs it until that is answered.
//
// D is not top-level: a push in parts that creates a top-level name changes the root's table, whose empty token path
// its seal record names as the first part's, which sidecar.ParseEvsSealRecordBody refuses, so FI-1's walk fails on
// it (question evs1-m2-40-seal-root-part).
//
// FS-9's same bound through a paused copy with carried rows counted untagged, the directory removal and creation
// races in both orders, as multi-part pushes sealed after the other commit, and a part adding to a full D are
// EVS1-M2-41's report's.

package fault

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs9 = Register("FS-9", "", []Tier{TierT2}, Twin(Fs9DirectoryAtItsBound, Fs9DirectoryBelowItsBound))

// The children that fill D's name table: names under 64 B pad to 64, seal to 104 B and frame to 128 B rows.
const fs9FullChildCount = sidecar.EvsNameTableMaxBoundByteCount / 128

// See the file header.
func Fs9DirectoryAtItsBound(net *Net) *Schedule {
	schedule := fs9Schedule(net, fs9FullChildCount)
	schedule.Refuses = "a child added to a directory whose name table is at 448 KiB, 409 DIRECTORY_FULL"
	return schedule
}

// See the file header.
func Fs9DirectoryBelowItsBound(net *Net) *Schedule {
	return fs9Schedule(net, fs9FullChildCount-2)
}

// A child name under 64 B, the same width for every index.
func fs9ChildName(index int) string {
	return fmt.Sprintf("child-%056d", index)
}

func fs9Schedule(net *Net, childCount int) *Schedule {
	world := NewEvsWorld(net, nil)
	full := childCount == fs9FullChildCount
	children := map[string][]byte{}
	names := []string{}
	for index := range childCount {
		name := fs9ChildName(index)
		children["x/d/"+name] = EvsWorldContent(name, 16)
		names = append(names, name)
	}
	addOne := func(device string, name string) func(ctx context.Context, net *Net) error {
		if full {
			return world.WriteRefused(device, "x/d/"+name, EvsWorldContent(name, 16), protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL)
		}
		return world.Write(device, "x/d/"+name, EvsWorldContent(name, 16))
	}
	firstAdd := fs9ChildName(9001)
	secondAdd := fs9ChildName(9002)
	listed := slices.Clone(names)
	if !full {
		listed = append(listed, firstAdd)
	}
	listedAfter := slices.Clone(listed)
	if !full {
		listedAfter = append(listedAfter, secondAdd)
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x/keep.txt", EvsWorldContent("fs9 keep", 16))},
		{Actor: "writerA", Action: world.WritePaths("writerA", children)},
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writerB", Action: addOne("writerB", firstAdd)},
		{Actor: "reader", Action: world.VerifyListing("reader", "x/d", listed...)},
		{Advance: time.Second},
		{Actor: "writerB", Action: addOne("writerB", secondAdd)},
		{Actor: "reader", Action: world.VerifyListing("reader", "x/d", listedAfter...)},
		{Actor: "reader", Action: world.Verify("reader", "x/d/"+names[0], "x/d/"+names[len(names)-1], "x/d/"+firstAdd, "x/d/"+secondAdd)},
	}
	return &Schedule{Id: "FS-9", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

// See the file header.
func Fs9UnfoldedListing(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	children := map[string][]byte{}
	names := []string{}
	for index := range fs9FullChildCount {
		name := fs9ChildName(index)
		children["x/d/"+name] = EvsWorldContent(name, 16)
		names = append(names, name)
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x/keep.txt", EvsWorldContent("fs9 keep", 16))},
		{Actor: "writerA", Action: world.WritePaths("writerA", children)},
		{Actor: "reader", Action: world.VerifyListing("reader", "x/d", names...)},
		{Actor: "writerB", Action: world.WriteRefused("writerB", "x/d/"+fs9ChildName(9001), EvsWorldContent("fs9 add", 16), protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL)},
	}
	return &Schedule{Id: "FS-9 unfolded listing", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

// A step action: device writes every path of files in one push (EvsRepo.WritePaths, in parts past 1,024 writes),
// which must commit; the ledger takes each path.
func (self *EvsWorld) WritePaths(device string, files map[string][]byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		paths := []string{}
		for path := range files {
			paths = append(paths, path)
		}
		slices.Sort(paths)
		writes := []*sidecar.EvsPathWrite{}
		ledger := []*evsWorldWrite{}
		self.stateLock.Lock()
		for _, path := range paths {
			write := &evsWorldWrite{device: device, content: bytes.Clone(files[path]), state: evsWorldWritePending}
			self.pathWrites[path] = append(self.pathWrites[path], write)
			ledger = append(ledger, write)
			pathWrite := &sidecar.EvsPathWrite{Path: path, Remove: files[path] == nil}
			if files[path] != nil {
				pathWrite.Content = bytes.NewReader(files[path])
			}
			writes = append(writes, pathWrite)
		}
		self.stateLock.Unlock()
		result, err := self.Device(device).Repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: writes})
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, write := range ledger {
			write.err = err
			if err == nil {
				write.state = evsWorldWriteCommitted
				write.version = result.Version
				write.pushId = result.PushId
			} else {
				write.state = evsWorldWriteUnknown
			}
		}
		if err != nil {
			return fmt.Errorf("%s's write of %d paths: %w", device, len(paths), err)
		}
		return nil
	}
}
