// FS-9 (§22.8; §11.7's directory bound, §11.8's 5g; EVS1-M2-41) on the evs world (evs_world.go), T2 alone as the
// catalog has it.
//
// The registered case, Fs9DirectoryAtItsBound, beside its twin: pushes of 512 writes, a step each so no actor holds
// the driver's baton past its stall bound, each followed by a fold and a commit raising folded_through over it, write
// 3,584 children of a top-level directory D, each name under 64 B, so each sealed name with its nonce and tag frames
// to a 128-byte row and the 448 KiB of name table binds exactly, before the 4,096-child count; D's table is folded; a
// child added by another writer is refused 409 DIRECTORY_FULL from 5g after the ref's fence, and so is a second a
// second later, once the first's refusal record is past §11.8's one a second, after the reader lists D whole. The
// twin, Fs9DirectoryBelowItsBound, writes 3,582, and both child adds commit, the second filling D to its bound, each
// listing taking them.
//
// The clause beside it, Fs9UnfoldedListing, writes D at its bound in one push in parts and lists it and adds a child
// before the fold, FS-9's unfolded half: D's 448 KiB of rows sit in the push's unfolded delta, which the read reply
// carries in a frame of its own after D's path frame (QD-662; question evs1-m2-40-unfolded-listing-frame), for the
// listing and for the creation's own read of D alike, so neither passes the frame's 1 MiB and 64 KiB.
//
// D is top-level (QD-661; question evs1-m2-40-seal-root-part): the push that creates it changes the root's table, and
// the clause's push in parts names the root's empty token path as its first part's, which its seal record's 52-byte
// part item carries and every reader of the seal, FI-1's walk among them, reads as the root.
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

// D's path: a top-level directory.
const fs9Directory = "d"

// A child's path under D.
func fs9ChildPath(name string) string {
	return fs9Directory + "/" + name
}

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
		children[fs9ChildPath(name)] = EvsWorldContent(name, 16)
		names = append(names, name)
	}
	addOne := func(device string, name string) func(ctx context.Context, net *Net) error {
		if full {
			return world.WriteRefused(device, fs9ChildPath(name), EvsWorldContent(name, 16), protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL)
		}
		return world.Write(device, fs9ChildPath(name), EvsWorldContent(name, 16))
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
	}
	for first := 0; first < childCount; first += 512 {
		chunk := map[string][]byte{}
		for _, name := range names[first:min(first+512, childCount)] {
			chunk[fs9ChildPath(name)] = children[fs9ChildPath(name)]
		}
		// each push plans on D folded, with folded_through over its table: a second unfolded delta of one directory
		// has no proof a read can carry (question evs1-m2-28-rooted-delta-proofs)
		steps = append(steps,
			&Step{Actor: "writerA", Action: world.WritePaths("writerA", chunk)},
			&Step{Actor: "folder", Action: world.Fold("evs1")},
			// outside D's directory: a plan under it would cross the push's rooted delta before folded_through does
			&Step{Actor: "writerA", Action: world.Write("writerA", fmt.Sprintf("top-%d.txt", first), EvsWorldContent(fmt.Sprintf("fs9 top %d", first), 16))},
		)
	}
	steps = append(steps, []*Step{
		{Actor: "folder", Action: world.Fold("evs1")},
		{Actor: "writerB", Action: addOne("writerB", firstAdd)},
		{Actor: "reader", Action: world.VerifyListing("reader", fs9Directory, listed...)},
		{Advance: time.Second},
		{Actor: "writerB", Action: addOne("writerB", secondAdd)},
		{Actor: "reader", Action: world.VerifyListing("reader", fs9Directory, listedAfter...)},
		{Actor: "reader", Action: world.Verify("reader", fs9ChildPath(names[0]), fs9ChildPath(names[len(names)-1]), fs9ChildPath(firstAdd), fs9ChildPath(secondAdd))},
	}...)
	return &Schedule{Id: "FS-9", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2}}
}

// See the file header.
func Fs9UnfoldedListing(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	children := map[string][]byte{}
	names := []string{}
	for index := range fs9FullChildCount {
		name := fs9ChildName(index)
		children[fs9ChildPath(name)] = EvsWorldContent(name, 16)
		names = append(names, name)
	}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x/keep.txt", EvsWorldContent("fs9 keep", 16))},
		{Actor: "writerA", Action: world.WritePaths("writerA", children)},
		{Actor: "reader", Action: world.VerifyListing("reader", fs9Directory, names...)},
		{Actor: "writerB", Action: world.WriteRefused("writerB", fs9ChildPath(fs9ChildName(9001)), EvsWorldContent("fs9 add", 16), protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL)},
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
