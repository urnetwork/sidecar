// FS-4's three-source reads (§22.8's "two removals during a paused copy, reads finding every path across three
// sources"; DESIGN-DETAILS 9.2.4 and 9.6's reads row; EVS1-M2-41) on the evs world, against EVS1-M2-47's mapper and
// EVS1-M2-44's and EVS1-M2-45's fences and reads, as a clause beside fs4.go's registered case.
//
// Fs4ThreeSources: in each of epochs 1, 2 and 3 writerA creates a file in a directory of that epoch's own and the
// fold takes it into that epoch's entries; then a reader leaves, writerA's next write rotates to a REMOVE generation
// and records the due, and writerA's mapper commits the next PATH_EPOCH, no copy running between, so the head ends at
// epoch 4 over sources 3, 2 and 1, each source holding one file's entry. The reader reads every file and lists every
// directory across the three sources and the current epoch, and after evs's copy into epoch 4 drops all three
// sources, reads and lists them again.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

// The readers that leave in turn, one a cut-over.
var fs4SourcesLeavers = []string{"leaver1", "leaver2", "leaver3"}

// See the file header.
func Fs4ThreeSources(net *Net) *Schedule {
	settings := DefaultEvsWorldSettings()
	for _, name := range fs4SourcesLeavers {
		settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: name, Instances: []string{"evsr"}})
	}
	settings.AdjustClient = func(device string, settings *sidecar.EvsSettings) {
		settings.MapUploadCount = 1
	}
	world := NewEvsWorld(net, settings)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "keep.txt", EvsWorldContent("fs4 keep 0", 64))},
	}
	files := []string{"keep.txt"}
	sources := []uint64{}
	for index, leaver := range fs4SourcesLeavers {
		epoch := uint64(index + 1)
		directory := fmt.Sprintf("e%d", epoch)
		path := directory + "/f.txt"
		files = append(files, path)
		steps = append(steps,
			&Step{Actor: "writerA", Action: world.Write("writerA", path, EvsWorldContent("fs4 "+path, 200))},
			// the file's version into epoch's entries, which writerA's next commit on evs1 raises folded_through over
			&Step{Actor: "folder", Action: world.Fold("evs1")},
			&Step{Actor: "writerA", Action: world.Write("writerA", "keep.txt", EvsWorldContent(fmt.Sprintf("fs4 keep %d", epoch), 64))},
			&Step{Actor: "reader", Action: world.Verify("reader", files...)},
			&Step{Actor: "admin", Action: world.DropReader(leaver)},
			// a modification crosses the REMOVE generation and records the due
			&Step{Actor: "writerA", Action: world.Write("writerA", "keep.txt", EvsWorldContent(fmt.Sprintf("fs4 keep %d due", epoch), 64))},
			&Step{Actor: "writerA", Action: world.TickMapper("writerA")},
		)
		sources = append([]uint64{epoch}, sources...)
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectEpochSources(epoch+1, sources...)})
	}
	steps = append(steps, &Step{Actor: "reader", Action: world.Verify("reader", files...)})
	for index := range fs4SourcesLeavers {
		directory := fmt.Sprintf("e%d", index+1)
		steps = append(steps, &Step{Actor: "reader", Action: world.VerifyListing("reader", directory, "f.txt")})
	}
	steps = append(steps, &Step{Actor: "copier", Action: world.CopyInto(4)}, &Step{Actor: "check", Action: world.ExpectEpoch(4)})
	steps = append(steps, &Step{Actor: "reader", Action: world.Verify("reader", files...)})
	for index := range fs4SourcesLeavers {
		directory := fmt.Sprintf("e%d", index+1)
		steps = append(steps, &Step{Actor: "reader", Action: world.VerifyListing("reader", directory, "f.txt")})
	}
	return &Schedule{Id: "FS-4 three sources", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: main's head stands at path epoch current with exactly the sources listed, in whatever order the head
// lists them.
func (self *EvsWorld) ExpectEpochSources(current uint64, sources ...uint64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		head, err := self.Head(ctx)
		if err != nil {
			return err
		}
		if head == nil {
			return errors.New("main has no head")
		}
		listed := []uint64{}
		for _, source := range head.GetPathEpoch().GetSources() {
			listed = append(listed, source.GetEpoch())
		}
		want := slices.Clone(sources)
		slices.Sort(listed)
		slices.Sort(want)
		if evsservice.EvsHeadCurrentEpoch(head) != current || !slices.Equal(listed, want) {
			return fmt.Errorf("main's path epoch %v, not %d over %v", head.GetPathEpoch(), current, sources)
		}
		return nil
	}
}
