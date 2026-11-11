// FS-4's steady creation through a batched epoch (§22.8's "a path created every second ... on a general ref under a
// batched one: each epoch still commits, first by its tail, then within a mapper's 2-min creation block"; §11.20's
// "steady creation through a batched epoch, which commits with a tail, then under a block"; DESIGN-DETAILS 9.2.7's
// tick, commit and block rows and 9.6's mapper row; EVS1-M2-41) on the evs world, against EVS1-M2-47's mapper and
// EVS1-M2-16's and EVS1-M2-44's 5e, tail check and block, as a clause beside fs4.go's registered case.
//
// Fs4BatchedEpoch: a reader's grant ends, which shrinks no holders, so writerA's next write rotates to a REMOVE
// generation whose crossing evs records as a batched due, and creation goes on. writerA's mapper starts at once, as
// the device that rotated; its PATH_EPOCH is held at step 6 on evs1 while writerB creates a file, so its tail misses
// it and evs refuses it 409 naming the path; its next push carries the file in its tail and commits epoch 2, which
// evs's copy then drains. A second grant ends, and 24 h and 11 min on, past the second due's due_by_ms and the 10 min
// the block waits for, the mapper's push is refused twice, writerB creating a file while each is held; after
// MapTailRefusalCount refusals the mapper blocks creation for 2 min, its third push is held while writerB's creation
// is refused 412 PATH_EPOCH_DUE, and the push commits epoch 3 inside the block. Once the block ends writerB creates
// again in epoch 3, and once evs's copy into 3 has drained source 2 the reader reads every file and lists the
// directory, as it does after epoch 2's copy.
//
// Fs4BatchedEpochReadBeforeCopy, a clause no test runs, reads before the copy into 3: the reader's read of d/n3.txt,
// created in epoch 2 by a push of generation 3 while the mapper's push was held and carried into epoch 3 by the
// PATH_EPOCH's tail, still unfolded, with the head at epoch 3 over source 2, fails with ErrEvsSealInvalid ("the seal
// does not open"), where the same read after the copy verifies (question evs1-m2-41-tail-creation-read).
//
// The holds are evs1's arrivals at evs.push.step6.before, which each push attempt reaches once, writerA's alone going
// to evs1: its two writes before each crossing and each of the mapper's pushes, a refused push's rerun and its
// record passing no step 6.

package fault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// See the file header.
func Fs4BatchedEpoch(net *Net) *Schedule {
	return fs4BatchedEpoch(net, false)
}

// See the file header.
func Fs4BatchedEpochReadBeforeCopy(net *Net) *Schedule {
	schedule := fs4BatchedEpoch(net, true)
	schedule.Id = "FS-4 batched epoch read before copy"
	return schedule
}

func fs4BatchedEpoch(net *Net, readBeforeCopy bool) *Schedule {
	settings := DefaultEvsWorldSettings()
	for _, name := range []string{"leaver1", "leaver2"} {
		settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: name, Instances: []string{"evsr"}})
	}
	settings.AdjustClient = func(device string, settings *sidecar.EvsSettings) {
		settings.MapUploadCount = 1
	}
	world := NewEvsWorld(net, settings)
	content := func(path string) []byte {
		return EvsWorldContent("fs4 batched "+path, 100)
	}
	files := []string{"keep.txt", "d/n0.txt"}
	hold := sidecartest.ActorBarrierSite("evs1", evsservice.BarrierPushStep6Before)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		// evs1's step 6 arrival 1
		{Actor: "writerA", Action: world.Write("writerA", "keep.txt", content("keep 0"))},
		{Actor: "writerB", Action: world.Write("writerB", "d/n0.txt", content("d/n0.txt"))},
		{Actor: "admin", Action: world.ExpireReader("leaver1", time.Hour)},
		{Advance: 2 * time.Hour},
		// arrival 2: the rotation's crossing
		{Actor: "writerA", Action: world.Write("writerA", "keep.txt", content("keep 1"))},
		{Actor: "check", Action: world.ExpectBatchedDue()},
		// a batched due holds no creation
		{Actor: "writerB", Action: world.Write("writerB", "d/n1.txt", content("d/n1.txt"))},
		{Actor: "writerA", Action: world.TickMapper("writerA"), Background: true},
		// arrival 3: the map's first push, whose tail misses what writerB creates while it is held
		{Actor: "evs1", Await: evsservice.BarrierPushStep6Before, AwaitSkip: 2},
		{Actor: "writerB", Action: world.Write("writerB", "d/n2.txt", content("d/n2.txt"))},
		{Advance: time.Second},
		{Release: []string{hold}},
		// arrival 4: its next push, d/n2.txt in its tail, commits
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectEpochSources(2, 1)},
		{Actor: "check", Action: world.ExpectRefusedPushes("writerA", 1)},
		{Actor: "copier", Action: world.CopyInto(2)},
		{Actor: "check", Action: world.ExpectEpoch(2)},
	}
	files = append(files, "d/n1.txt", "d/n2.txt")
	steps = append(steps, []*Step{
		{Actor: "reader", Action: world.Verify("reader", files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "d", "n0.txt", "n1.txt", "n2.txt")},
		{Actor: "admin", Action: world.ExpireReader("leaver2", time.Hour)},
		{Advance: 2 * time.Hour},
		// arrival 5: the second crossing, whose due_by_ms is 24 h on
		{Actor: "writerA", Action: world.Write("writerA", "keep.txt", content("keep 2"))},
		{Actor: "check", Action: world.ExpectBatchedDue()},
		// past due_by_ms by more than the block's 10 min, and short of epoch_overdue's hour
		{Advance: 24*time.Hour + 11*time.Minute},
		{Actor: "writerA", Action: world.TickMapper("writerA"), Background: true},
		// arrival 6: the first push, refused for d/n3.txt
		{Actor: "evs1", Await: evsservice.BarrierPushStep6Before, AwaitSkip: 2},
		{Actor: "writerB", Action: world.Write("writerB", "d/n3.txt", content("d/n3.txt"))},
		{Advance: time.Second},
		{Release: []string{hold}},
		// arrival 7: the second, refused for d/n4.txt
		{Actor: "evs1", Await: evsservice.BarrierPushStep6Before},
		{Actor: "writerB", Action: world.Write("writerB", "d/n4.txt", content("d/n4.txt"))},
		{Advance: time.Second},
		{Release: []string{hold}},
		// arrival 8: after the block, the third, held while a creation is refused
		{Actor: "evs1", Await: evsservice.BarrierPushStep6Before},
		{Actor: "check", Action: world.ExpectBlocks(1)},
		// past the mapper's refusal fence's 1 s, so the creation's refusal is recorded, not 429 WAIT
		{Advance: time.Second},
		{Actor: "writerB", Action: world.WriteHeldByBlock("writerB", "d/n5.txt", content("d/n5.txt"))},
		{Release: []string{hold}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectEpochSources(3, 2)},
		{Actor: "check", Action: world.ExpectRefusedPushes("writerA", 3)},
		// the block over, creation goes on in epoch 3
		{Advance: 2 * time.Minute},
		{Actor: "writerB", Action: world.Write("writerB", "d/n5.txt", content("d/n5.txt"))},
	}...)
	files = append(files, "d/n3.txt", "d/n4.txt", "d/n5.txt")
	reads := []*Step{
		{Actor: "reader", Action: world.Verify("reader", files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "d", "n0.txt", "n1.txt", "n2.txt", "n3.txt", "n4.txt", "n5.txt")},
	}
	copy := []*Step{
		{Actor: "copier", Action: world.CopyInto(3)},
		{Actor: "check", Action: world.ExpectEpoch(3)},
	}
	if readBeforeCopy {
		steps = append(append(append(steps, reads...), copy...), reads...)
	} else {
		steps = append(append(steps, copy...), reads...)
	}
	return &Schedule{Id: "FS-4 batched epoch", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: device's read of the repo ends after; the access log's grants say so, and no holder shrinks, so the
// REMOVE generation it calls for is batched (DESIGN-DETAILS 9.2.3).
func (self *EvsWorld) ExpireReader(device string, after time.Duration) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.Device(device)
		self.stateLock.Lock()
		self.readerExpiries[device] = net.Clock().Now().Add(after)
		self.stateLock.Unlock()
		self.appendView()
		return nil
	}
}

// A step action: main's head records a due that does not block creation.
func (self *EvsWorld) ExpectBatchedDue() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		head, err := self.Head(ctx)
		if err != nil {
			return err
		}
		if head == nil {
			return errors.New("main has no head")
		}
		epoch := head.GetPathEpoch()
		if epoch.GetDueGeneration() <= evsservice.EvsHeadCurrentEpoch(head) || epoch.GetDueBlocksCreation() {
			return fmt.Errorf("main's path epoch %v records no batched due", epoch)
		}
		return nil
	}
}

// A step action: device has posted exactly count push ids some instance refused.
func (self *EvsWorld) ExpectRefusedPushes(device string, count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		refused := 0
		for _, push := range self.DevicePushes(device) {
			for _, answer := range push.InstanceAnswers() {
				if answer.Refuses() {
					refused += 1
					break
				}
			}
		}
		if refused != count {
			return fmt.Errorf("%s posted %d refused pushes, not %d", device, refused, count)
		}
		return nil
	}
}

// A step action: count POSTs of .../path-epoch/block reached the lb.
func (self *EvsWorld) ExpectBlocks(count int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.blockRequestCount != count {
			return fmt.Errorf("%d path-epoch blocks requested, not %d", self.blockRequestCount, count)
		}
		return nil
	}
}

// A step action: device creates path during a mapper's block, which must not commit: evs refuses one of its pushes
// 412 PATH_EPOCH_DUE, and the client's tries after it, meeting that refusal's own fence, answer at most 429 WAIT,
// which refuses nothing.
func (self *EvsWorld) WriteHeldByBlock(device string, path string, content []byte) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		before := len(self.DevicePushes(device))
		write, err := self.write(ctx, device, path, content)
		if err != nil {
			return err
		}
		if write.state == evsWorldWriteCommitted {
			return fmt.Errorf("%s's creation of %q committed during the block", device, path)
		}
		for _, push := range self.DevicePushes(device)[before:] {
			for _, answer := range push.InstanceAnswers() {
				if answer.Code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE {
					return nil
				}
			}
		}
		return fmt.Errorf("no push of %s's creation of %q was refused PATH_EPOCH_DUE: %v", device, path, write.err)
	}
}
