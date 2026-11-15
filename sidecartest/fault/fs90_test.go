package fault

// FS-90 on T2 (EVSB-M10-06; DESIGN-DETAILS 10.6): the drop job killed at its steps and resumed by another instance once
// the lease lapses, two instances racing the take, and a clock unknown or 150 ms fast starting and deleting nothing,
// over the real resolve, mark, verify and deletes. Each ends with the same delete set: the segments only the listed
// versions name deleted once, live content kept, and freed bytes reported once. A stale instance's DELETE held past its
// deadline is the deletes' own test (evsservice's TestDropDeleteStaleDeleteIsRefusedPastItsDeadline). Kills here stop a
// seam after or around its work, as the job meets an error there; kills at every barrier through the schedule
// harness, and T3, wait for the review phase.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What a kill returns.
var errFs90Killed = errors.New("killed")

// A history whose drop lists x's two versions, x2 named by them alone and s1 shared with y: d1 and d2 go, s1 stays.
type fs90History struct {
	world      *fsDropWorld
	refA       sidecar.Id
	dropId     sidecar.Id
	d1, d2, s1 [32]byte
}

func newFs90History(t *testing.T) *fs90History {
	world := newFsDropWorld(t)
	history := &fs90History{world: world, refA: fsDropId16("ref a"), dropId: fsDropId16("drop x"), d1: fsDropSegment("d1"), d2: fsDropSegment("d2"), s1: fsDropSegment("s1")}
	x := fsDropPath("x")
	first := world.write(history.refA, x, 0, &fsDropEntry{segments: [][32]byte{history.d1, history.s1}})
	second := world.write(history.refA, x, 1, &fsDropEntry{segments: [][32]byte{history.d2}})
	world.write(history.refA, fsDropPath("y"), 0, &fsDropEntry{segments: [][32]byte{history.s1}})
	world.drop(history.refA, history.dropId, []*protocol.EvsDropPath{fsDropPathOf(3, 1, nil, fsDropSource(1, x))}, [][][]byte{{first, second}})
	world.ripen(50 * time.Hour)
	return history
}

// The delete set held: d1 and d2 deleted, s1 kept, the drop done, and freed bytes reported once.
func (self *fs90History) requireDone(t *testing.T) {
	world := self.world
	if world.dropState(self.dropId) != evsservice.DropStateDone {
		t.Fatalf("drop state %d", world.dropState(self.dropId))
	}
	if world.stored(self.d1) || world.stored(self.d2) || !world.stored(self.s1) {
		t.Fatalf("d1 %t, d2 %t, s1 %t", world.stored(self.d1), world.stored(self.d2), world.stored(self.s1))
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(world.networkId)); delta != -2000 {
		t.Fatalf("stored delta %d, want -2000 reported once", delta)
	}
}

// A seam stopped once, after or around its work as a kill would.
type fs90KillResolver struct {
	inner evsservice.DropResolver
	armed bool
}

func (self *fs90KillResolver) Resolve(ctx context.Context, request *evsservice.DropResolveRequest) (*evsservice.DropResolveResult, error) {
	result, err := self.inner.Resolve(ctx, request)
	if self.armed && err == nil {
		self.armed = false
		return nil, errFs90Killed
	}
	return result, err
}

func (self *fs90KillResolver) Preview(ctx context.Context, request *evsservice.DropPreviewResolveRequest) (*evsservice.DropPreviewResolveResult, error) {
	return self.inner.Preview(ctx, request)
}

type fs90KillMarker struct {
	inner evsservice.DropMarker
	armed bool
}

func (self *fs90KillMarker) Mark(ctx context.Context, request *evsservice.DropMarkRequest) (*evsservice.DropMarkResult, error) {
	result, err := self.inner.Mark(ctx, request)
	if self.armed && err == nil {
		self.armed = false
		return nil, errFs90Killed
	}
	return result, err
}

type fs90KillVerifier struct {
	inner evsservice.DropVerifier
	armed bool
}

func (self *fs90KillVerifier) Verify(ctx context.Context, request *evsservice.DropVerifyRequest) (*evsservice.DropVerifyResult, error) {
	result, err := self.inner.Verify(ctx, request)
	if self.armed && err == nil {
		self.armed = false
		return nil, errFs90Killed
	}
	return result, err
}

// Deletes the first half of D, then stops as a kill after half the DELETEs would.
type fs90HalfDeleter struct {
	inner evsservice.DropDeleter
	armed bool
}

func (self *fs90HalfDeleter) Delete(ctx context.Context, request *evsservice.DropDeleteRequest) (*evsservice.DropDeleteResult, error) {
	if !self.armed || len(request.Candidates) < 2 {
		return self.inner.Delete(ctx, request)
	}
	self.armed = false
	half := *request
	half.Candidates = request.Candidates[:len(request.Candidates)/2]
	if _, err := self.inner.Delete(ctx, &half); err != nil {
		return nil, err
	}
	return nil, errFs90Killed
}

// The real seams of the world, each a kill a case arms.
type fs90Seams struct {
	resolver *fs90KillResolver
	marker   *fs90KillMarker
	verifier *fs90KillVerifier
	deleter  *fs90HalfDeleter
}

func newFs90Seams(world *fsDropWorld) *fs90Seams {
	host := world.host.ServiceHost()
	resolver, err := evsservice.NewDropResolve(host, &evsservice.DropResolveDeps{Settings: world.dropSettings, EvsSettings: world.settings})
	if err != nil {
		world.t.Fatal(err)
	}
	marker, err := evsservice.NewDropMark(host, &evsservice.DropMarkDeps{Settings: world.dropSettings, EvsSettings: world.settings})
	if err != nil {
		world.t.Fatal(err)
	}
	deleter, err := evsservice.NewDropDelete(host, &evsservice.DropDeleteDeps{Format2: world.format2, Settings: world.dropSettings, EvsSettings: world.settings})
	if err != nil {
		world.t.Fatal(err)
	}
	return &fs90Seams{
		resolver: &fs90KillResolver{inner: resolver}, marker: &fs90KillMarker{inner: marker},
		verifier: &fs90KillVerifier{inner: fsDropVerifier{}}, deleter: &fs90HalfDeleter{inner: deleter},
	}
}

// FS-90: the job killed after resolve, after mark, after verify, after half its DELETEs, and between a HEAD and its
// DELETE, then resumed by another instance once the lease lapses: one delete set, each id deleted once or found gone,
// freed bytes reported once, no live content lost.
func TestFs90KilledAndResumedByAnotherInstance(t *testing.T) {
	kills := map[string]func(seams *fs90Seams, world *fsDropWorld){
		"after resolve":          func(seams *fs90Seams, world *fsDropWorld) { seams.resolver.armed = true },
		"after mark":             func(seams *fs90Seams, world *fsDropWorld) { seams.marker.armed = true },
		"after verify":           func(seams *fs90Seams, world *fsDropWorld) { seams.verifier.armed = true },
		"after half the DELETEs": func(seams *fs90Seams, world *fsDropWorld) { seams.deleter.armed = true },
		"between a HEAD and its DELETE": func(seams *fs90Seams, world *fsDropWorld) {
			if _, err := world.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
				Op: sidecartest.FaultOpDelete, KeyPrefix: "seg/", ClusterId: "seg-1", Result: sidecartest.FailBeforeApply,
			}); err != nil {
				world.t.Fatal(err)
			}
		},
	}
	for name, arm := range kills {
		history := newFs90History(t)
		world := history.world
		seams := newFs90Seams(world)
		arm(seams, world)
		first := world.jobWith("a", seams.resolver, seams.marker, seams.verifier, seams.deleter)
		result, err := world.run(first)
		if err == nil && result.Ended {
			t.Fatalf("%s: the first instance ran through", name)
		}
		// the first instance's lease lapses; another takes the job and finishes it
		world.ripen(5 * time.Minute)
		second := world.jobWith("b", seams.resolver, seams.marker, seams.verifier, seams.deleter)
		if result := world.runToEnd(second, 8); !result.Ended {
			t.Fatalf("%s: the second instance: %+v", name, result)
		}
		history.requireDone(t)
		// the first instance, woken late, finds nothing of its own to do
		if result, err := world.run(first); err != nil || result.Ended {
			t.Fatalf("%s: the stale instance: %+v, %v", name, result, err)
		}
		history.requireDone(t)
	}
}

// FS-90: two instances racing the take: the table's If-Match lets one start the job, the other stops, and the one
// delete set is deleted once.
func TestFs90TwoInstancesRacingTheTake(t *testing.T) {
	history := newFs90History(t)
	world := history.world
	jobs := []*evsservice.DropJob{world.job("a"), world.job("b")}
	world.hddKnown()
	var wait sync.WaitGroup
	errs := make([]error, len(jobs))
	for i, job := range jobs {
		wait.Go(func() {
			_, errs[i] = job.Run(world.ctx, "meta-1", world.repoId)
		})
	}
	wait.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for range 4 {
		for _, job := range jobs {
			world.ripen(5 * time.Minute)
			if _, err := world.run(job); err != nil {
				t.Fatal(err)
			}
		}
	}
	history.requireDone(t)
	if deletes := world.host.Blobs.RequestCount("seg-1", sidecartest.FaultOpDelete); deletes != 2 {
		t.Fatalf("%d DELETEs on the segment cluster for two ids", deletes)
	}
}

// FS-90's clock clause: taskworker's clock unknown, or 150 ms fast, starts and deletes nothing.
func TestFs90AnUnsureClockStartsAndDeletesNothing(t *testing.T) {
	for _, unsure := range []func(world *fsDropWorld){
		func(world *fsDropWorld) { world.host.ClockCheck.SetUnknown() },
		func(world *fsDropWorld) { world.host.ClockCheck.SetOffset(150 * time.Millisecond) },
	} {
		history := newFs90History(t)
		world := history.world
		unsure(world)
		result, err := world.run(world.job("a"))
		if err != nil || result.Waiting != evsservice.DropWaitClock {
			t.Fatalf("an unsure clock: %+v, %v", result, err)
		}
		if world.dropState(history.dropId) != evsservice.DropStatePending || !world.stored(history.d1) || !world.stored(history.d2) {
			t.Fatal("an unsure clock started or deleted")
		}
		if requests := world.host.Blobs.RequestCount("seg-1", sidecartest.FaultOpDelete); requests != 0 {
			t.Fatalf("%d DELETEs", requests)
		}
	}
}
