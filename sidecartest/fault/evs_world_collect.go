// The evs world's marker collection (evs_world.go; §11.7's collect row), a step FI-15's healthy run and FS-58's
// collection clause take (TEST-M2-04, EVS1-M2-41; QD-879).

package fault

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A step action: one marker collection of main, as taskworker's nightly pass queues it, its waits moving the Net's
// clock as a run's would: §11.7's window opens, waits out every fold planned on an older head and deletes the markers
// the horizon passed by a base range. A collection that was skipped, or that deleted no marker, fails the step, since
// what a schedule runs past it would prove nothing.
func (self *EvsWorld) CollectMarkers() func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		result, err := self.collectMarkers(ctx, net)
		if err != nil {
			return err
		}
		if result.MarkerDeletedCount == 0 {
			return errors.New("the collection deleted no marker")
		}
		return nil
	}
}

func (self *EvsWorld) collectMarkers(ctx context.Context, net *Net) (*evsservice.MarkerCollectResult, error) {
	host := *net.Host()
	host.Clock = &evsWorldSteppingClock{clock: net.Clock()}
	collector, err := evsservice.NewMarkerCollector(&host, nil)
	if err != nil {
		return nil, err
	}
	first, err := net.Host().Blobs.FirstCluster()
	if err != nil {
		return nil, err
	}
	result, err := collector.Collect(ctx, first.ClusterId(), self.RepoId, self.RefId())
	if err != nil {
		return result, err
	}
	if result.Skipped != "" {
		return result, errors.New("the collection was skipped: " + result.Skipped)
	}
	return result, nil
}

// The Net's clock for a collection run: a wait moves it as far as the wait asks, so a window's 15 s pass in the
// step that waits.
type evsWorldSteppingClock struct {
	clock *sidecartest.FakeClock
}

func (self *evsWorldSteppingClock) Now() time.Time {
	return self.clock.Now()
}

func (self *evsWorldSteppingClock) After(wait time.Duration) <-chan time.Time {
	self.clock.Advance(wait)
	fired := make(chan time.Time, 1)
	fired <- self.clock.Now()
	return fired
}

func (self *evsWorldSteppingClock) AfterFunc(wait time.Duration, function func()) (stop func() bool) {
	return self.clock.AfterFunc(wait, function)
}
