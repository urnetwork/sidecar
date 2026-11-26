package fault

// FS-21's last step (fs21.go's fs21Close) closes the world's gate cache and waits for its loaders. The row runs on T3
// alone, so this holds the step to it on T2's fakes, on a world with nothing but the cache: a load held in the cache's
// source when the step runs, on the Net's context, which no step ends, has returned, its OnLoad run with the close's
// cancel, by the step's end. Before, the step left the cache open, and the held load ran on past the schedule until
// the Net closed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A gate source whose cold start a test holds: Genesis reports on started and answers only once its context ends.
type fs21HeldSource struct {
	started chan struct{}
}

var _ sidecar.AclGateSource = (*fs21HeldSource)(nil)

func (self *fs21HeldSource) Genesis(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	self.started <- struct{}{}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (self *fs21HeldSource) Entries(ctx context.Context, networkId sidecar.Id, after *bridge.AuthPin) ([][]byte, error) {
	return nil, errors.New("the held source holds no entries")
}

func (self *fs21HeldSource) Rows(ctx context.Context, networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	return nil, errors.New("the held source holds no rows")
}

func TestFs21CloseWaitsForTheGateCachesLoad(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	// a failure's bound only
	guard := sidecartest.DefaultBarrierDriverSettings().AwaitTimeout
	world := &fs21World{fsTeamWorld: newFsTeamWorld(), devices: map[string]*fs21Device{}}
	source := &fs21HeldSource{started: make(chan struct{}, 1)}
	loadErrs := make(chan error, 1)
	settings := sidecar.DefaultAclGateSettings()
	settings.Log = sidecar.NewNoopLogger()
	settings.PollInterval = 0
	settings.FailureBackoff = 0
	settings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
		select {
		case loadErrs <- err:
		default:
		}
	}
	// as fs21Gate builds it, on the Net's context
	world.cache = sidecar.NewAclGateCache(net.Context(), source, net.Clock(), settings)
	// before the Net ends, on a path that fails early too; a second close returns at once
	defer world.cache.CloseAndWait()
	world.cache.Changed(sidecar.NewId())
	select {
	case <-source.started:
	case <-time.After(guard):
		t.Fatal("the gate cache's load never read its source")
	}

	if err := fs21Close(world).Action(t.Context(), net); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-loadErrs:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the held load ended with %v, not the close's cancel", err)
		}
	default:
		t.Fatal("the held load was still running when the last step returned")
	}
}
