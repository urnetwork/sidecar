//go:build sidecar_testhooks

// The evs world's own contract (evs_world.go), beside the rows that use it.

package fault

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// An instance started again is ready at the step after its start, and serves a read sent at once: the world waits out
// its readiness probe, which runs on a goroutine of its own, before the start's step ends, as warp sends a block
// nothing until it reads ready (§19.4). The engine answers whether or not it is ready, so this holds the world to
// warp's order; the 503s FS-7's twin met after its restart were the newest rule's (fs7.go's header).
func TestEvsWorldRestartedInstanceServesAtOnce(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("restart a", 100))},
	}
	for round := range 20 {
		steps = append(steps,
			&Step{Actor: "evsr", Kill: true},
			&Step{Actor: "evsr", Restart: "evsr"},
			&Step{Actor: "reader", Action: world.Expect(fmt.Sprintf("round %d's restarted instance is ready", round), func(ctx context.Context) error {
				if host := world.instanceHost("evsr"); host == nil || !host.Ready() {
					return fmt.Errorf("evsr is not ready")
				}
				return nil
			})},
			&Step{Actor: "reader", Action: world.Verify("reader", "a.txt")},
		)
	}
	result := Run(t.Context(), &Schedule{Id: "evs world restart", Steps: steps, Check: world.Checks()}, net)
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

// A RoundTripper of one function.
type evsWorldTestRoundTrip func(request *http.Request) (*http.Response, error)

func (self evsWorldTestRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return self(request)
}

// A device's transport in front of the model (DeviceTransport) answers what it takes and passes the model the rest,
// and an instance serves what reaches it from outside the model (InstanceHandler): T3's lb drain row's wiring
// (TEST-M2-15), here in one process. writerA's segment PUT is served past the model by evs2, once, its push goes
// through the model, which notes it, and the reader reads the write back.
func TestEvsWorldDeviceTransportSendsPastTheModel(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	settings := DefaultEvsWorldSettings()
	stateLock := sync.Mutex{}
	segmentTargets := map[string][]string{}
	var world *EvsWorld
	settings.DeviceTransport = func(device string, lb http.RoundTripper) http.RoundTripper {
		return evsWorldTestRoundTrip(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodPut || !strings.Contains(request.URL.Path, "/segments/") {
				return lb.RoundTrip(request)
			}
			func() {
				stateLock.Lock()
				defer stateLock.Unlock()
				segmentTargets[device] = append(segmentTargets[device], request.URL.RequestURI())
			}()
			recorder := httptest.NewRecorder()
			world.InstanceHandler("evs2").ServeHTTP(recorder, request)
			return recorder.Result(), nil
		})
	}
	world = NewEvsWorld(net, settings)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		// past what rides inline, so it goes in a segment
		{Actor: "writerA", Action: world.Write("writerA", "big.txt", EvsWorldContent("past the model", 64*1024))},
		{Actor: "reader", Action: world.Verify("reader", "big.txt")},
		{Actor: "check", Action: world.Expect("one segment PUT past the model, and the push through it", func(ctx context.Context) error {
			stateLock.Lock()
			defer stateLock.Unlock()
			if len(segmentTargets) != 1 || len(segmentTargets["writerA"]) != 1 {
				return fmt.Errorf("segment PUTs past the model: %v", segmentTargets)
			}
			if pushIds := world.DevicePushIds("writerA"); len(pushIds) != 1 {
				return fmt.Errorf("the model noted push ids %v", pushIds)
			}
			return nil
		})},
	}
	result := Run(t.Context(), &Schedule{Id: "evs world device transport", Steps: steps, Check: world.Checks()}, net)
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

// An instance that is not running cuts what reaches it from outside the model, with no answer.
func TestEvsWorldInstanceHandlerCutsAnInstanceNotRunning(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world := NewEvsWorld(net, nil)
	recorder := httptest.NewRecorder()
	recovered := func() (recovered any) {
		defer func() {
			recovered = recover()
		}()
		world.InstanceHandler("evs1").ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://evs.example/evs/v1/repos", nil))
		return nil
	}()
	if recovered != http.ErrAbortHandler || recorder.Body.Len() != 0 {
		t.Fatalf("an instance never started answered %d %q, recovering %v", recorder.Code, recorder.Body.String(), recovered)
	}
}
