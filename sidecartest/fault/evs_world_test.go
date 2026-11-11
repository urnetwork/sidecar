//go:build sidecar_testhooks

// The evs world's own contract (evs_world.go), beside the rows that use it.

package fault

import (
	"context"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// An instance started again serves the step after its start: the world waits out its readiness probe, which runs on
// a goroutine of its own, so a read the reader sends at once is served, never answered 503 (FS-7's twin, seed 4, met
// it under load before the wait).
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
