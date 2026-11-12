//go:build sidecar_testhooks

// The evs world's own contract (evs_world.go), beside the rows that use it.

package fault

import (
	"context"
	"fmt"
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
