//go:build !sidecar_http && !ios_extension

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Every registered clause's schedule and its twin, each built on a Net of its own, with its actors as a failing seed's
// trace writes them (actor_trace_test.go): a clause runs under the explorer as its case does, so a failing seed of it
// must replay.
func TestEveryRegisteredClausesActorsFitATrace(t *testing.T) {
	for _, registration := range RegisteredClauses() {
		func() {
			net := sidecartest.NewNet(t.Context(), nil)
			defer net.Close()
			schedule := registration.Build(net)
			expectActorsFitATrace(t, registration.String(), schedule)
			if schedule.Twin != nil {
				expectActorsFitATrace(t, registration.String()+"'s twin", schedule.Twin(net))
			}
		}()
	}
}
