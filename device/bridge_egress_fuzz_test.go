// FuzzBridgeEgressPolicy (§22.6): fuzz bytes steer the generator of bridge_egress_reference_test.go to a state and its
// flows, and the policy must decide each flow as the reference does. Past the fuzz bytes the generator reads zeros, so a
// case is a function of its bytes alone. Seeds are testdata/fuzz/FuzzBridgeEgressPolicy/.

package device_test

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"
)

// The flows one fuzz case tries against its state.
const egressFuzzFlowCount = 16

func FuzzBridgeEgressPolicy(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3})
	f.Fuzz(func(t *testing.T, data []byte) {
		gen := &egressGen{data: data}
		state := gen.state()
		flows := []*connect.EgressFlow{}
		nows := []time.Time{}
		for range egressFuzzFlowCount {
			flow, now := gen.flow(state)
			flows = append(flows, flow)
			nows = append(nows, now)
		}
		if difference := egressCompare(state, flows, nows); difference != "" {
			t.Fatal(difference)
		}
	})
}
