//go:build !sidecar_http && !ios_extension

// BRIDGE-M6-08's schedules on T2 (fs_bridge_m6.go): FS-38's share rows, under every rule §22.8 gives the case;
// server/controller/connect_bridge_m6_test.go runs the same builders on T3. Beside them, the schedules' actors as a
// failing seed's trace must write them.

package fault

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs38Share(t *testing.T) {
	RunRow(t, "FS-38", "shares", nil)
}

// A failing seed of either schedule leaves its trace (§22.8's explorer row), one event a line with its actor as one
// field, so no actor of theirs may hold a space: "Y's ungranted reader" did, and the seed that failed in its step left
// no trace to replay.
func TestFs38ShareActorsFitATrace(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	for _, builder := range []Builder{Fs38ShareRefusals, Fs38ShareSigner} {
		schedule := builder(net)
		trace := &Trace{Id: "FS-38's shares", Seed: 1}
		for _, step := range schedule.Steps {
			trace.Events = append(trace.Events, &sidecartest.BarrierEvent{Kind: sidecartest.BarrierRan, Actor: step.Actor})
		}
		data, err := trace.Bytes()
		if err != nil {
			t.Fatalf("a trace of the schedule's actors: %v", err)
		}
		parsed, err := ParseTrace(data)
		if err != nil {
			t.Fatalf("the trace written: %v", err)
		}
		for index, event := range parsed.Events {
			if event.Actor != schedule.Steps[index].Actor {
				t.Fatalf("step %d's actor %q came back from its trace as %q", index, schedule.Steps[index].Actor, event.Actor)
			}
		}
	}
}
