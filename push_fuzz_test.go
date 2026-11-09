//go:build !js

// §22.6's FuzzPushState: any sequence of reset parts, hints, whole resets and reconciles leaves the
// machine bounded, with no durable topic ever lowered by a reset, no partial run applied, and every run
// either applied whole or abandoned for versions. The seed corpus is testdata/fuzz/FuzzPushState/, off
// the js leg, whose tests cannot open it.

package sidecar

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The topics a fuzzed input draws from: each class, and one unknown.
var testFuzzPushTopics = []string{PushTopicTeam, PushTopicDns, PushTopicCore, PushTopicSock, PushTopicGkm, "gkm:" + Id{1}.String(), "evs:" + Id{2}.String(), "unknown"}

func FuzzPushState(f *testing.F) {
	f.Add([]byte{0, 1, 0, 5, 1, 1, 1, 9, 2, 0, 0, 3})
	f.Add([]byte{0, 1, 0, 5, 0, 2, 0, 9, 1, 3, 0, 1, 3, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		settings := DefaultPushClientSettings()
		settings.MaxTopicCount = 4
		machine := newPushMachine(settings, nil)
		durable := map[string]uint64{}
		take := func() byte {
			if len(input) == 0 {
				return 0
			}
			b := input[0]
			input = input[1:]
			return b
		}
		for 0 < len(input) {
			op, epoch, topic, version := take()%5, uint64(take()%3), testFuzzPushTopics[int(take())%len(testFuzzPushTopics)], uint64(take())
			before := map[string]uint64{}
			for topic, version := range machine.topicVersions {
				before[topic] = version
			}
			switch op {
			case 0, 1:
				machine.resetPart(&protocol.PushReset{Epoch: epoch, Complete: op == 1, Versions: []*protocol.TopicVersion{{Topic: topic, Version: version}}})
				if op == 0 {
					// a part that is not complete changes nothing applied
					for topic, version := range machine.topicVersions {
						if before[topic] != version {
							t.Fatalf("a partial part moved %s from %d to %d", topic, before[topic], version)
						}
					}
				}
			case 2:
				machine.hint(&protocol.PushHint{Seq: epoch, Topic: topic, Version: version})
			case 3:
				machine.reset(map[string]uint64{topic: version})
			case 4:
				// an owner's reconcile may lower a durable topic: what the machine then holds is the floor
				machine.reconcile(topic, version)
			}
			if op != 4 {
				for topic, version := range durable {
					if machine.topicVersions[topic] < version {
						t.Fatalf("%s fell from %d to %d without a reconcile", topic, version, machine.topicVersions[topic])
					}
				}
			}
			for topic, version := range machine.topicVersions {
				if PushTopicClassOf(topic) == PushTopicDurable {
					durable[topic] = version
				}
			}
			if settings.MaxTopicCount < len(machine.topicVersions) || settings.MaxTopicCount < len(machine.runVersions) {
				t.Fatalf("%d topics, a run of %d", len(machine.topicVersions), len(machine.runVersions))
			}
			if _, unknown := machine.topicVersions["unknown"]; unknown {
				t.Fatalf("an unknown topic was applied")
			}
		}
	})
}
