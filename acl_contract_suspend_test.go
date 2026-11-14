//go:build !sidecar_http && !ios_extension

// §22.5's §8 row "suspension <= 5 s" at the contract gate (ACL-M4-04; §8.6's one switch, §8.9's targets, D-ACL-8):
// a Suspend whose {acl_}v event is lost still refuses the suspended sidecar's contracts at the gate's next heads load,
// one HeadsInterval, 5 s, after the head row moved, through a real AclGateCache over the log, on the gate's clock and
// no sleep.

package sidecar

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

func TestAclContractGateHoldsASuspensionWithinItsHeadsInterval(t *testing.T) {
	if interval := DefaultAclContractGateSettings().HeadsInterval; 5*time.Second < interval {
		t.Fatalf("the heads interval is %v, past §8.9's 5 s", interval)
	}
	net := newTestConfigNet(t)
	peer := net.admitMemberDevice("contract peer")
	source := newAclGateTestSource()
	source.publish(net)
	cache, cacheLoads := newAclGateTestCache(t, source, newAclGateTestClock(), nil)
	heads := &aclContractTestHeads{}
	heads.set(map[Id]uint64{net.networkId: net.n}, nil)
	gate, clock, loads := newAclContractTestGate(t, cache, heads)
	aclGateTestNextLoad(t, cacheLoads)

	end := func(sidecarId Id) AclContractEnd {
		return AclContractEnd{Known: true, NetworkId: net.networkId, SubjectClientId: NewId(), SidecarId: sidecarId, SidecarHeld: true}
	}
	decide := func() AclContractVerdict {
		return gate.Decide(&AclContractRequest{Source: end(net.owner.sidecarId), Destination: end(peer.sidecarId)}, time.UnixMilli(net.timeMs))
	}
	if verdict := decide(); verdict.Outcome != AclContractAllow || verdict.Class != AclContractClassControl {
		t.Fatalf("before the Suspend: %+v", verdict)
	}

	// the Suspend lands and network_acl_head moves, but its {acl_}v event is lost: the cache is told nothing
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Header: net.header(), Subject: peer.sidecarId.Bytes(), SuspendId: aclTestSuspendId("m4")})
	source.publish(net)
	heads.set(map[Id]uint64{net.networkId: net.n}, nil)
	if verdict := decide(); verdict.Outcome != AclContractAllow {
		t.Fatalf("before the gate's next heads load: %+v", verdict)
	}

	// one heads interval on the gate's clock: the moved head asks the cache to load, and the load refuses the peer
	clock.fire <- clock.Now().Add(DefaultAclContractGateSettings().HeadsInterval)
	if err := aclContractTestNextLoad(t, loads); err != nil {
		t.Fatal(err)
	}
	aclGateTestNextLoad(t, cacheLoads)
	if verdict := decide(); verdict.Outcome != AclContractRefuse || verdict.Decision.Reason != AclReasonSuspended {
		t.Errorf("after one heads interval: %+v", verdict)
	}
	if armed := <-clock.armed; armed != DefaultAclContractGateSettings().HeadsInterval {
		t.Errorf("the next heads load is %v away", armed)
	}
}
