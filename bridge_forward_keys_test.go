// The Forwarder's generation keys on the root's fakes (BRIDGE-M8-05; DESIGN-DETAILS 4.2.5's Compile, step 2): the
// config's RK_g opened by a DelegationWrap to the forwarding reader key and kept, a missing wrap, and a key set a newer
// Delegation superseded.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A route of the peer's whose body is sealed to a generation, so a compile wants that generation's key.
func (self *testForwarderWorld) postSealedTo(generation uint64) {
	self.t.Helper()
	route := self.net.bridgeRouteAt(self.peer, testBridgeRuleId("sealed later"), testBridgeSubnet(testBridgePrefix(10, 9, 0, 0, 24), "site"), generation)
	self.net.mustPost(self.peer, bridge.SignedType_SIGNED_BRIDGE_ROUTE, route)
}

// A DelegationWrap to the forwarding reader key opens the config's generation: the addresses sealed under it then
// compile to a link once the peer's binding is fetched, the key is kept in the store, and a restart reads it there
// with no read of gkm.
func TestADelegationWrapOpensTheConfigAndItsBodiesLink(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	status := forwarder.Status()
	targets, inForce := forwarder.LinkTargets()
	if !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || status.GenerationCount != 1 || len(status.Alarms) != 0 {
		t.Fatalf("links %v in force %t, status %+v", targets, inForce, status)
	}
	if key := forwarder.RepoKeyAt(1); key == nil || key.Generation() != 1 || key.RepoId() != world.net.configRepoId() || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("the generation keys the store answers: %v", key)
	}
	if len(world.stored(forwarderGenerationPrefix)) != 1 {
		t.Fatalf("the store holds %v", world.stored(""))
	}

	forwarder.Close()
	world.gkm.stateLock.Lock()
	reads := world.gkm.generationsReadCount
	world.gkm.stateLock.Unlock()
	restarted := world.forwarder()
	world.net.consentedMember("after the restart")
	world.hint(restarted)
	targets, inForce = restarted.LinkTargets()
	world.gkm.stateLock.Lock()
	defer world.gkm.stateLock.Unlock()
	if !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || world.gkm.generationsReadCount != reads || restarted.Status().CompiledPin.GetVersion() != world.net.n {
		t.Errorf("a restart's links %v in force %t after %d reads of gkm", targets, inForce, world.gkm.generationsReadCount-reads)
	}

	// a record whose key is not its GenRotate's is no key
	record := world.forwardStore.files[forwarderNumberName(forwarderGenerationPrefix, 1)]
	record[len(record)-1] ^= 1
	if restarted.RepoKeyAt(1) != nil {
		t.Error("a generation record with another key opened")
	}
}

// A generation with no DelegationWrap yet waits: the generations below it still open and their bodies compile, the
// wrap is asked for late, config_key_waiting is raised once it has waited KeyWaitAlarmInterval, and the wrap's arrival
// opens it and clears the alarm.
func TestAMissingWrapAlarmsConfigKeyWaitingWhileOlderBodiesCompile(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.rotate()
	world.bind(world.peer)
	world.postSealedTo(2)
	world.publish()
	forwarder := world.forwarder()
	status := forwarder.Status()
	targets, inForce := forwarder.LinkTargets()
	if !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || status.GenerationCount != 1 || len(status.Alarms) != 0 {
		t.Fatalf("with generation 2 waiting: links %v in force %t, status %+v", targets, inForce, status)
	}
	if !slices.Contains(status.Waits, BridgeCompileWait{Kind: BridgeCompileWaitGeneration, Generation: 2}) {
		t.Fatalf("the compile's waits: %v", status.Waits)
	}
	for _, wait := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute} {
		world.advance(forwarder, wait)
	}
	if testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatal("config_key_waiting before its interval")
	}
	world.advance(forwarder, 8*time.Minute)
	world.gkm.stateLock.Lock()
	lateAskCount := world.gkm.lateAskCount
	world.gkm.stateLock.Unlock()
	if status := forwarder.Status(); !testForwarderAlarmStands(status, ForwarderAlarmConfigKeyWaiting) || status.GenerationCount != 1 || lateAskCount == 0 {
		t.Fatalf("after the interval: %+v, %d late asks", status, lateAskCount)
	}
	if _, inForce := forwarder.LinkTargets(); !inForce {
		t.Error("a waiting generation took the state out of force")
	}

	world.wrap(2, world.recipient())
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	status = forwarder.Status()
	if status.GenerationCount != 2 || len(status.Alarms) != 0 || forwarder.RepoKeyAt(2) == nil {
		t.Fatalf("after the wrap arrived: %+v", status)
	}
	if slices.ContainsFunc(status.Waits, func(wait BridgeCompileWait) bool { return wait.Kind == BridgeCompileWaitGeneration }) {
		t.Errorf("a generation still waits: %v", status.Waits)
	}
	if count := world.count(func(event string) bool { return event == "alarm "+ForwarderAlarmConfigKeyWaiting }); count != 1 {
		t.Errorf("config_key_waiting raised %d times", count)
	}
}

// A key set a newer forwarding Delegation superseded opens no generation rotated after it, and its signer signs
// nothing; the next key set's reader key, once handed off, opens that generation, and its signer signs once it is
// promoted.
func TestASupersededKeySetOpensNoLaterGeneration(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	superseded, err := forwarder.NewSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := &ForwardingSignRequest{
		NetworkId: world.net.networkId, SubjectSidecarId: world.host.sidecarId, WindowClientId: Id{1, 2, 3},
		WindowClientPublicKey: bytes.Repeat([]byte{9}, 32), TargetSidecarId: world.peer.sidecarId, NotAfter: world.clock.Now().Add(time.Hour),
	}
	if _, err := superseded.SignWindowDelegation(request); err != nil {
		t.Fatalf("the current key set's signer: %v", err)
	}

	nextDelegationId, nextReaderKey, nextForwardKey := world.forward("next")
	world.rotate(testForwarderRecipient{delegationId: nextDelegationId, readerKey: nextReaderKey})
	world.postSealedTo(2)
	world.hint(forwarder)
	status := forwarder.Status()
	if status.GenerationCount != 1 || forwarder.RepoKeyAt(2) != nil || !bytes.Equal(status.ForwardDelegationId, nextDelegationId) || status.CompiledPin.GetVersion() != world.net.n {
		t.Fatalf("with the superseded key set alone: %+v", status)
	}
	if _, err := superseded.SignWindowDelegation(request); err == nil {
		t.Fatal("a superseded key set's signer signed")
	}

	world.keys.handOff(nextDelegationId, nextReaderKey)
	world.advance(forwarder, world.settings.CompileRetryInterval)
	if status := forwarder.Status(); status.GenerationCount != 2 || forwarder.RepoKeyAt(2) == nil {
		t.Fatalf("with the next reader key handed off: %+v", status)
	}
	world.keys.stateLock.Lock()
	world.keys.delegationId, world.keys.key = [sha256.Size]byte(nextDelegationId), nextForwardKey
	world.keys.stateLock.Unlock()
	promoted, err := forwarder.NewSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := promoted.SignWindowDelegation(request); err != nil {
		t.Fatalf("the promoted key set's signer: %v", err)
	}
}
