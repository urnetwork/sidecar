// The Forwarder's head_alarm, once per condition (§17.8; owner decision 716; bridge_forward.go's conditions), on the
// root's fakes: a generation gkm lists off the held chain, a head that is not its base's, a page off the stored chain
// and a witness off it each raise head_alarm once however often a retry or a repeat meets them, and again once the
// condition has ended and comes back.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// How many head_alarms of a kind the world's events hold.
func (self *testForwarderWorld) headAlarmCount(kind SidecarHeadAlarm) int {
	return self.count(func(event string) bool { return event == "head_alarm "+string(kind) })
}

// Whether a generation's key opened, and in which group, for a failure's message: never the key.
func testForwarderKeyOpened(key *EvsRepoKey) string {
	if key == nil {
		return "none"
	}
	return "opened in " + key.GroupId().String()
}

// Serves the config group's gen/2 as signed, nil for none, after its gen/1.
func (self *testForwarderWorld) serveGeneration2(signed *bridge.Signed) {
	self.gkm.stateLock.Lock()
	defer self.gkm.stateLock.Unlock()
	self.gkm.generations = self.gkm.generations[:1]
	if signed != nil {
		self.gkm.generations = append(self.gkm.generations, signed)
	}
}

// A listed gen/2 that does not chain from the held gen/1 raises head_alarm (fork) at the first compile and at none of the
// retries that list it again while gkm serves it; gkm listing no gen/2 ends the condition, so the same statement served
// once more raises it again, once; and the statement on the chain opens gen/2 and raises nothing. Before, every retry
// that listed the statement raised head_alarm again.
func TestAListingOffTheHeldChainRaisesHeadAlarmOncePerCondition(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	offChain := world.genRotateOver(world.groupId, world.net.configRepoId(), 2, bytes.Repeat([]byte{0xee}, gkmRepoKeyByteCount))
	world.serveGeneration2(offChain)
	world.wrap(2, world.recipient())
	world.postRouteSealedTo("off the chain", 2)
	world.hint(forwarder)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 1 || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("an off-chain gen/2: %d forks, its key %s", forks, testForwarderKeyOpened(forwarder.RepoKeyAt(2)))
	}

	compileErrors := forwarder.Status().CompileErrorCount
	compiles := forwarder.Status().CompileCount
	world.advancePastKeyWaitAlarm(forwarder)
	status := forwarder.Status()
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 1 {
		t.Fatalf("the retries raised head_alarm again: %d forks, %v", forks, world.events.list())
	}
	if status.CompileCount+status.CompileErrorCount-compiles-compileErrors < 5 {
		t.Fatalf("the retries did not run: %+v", status)
	}
	if alarm := testForwarderAlarm(status, ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "does not chain from the generation below it") {
		t.Fatalf("config_key_waiting after the interval: %+v", alarm)
	}

	world.serveGeneration2(nil)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 1 || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("with gen/2 unlisted: %d forks, its key %s", forks, testForwarderKeyOpened(forwarder.RepoKeyAt(2)))
	}
	world.serveGeneration2(offChain)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 2 {
		t.Fatalf("the condition come back: %d forks, %v", forks, world.events.list())
	}
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 2 {
		t.Fatalf("a retry of the condition come back: %d forks", forks)
	}

	world.serveGeneration2(nil)
	world.rotate(world.recipient())
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	status = forwarder.Status()
	if forwarder.RepoKeyAt(2) == nil || testForwarderAlarmStands(status, ForwarderAlarmConfigKeyWaiting) || world.headAlarmCount(SidecarHeadAlarmFork) != 2 {
		t.Fatalf("gen/2 on the chain: key %s, %d forks, status %+v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), world.headAlarmCount(SidecarHeadAlarmFork), status)
	}
}

// A head that is not the one its base names raises head_alarm at the compile that reads it and at none of the retries
// that read it again; the base's own head ends the condition, so the same base read again from a reader serving
// another head raises it again, once. Before, each retry raised it.
func TestAHeadNotTheBasesRaisesHeadAlarmOncePerCondition(t *testing.T) {
	world := newTestForwarderWorld(t)
	net := world.net
	genesis := &bridge.Genesis{
		NetworkId: testConfigId("another network").Bytes(), ConfigRepoId: net.configRepoId().Bytes(), OwnerMemberId: net.ownerMemberId.Bytes(),
		OwnerSidecarId: net.owner.sidecarId.Bytes(), OwnerIdentityPublicKey: net.owner.publicKey(), TimeMs: testConfigStartMs,
	}
	forged, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: net.sign(net.owner, bridge.SignedType_SIGNED_GENESIS, genesis)})
	if err != nil {
		t.Fatal(err)
	}
	world.forwardHeads.forged.Store(forged)
	// generation 1 opens, so the compile waits on nothing but the head
	world.rotate(world.recipient())
	forwarder := world.forwarder()
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 1 || world.stateCount() != 0 {
		t.Fatalf("another network's head: %d forks, %v", forks, world.events.list())
	}
	compileErrors := forwarder.Status().CompileErrorCount
	for _, wait := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute} {
		world.advance(forwarder, wait)
	}
	if status := forwarder.Status(); world.headAlarmCount(SidecarHeadAlarmFork) != 1 || status.CompileErrorCount != compileErrors+3 || world.stateCount() != 0 {
		t.Fatalf("three retries: %d forks, status %+v", world.headAlarmCount(SidecarHeadAlarmFork), status)
	}

	world.forwardHeads.forged.Store(nil)
	world.advance(forwarder, 4*time.Minute)
	if world.stateCount() != 1 || world.headAlarmCount(SidecarHeadAlarmFork) != 1 {
		t.Fatalf("the base's own head: %v", world.events.list())
	}
	world.forwardHeads.forged.Store(forged)
	for _, name := range world.stored(forwarderHeadPrefix) {
		if err := world.forwardStore.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	net.consentedMember("joined after the head")
	world.hint(forwarder)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 2 || world.stateCount() != 1 {
		t.Fatalf("the base's head read again from a forged reader: %d forks, %v", forks, world.events.list())
	}
	world.advance(forwarder, 30*time.Second)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 2 {
		t.Fatalf("its retry: %d forks", forks)
	}
}

// A page whose first entry does not chain onto the stored tip raises head_alarm (fork) at the follow that reads it and at
// none of the follow's retries while api serves it; a follow api answers with nothing past the tip ends the condition,
// so the same page served again raises it again, once; and the log's own entries are then taken. Before, each retry
// raised it.
func TestAPageOffTheStoredChainRaisesHeadAlarmOncePerCondition(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	net := world.net
	tip := net.n
	net.consentedMember("after the fork")
	forgedEntry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(net.entries[tip], forgedEntry); err != nil {
		t.Fatal(err)
	}
	forgedEntry.PrevChain = bytes.Repeat([]byte{9}, sha256.Size)
	serve := func(entries [][]byte) {
		world.projection.stateLock.Lock()
		defer world.projection.stateLock.Unlock()
		world.projection.entries = entries
	}
	forgedEntries := append(slices.Clone(net.entries[:tip]), testConfigMarshal(t, forgedEntry))
	world.projection.publish(net)
	serve(forgedEntries)
	forwarder.ReceiveHint(tip + 1)
	world.settle(forwarder)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 1 {
		t.Fatalf("a page off the chain: %d forks, %v", forks, world.events.list())
	}
	follows := forwarder.Status().FollowCount
	for _, wait := range []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second} {
		world.advance(forwarder, wait)
	}
	if status := forwarder.Status(); world.headAlarmCount(SidecarHeadAlarmFork) != 1 || status.FollowCount != follows+3 || status.Tip.GetVersion() != tip {
		t.Fatalf("three retries: %d forks, status %+v", world.headAlarmCount(SidecarHeadAlarmFork), status)
	}

	serve(slices.Clone(net.entries[:tip]))
	world.advance(forwarder, 80*time.Second)
	if status := forwarder.Status(); world.headAlarmCount(SidecarHeadAlarmFork) != 1 || status.FollowCount != follows+4 || status.Tip.GetVersion() != tip {
		t.Fatalf("nothing past the tip: %d forks, status %+v", world.headAlarmCount(SidecarHeadAlarmFork), status)
	}
	serve(forgedEntries)
	forwarder.ReceiveHint(tip + 1)
	world.settle(forwarder)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 2 {
		t.Fatalf("the page served again: %d forks, %v", forks, world.events.list())
	}
	world.advance(forwarder, 10*time.Second)
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 2 {
		t.Fatalf("its retry: %d forks", forks)
	}
	world.hint(forwarder)
	if status := forwarder.Status(); status.Tip.GetVersion() != net.n || status.CompiledPin.GetVersion() != net.n || world.headAlarmCount(SidecarHeadAlarmFork) != 2 {
		t.Fatalf("the log's own entries: %+v", status)
	}
}

// The app's sidecar role witnessing again while api still serves less than its pin, or while its chain and the
// Forwarder's still disagree, raises nothing more: withheld and fork are each raised once while they stand, a witness
// api serves through on another chain ends withheld, and one on the Forwarder's own chain ends both, so each met again
// is raised again. Before, each witness raised its alarm.
func TestAWitnessRaisesHeadAlarmOncePerCondition(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	tip := world.net.log.State().Pin()
	ahead := &bridge.AuthPin{Version: tip.GetVersion() + 40, Chain: bytes.Repeat([]byte{4}, sha256.Size)}
	offChain := &bridge.AuthPin{Version: tip.GetVersion(), Chain: bytes.Repeat([]byte{4}, sha256.Size)}
	witness := func(pin *bridge.AuthPin, times int) {
		t.Helper()
		for range times {
			if err := forwarder.Witness(pin, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	counts := func() (int, int) {
		return world.headAlarmCount(SidecarHeadAlarmWithheld), world.headAlarmCount(SidecarHeadAlarmFork)
	}
	witness(ahead, 3)
	if withheld, forks := counts(); withheld != 1 || forks != 0 {
		t.Fatalf("three witnesses past api's tip: %d withheld, %d forks", withheld, forks)
	}
	witness(offChain, 3)
	if withheld, forks := counts(); withheld != 1 || forks != 1 {
		t.Fatalf("three witnesses off the chain: %d withheld, %d forks", withheld, forks)
	}
	witness(ahead, 2)
	if withheld, forks := counts(); withheld != 2 || forks != 1 {
		t.Fatalf("past api's tip again after a witness it serves through: %d withheld, %d forks", withheld, forks)
	}
	witness(tip, 1)
	witness(offChain, 2)
	if withheld, forks := counts(); withheld != 2 || forks != 2 {
		t.Fatalf("off the chain again after a witness on it: %d withheld, %d forks", withheld, forks)
	}
}
