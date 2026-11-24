// The Forwarder's head_alarm, once per condition, and §10.6's GroupForm signer rule on the walk to the config's newest
// group (§17.8; owner decision 716; bridge_forward.go's conditions, bridge_forward_keys.go's forms), on the root's
// fakes: a generation gkm lists off the held chain, a head that is not its base's, a page off the stored chain and a
// witness off it each raise head_alarm once however often a retry or a repeat meets them, and again once the condition
// has ended and comes back; and a re-form whose form a device the rule does not allow signed, one on the chain to the
// newest, and one pinned off the judged chain or past it, are not followed, their generations waiting as forms that do
// not lead on, the off-chain pin raising head_alarm (fork) with the form's pin for evidence.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
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

// Keeps each head_alarm the Forwarder raises from now on whole, its evidence too, beside the world's events, and answers
// a reader of them in the order raised. Swapped in on the loop's goroutine, the one that calls Emit.
func (self *testForwarderWorld) keepHeadAlarms(forwarder *Forwarder) func() []SidecarEvent {
	self.t.Helper()
	var stateLock sync.Mutex
	kept := []SidecarEvent{}
	err := forwarder.onRun(func() {
		emit := forwarder.args.Emit
		forwarder.args.Emit = func(event SidecarEvent) {
			if event.Kind == SidecarEventHeadAlarm {
				stateLock.Lock()
				kept = append(kept, event)
				stateLock.Unlock()
			}
			emit(event)
		}
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return func() []SidecarEvent {
		stateLock.Lock()
		defer stateLock.Unlock()
		return slices.Clone(kept)
	}
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

// A Signed GroupForm of the config repo making groupId, re-forming previousGroupId at generation, signed by signer with
// auth as the signer's state: one that verifies under the signer's admitted key, whoever the signer is.
func (self *testForwarderWorld) groupFormBy(signer testConfigDevice, groupId Id, previousGroupId Id, generation uint64, auth *bridge.AuthPin) *bridge.Signed {
	self.t.Helper()
	body := &protocol.GroupForm{
		RepoId: self.net.configRepoId().Bytes(), GroupId: groupId.Bytes(), PreviousGroupId: previousGroupId.Bytes(),
		Generation: generation, Auth: auth,
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := gkmSign(gkmGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, bodyBytes, gkmForwardSigner(signer))
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// Serves signed in place of the form that makes the group it names.
func (self *testForwarderReformGkm) replaceForm(signed *bridge.Signed) {
	t := self.world.t
	t.Helper()
	body := &protocol.GroupForm{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		t.Fatal(err)
	}
	replaced := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for index, form := range self.forms {
			held := &protocol.GroupForm{}
			if proto.Unmarshal(form.GetBody(), held) == nil && bytes.Equal(held.GetGroupId(), body.GetGroupId()) {
				self.forms[index] = signed
				return true
			}
		}
		return false
	}()
	if !replaced {
		t.Fatal("no form makes the group")
	}
}

// Serves forms as the repo's GroupForms, oldest first: none for nil.
func (self *testForwarderReformGkm) serveForms(forms []*bridge.Signed) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.forms = slices.Clone(forms)
}

// The repo's GroupForms as served now.
func (self *testForwarderReformGkm) servedForms() []*bridge.Signed {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.forms)
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

// A re-form of the config's group whose GroupForm a device §10.6 does not allow signed, a member's device that is no
// repo admin's and whose member administers nothing, is not followed though its signature verifies: the new group's
// claim stays unlisted, config_key_waiting names the form and its refusal once the claim has waited, and no head_alarm
// is raised; the same re-form under the owner's device is followed and opens the claim. Before, the Forwarder took any
// form that verified and opened the claim at once.
func TestAGroupFormItsSignerMayNotMakeIsNotFollowed(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	gkm.replaceForm(world.groupFormBy(world.peer, reformedGroupId, world.groupId, 1, world.net.log.State().Pin()))
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	if forwarder.RepoKeyAt(2) != nil {
		t.Fatal("a re-form the peer signed was followed")
	}
	world.advancePastKeyWaitAlarm(forwarder)
	status := forwarder.Status()
	if alarm := testForwarderAlarm(status, ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "the newest GroupForm, of "+reformedGroupId.String()) ||
		!strings.Contains(alarm.Detail, "may not form the group") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("the peer's re-form: %+v", alarm)
	}
	if generationReads, _ := gkm.readCounts(reformedGroupId); generationReads != 0 || len(world.stored(forwarderGroupsName)) != 0 {
		t.Fatalf("the refused group was listed in %d times, the groups record %v", generationReads, world.stored(forwarderGroupsName))
	}
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 0 {
		t.Fatalf("a refused signer raised %d forks", forks)
	}

	gkm.replaceForm(world.groupForm(reformedGroupId, world.groupId, 1))
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	status = forwarder.Status()
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != reformedGroupId || testForwarderAlarmStands(status, ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("the owner's re-form: key %s, status %+v", testForwarderKeyOpened(key), status)
	}
}

// Two re-forms past the group held, the first's form signed by a device §10.6 does not allow and the newest's by the
// owner's device: the chain to the newest does not stand, so the Forwarder stays, config_key_waiting naming the form on
// the chain and its refusal; once the owner's device signed the first form too, the chain is followed to the newest
// group and its claim opens. Before, the chain was followed through the refused form.
func TestAChainThroughAGroupFormItsSignerMayNotMakeIsNotFollowed(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	firstGroupId, secondGroupId := testConfigId("first re-formed config group"), testConfigId("second re-formed config group")
	gkm.reform(firstGroupId)
	gkm.replaceForm(world.groupFormBy(world.peer, firstGroupId, world.groupId, 1, world.net.log.State().Pin()))
	gkm.reform(secondGroupId)
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil ||
		!strings.Contains(alarm.Detail, "the GroupForm of "+firstGroupId.String()+", on the chain to "+secondGroupId.String()) ||
		!strings.Contains(alarm.Detail, "may not form the group") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("a chain through the peer's form: %+v", alarm)
	}
	if generationReads, _ := gkm.readCounts(secondGroupId); generationReads != 0 {
		t.Fatalf("the newest group was listed in %d times", generationReads)
	}

	gkm.replaceForm(world.groupForm(firstGroupId, world.groupId, 1))
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != secondGroupId || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("the chain under the owner's forms: key %s, status %+v", testForwarderKeyOpened(key), forwarder.Status())
	}
	if groups := world.storedGroups(); !slices.Equal(groups, []Id{world.groupId, firstGroupId, secondGroupId}) {
		t.Errorf("the groups record: %v", groups)
	}
}

// A re-form whose GroupForm the owner's device signed with an auth pin off the judged chain is a fork, as a member's
// fork verdict is: head_alarm (fork) with the compile's pin and the form's for evidence, raised once while the retries'
// walks meet it, the form not followed and its group's claim waiting with the refusal as its cause; gkm serving no form
// ends the condition, so the form served again raises it again, once; and the form at a pin on the chain is followed.
// Before, the pin was never judged: the form was followed and nothing raised.
func TestAGroupFormPinnedOffTheJudgedChainRaisesHeadAlarmOnce(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	headAlarms := world.keepHeadAlarms(forwarder)
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	offChain := &bridge.AuthPin{Version: world.net.n, Chain: bytes.Repeat([]byte{7}, sha256.Size)}
	gkm.replaceForm(world.groupFormBy(world.net.owner, reformedGroupId, world.groupId, 1, offChain))
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	if raised := headAlarms(); len(raised) != 1 || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("a form off the chain: %d head alarms, its claim's key %s", len(raised), testForwarderKeyOpened(forwarder.RepoKeyAt(2)))
	}
	raised := headAlarms()[0]
	compilePin, formPin := &bridge.AuthPin{}, &bridge.AuthPin{}
	if err := proto.Unmarshal(raised.Evidence[0], compilePin); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(raised.Evidence[1], formPin); err != nil {
		t.Fatal(err)
	}
	if raised.HeadAlarm != SidecarHeadAlarmFork || !proto.Equal(formPin, offChain) || compilePin.GetVersion() != world.net.n || bytes.Equal(compilePin.GetChain(), offChain.GetChain()) {
		t.Fatalf("the alarm %s, its evidence %v and %v", raised.HeadAlarm, compilePin, formPin)
	}

	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "off the chain") || len(headAlarms()) != 1 || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("after the retries: %+v, %d head alarms", alarm, len(headAlarms()))
	}

	forms := gkm.servedForms()
	gkm.serveForms(nil)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if len(headAlarms()) != 1 {
		t.Fatalf("with no form served: %d head alarms", len(headAlarms()))
	}
	gkm.serveForms(forms)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if raised := headAlarms(); len(raised) != 2 || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("the form served again: %d head alarms", len(raised))
	}

	gkm.replaceForm(world.groupForm(reformedGroupId, world.groupId, 1))
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != reformedGroupId || len(headAlarms()) != 2 {
		t.Fatalf("the form on the chain: key %s, %d head alarms", testForwarderKeyOpened(key), len(headAlarms()))
	}
}

// A re-form whose GroupForm is pinned past the state the Forwarder judged waits for the log: not followed while its
// pin is above what the store holds, its claim waiting with the cause naming the wait, and followed once a follow
// brings the log to the pin. Before, the pin was never judged and the form was followed at once.
func TestAGroupFormPinnedPastTheJudgedStateWaitsForTheLog(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	// an entry api has not served yet, and a re-form its signer signed there
	world.net.consentedMember("joined before the re-form")
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	gkm.rotateIn(world.recipient())
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "waits for the log") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("a form pinned past the judged state: %+v", alarm)
	}

	// the follow brings the log to the pin, and the compile it wants runs at the retry already due
	world.hint(forwarder)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != reformedGroupId || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("once the log reaches the form's pin: key %s, status %+v", testForwarderKeyOpened(key), forwarder.Status())
	}
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 0 {
		t.Errorf("a form that waited raised %d forks", forks)
	}
}
