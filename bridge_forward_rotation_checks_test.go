// The Forwarder's §10.9 rotation and delivery checks, and its judge's reach back to the previous base (§10.9's judged
// rows; owner decision 716; bridge_forward_keys.go's checks, bridge_forward_compile.go's step 1), on the root's fakes: a
// rotation a read_only device signed is refused and alarmed, stays refused past the judged window, and the generation
// above it stands only as REMOVE; a rotation pinned past the judged state waits for the log; a DelegationWrap the
// delivery checks refuse opens nothing, one pinned off the judged chain raising head_alarm (fork) once; a GroupForm and a
// rotation pinned between the previous base and the newest are judged, and are not where the store cannot restore at
// the previous base; and the admission rule falls back to the newest base's estimate.

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

// A read_only device of the owner's member, admitted by the owner's device: it reads the config, and §10.9's signer rows
// let it rotate and deliver none of the config's generations.
func (self *testForwarderWorld) admitReadOnly(label string) testConfigDevice {
	self.t.Helper()
	device := self.net.device(label, self.net.ownerMemberId)
	self.net.admitDevice(self.net.owner, device, testConfigReadOnly)
	return device
}

// Serves signed as the config group's gen/<generation>, in place of any served there and past it; those below it must
// be served.
func (self *testForwarderWorld) serveGeneration(generation uint64, signed *bridge.Signed) {
	self.t.Helper()
	self.gkm.stateLock.Lock()
	defer self.gkm.stateLock.Unlock()
	if uint64(len(self.gkm.generations)) < generation-1 {
		self.t.Fatalf("gen/%d served past %d generations", generation, len(self.gkm.generations))
	}
	self.gkm.generations = append(self.gkm.generations[:generation-1], signed)
}

// A DelegationWrap of gen/<generation> as gkm serves it now to recipient's reader key, of kind, signed by signer: a LATE
// one at auth, the net's tip for nil, and the net's time.
func (self *testForwarderWorld) wrapBy(signer testConfigDevice, generation uint64, recipient testForwarderRecipient, kind GkmDeliveryKind, auth *bridge.AuthPin) {
	self.t.Helper()
	self.gkm.stateLock.Lock()
	signedRotate := self.gkm.generations[generation-1]
	self.gkm.stateLock.Unlock()
	state := self.net.log.State()
	parsed, err := ParseGenRotate(testConfigMarshal(self.t, signedRotate), self.groupId, generation, GkmIdentityKeys(state))
	if err != nil {
		self.t.Fatal(err)
	}
	key, err := OpenEvsRepoKey(parsed, testConfigSealKey(generation).repoKey)
	if err != nil {
		self.t.Fatal(err)
	}
	args := &GkmDeliveryArgs{
		GroupId: self.groupId, Type: GkmWrapTypeDelegation, Recipient: recipient.delegationId,
		RecipientPublicKey: recipient.readerKey.PublicKey().Bytes(), Kind: kind,
	}
	if kind == GkmDeliveryLate {
		if auth == nil {
			auth = state.Pin()
		}
		args.Auth, args.Time = auth, time.UnixMilli(state.TimeMs())
	}
	delivery, err := SealGkmDelivery(key, args)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := SignGkmDelivery(delivery, GkmWrapTypeDelegation, gkmForwardSigner(signer))
	if err != nil {
		self.t.Fatal(err)
	}
	self.gkm.stateLock.Lock()
	defer self.gkm.stateLock.Unlock()
	if self.gkm.wraps[generation] == nil {
		self.gkm.wraps[generation] = map[string][]*bridge.Signed{}
	}
	name := forwarderWrapRecipient(recipient.delegationId)
	self.gkm.wraps[generation][name] = append(self.gkm.wraps[generation][name], signed)
}

// The read_only device's own gen/2 over the world's gen/1, as an honest rotator would write it but for who signs it, with
// its STAGED wrap to the forwarding reader key, and a route sealed to it, so a compile wants it.
func (self *testForwarderWorld) rotateByReadOnly(device testConfigDevice) {
	self.t.Helper()
	self.serveGeneration(2, self.genRotateBy(device, self.groupId, self.net.configRepoId(), 2, testConfigSealKey(1).repoKey))
	self.wrapBy(device, 2, self.recipient(), GkmDeliveryStaged, nil)
	self.postRouteSealedTo("rotated by the read_only device", 2)
}

// A GenRotate of the config that a device §10.9's rotation checks do not allow signed, a read_only device's, is refused
// though it verifies under the device's admitted key and its wrap reaches the forwarding reader key: its key is not kept,
// the body sealed to it stays pending while the state in force stands, its refusal is kept, config_key_waiting names it
// once it has waited, and no head_alarm is raised; the owner's gen/2 in its place opens and clears the alarm. Before,
// the Forwarder ran no rotation check and opened the read_only device's generation at once.
func TestARotationByADeviceTheRotationChecksDoNotAllowIsRefusedAndAlarmed(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	kiosk := world.admitReadOnly("kiosk")
	forwarder := world.forwarder()
	world.rotateByReadOnly(kiosk)
	world.hint(forwarder)
	status := forwarder.Status()
	if forwarder.RepoKeyAt(2) != nil || !slices.Equal(testForwarderGenerationWaits(status), []uint64{2}) || len(world.stored(forwarderPoisonedPrefix)) != 1 {
		t.Fatalf("the read_only device's gen/2: key %s, status %+v, store %v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), status, world.stored(""))
	}
	if _, inForce := forwarder.LinkTargets(); !inForce || status.CompiledPin.GetVersion() != world.net.n {
		t.Fatalf("the refusal took the state out of force: %+v", status)
	}
	world.advancePastKeyWaitAlarm(forwarder)
	alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting)
	if alarm == nil || !strings.Contains(alarm.Detail, "gen/2 in "+world.groupId.String()+" is refused") || !strings.Contains(alarm.Detail, "read_only") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("after the interval: %+v", alarm)
	}
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 0 {
		t.Fatalf("a refused signer raised %d forks", forks)
	}

	world.serveGeneration(2, world.genRotateOver(world.groupId, world.net.configRepoId(), 2, testConfigSealKey(1).repoKey))
	world.wrap(2, world.recipient())
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	status = forwarder.Status()
	if key := forwarder.RepoKeyAt(2); key == nil || testForwarderAlarmStands(status, ForwarderAlarmConfigKeyWaiting) || len(testForwarderGenerationWaits(status)) != 0 {
		t.Fatalf("the owner's gen/2: key %s, status %+v", testForwarderKeyOpened(key), status)
	}
}

// A refused rotation stays refused once its pin has left the judged window: its poisoned/<g> record refuses the same
// statement with no judging, as a member's keychain keeps a poisoned generation. Two bases past its pin the read_only
// device's gen/2 still opens nothing; with the record gone, the same statement, pinned before the window, counts
// against no one and opens, which is what the record holds off.
func TestARefusedRotationStaysRefusedPastTheJudgedWindow(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	kiosk := world.admitReadOnly("kiosk")
	forwarder := world.forwarder()
	world.rotateByReadOnly(kiosk)
	world.hint(forwarder)
	if forwarder.RepoKeyAt(2) != nil || len(world.stored(forwarderPoisonedPrefix)) != 1 {
		t.Fatalf("the read_only device's gen/2: key %s, store %v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), world.stored(""))
	}
	// a generation waits, so each compile after a hint runs at its retry
	for _, label := range []string{"before the second base", "before the third base"} {
		world.net.consentedMember(label)
		world.ledger.foldLedger(world.net.n, nil)
		world.hint(forwarder)
		world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	}
	if status := forwarder.Status(); forwarder.RepoKeyAt(2) != nil || status.CompiledPin.GetVersion() != world.net.n {
		t.Fatalf("two bases past its pin: key %s, status %+v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), status)
	}

	for _, name := range world.stored(forwarderPoisonedPrefix) {
		if err := world.forwardStore.Remove(name); err != nil {
			t.Fatal(err)
		}
	}
	world.net.consentedMember("after the record")
	world.hint(forwarder)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if forwarder.RepoKeyAt(2) == nil {
		t.Fatal("with no record, a rotation pinned before the window did not open: the window still reaches its pin")
	}
}

// The generation above a refused rotation stands only as REMOVE (§10.9's cause row, a poisoned parent): the owner's
// gen/3 of cause SCHEDULE on the read_only device's gen/2 is refused too, config_key_waiting naming its cause, and the
// owner's REMOVE in its place opens, gen/2 staying unkept below it and, wanted by nothing, waiting for nothing. Before,
// neither rotation was judged and both opened.
func TestAGenerationAboveARefusedRotationStandsOnlyAsRemove(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	kiosk := world.admitReadOnly("kiosk")
	forwarder := world.forwarder()
	repoId := world.net.configRepoId()
	world.serveGeneration(2, world.genRotateBy(kiosk, world.groupId, repoId, 2, testConfigSealKey(1).repoKey))
	world.serveGeneration(3, world.signGenRotate(world.net.owner, world.genRotateBody(world.groupId, repoId, 3, testConfigSealKey(2).repoKey, GkmCauseSchedule)))
	world.wrap(3, world.recipient())
	world.postRouteSealedTo("sealed to 3", 3)
	world.hint(forwarder)
	if forwarder.RepoKeyAt(2) != nil || forwarder.RepoKeyAt(3) != nil {
		t.Fatalf("SCHEDULE on a refused parent: gen/2 %s, gen/3 %s", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), testForwarderKeyOpened(forwarder.RepoKeyAt(3)))
	}
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "gen/3 in "+world.groupId.String()+" is refused") ||
		!strings.Contains(alarm.Detail, "requires REMOVE") {
		t.Fatalf("after the interval: %+v", alarm)
	}

	world.serveGeneration(3, world.genRotateOver(world.groupId, repoId, 3, testConfigSealKey(2).repoKey))
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	status := forwarder.Status()
	if forwarder.RepoKeyAt(3) == nil || forwarder.RepoKeyAt(2) != nil || testForwarderAlarmStands(status, ForwarderAlarmConfigKeyWaiting) || len(testForwarderGenerationWaits(status)) != 0 {
		t.Fatalf("REMOVE on the refused parent: gen/2 %s, gen/3 %s, status %+v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), testForwarderKeyOpened(forwarder.RepoKeyAt(3)), status)
	}
}

// A GenRotate pinned past the state the Forwarder judged waits for the log: its listing stops there, the body sealed to
// it waiting with the cause naming the wait, and it opens once a follow brings the log to its pin. Before, its pin was
// never judged and it opened at once.
func TestARotationPinnedPastTheJudgedStateWaitsForTheLog(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	world.postRouteSealedTo("sealed to 2", 2)
	world.hint(forwarder)
	// an entry api has not served yet, and a rotation its rotator signed there
	world.net.consentedMember("joined before the rotation")
	world.rotate(world.recipient())
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "gen/2 in "+world.groupId.String()+" waits") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("a rotation pinned past the judged state: %+v", alarm)
	}

	world.hint(forwarder)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("once the log reaches its pin: key %s, status %+v", testForwarderKeyOpened(key), forwarder.Status())
	}
}

// A DelegationWrap §10.9's delivery checks refuse, a LATE one a read_only device signed, opens nothing though it seals
// the generation's key to the forwarding reader key: the generation waits with config_key_waiting naming the refused
// wrap, and no head_alarm is raised. The wrap poisons nothing here, since the Forwarder rotates past nothing and the
// members sealing to the generation read none of its wraps: the owner's LATE wrap opens the generation and the body
// sealed to it. Before, the Forwarder took any wrap that verified.
func TestADelegationWrapTheDeliveryChecksRefuseOpensNothing(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	kiosk := world.admitReadOnly("kiosk")
	forwarder := world.forwarder()
	world.rotate()
	world.wrapBy(kiosk, 2, world.recipient(), GkmDeliveryLate, nil)
	world.postRouteSealedTo("sealed to 2", 2)
	world.hint(forwarder)
	if forwarder.RepoKeyAt(2) != nil {
		t.Fatal("a LATE wrap a read_only device signed opened the generation")
	}
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil ||
		!strings.Contains(alarm.Detail, "a DelegationWrap of gen/2 in "+world.groupId.String()+" is refused") || !strings.Contains(alarm.Detail, "read_only") {
		t.Fatalf("after the interval: %+v", alarm)
	}
	if forks, poisoned := world.headAlarmCount(SidecarHeadAlarmFork), world.stored(forwarderPoisonedPrefix); forks != 0 || len(poisoned) != 0 {
		t.Fatalf("a refused wrap raised %d forks and kept %v", forks, poisoned)
	}

	world.wrapBy(world.net.owner, 2, world.recipient(), GkmDeliveryLate, nil)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	status := forwarder.Status()
	if key := forwarder.RepoKeyAt(2); key == nil || testForwarderAlarmStands(status, ForwarderAlarmConfigKeyWaiting) || len(testForwarderGenerationWaits(status)) != 0 {
		t.Fatalf("the owner's LATE wrap: key %s, status %+v", testForwarderKeyOpened(key), status)
	}
}

// A LATE DelegationWrap pinned off the judged chain is refused as a fork: head_alarm (fork) with the compile's pin and the
// wrap's for evidence, raised once while the retries' listings meet it, and it opens nothing; a wrap on the chain then
// opens the generation and raises nothing more. Before, the wrap's pin was never judged: it opened the generation and
// nothing was raised.
func TestADelegationWrapPinnedOffTheJudgedChainRaisesHeadAlarmOnce(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	headAlarms := world.keepHeadAlarms(forwarder)
	world.rotate()
	offChain := &bridge.AuthPin{Version: world.net.n, Chain: bytes.Repeat([]byte{7}, sha256.Size)}
	world.wrapBy(world.net.owner, 2, world.recipient(), GkmDeliveryLate, offChain)
	world.postRouteSealedTo("sealed to 2", 2)
	world.hint(forwarder)
	raised := headAlarms()
	if len(raised) != 1 || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("a wrap off the chain: %d head alarms, its generation's key %s", len(raised), testForwarderKeyOpened(forwarder.RepoKeyAt(2)))
	}
	compilePin, wrapPin := &bridge.AuthPin{}, &bridge.AuthPin{}
	if err := proto.Unmarshal(raised[0].Evidence[0], compilePin); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(raised[0].Evidence[1], wrapPin); err != nil {
		t.Fatal(err)
	}
	if raised[0].HeadAlarm != SidecarHeadAlarmFork || !proto.Equal(wrapPin, offChain) || compilePin.GetVersion() != world.net.n {
		t.Fatalf("the alarm %s, its evidence %v and %v", raised[0].HeadAlarm, compilePin, wrapPin)
	}
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "off the chain") || len(headAlarms()) != 1 {
		t.Fatalf("after the retries: %+v, %d head alarms", alarm, len(headAlarms()))
	}

	world.wrap(2, world.recipient())
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || len(headAlarms()) != 1 || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("a wrap on the chain: key %s, %d head alarms", testForwarderKeyOpened(key), len(headAlarms()))
	}
}

// A re-form's GroupForm pinned between the Forwarder's previous base and its newest, signed by a device §10.6 does not
// let form the config's group, is judged at its pin and not followed, as a long-running member judges it: the compile
// restores at the previous base, so the form's pin lies in its window. Its claim waits with config_key_waiting naming
// the refusal; the owner's form at the same pin is followed and opens the claim. Before, the judge started at the
// newest base, the form's pin counted against no one, and the peer's re-form was followed.
func TestAGroupFormPinnedBeforeTheNewestBaseIsJudged(t *testing.T) {
	world := newTestForwarderWorld(t)
	gkm := newTestForwarderReformGkm(world)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	formPin := world.net.log.State().Pin()
	world.ledger.foldLedger(world.net.n, nil)
	if base := world.net.log.State().Base(); base == nil || base.GetVersion() <= formPin.GetVersion() {
		t.Fatalf("the base %v is not past the form's pin %d", base, formPin.GetVersion())
	}
	reformedGroupId := testConfigId("re-formed config group")
	gkm.reform(reformedGroupId)
	gkm.replaceForm(world.groupFormBy(world.peer, reformedGroupId, world.groupId, 1, formPin))
	gkm.rotateIn(world.recipient())
	world.postRouteSealedTo("claimed", 2)
	world.hint(forwarder)
	if status := forwarder.Status(); forwarder.RepoKeyAt(2) != nil || status.CompiledPin.GetVersion() != world.net.n {
		t.Fatalf("the peer's form before the newest base: key %s, status %+v", testForwarderKeyOpened(forwarder.RepoKeyAt(2)), status)
	}
	world.advancePastKeyWaitAlarm(forwarder)
	if alarm := testForwarderAlarm(forwarder.Status(), ForwarderAlarmConfigKeyWaiting); alarm == nil || !strings.Contains(alarm.Detail, "may not form the group") || forwarder.RepoKeyAt(2) != nil {
		t.Fatalf("after the interval: %+v", alarm)
	}
	if forks := world.headAlarmCount(SidecarHeadAlarmFork); forks != 0 {
		t.Fatalf("a refused signer raised %d forks", forks)
	}

	gkm.replaceForm(world.groupFormBy(world.net.owner, reformedGroupId, world.groupId, 1, formPin))
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if key := forwarder.RepoKeyAt(2); key == nil || key.GroupId() != reformedGroupId || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmConfigKeyWaiting) {
		t.Fatalf("the owner's form at the same pin: key %s, status %+v", testForwarderKeyOpened(key), forwarder.Status())
	}
}

// A rotation pinned between the previous base and the newest is judged where the store restores at the previous base,
// and a read_only device's is refused there; where the store lacks the previous base's rows, the compile restores at
// the newest base as a new device's log does, and the same rotation, pinned before its window, counts against no one
// and opens (the judge's fallback, bridge_forward_compile.go's step 1).
func TestARotationPinnedBeforeTheNewestBaseIsJudgedWhereThePreviousBaseRestores(t *testing.T) {
	for _, keepRows := range []bool{true, false} {
		world := newTestForwarderWorld(t)
		world.rotate(world.recipient())
		world.bind(world.peer)
		kiosk := world.admitReadOnly("kiosk")
		forwarder := world.forwarder()
		previousRows := forwarderRowsName(world.net.log.State().Base().GetRowsSha256())
		world.serveGeneration(2, world.genRotateBy(kiosk, world.groupId, world.net.configRepoId(), 2, testConfigSealKey(1).repoKey))
		world.wrapBy(kiosk, 2, world.recipient(), GkmDeliveryStaged, nil)
		world.ledger.foldLedger(world.net.n, nil)
		if !keepRows {
			if err := world.forwardStore.Remove(previousRows); err != nil {
				t.Fatal(err)
			}
		}
		world.postRouteSealedTo("rotated by the read_only device", 2)
		world.hint(forwarder)
		world.advance(forwarder, world.settings.CompileRetryMaxInterval)
		status := forwarder.Status()
		if status.CompiledPin.GetVersion() != world.net.n {
			t.Fatalf("keeping rows %t: status %+v", keepRows, status)
		}
		if opened := forwarder.RepoKeyAt(2) != nil; opened == keepRows {
			t.Fatalf("keeping the previous base's rows %t: gen/2 %s", keepRows, testForwarderKeyOpened(forwarder.RepoKeyAt(2)))
		}
		forwarder.Close()
	}
}

// The admission rule takes the first of a compile's sizes it admits, on one reading of the heap: the estimate with the
// previous base's rows where it fits, else the newest base's alone, else neither, which is refused with its alarm.
func TestTheAdmissionRuleFallsBackToTheNewestBasesEstimate(t *testing.T) {
	world := newTestForwarderWorld(t)
	forwarder := world.forwarder()
	shallow := ForwarderCompileSize{RowsByteCount: 1000}
	deep := ForwarderCompileSize{RowsByteCount: world.settings.CompileMemoryMaxByteCount}
	admit := func(sizes ...ForwarderCompileSize) (int, forwarderCompileOutcome) {
		t.Helper()
		var chosen int
		var outcome forwarderCompileOutcome
		if err := forwarder.onRun(func() {
			chosen, outcome = forwarder.admit(world.net.n, sizes...)
		}); err != nil {
			t.Fatal(err)
		}
		return chosen, outcome
	}
	if chosen, _ := admit(shallow, deep); chosen != 0 {
		t.Fatalf("both fit the first: %d", chosen)
	}
	if chosen, _ := admit(deep, shallow); chosen != 1 || testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmCompileOverBudget) {
		t.Fatalf("the deeper estimate past the cap: %d, %+v", chosen, forwarder.Status())
	}
	if chosen, outcome := admit(deep, deep); chosen != -1 || outcome != forwarderCompileRefused || !testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmCompileOverBudget) {
		t.Fatalf("neither fits: %d, %d, %+v", chosen, outcome, forwarder.Status())
	}
}
