//go:build !ios_extension && !sidecar_http

// QD-1205 on the test network. A reader that holds a bridge block keeps it from a head that carries its record byte for
// byte once the record's signer is revoked, raising nothing, and judges every other record as before. A writer's next
// head signs again the block of the record every reader of the newest base holds once its signer no longer stands,
// whichever base carried it there, and leaves alone a record readers do not hold, a record the head being saved
// replaces, and a block its own signature could not carry. The test network's log opens no head, so the record its
// readers hold is set on the state here, as a full reader's head check sets it (bridge_block_resign_carry_test.go runs
// that through real bases).

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/rand/v2"
	"testing"
	"testing/iotest"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The owner's second device, admitted by the owner's first, and the head whose bridge/block is a block it signed.
func testResignWorld(t *testing.T, second uint32) (*testConfigNet, testConfigDevice, *bridge.BridgeBlock, []byte, *ConfigHead) {
	t.Helper()
	net := newTestConfigNet(t)
	laptop := net.device("owner laptop", net.owner.memberId)
	net.admitDevice(net.owner, laptop, 0)
	block := testFirstBlock(second)
	record := net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_BLOCK, block)
	head, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, record)
	if err != nil {
		t.Fatal(err)
	}
	return net, laptop, block, record, head
}

// A reader holding a block from a record keeps it once the record's signer is revoked, with no alarm, from a head
// carrying that record byte for byte; with no record held it refuses it as before, keeping its block; another record
// of the same block, a member's device's, is judged and refused; and a new block an Owner's device signs is taken with
// its record.
func TestAReaderKeepsTheBridgeBlockRecordItHoldsOnceItsSignerIsRevoked(t *testing.T) {
	net, laptop, held, record, head := testResignWorld(t, 74)
	if block, taken, err := readBridgeBlockHeld(head, net.log.State(), nil, nil); err != nil || !proto.Equal(block, held) || !bytes.Equal(taken, record) {
		t.Fatalf("the laptop's block while it stands: %v %v", block, err)
	}
	member := net.admitMemberDevice("plain")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	revoked := net.log.State()

	block, kept, err := readBridgeBlockHeld(head, revoked, held, record)
	if err != nil || block != held || !bytes.Equal(kept, record) {
		t.Fatalf("the record it holds, its signer revoked: %v %v", block, err)
	}
	if block, _, err := readBridgeBlockHeld(head, revoked, held, nil); !errors.Is(err, ErrBridgeBlockRefused) || block != held {
		t.Fatalf("a reader holding no record: %v %v", block, err)
	}
	if block, err := ReadBridgeBlock(head, revoked, held); !errors.Is(err, ErrBridgeBlockRefused) || block != held {
		t.Fatalf("ReadBridgeBlock, holding no record: %v %v", block, err)
	}
	other, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, net.sign(member, bridge.SignedType_SIGNED_BRIDGE_BLOCK, held))
	if err != nil {
		t.Fatal(err)
	}
	if block, kept, err := readBridgeBlockHeld(other, revoked, held, record); !errors.Is(err, ErrBridgeBlockRefused) || block != held || !bytes.Equal(kept, record) {
		t.Fatalf("a member's record of the same block: %v %v", block, err)
	}
	freshRecord := net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(75))
	fresh, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, freshRecord)
	if err != nil {
		t.Fatal(err)
	}
	if block, taken, err := readBridgeBlockHeld(fresh, revoked, held, record); err != nil || !proto.Equal(block, testFirstBlock(75)) || !bytes.Equal(taken, freshRecord) {
		t.Fatalf("an Owner's new block: %v %v", block, err)
	}
}

// state with record as the BridgeBlock its newest base's readers hold, nil for none, as a full reader's head check
// leaves it.
func testResignHolding(state *ConfigState, record []byte) *ConfigState {
	holding := configCopyState(state)
	holding.bridgeBlockRecordSha256 = nil
	if record != nil {
		digest := sha256.Sum256(record)
		holding.bridgeBlockRecordSha256 = digest[:]
	}
	return holding
}

// Every reader holds the laptop's block; once the laptop is revoked the owner's writer signs the same block again,
// which a reader with no block takes, and again after a base its revocation lands before, whoever published that. The
// writer leaves the head as it is where readers hold no record (a rows-only state's, or one a head first holds), where
// the head being saved carries another record than the one held, a member's of the same block among them, where the
// record held still stands, and for a signer whose block readers refuse, reading no randomness on any path.
func TestAWriterReSignsTheBridgeBlockItsSignerNoLongerStandsFor(t *testing.T) {
	net, laptop, held, record, head := testResignWorld(t, 76)
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatalf("the base the laptop's block takes effect at: %v", verdict.Refusal)
	}
	member := net.admitMemberDevice("plain")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	state := testResignHolding(net.log.State(), record)
	noDraw := iotest.ErrReader(errors.New("no draw"))

	if _, err := ReadBridgeBlock(head, state, nil); !errors.Is(err, ErrBridgeBlockRefused) {
		t.Fatalf("a reader with no block, the laptop revoked: %v", err)
	}
	resigned := func(name string, state *ConfigState) {
		t.Helper()
		next, err := WithBridgeBlock(state, head, testFirstBlockSign(net.owner), noDraw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		block, err := ReadBridgeBlock(next, state, nil)
		signed := &bridge.Signed{}
		if err != nil || !proto.Equal(block, held) || bytes.Equal(next.File(ConfigHeadBridgeBlockPath), record) ||
			proto.Unmarshal(next.File(ConfigHeadBridgeBlockPath), signed) != nil || !bytes.Equal(signed.GetSignerId(), net.owner.sidecarId.Bytes()) {
			t.Fatalf("%s: the re-signed block %v, by %x: %v", name, block, signed.GetSignerId(), err)
		}
	}
	resigned("the laptop revoked", state)

	unchanged := func(name string, saving *ConfigHead, state *ConfigState, signer testConfigDevice) {
		t.Helper()
		next, err := WithBridgeBlock(state, saving, testFirstBlockSign(signer), noDraw)
		if err != nil || !bytes.Equal(next.File(ConfigHeadBridgeBlockPath), saving.File(ConfigHeadBridgeBlockPath)) {
			t.Errorf("%s: the head's block changed: %v", name, err)
		}
	}
	unchanged("a record readers do not hold", head, testResignHolding(state, nil), net.owner)
	unchanged("a rows-only state", head, net.log.State(), net.owner)
	replaced, err := head.WithFile(ConfigHeadBridgeBlockPath, net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(77)))
	if err != nil {
		t.Fatal(err)
	}
	unchanged("a head replacing the record held", replaced, state, net.owner)
	memberHead, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, net.sign(member, bridge.SignedType_SIGNED_BRIDGE_BLOCK, held))
	if err != nil {
		t.Fatal(err)
	}
	unchanged("a member's record of the block held", memberHead, state, net.owner)
	unchanged("a member's writer", head, state, member)

	// a base after the revocation carries the record on, as a Network admin's writer's, which cannot re-sign it, would
	if verdict := net.fold(net.owner, net.n, 3); !verdict.Accepted() {
		t.Fatalf("the base after the revocation: %v", verdict.Refusal)
	}
	resigned("after a base the revocation lands before", testResignHolding(net.log.State(), record))

	// a held record its signer still stands for is left alone, and a blockless head still draws
	standingRecord := net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, held)
	standing, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, standingRecord)
	if err != nil {
		t.Fatal(err)
	}
	unchanged("a record that stands", standing, testResignHolding(net.log.State(), standingRecord), net.owner)
	drawn, err := WithBridgeBlock(net.log.State(), testConfigHead(t, net), testFirstBlockSign(net.owner), rand.NewChaCha8(sha256.Sum256([]byte("resign draw"))))
	if err != nil || drawn.File(ConfigHeadBridgeBlockPath) == nil {
		t.Fatalf("a blockless head drew no block: %v", err)
	}
}

// QD-1205 in the compile: a compile that took the block from a record keeps it, raising nothing, at a base after that
// record's signer is revoked, from a head carrying the record byte for byte, and hands the record on with the block;
// holding no record, it alarms block_refused and keeps its block, as before.
func TestCompileKeepsTheBlockRecordItHoldsOnceItsSignerIsRevoked(t *testing.T) {
	net := newTestBridgeCompileNet(t)
	laptop := net.device("owner second laptop", net.owner.memberId)
	net.admitDevice(net.owner, laptop, 0)
	record := net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testBridgeCompileBlock())
	net.blockFile = record
	net.foldLedger(net.n, nil)
	taken, _ := testBridgeCompile(t, net.view(), net.local())
	if testBridgeCompileAlarmed(taken, SidecarBridgeAlarmBlockRefused) || !proto.Equal(taken.Block, testBridgeCompileBlock()) || !bytes.Equal(taken.BlockRecord, record) {
		t.Fatalf("the laptop's block while it stands: %v, record %x, alarms %v", taken.Block, taken.BlockRecord, taken.Alarms)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.foldLedger(net.n, nil)
	local := net.local()
	local.PreviousBlock, local.PreviousBlockRecord = taken.Block, taken.BlockRecord
	kept, rules := testBridgeCompile(t, net.view(), local)
	if testBridgeCompileAlarmed(kept, SidecarBridgeAlarmBlockRefused) || kept.Block != taken.Block || !bytes.Equal(kept.BlockRecord, record) ||
		!proto.Equal(rules.GetBlock(), testBridgePrefix(100, 80, 0, 0, 16)) {
		t.Fatalf("the record it holds, its signer revoked: %v, record %x, alarms %v", kept.Block, kept.BlockRecord, kept.Alarms)
	}
	local.PreviousBlockRecord = nil
	refused, _ := testBridgeCompile(t, net.view(), local)
	if !testBridgeCompileAlarmed(refused, SidecarBridgeAlarmBlockRefused) || refused.Block != taken.Block {
		t.Fatalf("holding no record: %v, alarms %v", refused.Block, refused.Alarms)
	}
}

// A desktop that followed its network's bases, each head carrying a block the owner's laptop signed, holds the record
// at each base, and keeps it with the head it verified in authlog/ once the laptop is revoked and a base carries the
// record on. Its restart anchors at its newest kept base with that head, while every head read would answer another
// network's head, and holds the record still, where a reader starting there would judge it and hold none; so its
// writer signs the block again from the restart on.
func TestARestartKeepsTheBridgeBlockRecordItsReadersHold(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	laptop := net.device("owner laptop", net.ownerMemberId)
	net.admitDevice(net.owner, laptop, 0)
	block := testFirstBlock(78)
	record := net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_BLOCK, block)
	world.heads.stateLock.Lock()
	world.heads.blockRecord = record
	world.heads.stateLock.Unlock()
	want := sha256.Sum256(record)
	for _, c := range []struct {
		member        string
		configVersion uint64
	}{{member: "member a", configVersion: 2}, {member: "member b", configVersion: 3}} {
		net.admitMember(net.owner, testConfigId(c.member), bridge.MemberRole_MEMBER_ROLE_MEMBER)
		net.fold(net.owner, net.n, c.configVersion)
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.fold(net.owner, net.n, 4)
	world.publish()

	desktop := DefaultConfigClientSettings()
	desktop.RetainFullTail = true
	client := world.client(desktop)
	state := world.caughtUp(client)
	if state.Base().GetConfigVersion() != 4 || !bytes.Equal(state.bridgeBlockRecordSha256, want[:]) {
		t.Fatalf("the desktop holds %x at head %d", state.bridgeBlockRecordSha256, state.Base().GetConfigVersion())
	}
	client.Close()
	document := world.store.document(t)
	kept := false
	for _, verified := range document.VerifiedHeads {
		if bytes.Equal(verified.ConfigHeadSha256, state.Base().GetConfigHeadSha256()) {
			kept = bytes.Equal(verified.BridgeBlockRecordSha256, want[:])
		}
	}
	if !kept {
		t.Fatal("authlog/ keeps the newest base's head without the block record its readers hold")
	}
	first := &bridge.AuthEntry{}
	if err := proto.Unmarshal(document.Entries[0], first); err != nil || first.GetN() <= 1 {
		t.Fatalf("the kept entries start at %d: %v", first.GetN(), err)
	}

	world.heads.stateLock.Lock()
	world.heads.forged = testConfigHead(t, newTestConfigNetOf(t, "another network"))
	world.heads.stateLock.Unlock()
	restored := world.client(desktop).State()
	if restored == nil || !proto.Equal(restored.Pin(), state.Pin()) || !bytes.Equal(restored.bridgeBlockRecordSha256, want[:]) {
		t.Fatalf("the restart stands at %v holding %x", restored.Pin(), restored.bridgeBlockRecordSha256)
	}
	head, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, record)
	if err != nil {
		t.Fatal(err)
	}
	next, err := WithBridgeBlock(restored, head, testFirstBlockSign(net.owner), iotest.ErrReader(errors.New("no draw")))
	if err != nil || bytes.Equal(next.File(ConfigHeadBridgeBlockPath), record) {
		t.Fatalf("the restarted writer left the block: %v", err)
	}
	if signed, err := ReadBridgeBlock(next, restored, nil); err != nil || !proto.Equal(signed, block) {
		t.Fatalf("the restarted writer's block %v: %v", signed, err)
	}
}
