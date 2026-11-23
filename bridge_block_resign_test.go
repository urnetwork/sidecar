//go:build !ios_extension && !sidecar_http

// QD-1205 on the test network. A reader that holds a bridge block keeps it from a head that carries its record byte for
// byte once the record's signer is revoked, raising nothing, and judges every other record as before. A writer's next
// head signs again the block the head in force carries once its signer no longer stands, where every reader took that
// record at the newest base, and leaves alone a record no reader took there, a head waiting for its base, a record the
// head being saved replaces, and a block its own signature could not carry.

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

// The head in force carries the laptop's block, which every reader took at the newest base; once the laptop is revoked
// the owner's writer signs the same block again, which a reader with no block takes. The writer leaves the head as it is
// with no head in force (one waiting for its base), where the head being saved carries another record, where no reader
// took the record at the newest base (the base after the revocation, a member's record), and for a signer whose block
// readers refuse, reading no randomness on any path.
func TestAWriterReSignsTheBridgeBlockItsSignerNoLongerStandsFor(t *testing.T) {
	net, laptop, held, record, head := testResignWorld(t, 76)
	if verdict := net.fold(net.owner, net.n, 2); !verdict.Accepted() {
		t.Fatalf("the base the laptop's block takes effect at: %v", verdict.Refusal)
	}
	member := net.admitMemberDevice("plain")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	state := net.log.State()
	noDraw := iotest.ErrReader(errors.New("no draw"))

	if _, err := ReadBridgeBlock(head, state, nil); !errors.Is(err, ErrBridgeBlockRefused) {
		t.Fatalf("a reader with no block, the laptop revoked: %v", err)
	}
	resigned, err := WithBridgeBlock(state, head, head, testFirstBlockSign(net.owner), noDraw)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ReadBridgeBlock(resigned, state, nil)
	signed := &bridge.Signed{}
	if err != nil || !proto.Equal(block, held) || bytes.Equal(resigned.File(ConfigHeadBridgeBlockPath), record) ||
		proto.Unmarshal(resigned.File(ConfigHeadBridgeBlockPath), signed) != nil || !bytes.Equal(signed.GetSignerId(), net.owner.sidecarId.Bytes()) {
		t.Fatalf("the re-signed block %v, by %x: %v", block, signed.GetSignerId(), err)
	}

	unchanged := func(name string, inForce *ConfigHead, saving *ConfigHead, state *ConfigState, signer testConfigDevice) {
		t.Helper()
		next, err := WithBridgeBlock(state, inForce, saving, testFirstBlockSign(signer), noDraw)
		if err != nil || !bytes.Equal(next.File(ConfigHeadBridgeBlockPath), saving.File(ConfigHeadBridgeBlockPath)) {
			t.Errorf("%s: the head's block changed: %v", name, err)
		}
	}
	unchanged("no head in force", nil, head, state, net.owner)
	replaced, err := head.WithFile(ConfigHeadBridgeBlockPath, net.sign(laptop, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(77)))
	if err != nil {
		t.Fatal(err)
	}
	unchanged("a head replacing the record in force", head, replaced, state, net.owner)
	memberHead, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, net.sign(member, bridge.SignedType_SIGNED_BRIDGE_BLOCK, held))
	if err != nil {
		t.Fatal(err)
	}
	unchanged("a member's record no reader took", memberHead, memberHead, state, net.owner)
	unchanged("a member's writer", head, head, state, member)
	if verdict := net.fold(net.owner, net.n, 3); !verdict.Accepted() {
		t.Fatalf("the base after the revocation: %v", verdict.Refusal)
	}
	unchanged("a record refused at the newest base", head, head, net.log.State(), net.owner)

	// a held record its signer still stands for is left alone, and a blockless head still draws
	standing, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, held))
	if err != nil {
		t.Fatal(err)
	}
	unchanged("a record that stands", standing, standing, net.log.State(), net.owner)
	drawn, err := WithBridgeBlock(net.log.State(), nil, testConfigHead(t, net), testFirstBlockSign(net.owner), rand.NewChaCha8(sha256.Sum256([]byte("resign draw"))))
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
