//go:build !ios_extension && !sidecar_http

// §17.4's first block row on the test network: WithFirstBridgeBlock draws for a head that holds no block, signed by a
// writer whose block every reader takes, an Owner's or Admin's device, and by no Network or IT admin's, whose block
// readers refuse; it keeps a block a head holds, refused or not; and the first CLI device's draft gives a retry back the
// block its kept push sealed, or none for a draft kept before the bootstrap drew one.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"testing"
	"testing/iotest"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// device's identity key as a config writer signs with it.
func testFirstBlockSign(device testConfigDevice) ConfigSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  device.sidecarId.Bytes(),
			Signature: ed25519.Sign(device.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// A BridgeBlock of the /16 at 100.<second>.0.0.
func testFirstBlock(second uint32) *bridge.BridgeBlock {
	return &bridge.BridgeBlock{Ipv4Prefix: &bridge.BridgeIpv4Prefix{Address: 100<<24 | second<<16, Length: 16}}
}

// An Owner's and an Admin's writer add the first block to a head that holds none, which a reader takes signed by that
// device; a Network admin's and an IT admin's writer, config writers whose block every reader refuses, add none; a head
// that holds a block keeps it, an Owner's and a member's refused one alike, reading no randomness; and with no state
// or signer nothing is drawn.
func TestFirstBridgeBlockIsAnOwnersOrAdminsWritersAlone(t *testing.T) {
	team := newTestConfigTeam(t)
	itAdmin, networkAdmin := testConfigId("it admin"), testConfigId("network admin")
	team.admitMember(team.owner, itAdmin, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	team.admitMember(team.owner, networkAdmin, bridge.MemberRole_MEMBER_ROLE_MEMBER)
	itLaptop, networkLaptop := team.device("it laptop", itAdmin), team.device("network laptop", networkAdmin)
	team.admitDevice(team.owner, itLaptop, 0)
	team.admitDevice(team.owner, networkLaptop, 0)
	roles := team.adminSet(0)
	roles.ItAdmins = [][]byte{itAdmin.Bytes()}
	roles.NetworkAdmins = [][]byte{networkAdmin.Bytes()}
	_, setId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, roles)
	if verdict := team.cosign(team.adminB, setId); !verdict.Accepted() {
		t.Fatal(verdict.Refusal)
	}
	member := team.admitMemberDevice("plain")
	state := team.log.State()
	for _, device := range []testConfigDevice{itLaptop, networkLaptop} {
		if !state.IsConfigWriter(device.sidecarId) {
			t.Fatalf("%s writes no config head", device.sidecarId)
		}
	}

	blank := testConfigHead(t, team.testConfigNet)
	for _, c := range []struct {
		name   string
		device testConfigDevice
		draws  bool
	}{
		{name: "an Owner's device", device: team.owner, draws: true},
		{name: "an Admin's device", device: team.adminB, draws: true},
		{name: "an IT admin's device", device: itLaptop, draws: false},
		{name: "a Network admin's device", device: networkLaptop, draws: false},
	} {
		random := rand.NewChaCha8(sha256.Sum256([]byte("first block test " + c.name)))
		want, err := ChooseBridgeBlock(rand.NewChaCha8(sha256.Sum256([]byte("first block test " + c.name))))
		if err != nil {
			t.Fatal(err)
		}
		head, err := WithFirstBridgeBlock(state, blank, testFirstBlockSign(c.device), random)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !c.draws {
			if head.File(ConfigHeadBridgeBlockPath) != nil {
				t.Errorf("%s added a block every reader refuses", c.name)
			}
			continue
		}
		block, err := ReadBridgeBlock(head, state, nil)
		if err != nil || block == nil || !proto.Equal(block.GetIpv4Prefix(), want) || block.GetPreviousPrefix() != nil {
			t.Errorf("%s: the reader holds %v (%v), want %v", c.name, block, err, want)
			continue
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(head.File(ConfigHeadBridgeBlockPath), signed); err != nil || !bytes.Equal(signed.GetSignerId(), c.device.sidecarId.Bytes()) {
			t.Errorf("%s: the block's signer %x", c.name, signed.GetSignerId())
		}
	}

	for name, record := range map[string][]byte{
		"an Owner's block":         team.sign(team.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(70)),
		"a member's refused block": team.sign(member, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(71)),
	} {
		holding, err := blank.WithFile(ConfigHeadBridgeBlockPath, record)
		if err != nil {
			t.Fatal(err)
		}
		head, err := WithFirstBridgeBlock(state, holding, testFirstBlockSign(team.owner), iotest.ErrReader(errors.New("no draw")))
		if err != nil || !bytes.Equal(head.File(ConfigHeadBridgeBlockPath), record) {
			t.Errorf("%s: the head's block changed: %v", name, err)
		}
	}
	if _, err := WithFirstBridgeBlock(nil, blank, testFirstBlockSign(team.owner), nil); err == nil {
		t.Error("a draw with no state")
	}
	if _, err := WithFirstBridgeBlock(state, blank, nil, nil); err == nil {
		t.Error("a draw with no signer")
	}
}

// The first CLI device's draft keeps the first head's block with its push, across its store's JSON: a retry's head,
// which drew another block, gets the kept one back; a draft kept before the bootstrap drew one gives the retry no block,
// as the head its push sealed held none; and a Team's draft gives back its starter files beside its block.
func TestFirstConfigDraftRestoresItsBridgeBlock(t *testing.T) {
	net := newTestConfigNet(t)
	kept := net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(72))
	drawn := net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, testFirstBlock(73))
	retry, err := testConfigHead(t, net).WithFile(ConfigHeadBridgeBlockPath, drawn)
	if err != nil {
		t.Fatal(err)
	}

	record, err := json.Marshal(&sidecarFirstConfigDraft{BridgeBlock: kept, SignedPush: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	draft := &sidecarFirstConfigDraft{}
	if err := json.Unmarshal(record, draft); err != nil {
		t.Fatal(err)
	}
	head, err := draft.restoreHead(retry)
	if err != nil || !bytes.Equal(head.File(ConfigHeadBridgeBlockPath), kept) {
		t.Fatalf("the retry's head holds another block than the kept push sealed: %v", err)
	}

	older := &sidecarFirstConfigDraft{}
	if err := json.Unmarshal([]byte(`{"SignedPush":"AQ=="}`), older); err != nil {
		t.Fatal(err)
	}
	if head, err := older.restoreHead(retry); err != nil || head.File(ConfigHeadBridgeBlockPath) != nil {
		t.Fatalf("a draft kept before the first block gives the retry a block: %v", err)
	}

	policyFiles := map[string][]byte{}
	for _, path := range aclSaveHeadPaths {
		policyFiles[path] = nil
	}
	policyFiles[ConfigHeadPolicyPath] = []byte("{}")
	team := &sidecarFirstConfigDraft{Team: true, PolicyFiles: policyFiles, BridgeBlock: kept, SignedPush: []byte{1}}
	head, err = team.restoreHead(retry)
	if err != nil || !bytes.Equal(head.File(ConfigHeadBridgeBlockPath), kept) || string(head.File(ConfigHeadPolicyPath)) != "{}" {
		t.Fatalf("a Team's retry: %v", err)
	}
}
