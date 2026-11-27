//go:build !ios_extension && !sidecar_http && !js

// The network's acknowledgment of a disclosure (CTRUST-M12-02) on a fake verified state whose devices a test sets, the
// fixture policy and the acknowledgment world (disclosure_ack_test.go): the statement's bytes and purpose, a tagged
// runner refused before an Owner's entry and covered after it, every refusal of the judge, the act's refusals, a
// member's device and an enclave taking only the person's, and the new-version notice. The saves through a real writer
// are disclosure_network_save_test.go's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device of the fake state.
type testNetworkDisclosureDevice struct {
	member          Id
	key             ed25519.PrivateKey
	role            bridge.MemberRole
	approvalCapable bool
	tagged          bool
}

// A network's verified state as a test sets it: its devices, the chain it holds at each position from retainedFrom to
// the verified pin, and roles that differ at earlier positions.
type testNetworkDisclosureState struct {
	network      Id
	verified     uint64
	retainedFrom uint64
	devices      map[Id]*testNetworkDisclosureDevice
	// by position, a member's role there where it differs from now
	rolesAt map[uint64]map[Id]bridge.MemberRole
}

// A state at position 40 holding everything from 10.
func newTestNetworkDisclosureState() *testNetworkDisclosureState {
	return &testNetworkDisclosureState{
		network:      testConfigId("network disclosures network"),
		verified:     40,
		retainedFrom: 10,
		devices:      map[Id]*testNetworkDisclosureDevice{},
		rolesAt:      map[uint64]map[Id]bridge.MemberRole{},
	}
}

// A device of a member of role, its key from its label.
func (self *testNetworkDisclosureState) add(label string, role bridge.MemberRole, approvalCapable bool, tagged bool) Id {
	seed := sha256.Sum256([]byte("network disclosure key " + label))
	sidecarId := testConfigId("network disclosure device " + label)
	self.devices[sidecarId] = &testNetworkDisclosureDevice{
		member:          testConfigId("network disclosure member " + label),
		key:             ed25519.NewKeyFromSeed(seed[:]),
		role:            role,
		approvalCapable: approvalCapable,
		tagged:          tagged,
	}
	return sidecarId
}

// The chain at version, as this state holds it.
func (self *testNetworkDisclosureState) chainAt(version uint64) []byte {
	chain := sha256.Sum256([]byte{byte(version), byte(version >> 8), 'c'})
	return chain[:]
}

func (self *testNetworkDisclosureState) networkId() Id {
	return self.network
}

func (self *testNetworkDisclosureState) pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.verified, Chain: self.chainAt(self.verified)}
}

func (self *testNetworkDisclosureState) identityKey(sidecarId Id) []byte {
	device := self.devices[sidecarId]
	if device == nil {
		return nil
	}
	return device.key.Public().(ed25519.PublicKey)
}

func (self *testNetworkDisclosureState) signerAt(pin *bridge.AuthPin, sidecarId Id, memberId Id) (*computeNetworkDisclosureSigner, error) {
	device := self.devices[sidecarId]
	switch {
	case self.verified < pin.GetVersion():
		return nil, ErrConfigPinAhead
	case device == nil:
		return nil, ErrConfigSignerNotAdmitted
	case pin.GetVersion() < self.retainedFrom:
		// judged at the verified state, as ConfigState's are past what it holds
		return &computeNetworkDisclosureSigner{
			approvalCapable: device.approvalCapable && !device.tagged && device.member == memberId, role: device.role,
		}, nil
	case !bytes.Equal(pin.GetChain(), self.chainAt(pin.GetVersion())):
		return nil, ErrConfigPinOffChain
	}
	role := device.role
	if at, ok := self.rolesAt[pin.GetVersion()][device.member]; ok {
		role = at
	}
	return &computeNetworkDisclosureSigner{
		approvalCapable: device.approvalCapable && !device.tagged && device.member == memberId,
		role:            role,
		atMs:            int64(pin.GetVersion()) * 1000,
	}, nil
}

func (self *testNetworkDisclosureState) device(sidecarId Id) (Id, *computeNetworkDisclosureSigner, bool) {
	device := self.devices[sidecarId]
	if device == nil || device.tagged {
		return Id{}, nil, false
	}
	return device.member, &computeNetworkDisclosureSigner{approvalCapable: device.approvalCapable, role: device.role}, true
}

// The statement signerId signs of id at version under purpose, at the verified pin unless edit changes it, as the block
// holds it.
func (self *testNetworkDisclosureState) statement(t *testing.T, signerId Id, id string, version uint32, purpose string,
	edit func(ack *protocol.DisclosureAck, signed *bridge.Signed)) AclComputeDisclosure {
	t.Helper()
	device := self.devices[signerId]
	ack := &protocol.DisclosureAck{
		NetworkId:    self.network.Bytes(),
		DisclosureId: id,
		Version:      version,
		Locale:       "en",
		MemberId:     device.member.Bytes(),
		SidecarId:    signerId.Bytes(),
		AuthPin:      self.pin(),
	}
	signed := &bridge.Signed{SignerId: signerId.Bytes(), Type: uint32(bridge.SignedType_SIGNED_DISCLOSURE_ACK)}
	if edit != nil {
		edit(ack, nil)
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	signed.Body = body
	signed.Signature = ed25519.Sign(device.key, bridge.SignedBytes(purpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body))
	if edit != nil {
		edit(nil, signed)
	}
	encoded, err := encodeComputeDisclosureAckStatement(signed)
	if err != nil {
		t.Fatal(err)
	}
	return AclComputeDisclosure{Id: id, Statement: encoded}
}

// The network acknowledgments over state and entries, the world's registry and clock.
func testNetworkDisclosures(world *testDisclosureAckWorld, state computeNetworkDisclosureState, entries *[]AclComputeDisclosure) *ComputeNetworkDisclosures {
	return newComputeNetworkDisclosures(&computeNetworkDisclosuresArgs{
		registry: func() (*ComputeDisclosureRegistry, error) { return world.registry, nil },
		read: func() (computeNetworkDisclosureState, []AclComputeDisclosure, error) {
			return state, slices.Clone(*entries), nil
		},
		now:      world.clock.Now,
		settings: world.registry.Settings(),
	})
}

// The fixed statement of testdata/disclosure/disclosure_ack.json, which another implementation checks its bytes by.
type testDisclosureAckVector struct {
	Comment      string `json:"comment"`
	SeedHex      string `json:"seed_hex"`
	NetworkId    string `json:"network_id"`
	DisclosureId string `json:"disclosure_id"`
	Version      uint32 `json:"version"`
	Locale       string `json:"locale"`
	Revision     uint32 `json:"revision"`
	MemberId     string `json:"member_id"`
	SidecarId    string `json:"sidecar_id"`
	PinVersion   uint64 `json:"pin_version"`
	PinChainHex  string `json:"pin_chain_hex"`
	// What the inputs make: the body, the signed bytes' SHA-256, the signature and the block's statement.
	BodyHex              string `json:"body_hex"`
	SignedBytesSha256Hex string `json:"signed_bytes_sha256_hex"`
	SignatureHex         string `json:"signature_hex"`
	Statement            string `json:"statement"`
}

// The vector's path, and the variable that writes it again from its inputs.
var testDisclosureAckVectorPath = filepath.Join("testdata", "disclosure", "disclosure_ack.json")

const testDisclosureAckVectorRegenerate = "SIDECAR_REGENERATE_DISCLOSURE_ACK_VECTOR"

// DisclosureAck's numbers are §2.8's list in order, then the device and its pin; the identity key signs it as
// disclosure-ack, type 0x1809, over §6.9's bytes, whose fixed vector holds; Sign refuses the type under another purpose,
// and a statement signed under another purpose verifies as no disclosure-ack.
func TestDisclosureAckStatementRoundTrip(t *testing.T) {
	fields := (&protocol.DisclosureAck{}).ProtoReflect().Descriptor().Fields()
	for name, number := range map[string]int32{
		"network_id": 1, "disclosure_id": 2, "version": 3, "locale": 4, "revision": 5, "member_id": 6, "sidecar_id": 7,
		"auth_pin": 8,
	} {
		if field := fields.ByTextName(name); field == nil || int32(field.Number()) != number {
			t.Errorf("DisclosureAck.%s is not field %d", name, number)
		}
	}
	if fields.Len() != 8 || bridge.SignedType_SIGNED_DISCLOSURE_ACK != 0x1809 {
		t.Fatalf("%d fields, type %#x", fields.Len(), int32(bridge.SignedType_SIGNED_DISCLOSURE_ACK))
	}
	if purpose, ok := sidecarIdentitySignedPurpose(bridge.SignedType_SIGNED_DISCLOSURE_ACK); !ok || purpose != ComputeDisclosureAckPurpose {
		t.Fatalf("the identity key signs 0x1809 as %q, %v", purpose, ok)
	}

	// the identity key signs it, as disclosure-ack alone
	sidecar, _, keys := newIdentityTestSidecar(t)
	body := []byte("a disclosure-ack body")
	signed, err := sidecar.Sign(ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(keys.identityPublicKey(), bridge.SignedBytes(ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body), signed.Signature) {
		t.Fatal("the statement does not verify under the identity key")
	}
	for _, purpose := range []string{"approval", "attach-origin", bridge.SignedPurposeAuthority} {
		if _, err := sidecar.Sign(purpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body, nil); !errors.Is(err, ErrSidecarSignRefused) {
			t.Errorf("0x1809 under %s: %v", purpose, err)
		}
	}

	// the fixed vector: the inputs make its bytes, which verify and judge whole
	data, err := os.ReadFile(testDisclosureAckVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	vector := &testDisclosureAckVector{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("the seed: %v", err)
	}
	chain, err := hex.DecodeString(vector.PinChainHex)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]Id{}
	for name, text := range map[string]string{"network": vector.NetworkId, "member": vector.MemberId, "sidecar": vector.SidecarId} {
		id, err := ParseId(text)
		if err != nil {
			t.Fatalf("the vector's %s: %v", name, err)
		}
		ids[name] = id
	}
	made, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.DisclosureAck{
		NetworkId: ids["network"].Bytes(), DisclosureId: vector.DisclosureId, Version: vector.Version, Locale: vector.Locale,
		Revision: vector.Revision, MemberId: ids["member"].Bytes(), SidecarId: ids["sidecar"].Bytes(),
		AuthPin: &bridge.AuthPin{Version: vector.PinVersion, Chain: chain},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	signedBytes := bridge.SignedBytes(ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, made)
	signedBytesSha256 := sha256.Sum256(signedBytes)
	madeSigned := &bridge.Signed{Body: made, SignerId: ids["sidecar"].Bytes(), Signature: ed25519.Sign(key, signedBytes),
		Type: uint32(bridge.SignedType_SIGNED_DISCLOSURE_ACK)}
	statement, err := encodeComputeDisclosureAckStatement(madeSigned)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv(testDisclosureAckVectorRegenerate) == "1" {
		vector.BodyHex, vector.SignedBytesSha256Hex = hex.EncodeToString(made), hex.EncodeToString(signedBytesSha256[:])
		vector.SignatureHex, vector.Statement = hex.EncodeToString(madeSigned.Signature), statement
		encoded, err := json.MarshalIndent(vector, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testDisclosureAckVectorPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", testDisclosureAckVectorPath)
		return
	}
	if hex.EncodeToString(made) != vector.BodyHex || hex.EncodeToString(signedBytesSha256[:]) != vector.SignedBytesSha256Hex ||
		hex.EncodeToString(madeSigned.Signature) != vector.SignatureHex || statement != vector.Statement {
		t.Fatalf("the vector's bytes moved: body %x", made)
	}
	parsed, err := parseComputeDisclosureAckStatement(vector.Statement)
	if err != nil {
		t.Fatal(err)
	}
	err = bridge.VerifySigned(parsed, ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, bridge.SignedKeyAlgEd25519, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if body, err := parseComputeDisclosureAckBody(parsed); err != nil || body.GetDisclosureId() != vector.DisclosureId || body.GetLocale() != vector.Locale {
		t.Fatalf("the vector's body: %v %v", body, err)
	}
	// the same body signed under another purpose is no disclosure-ack
	other := proto.Clone(madeSigned).(*bridge.Signed)
	other.Signature = ed25519.Sign(key, bridge.SignedBytes("approval", bridge.SignedType_SIGNED_DISCLOSURE_ACK, made))
	if err := bridge.VerifySigned(other, ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, bridge.SignedKeyAlgEd25519, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a statement signed as approval verified as a disclosure-ack")
	}
}

// A tagged CI runner's check for an engy model is refused, naming an Owner's or Admin's --network, until an Owner's
// entry stands; then covered, on the network's scope; at a new version it stands through the grace and is refused at
// its end.
func TestNetworkDisclosureCoversTaggedRunner(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	entries := []AclComputeDisclosure{}
	network := testNetworkDisclosures(world, state, &entries)
	runner := world.acksOf(t, world.config.storeOf(t, world.config.tagged))
	check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{Registry: world.registry, Acks: runner, Network: network, Now: world.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	err = check.Require(t.Context(), "inference:engy", "")
	required := &DisclosureRequiredError{}
	if !errors.As(err, &required) || required.Scope != ComputeDisclosureScopeNetwork || !strings.Contains(err.Error(), "ur disclosures ack inference:engy --network") {
		t.Fatalf("before the Owner's entry: %v", err)
	}
	if verdict, err := check.Check(t.Context(), "inference:engy"); err != nil || verdict.Askable || verdict.Covered {
		t.Fatalf("no person to ask on a runner: %+v, %v", verdict, err)
	}

	entries = append(entries, state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, nil))
	verdict, err := check.Check(t.Context(), "inference:engy")
	if err != nil || !verdict.Covered || verdict.Scope != ComputeDisclosureScopeNetwork || verdict.Acknowledged != 1 {
		t.Fatalf("after the Owner's entry: %+v, %v", verdict, err)
	}
	if stands, err := network.Stands(t.Context(), "inference:engy"); err != nil || !stands {
		t.Fatalf("Stands: %v, %v", stands, err)
	}
	entry, err := network.Entry(t.Context(), "inference:engy")
	if err != nil || entry == nil || !entry.Taken || entry.MemberId != state.devices[owner].member || entry.SidecarId != owner ||
		entry.PinVersion != 40 || entry.SignedAtMs != 40000 || entry.Locale != "en" {
		t.Fatalf("the entry %+v, %v", entry, err)
	}

	// a new version: the previous one's entry stands through the grace, then refuses
	since := world.clock.Now().Add(-time.Hour)
	testDisclosureSetVersion(world.source.policy, "inference:engy", 2, since, 14)
	world.source.policy = testDisclosurePolicyCopy(world.source.policy)
	if err := check.Require(t.Context(), "inference:engy", ""); err != nil {
		t.Fatalf("in the grace: %v", err)
	}
	if entry, _ := network.Entry(t.Context(), "inference:engy"); !entry.Stands || !entry.InGrace || entry.GraceEndMs != since.Add(14*24*time.Hour).UnixMilli() {
		t.Fatalf("in the grace: %+v", entry)
	}
	world.clock.Advance(since.Add(14 * 24 * time.Hour).Sub(world.clock.Now()))
	if err := check.Require(t.Context(), "inference:engy", ""); !errors.Is(err, ErrDisclosureRequired) {
		t.Fatalf("past the grace: %v", err)
	}
	if stands, _ := network.Stands(t.Context(), "inference:engy"); stands {
		t.Fatal("an entry past its grace stands")
	}
}

// Every entry the judge refuses, each counting for nothing, and the one it takes.
func TestNetworkDisclosureRefusals(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	admin := state.add("admin", bridge.MemberRole_MEMBER_ROLE_ADMIN, true, false)
	networkAdmin := state.add("network admin", bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, true, false)
	member := state.add("member", bridge.MemberRole_MEMBER_ROLE_MEMBER, true, false)
	tagged := state.add("tagged", bridge.MemberRole_MEMBER_ROLE_OWNER, true, true)
	readOnly := state.add("read only", bridge.MemberRole_MEMBER_ROLE_OWNER, false, false)
	promoted := state.add("promoted", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	state.rolesAt[30] = map[Id]bridge.MemberRole{state.devices[promoted].member: bridge.MemberRole_MEMBER_ROLE_MEMBER}
	atPin := func(version uint64) func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
		return func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if ack != nil {
				ack.AuthPin = &bridge.AuthPin{Version: version, Chain: state.chainAt(version)}
			}
		}
	}
	cases := []struct {
		name    string
		entry   AclComputeDisclosure
		refusal string
	}{
		{name: "a Network admin's", entry: state.statement(t, networkAdmin, "inference:engy", 1, ComputeDisclosureAckPurpose, nil), refusal: ComputeNetworkDisclosureRefusalSigner},
		{name: "a Member's", entry: state.statement(t, member, "inference:engy", 1, ComputeDisclosureAckPurpose, nil), refusal: ComputeNetworkDisclosureRefusalSigner},
		{name: "a tagged device's", entry: state.statement(t, tagged, "inference:engy", 1, ComputeDisclosureAckPurpose, nil), refusal: ComputeNetworkDisclosureRefusalSigner},
		{name: "a device not approval-capable", entry: state.statement(t, readOnly, "inference:engy", 1, ComputeDisclosureAckPurpose, nil), refusal: ComputeNetworkDisclosureRefusalSigner},
		{name: "a signer no Owner or Admin at its pin", entry: state.statement(t, promoted, "inference:engy", 1, ComputeDisclosureAckPurpose, atPin(30)), refusal: ComputeNetworkDisclosureRefusalSigner},
		{name: "another network's", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if ack != nil {
				ack.NetworkId = testConfigId("another network").Bytes()
			}
		}), refusal: ComputeNetworkDisclosureRefusalNetwork},
		{name: "under another id", entry: func() AclComputeDisclosure {
			entry := state.statement(t, owner, "inference:saygm", 1, ComputeDisclosureAckPurpose, nil)
			entry.Id = "inference:engy"
			return entry
		}(), refusal: ComputeNetworkDisclosureRefusalId},
		{name: "a family the network's does not cover", entry: state.statement(t, owner, "enclave:hippius", 1, ComputeDisclosureAckPurpose, nil), refusal: ComputeNetworkDisclosureRefusalId},
		{name: "a bad signature", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if signed != nil {
				signed.Signature[0] ^= 0x01
			}
		}), refusal: ComputeNetworkDisclosureRefusalSignature},
		{name: "signed under another purpose", entry: state.statement(t, owner, "inference:engy", 1, "approval", nil), refusal: ComputeNetworkDisclosureRefusalSignature},
		{name: "a signer no row admits", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if signed != nil {
				signed.SignerId = testConfigId("nobody").Bytes()
			}
		}), refusal: ComputeNetworkDisclosureRefusalSignature},
		{name: "a signer other than the device it names", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if ack != nil {
				ack.SidecarId = admin.Bytes()
			}
		}), refusal: ComputeNetworkDisclosureRefusalSigner},
		{name: "a pin ahead of the state", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if ack != nil {
				ack.AuthPin = &bridge.AuthPin{Version: 41, Chain: state.chainAt(41)}
			}
		}), refusal: ComputeNetworkDisclosureRefusalPin},
		{name: "a pin off the chain", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if ack != nil {
				ack.AuthPin = &bridge.AuthPin{Version: 20, Chain: state.chainAt(21)}
			}
		}), refusal: ComputeNetworkDisclosureRefusalPin},
		{name: "a key_id beside the identity key", entry: state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, func(ack *protocol.DisclosureAck, signed *bridge.Signed) {
			if signed != nil {
				signed.KeyId = []byte("a presence key")
			}
		}), refusal: ComputeNetworkDisclosureRefusalStatement},
		{name: "no version", entry: state.statement(t, owner, "inference:engy", 0, ComputeDisclosureAckPurpose, nil), refusal: ComputeNetworkDisclosureRefusalStatement},
		{name: "no base64", entry: AclComputeDisclosure{Id: "inference:engy", Statement: "not base64!"}, refusal: ComputeNetworkDisclosureRefusalStatement},
		{name: "another type", entry: func() AclComputeDisclosure {
			signed := &bridge.Signed{Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION), SignerId: owner.Bytes()}
			encoded, _ := encodeComputeDisclosureAckStatement(signed)
			return AclComputeDisclosure{Id: "inference:engy", Statement: encoded}
		}(), refusal: ComputeNetworkDisclosureRefusalStatement},
	}
	for _, c := range cases {
		entries := []AclComputeDisclosure{c.entry}
		network := testNetworkDisclosures(world, state, &entries)
		entry, err := network.Entry(t.Context(), c.entry.Id)
		if err != nil || entry == nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if entry.Taken || entry.Stands || entry.Refusal != c.refusal {
			t.Errorf("%s: taken %v, stands %v, refusal %q, want %q", c.name, entry.Taken, entry.Stands, entry.Refusal, c.refusal)
		}
		if versions, err := network.Versions(t.Context()); err != nil || len(versions) != 0 {
			t.Errorf("%s: versions %v, %v", c.name, versions, err)
		}
	}

	// an older version is taken, and covers nothing at the current one; an Admin's, and an Owner's from before what the
	// state holds, are taken
	testDisclosureSetVersion(world.source.policy, "inference:engy", 3, world.clock.Now().Add(-time.Hour), 14)
	world.source.policy = testDisclosurePolicyCopy(world.source.policy)
	entries := []AclComputeDisclosure{
		state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, nil),
		state.statement(t, admin, "search:parallel", 1, ComputeDisclosureAckPurpose, nil),
		state.statement(t, owner, "listeners:publish", 1, ComputeDisclosureAckPurpose, atPin(5)),
	}
	network := testNetworkDisclosures(world, state, &entries)
	listed, err := network.Entries(t.Context())
	if err != nil || len(listed) != 3 {
		t.Fatalf("%v, %v", listed, err)
	}
	if !listed[0].Taken || listed[0].Stands || listed[0].Refusal != "" {
		t.Errorf("an older version: %+v", listed[0])
	}
	if !listed[1].Taken || !listed[1].Stands {
		t.Errorf("an Admin's: %+v", listed[1])
	}
	if !listed[2].Taken || !listed[2].Stands || listed[2].SignedAtMs != 0 || listed[2].PinVersion != 5 {
		t.Errorf("an Owner's from before what the state holds: %+v", listed[2])
	}
}

// A member's device, and its agents' enclave, take only the person's acknowledgments, never the network's, though an
// Owner's entry stands for the id.
func TestNetworkDisclosureNeverForMemberDevices(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	entries := []AclComputeDisclosure{state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, nil)}
	network := testNetworkDisclosures(world, state, &entries)
	if stands, err := network.Stands(t.Context(), "inference:engy"); err != nil || !stands {
		t.Fatalf("the Owner's entry: %v, %v", stands, err)
	}
	for name, sidecarId := range map[string]Id{"the member's phone": world.config.phone, "the member's agents' enclave": world.config.enclave} {
		acks := world.acksOf(t, world.config.storeOf(t, sidecarId))
		check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{Registry: world.registry, Acks: acks, Network: network, Now: world.clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		verdict, err := check.Check(t.Context(), "inference:engy")
		if err != nil || verdict.Covered || verdict.Scope != ComputeDisclosureScopePerson || verdict.Acknowledged != 0 {
			t.Errorf("%s: %+v, %v", name, verdict, err)
		}
	}
	// once the person acknowledges, their own covers them
	if err := world.acks.Ack(t.Context(), testDisclosureConfirmed("inference:engy", 1)); err != nil {
		t.Fatal(err)
	}
	check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{Registry: world.registry, Acks: world.acks, Network: network, Now: world.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := check.Require(t.Context(), "inference:engy", ""); err != nil {
		t.Fatalf("the person's own: %v", err)
	}
}

// The act refuses, before anything is signed or saved: an origin that is no person's confirmation, a harness ancestor,
// a Member's, a Network admin's, a tagged or a non-approval-capable device, a family the network's does not cover, and
// a text that is not the current version's; an Owner's act passes every check and reaches the save, which needs a
// config writer.
func TestNetworkDisclosureAckRefusals(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	signs := 0
	actor := func(sidecarId Id) *computeNetworkDisclosureActor {
		return &computeNetworkDisclosureActor{
			sidecarId: sidecarId,
			view:      state,
			registry:  world.registry,
			sign: func(body []byte) (*bridge.Signed, error) {
				signs += 1
				device := state.devices[sidecarId]
				return &bridge.Signed{Body: body, SignerId: sidecarId.Bytes(), Type: uint32(bridge.SignedType_SIGNED_DISCLOSURE_ACK),
					Signature: ed25519.Sign(device.key, bridge.SignedBytes(ComputeDisclosureAckPurpose, bridge.SignedType_SIGNED_DISCLOSURE_ACK, body))}, nil
			},
		}
	}
	act := func(id string, version uint32, locale string) *ComputeNetworkDisclosureAckArgs {
		return &ComputeNetworkDisclosureAckArgs{Id: id, Version: version, Locale: locale, Origin: SidecarActConfirmed}
	}
	for name, c := range map[string]struct {
		sidecarId Id
		args      *ComputeNetworkDisclosureAckArgs
		want      error
	}{
		"an MCP origin":                          {sidecarId: owner, args: &ComputeNetworkDisclosureAckArgs{Id: "inference:engy", Version: 1, Locale: "en", Origin: SidecarActMcp}, want: ErrNetworkDisclosureRefused},
		"a hook":                                 {sidecarId: owner, args: &ComputeNetworkDisclosureAckArgs{Id: "inference:engy", Version: 1, Locale: "en", Origin: SidecarActHook}, want: ErrNetworkDisclosureRefused},
		"a harness ancestor":                     {sidecarId: owner, args: &ComputeNetworkDisclosureAckArgs{Id: "inference:engy", Version: 1, Locale: "en", Origin: SidecarActConfirmed, HarnessAncestor: true}, want: ErrNetworkDisclosureRefused},
		"no act":                                 {sidecarId: owner, want: ErrNetworkDisclosureRefused},
		"a Member's device":                      {sidecarId: state.add("member", bridge.MemberRole_MEMBER_ROLE_MEMBER, true, false), args: act("inference:engy", 1, "en"), want: ErrNetworkDisclosureRefused},
		"a Network admin's":                      {sidecarId: state.add("network admin", bridge.MemberRole_MEMBER_ROLE_NETWORK_ADMIN, true, false), args: act("inference:engy", 1, "en"), want: ErrNetworkDisclosureRefused},
		"a tagged device":                        {sidecarId: state.add("tagged", bridge.MemberRole_MEMBER_ROLE_OWNER, true, true), args: act("inference:engy", 1, "en"), want: ErrNetworkDisclosureRefused},
		"an Owner's device not approval-capable": {sidecarId: state.add("read only", bridge.MemberRole_MEMBER_ROLE_OWNER, false, false), args: act("inference:engy", 1, "en"), want: ErrNetworkDisclosureRefused},
		"an enclave provider":                    {sidecarId: owner, args: act("enclave:hippius", 1, "en"), want: ErrNetworkDisclosureUncovered},
		"a connected service":                    {sidecarId: owner, args: act("connect:google", 1, "en"), want: ErrNetworkDisclosureUncovered},
		"a version not current":                  {sidecarId: owner, args: act("inference:engy", 2, "en"), want: ErrDisclosureChanged},
		"a locale the version has no text in":    {sidecarId: owner, args: act("inference:engy", 1, "fr"), want: ErrDisclosureChanged},
		"a revision past the current one": {sidecarId: owner, args: &ComputeNetworkDisclosureAckArgs{Id: "inference:engy", Version: 1, Locale: "en", Revision: 4, Origin: SidecarActConfirmed},
			want: ErrDisclosureChanged},
		"an id the policy does not carry": {sidecarId: owner, args: act("inference:nobody", 1, "en"), want: ErrComputeDisclosureNotCarried},
	} {
		if _, err := actor(c.sidecarId).ack(t.Context(), c.args); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if signs != 0 {
		t.Fatalf("a refused act signed %d times", signs)
	}
	// an Owner's act, shown German where the policy has it, passes every check, is signed once, and refuses at the save
	// for want of a writer
	if _, err := actor(owner).ack(t.Context(), act("inference:local", 1, "DE")); !errors.Is(err, ErrNetworkDisclosureRefused) || !strings.Contains(err.Error(), "config writer") || signs != 1 {
		t.Fatalf("the Owner's act: %v, %d signs", err, signs)
	}
	// a removal by a Member, or of no id of §2.8's, saves nothing
	if _, err := actor(state.add("member two", bridge.MemberRole_MEMBER_ROLE_MEMBER, true, false)).remove(t.Context(),
		&ComputeNetworkDisclosureRemoveArgs{Id: "inference:engy", Origin: SidecarActConfirmed}); !errors.Is(err, ErrNetworkDisclosureRefused) {
		t.Errorf("a Member's removal: %v", err)
	}
	if _, err := actor(owner).remove(t.Context(), &ComputeNetworkDisclosureRemoveArgs{Id: "Inference:engy", Origin: SidecarActConfirmed}); !errors.Is(err, ErrComputeDisclosureIdInvalid) {
		t.Errorf("a removal of no id: %v", err)
	}
	if _, err := actor(owner).remove(t.Context(), &ComputeNetworkDisclosureRemoveArgs{Id: "inference:engy", Origin: SidecarActUnconfirmed}); !errors.Is(err, ErrNetworkDisclosureRefused) {
		t.Errorf("an unconfirmed removal: %v", err)
	}
}

// At a new version of an id the block holds, disclosure_changed reaches an Owner's or Admin's device once a version,
// naming the id and its current version; a Member's device and a tagged sidecar raise none, and nor does an id whose
// entry names the current version.
func TestNetworkDisclosureNewVersionNotice(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	admin := state.add("admin", bridge.MemberRole_MEMBER_ROLE_ADMIN, true, false)
	member := state.add("member", bridge.MemberRole_MEMBER_ROLE_MEMBER, true, false)
	runner := state.add("runner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, true)
	entries := []AclComputeDisclosure{
		state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, nil),
		state.statement(t, admin, "search:parallel", 1, ComputeDisclosureAckPurpose, nil),
	}
	network := testNetworkDisclosures(world, state, &entries)
	notices := func(sidecarId Id) (*computeNetworkDisclosureNotices, *[]SidecarEvent) {
		events := &[]SidecarEvent{}
		return &computeNetworkDisclosureNotices{
			disclosures: network,
			self:        func() (Id, bool) { return sidecarId, true },
			emit:        func(event SidecarEvent) { *events = append(*events, event) },
			noticed:     map[string]uint32{},
		}, events
	}
	ownerNotices, ownerEvents := notices(owner)
	if raised := ownerNotices.notice(t.Context()); len(raised) != 0 {
		t.Fatalf("at the current version: %v", raised)
	}
	testDisclosureSetVersion(world.source.policy, "inference:engy", 2, world.clock.Now().Add(-time.Hour), 14)
	world.source.policy = testDisclosurePolicyCopy(world.source.policy)
	if raised := ownerNotices.notice(t.Context()); !slices.Equal(raised, []string{"inference:engy"}) {
		t.Fatalf("at version 2: %v", raised)
	}
	if len(*ownerEvents) != 1 || (*ownerEvents)[0].Kind != SidecarEventDisclosureChanged || (*ownerEvents)[0].DisclosureId != "inference:engy" ||
		(*ownerEvents)[0].Version != 2 {
		t.Fatalf("the event %+v", *ownerEvents)
	}
	// once a version
	if raised := ownerNotices.notice(t.Context()); len(raised) != 0 {
		t.Fatalf("again at version 2: %v", raised)
	}
	adminNotices, _ := notices(admin)
	if raised := adminNotices.notice(t.Context()); !slices.Equal(raised, []string{"inference:engy"}) {
		t.Fatalf("an Admin's device: %v", raised)
	}
	for name, sidecarId := range map[string]Id{"a Member's device": member, "a tagged runner": runner} {
		quiet, events := notices(sidecarId)
		if raised := quiet.notice(t.Context()); len(raised) != 0 || len(*events) != 0 {
			t.Errorf("%s: %v", name, raised)
		}
	}
	// another version, another notice
	testDisclosureSetVersion(world.source.policy, "inference:engy", 3, world.clock.Now().Add(-time.Hour), 14)
	world.source.policy = testDisclosurePolicyCopy(world.source.policy)
	if raised := ownerNotices.notice(t.Context()); !slices.Equal(raised, []string{"inference:engy"}) || (*ownerEvents)[1].Version != 3 {
		t.Fatalf("at version 3: %v %+v", raised, *ownerEvents)
	}
}

// The lists name each id's network acknowledgment where the block holds one, on every device: who gave it and when,
// beside the person's own.
func TestComputeDisclosuresListNamesTheNetworks(t *testing.T) {
	world := newTestDisclosureAckWorld(t)
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	entries := []AclComputeDisclosure{state.statement(t, owner, "search:parallel", 1, ComputeDisclosureAckPurpose, nil)}
	check, err := NewComputeDisclosureCheck(&ComputeDisclosureCheckArgs{
		Registry: world.registry, Acks: world.acks, Network: &testNetworkDisclosureEntriesAcks{network: testNetworkDisclosures(world, state, &entries)},
		marks: world.marks, Now: world.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	component := &computeDisclosureComponent{sidecar: &Sidecar{log: NewNoopLogger()}, settings: world.registry.Settings(),
		registry: world.registry, acks: world.acks, marks: world.marks, check: check}
	list, err := component.list(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range list.Disclosures {
		switch view.Id {
		case "search:parallel":
			if view.Network == nil || !view.Network.Stands || view.Network.MemberId != state.devices[owner].member ||
				view.Scope != ComputeDisclosureScopePerson || view.Acknowledged != 0 {
				t.Errorf("search:parallel %+v, network %+v", view, view.Network)
			}
		default:
			if view.Network != nil {
				t.Errorf("%s names a network acknowledgment", view.Id)
			}
		}
	}
	encoded, err := json.Marshal(list)
	if err != nil || !strings.Contains(string(encoded), `"network":{"id":"search:parallel","version":1,"locale":"en"`) {
		t.Errorf("the JSON: %s, %v", encoded, err)
	}
}

// The Sidecar's seam's shape over a ComputeNetworkDisclosures: versions and entries.
type testNetworkDisclosureEntriesAcks struct {
	network *ComputeNetworkDisclosures
}

func (self *testNetworkDisclosureEntriesAcks) Versions(ctx context.Context) (map[string]uint32, error) {
	return self.network.Versions(ctx)
}

func (self *testNetworkDisclosureEntriesAcks) Entries(ctx context.Context) ([]*ComputeNetworkDisclosure, error) {
	return self.network.Entries(ctx)
}

// A statement the block holds parses only as a Signed DisclosureAck in standard base64: padding, a URL alphabet and
// trailing bytes are refused.
func TestDisclosureAckStatementParseStrict(t *testing.T) {
	state := newTestNetworkDisclosureState()
	owner := state.add("owner", bridge.MemberRole_MEMBER_ROLE_OWNER, true, false)
	entry := state.statement(t, owner, "inference:engy", 1, ComputeDisclosureAckPurpose, nil)
	if _, err := parseComputeDisclosureAckStatement(entry.Statement); err != nil {
		t.Fatal(err)
	}
	data, _ := base64.StdEncoding.DecodeString(entry.Statement)
	statements := map[string]string{
		"a character outside the alphabet": entry.Statement[:4] + "-" + entry.Statement[5:],
		"a field it reads not":             base64.StdEncoding.EncodeToString(append(slices.Clone(data), 0xf8, 0x01, 0x01)),
	}
	// the statement with its padding taken off, where its length gives it padding: a fixed statement, so either always
	// or never
	if strings.HasSuffix(entry.Statement, "=") {
		statements["its padding taken off"] = strings.TrimRight(entry.Statement, "=")
	}
	for name, statement := range statements {
		if _, err := parseComputeDisclosureAckStatement(statement); err == nil {
			t.Errorf("%s parsed", name)
		}
	}
}
