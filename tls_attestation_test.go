// §13.8's key attestation: fixed inputs and the exact bytes they give, on every leg, each also checked against bytes
// written out by hand here; then every refusal, a statement passing only as its own type and purpose (§22.6) among
// them. A format change regenerates the file:
//
//	go test -run TestTlsKeyAttestationVectors . -args -update-tls-vectors
//
// which is a format change, and is read as one in review. The Worker has no file system, so the vectors are embedded.
// Seeds, scalars and ids are synthetic.

package sidecar

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/tls/attestations.json
var tlsAttestationVectorsJson []byte

var updateTlsVectors = flag.Bool("update-tls-vectors", false, "rewrite testdata/tls/attestations.json")

// One attestation: its inputs, then what they give.
type tlsAttestationVector struct {
	Name string `json:"name"`
	// The identity key's Ed25519 seed.
	IdentitySeed hexBytes `json:"identity_seed"`
	NetworkId    hexBytes `json:"network_id"`
	SidecarId    hexBytes `json:"sidecar_id"`
	// The device key's P-256 scalar, whose public half the SPKI holds.
	DeviceScalar    hexBytes `json:"device_scalar"`
	Root            string   `json:"root"`
	Label           string   `json:"label"`
	Scope           string   `json:"scope,omitempty"`
	Aliases         []string `json:"aliases,omitempty"`
	IssueTimeMillis uint64   `json:"issue_time_millis"`

	IdentityPublicKey   hexBytes `json:"identity_public_key"`
	Spki                hexBytes `json:"spki"`
	SpkiSha256          hexBytes `json:"spki_sha256"`
	IdentifierSet       []string `json:"identifier_set"`
	IdentifierSetSha256 hexBytes `json:"identifier_set_sha256"`
	// The TlsKeyAttestation, then the Signed around it, each as encoded.
	Body   hexBytes `json:"body"`
	Signed hexBytes `json:"signed"`
}

// The file's shape.
type tlsAttestationVectorFile struct {
	Attestations []*tlsAttestationVector `json:"attestations"`
}

// The inputs: a network's set, one with aliases and a scope's.
func testTlsAttestationInputs() []*tlsAttestationVector {
	sequence := func(first byte, count int) hexBytes {
		values := make(hexBytes, count)
		for index := range values {
			values[index] = first + byte(index)
		}
		return values
	}
	return []*tlsAttestationVector{
		{
			Name:            "network",
			IdentitySeed:    sequence(0x00, 32),
			NetworkId:       bytes.Repeat([]byte{0x01}, 16),
			SidecarId:       bytes.Repeat([]byte{0xa1}, 16),
			DeviceScalar:    bytes.Repeat([]byte{0x07}, 32),
			Root:            testTlsRoot,
			Label:           testTlsLabel,
			IssueTimeMillis: 1767225600000,
		},
		{
			Name:            "aliases",
			IdentitySeed:    sequence(0x20, 32),
			NetworkId:       bytes.Repeat([]byte{0x02}, 16),
			SidecarId:       bytes.Repeat([]byte{0xa2}, 16),
			DeviceScalar:    bytes.Repeat([]byte{0x08}, 32),
			Root:            testTlsRoot,
			Label:           testTlsLabel,
			Aliases:         []string{"blog", "acme"},
			IssueTimeMillis: 1767225600001,
		},
		{
			Name:            "scope",
			IdentitySeed:    sequence(0x40, 32),
			NetworkId:       bytes.Repeat([]byte{0x03}, 16),
			SidecarId:       bytes.Repeat([]byte{0xa3}, 16),
			DeviceScalar:    bytes.Repeat([]byte{0x09}, 32),
			Root:            testTlsRoot,
			Label:           testTlsLabel,
			Scope:           "eng",
			IssueTimeMillis: 1767225600002,
		},
	}
}

// Signs as Sidecar.Sign does, by the identity key of seed, signer_id sidecarId.
func testTlsSign(seed []byte, sidecarId []byte) TlsKeyAttestationSignFunction {
	privateKey := ed25519.NewKeyFromSeed(seed)
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  sidecarId,
			Signature: ed25519.Sign(privateKey, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// What a device holds for one input: its SPKI, set and their hashes, and the attestation of them.
func testTlsAttest(t *testing.T, input *tlsAttestationVector) *tlsAttestationVector {
	t.Helper()
	deviceKey, err := ecdh.P256().NewPrivateKey(input.DeviceScalar)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(deviceKey.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	identifierSet, err := TlsIdentifierSet(input.Root, input.Label, input.Scope, input.Aliases)
	if err != nil {
		t.Fatal(err)
	}
	identifierSetSha256, err := TlsIdentifierSetHash(identifierSet)
	if err != nil {
		t.Fatal(err)
	}
	spkiSha256 := sha256.Sum256(spki)
	attestation := &protocol.TlsKeyAttestation{
		NetworkId:           input.NetworkId,
		SidecarId:           input.SidecarId,
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: identifierSetSha256[:],
		IssueTimeMillis:     input.IssueTimeMillis,
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(attestation)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTlsKeyAttestation(attestation, testTlsSign(input.IdentitySeed, input.SidecarId))
	if err != nil {
		t.Fatal(err)
	}
	vector := *input
	vector.IdentityPublicKey = hexBytes(ed25519.NewKeyFromSeed(input.IdentitySeed).Public().(ed25519.PublicKey))
	vector.Spki = spki
	vector.SpkiSha256 = spkiSha256[:]
	vector.IdentifierSet = identifierSet
	vector.IdentifierSetSha256 = identifierSetSha256[:]
	vector.Body = body
	vector.Signed = signed
	return &vector
}

// The file as checked in, with what this leg computes from the same inputs beside it.
func TestTlsKeyAttestationVectorsAreByteEqual(t *testing.T) {
	file := &tlsAttestationVectorFile{}
	for _, input := range testTlsAttestationInputs() {
		file.Attestations = append(file.Attestations, testTlsAttest(t, input))
	}
	encoded, err := json.MarshalIndent(file, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updateTlsVectors {
		if err := os.WriteFile("testdata/tls/attestations.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(encoded, tlsAttestationVectorsJson) {
		t.Error("a vector moved: this leg computes other bytes than testdata/tls/attestations.json holds")
	}
}

// The checked-in vectors.
func testTlsAttestationVectors(t *testing.T) []*tlsAttestationVector {
	t.Helper()
	file := &tlsAttestationVectorFile{}
	if err := json.Unmarshal(tlsAttestationVectorsJson, file); err != nil {
		t.Fatal(err)
	}
	if len(file.Attestations) != len(testTlsAttestationInputs()) {
		t.Fatalf("%d vectors", len(file.Attestations))
	}
	return file.Attestations
}

// Each vector against bytes written out here from reading #2 and §6.9, apart from the code, and through
// VerifyTlsKeyAttestation, so the file cannot pin bytes no verifier takes.
func TestTlsKeyAttestationVectorsVerify(t *testing.T) {
	for _, vector := range testTlsAttestationVectors(t) {
		spkiSha256 := sha256.Sum256(vector.Spki)
		if !bytes.Equal(spkiSha256[:], vector.SpkiSha256) {
			t.Errorf("%s: spki_sha256 is not the SPKI's", vector.Name)
		}
		if _, err := x509.ParsePKIXPublicKey(vector.Spki); err != nil {
			t.Errorf("%s: the SPKI does not parse: %v", vector.Name, err)
		}
		identifierSetSha256 := testTlsIdentifierSetHash(vector.IdentifierSet)
		if !bytes.Equal(identifierSetSha256[:], vector.IdentifierSetSha256) {
			t.Errorf("%s: identifier_set_sha256 is not the set's", vector.Name)
		}

		body := protowire.AppendTag(nil, 1, protowire.BytesType)
		body = protowire.AppendBytes(body, vector.NetworkId)
		body = protowire.AppendTag(body, 2, protowire.BytesType)
		body = protowire.AppendBytes(body, vector.SidecarId)
		body = protowire.AppendTag(body, 3, protowire.BytesType)
		body = protowire.AppendBytes(body, vector.SpkiSha256)
		body = protowire.AppendTag(body, 4, protowire.BytesType)
		body = protowire.AppendBytes(body, vector.IdentifierSetSha256)
		body = protowire.AppendTag(body, 5, protowire.VarintType)
		body = protowire.AppendVarint(body, vector.IssueTimeMillis)
		if !bytes.Equal(body, vector.Body) {
			t.Errorf("%s: the body is not reading #2's fields in order", vector.Name)
		}

		signedBytes := append([]byte("urnetwork-sidecar-v1/tls-key\x00"), 0x00, 0x00, 0x15, 0x01)
		signedBytes = append(signedBytes, body...)
		signature := ed25519.Sign(ed25519.NewKeyFromSeed(vector.IdentitySeed), signedBytes)
		signed := protowire.AppendTag(nil, 1, protowire.BytesType)
		signed = protowire.AppendBytes(signed, body)
		signed = protowire.AppendTag(signed, 2, protowire.BytesType)
		signed = protowire.AppendBytes(signed, vector.SidecarId)
		signed = protowire.AppendTag(signed, 4, protowire.BytesType)
		signed = protowire.AppendBytes(signed, signature)
		signed = protowire.AppendTag(signed, 6, protowire.VarintType)
		signed = protowire.AppendVarint(signed, 0x1501)
		if !bytes.Equal(signed, vector.Signed) {
			t.Errorf("%s: the Signed is not §6.9's over those bytes", vector.Name)
		}

		networkId, err := IdFromBytes(vector.NetworkId)
		if err != nil {
			t.Fatal(err)
		}
		sidecarId, err := IdFromBytes(vector.SidecarId)
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := VerifyTlsKeyAttestation(
			vector.Signed,
			vector.IdentityPublicKey,
			networkId,
			sidecarId,
			[sha256.Size]byte(vector.SpkiSha256),
			[sha256.Size]byte(vector.IdentifierSetSha256),
		)
		if err != nil {
			t.Errorf("%s: %v", vector.Name, err)
			continue
		}
		if attestation.GetIssueTimeMillis() != vector.IssueTimeMillis {
			t.Errorf("%s: issue time %d", vector.Name, attestation.GetIssueTimeMillis())
		}
	}
}

// One attestation and what it covers, for the refusal tests.
type testTlsAttested struct {
	signed              []byte
	identityPublicKey   []byte
	networkId           Id
	sidecarId           Id
	spkiSha256          [sha256.Size]byte
	identifierSetSha256 [sha256.Size]byte
	seed                []byte
	body                []byte
}

// The network vector's attestation, from its inputs.
func testTlsAttestedNetwork(t *testing.T) *testTlsAttested {
	t.Helper()
	vector := testTlsAttest(t, testTlsAttestationInputs()[0])
	networkId, err := IdFromBytes(vector.NetworkId)
	if err != nil {
		t.Fatal(err)
	}
	sidecarId, err := IdFromBytes(vector.SidecarId)
	if err != nil {
		t.Fatal(err)
	}
	return &testTlsAttested{
		signed:              vector.Signed,
		identityPublicKey:   vector.IdentityPublicKey,
		networkId:           networkId,
		sidecarId:           sidecarId,
		spkiSha256:          [sha256.Size]byte(vector.SpkiSha256),
		identifierSetSha256: [sha256.Size]byte(vector.IdentifierSetSha256),
		seed:                vector.IdentitySeed,
		body:                vector.Body,
	}
}

// Verifies signed as the attestation of attested's network, sidecar, key and set.
func (self *testTlsAttested) verify(signed []byte) error {
	_, err := VerifyTlsKeyAttestation(
		signed,
		self.identityPublicKey,
		self.networkId,
		self.sidecarId,
		self.spkiSha256,
		self.identifierSetSha256,
	)
	return err
}

// A chain for another key or other names, or a statement for another network or sidecar, never verifies, and the
// error names the field and never its value (I-13).
func TestVerifyTlsKeyAttestationRefusesWhatItDoesNotSay(t *testing.T) {
	attested := testTlsAttestedNetwork(t)
	otherSet, err := TlsIdentifierSetHash([]string{"*.other.ur.example", "other.ur.example"})
	if err != nil {
		t.Fatal(err)
	}
	otherId := Id(bytes.Repeat([]byte{0x0f}, 16))
	cases := []struct {
		field string
		run   func() error
	}{
		{field: "network", run: func() error {
			_, err := VerifyTlsKeyAttestation(attested.signed, attested.identityPublicKey, otherId, attested.sidecarId, attested.spkiSha256, attested.identifierSetSha256)
			return err
		}},
		{field: "sidecar", run: func() error {
			_, err := VerifyTlsKeyAttestation(attested.signed, attested.identityPublicKey, attested.networkId, otherId, attested.spkiSha256, attested.identifierSetSha256)
			return err
		}},
		{field: "key", run: func() error {
			_, err := VerifyTlsKeyAttestation(attested.signed, attested.identityPublicKey, attested.networkId, attested.sidecarId, sha256.Sum256([]byte("another key")), attested.identifierSetSha256)
			return err
		}},
		{field: "identifier set", run: func() error {
			_, err := VerifyTlsKeyAttestation(attested.signed, attested.identityPublicKey, attested.networkId, attested.sidecarId, attested.spkiSha256, otherSet)
			return err
		}},
	}
	for _, c := range cases {
		err := c.run()
		if !errors.Is(err, ErrTlsKeyAttestationMismatch) || !strings.HasSuffix(err.Error(), ": "+c.field) {
			t.Errorf("%s: %v", c.field, err)
		}
	}
	// another identity key: the signature
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, 32)).Public().(ed25519.PublicKey)
	_, err = VerifyTlsKeyAttestation(attested.signed, otherKey, attested.networkId, attested.sidecarId, attested.spkiSha256, attested.identifierSetSha256)
	if !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("another identity key: %v", err)
	}
	for _, identityPublicKey := range [][]byte{nil, otherKey[:31]} {
		_, err = VerifyTlsKeyAttestation(attested.signed, identityPublicKey, attested.networkId, attested.sidecarId, attested.spkiSha256, attested.identifierSetSha256)
		if !errors.Is(err, bridge.ErrSignedKey) {
			t.Errorf("a %d-byte identity key: %v", len(identityPublicKey), err)
		}
	}
}

// No signature covers signer_id, so a statement whose Signed names another signer is refused rather than left to a
// caller that resolved its key from there.
func TestVerifyTlsKeyAttestationRefusesAnotherSignerId(t *testing.T) {
	attested := testTlsAttestedNetwork(t)
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(attested.signed, signed); err != nil {
		t.Fatal(err)
	}
	for _, signerId := range [][]byte{nil, bytes.Repeat([]byte{0x0f}, 16)} {
		signed.SignerId = signerId
		encoded, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := attested.verify(encoded); !errors.Is(err, ErrTlsKeyAttestationMismatch) {
			t.Errorf("signer %x: %v", signerId, err)
		}
	}
}

// §22.6: the attestation's body passes as SIGNED_TLS_KEY_ATTESTATION under purpose tls-key alone. Signed as another
// type it fails the type check; relabeled as this type after signing, or signed under another purpose, the signature;
// and another message's body signed as this type fails its fields.
func TestTlsKeyAttestationParsesOnlyAsItsType(t *testing.T) {
	attested := testTlsAttestedNetwork(t)
	privateKey := ed25519.NewKeyFromSeed(attested.seed)
	encode := func(purpose string, signedAs bridge.SignedType, presentedAs bridge.SignedType, body []byte) []byte {
		encoded, err := proto.Marshal(&bridge.Signed{
			Body:      body,
			SignerId:  attested.sidecarId[:],
			Signature: ed25519.Sign(privateKey, bridge.SignedBytes(purpose, signedAs, body)),
			Type:      uint32(presentedAs),
		})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	tlsType := bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION
	if err := attested.verify(encode(TlsKeyAttestationPurpose, tlsType, tlsType, attested.body)); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for _, signedType := range []bridge.SignedType{
		bridge.SignedType_SIGNED_SOCKET_REGISTRATION,
		bridge.SignedType_SIGNED_SOCKET_TICKET,
		bridge.SignedType_SIGNED_EVS_IMPORT,
		bridge.SignedType_SIGNED_RECORD_HEADER,
		bridge.SignedType_SIGNED_TYPE_NONE,
	} {
		err := attested.verify(encode(TlsKeyAttestationPurpose, signedType, signedType, attested.body))
		if !errors.Is(err, bridge.ErrSignedTypeMismatch) {
			t.Errorf("signed as %s: %v", signedType, err)
		}
		err = attested.verify(encode(TlsKeyAttestationPurpose, signedType, tlsType, attested.body))
		if !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("signed as %s and relabeled: %v", signedType, err)
		}
	}
	for _, purpose := range []string{"socket-registration", "edge-login", "authority"} {
		err := attested.verify(encode(purpose, tlsType, tlsType, attested.body))
		if !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("purpose %s: %v", purpose, err)
		}
	}
	// a SocketHint's bytes: kind, then a 16-byte listen_id where sidecar_id would be, and no network
	socketHint, err := proto.Marshal(&protocol.SocketHint{Kind: protocol.SocketHintKind_SOCKET_HINT_REVOKED, ListenId: attested.sidecarId[:]})
	if err != nil {
		t.Fatal(err)
	}
	err = attested.verify(encode(TlsKeyAttestationPurpose, tlsType, tlsType, socketHint))
	if !errors.Is(err, ErrTlsKeyAttestationMalformed) {
		t.Errorf("a SocketHint body: %v", err)
	}
}

// A field a newer device adds is signed like any other and kept (§22.6), so nothing re-marshals what was signed.
func TestVerifyTlsKeyAttestationKeepsWhatANewerDeviceAdds(t *testing.T) {
	attested := testTlsAttestedNetwork(t)
	body := protowire.AppendTag(bytes.Clone(attested.body), 9, protowire.VarintType)
	body = protowire.AppendVarint(body, 7)
	encoded, err := proto.Marshal(&bridge.Signed{
		Body:     body,
		SignerId: attested.sidecarId[:],
		Signature: ed25519.Sign(
			ed25519.NewKeyFromSeed(attested.seed),
			bridge.SignedBytes(TlsKeyAttestationPurpose, bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION, body),
		),
		Type: uint32(bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION),
	})
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := VerifyTlsKeyAttestation(encoded, attested.identityPublicKey, attested.networkId, attested.sidecarId, attested.spkiSha256, attested.identifierSetSha256)
	if err != nil {
		t.Fatal(err)
	}
	if len(attestation.ProtoReflect().GetUnknown()) == 0 {
		t.Error("the added field was dropped")
	}
}

func TestVerifyTlsKeyAttestationRefusesWhatIsNoAttestation(t *testing.T) {
	attested := testTlsAttestedNetwork(t)
	for _, encoded := range [][]byte{nil, {}, {0x0a, 0x7f}, attested.signed[:len(attested.signed)/2], []byte("an attestation")} {
		if err := attested.verify(encoded); err == nil {
			t.Errorf("%x passed", encoded)
		}
	}
}

// Fields that cannot be an attestation are refused before anything is signed, and a sign function that answers
// something else is caught here rather than at certs.
func TestSignTlsKeyAttestationRefusesWhatCannotBeOne(t *testing.T) {
	input := testTlsAttestationInputs()[0]
	sign := testTlsSign(input.IdentitySeed, input.SidecarId)
	valid := func() *protocol.TlsKeyAttestation {
		return &protocol.TlsKeyAttestation{
			NetworkId:           input.NetworkId,
			SidecarId:           input.SidecarId,
			SpkiSha256:          bytes.Repeat([]byte{0x33}, 32),
			IdentifierSetSha256: bytes.Repeat([]byte{0x44}, 32),
			IssueTimeMillis:     input.IssueTimeMillis,
		}
	}
	for index, mutate := range []func(*protocol.TlsKeyAttestation){
		func(attestation *protocol.TlsKeyAttestation) { attestation.NetworkId = nil },
		func(attestation *protocol.TlsKeyAttestation) { attestation.SidecarId = attestation.SidecarId[:15] },
		func(attestation *protocol.TlsKeyAttestation) { attestation.SpkiSha256 = nil },
		func(attestation *protocol.TlsKeyAttestation) { attestation.IdentifierSetSha256 = make([]byte, 33) },
		func(attestation *protocol.TlsKeyAttestation) { attestation.IssueTimeMillis = 0 },
	} {
		attestation := valid()
		mutate(attestation)
		if signed, err := SignTlsKeyAttestation(attestation, sign); !errors.Is(err, ErrTlsKeyAttestationMalformed) || signed != nil {
			t.Errorf("case %d: %x %v", index, signed, err)
		}
	}
	signError := errors.New("locked")
	answers := []func(*bridge.Signed) (*bridge.Signed, error){
		func(*bridge.Signed) (*bridge.Signed, error) { return nil, nil },
		func(*bridge.Signed) (*bridge.Signed, error) { return nil, signError },
		func(signed *bridge.Signed) (*bridge.Signed, error) {
			signed.Type = uint32(bridge.SignedType_SIGNED_SOCKET_REGISTRATION)
			return signed, nil
		},
		func(signed *bridge.Signed) (*bridge.Signed, error) {
			signed.Body = append(signed.Body, 0x48, 0x01)
			return signed, nil
		},
		func(signed *bridge.Signed) (*bridge.Signed, error) {
			signed.SignerId = bytes.Repeat([]byte{0x0f}, 16)
			return signed, nil
		},
	}
	for index, answer := range answers {
		wrapped := func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
			signed, err := sign(purpose, signedType, body, agentId)
			if err != nil {
				return nil, err
			}
			return answer(signed)
		}
		signed, err := SignTlsKeyAttestation(valid(), wrapped)
		if err == nil || signed != nil {
			t.Errorf("answer %d: %x %v", index, signed, err)
		}
		if index == 1 && !errors.Is(err, signError) {
			t.Errorf("sign's own error became %v", err)
		}
	}
	// the purpose and type sign is asked for, and no agent label
	asked := func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		if purpose != "tls-key" || signedType != bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION || agentId != nil {
			t.Errorf("asked for %q %s %v", purpose, signedType, agentId)
		}
		return sign(purpose, signedType, body, agentId)
	}
	if _, err := SignTlsKeyAttestation(valid(), asked); err != nil {
		t.Error(err)
	}
}

// The signed bytes' type is §6.11's u32be, as the hand-written bytes above take it.
func TestTlsKeyAttestationTypeIs0x1501(t *testing.T) {
	signedBytes := bridge.SignedBytes(TlsKeyAttestationPurpose, bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION, nil)
	if got := binary.BigEndian.Uint32(signedBytes[len(signedBytes)-4:]); got != 0x1501 {
		t.Errorf("type %#x", got)
	}
}

// A Sidecar's Sign is a sign function as it stands, so a device attests through its identity key and no other path.
func TestSignTlsKeyAttestationTakesSidecarSign(t *testing.T) {
	sidecar, _, keys := newIdentityTestSidecar(t)
	binding := testBindingFields()
	identifierSetSha256 := testTlsIdentifierSetHash([]string{"*.k7m2q9xa.ur.example", "k7m2q9xa.ur.example"})
	spkiSha256 := sha256.Sum256([]byte("a device key's SPKI"))
	signed, err := SignTlsKeyAttestation(&protocol.TlsKeyAttestation{
		NetworkId:           binding.NetworkId.Bytes(),
		SidecarId:           binding.SidecarId.Bytes(),
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: identifierSetSha256[:],
		IssueTimeMillis:     1767225600000,
	}, sidecar.Sign)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyTlsKeyAttestation(signed, keys.identityPublicKey(), binding.NetworkId, binding.SidecarId, spkiSha256, identifierSetSha256)
	if err != nil {
		t.Error(err)
	}
}
