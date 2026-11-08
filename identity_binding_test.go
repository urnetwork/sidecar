package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// testdata/binding/vectors.json: a binding's seeds and fields, and the wrapper bytes they sign to, the same on
// every leg, since Ed25519 signs deterministically.
type bindingVector struct {
	Name              string `json:"name"`
	IdentitySeed      string `json:"identity_seed"`
	ClientKeySeed     string `json:"client_key_seed"`
	NetworkId         string `json:"network_id"`
	SidecarId         string `json:"sidecar_id"`
	ClientId          string `json:"client_id"`
	Generation        int64  `json:"generation"`
	IssuedAtMs        int64  `json:"issued_at_ms"`
	IdentityPublicKey string `json:"identity_public_key"`
	ClientPublicKey   string `json:"client_public_key"`
	SignedBinding     string `json:"signed_binding"`
}

// Fixed synthetic seeds: identity 0x11.., ClientKey 0x51...
func testBindingSeeds() ([]byte, []byte) {
	return countingBytes(0x11, ed25519.SeedSize), countingBytes(0x51, ed25519.SeedSize)
}

// A binding of generation 1 with fixed synthetic ids and time.
func testBindingFields() *SidecarIdentityBinding {
	networkId, _ := IdFromBytes(countingBytes(0x01, 16))
	sidecarId, _ := IdFromBytes(countingBytes(0x21, 16))
	clientId, _ := IdFromBytes(countingBytes(0x31, 16))
	return &SidecarIdentityBinding{
		NetworkId:  networkId,
		SidecarId:  sidecarId,
		ClientId:   clientId,
		Generation: 1,
		IssuedAt:   time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC),
	}
}

// The synthetic binding's wrapper bytes.
func testSignedBinding(t *testing.T) []byte {
	t.Helper()
	identitySeed, clientKeySeed := testBindingSeeds()
	signedBinding, err := NewSidecarIdentityBinding(testBindingFields(), identitySeed, clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	return signedBinding
}

// The wrapper and body of signedBinding, decoded, for a test that breaks one part.
func splitTestBinding(t *testing.T, signedBinding []byte) (*bridge.SignedSidecarIdentityBinding, *bridge.SidecarIdentityBinding) {
	t.Helper()
	signed := &bridge.SignedSidecarIdentityBinding{}
	if err := proto.Unmarshal(signedBinding, signed); err != nil {
		t.Fatal(err)
	}
	body := &bridge.SidecarIdentityBinding{}
	if err := proto.Unmarshal(signed.Body, body); err != nil {
		t.Fatal(err)
	}
	return signed, body
}

// message's canonical bytes.
func marshalCanonical(t *testing.T, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// A binding of both keys verifies, and answers exactly what was signed.
func TestBindingVerifiesBothSignatures(t *testing.T) {
	identitySeed, clientKeySeed := testBindingSeeds()
	binding, err := VerifySidecarIdentityBinding(testSignedBinding(t))
	if err != nil {
		t.Fatal(err)
	}
	want := testBindingFields()
	if binding.NetworkId != want.NetworkId || binding.SidecarId != want.SidecarId || binding.ClientId != want.ClientId ||
		binding.Generation != 1 || !binding.IssuedAt.Equal(want.IssuedAt) {
		t.Errorf("fields differ: %+v", binding)
	}
	if !bytes.Equal(binding.IdentityPublicKey, ed25519.NewKeyFromSeed(identitySeed).Public().(ed25519.PublicKey)) ||
		!bytes.Equal(binding.ClientPublicKey, ed25519.NewKeyFromSeed(clientKeySeed).Public().(ed25519.PublicKey)) {
		t.Error("public keys differ")
	}
}

// Each signature alone, a signature moved to the other slot, or one key signing both, is refused: a copied token's
// holder cannot bind a key without the identity key, nor the identity key bind without the ClientKey (§5.7).
func TestBindingRefusesEitherSignatureAlone(t *testing.T) {
	signed, body := splitTestBinding(t, testSignedBinding(t))
	identitySeed, clientKeySeed := testBindingSeeds()
	otherKey := ed25519.NewKeyFromSeed(countingBytes(0x91, ed25519.SeedSize))
	signWith := func(seed []byte, purpose string) []byte {
		return ed25519.Sign(ed25519.NewKeyFromSeed(seed), bridge.SignedBytes(purpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, signed.Body))
	}
	cases := []*bridge.SignedSidecarIdentityBinding{
		{Body: signed.Body, ClientSignature: signed.ClientSignature},
		{Body: signed.Body, IdentitySignature: signed.IdentitySignature},
		{Body: signed.Body, ClientSignature: signed.IdentitySignature, IdentitySignature: signed.ClientSignature},
		{Body: signed.Body, ClientSignature: signWith(identitySeed, sidecarBindingClientPurpose), IdentitySignature: signed.IdentitySignature},
		{Body: signed.Body, ClientSignature: signed.ClientSignature, IdentitySignature: signWith(clientKeySeed, sidecarBindingIdentityPurpose)},
		// the right keys under each other's purposes
		{Body: signed.Body, ClientSignature: signWith(clientKeySeed, sidecarBindingIdentityPurpose), IdentitySignature: signWith(identitySeed, sidecarBindingClientPurpose)},
		{Body: signed.Body, ClientSignature: signed.ClientSignature,
			IdentitySignature: ed25519.Sign(otherKey, bridge.SignedBytes(sidecarBindingIdentityPurpose, bridge.SignedType_SIGNED_SIDECAR_BINDING, signed.Body))},
	}
	for i, c := range cases {
		if _, err := VerifySidecarIdentityBinding(marshalCanonical(t, c)); !errors.Is(err, ErrSidecarBindingInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	// a body naming another identity key than the one that signed it
	body.IdentityPublicKey = otherKey.Public().(ed25519.PublicKey)
	swapped := &bridge.SignedSidecarIdentityBinding{Body: marshalCanonical(t, body), ClientSignature: signed.ClientSignature, IdentitySignature: signed.IdentitySignature}
	if _, err := VerifySidecarIdentityBinding(marshalCanonical(t, swapped)); !errors.Is(err, ErrSidecarBindingInvalid) {
		t.Errorf("a body with another key: %v", err)
	}
}

// The verifier checks the bytes as received: a body or wrapper written another way, with the same fields, is
// refused, whether or not the signatures would cover a re-marshal.
func TestBindingRefusesReencodedBytes(t *testing.T) {
	signedBinding := testSignedBinding(t)
	signed, _ := splitTestBinding(t, signedBinding)

	// the body's fields in another order: the same message, other bytes, which the signatures do not cover
	reordered := []byte{}
	fieldsByNumber := map[protowire.Number][]byte{}
	numbers := []protowire.Number{}
	rest := signed.Body
	for 0 < len(rest) {
		number, wireType, length := protowire.ConsumeTag(rest)
		valueLength := protowire.ConsumeFieldValue(number, wireType, rest[length:])
		fieldsByNumber[number] = rest[:length+valueLength]
		numbers = append(numbers, number)
		rest = rest[length+valueLength:]
	}
	for i := len(numbers) - 1; 0 <= i; i -= 1 {
		reordered = append(reordered, fieldsByNumber[numbers[i]]...)
	}
	bodyReordered := marshalCanonical(t, &bridge.SignedSidecarIdentityBinding{Body: reordered, ClientSignature: signed.ClientSignature, IdentitySignature: signed.IdentitySignature})
	// an unknown field appended to the body, and one appended to the wrapper
	bodyExtended := marshalCanonical(t, &bridge.SignedSidecarIdentityBinding{
		Body:            protowire.AppendVarint(protowire.AppendTag(bytes.Clone(signed.Body), 15, protowire.VarintType), 1),
		ClientSignature: signed.ClientSignature, IdentitySignature: signed.IdentitySignature,
	})
	wrapperExtended := protowire.AppendVarint(protowire.AppendTag(bytes.Clone(signedBinding), 15, protowire.VarintType), 1)
	// the wrapper's fields in another order
	wrapperReordered := []byte{}
	wrapperReordered = protowire.AppendTag(wrapperReordered, 3, protowire.BytesType)
	wrapperReordered = protowire.AppendBytes(wrapperReordered, signed.IdentitySignature)
	wrapperReordered = protowire.AppendTag(wrapperReordered, 1, protowire.BytesType)
	wrapperReordered = protowire.AppendBytes(wrapperReordered, signed.Body)
	wrapperReordered = protowire.AppendTag(wrapperReordered, 2, protowire.BytesType)
	wrapperReordered = protowire.AppendBytes(wrapperReordered, signed.ClientSignature)

	for name, encoded := range map[string][]byte{
		"body reordered":    bodyReordered,
		"body extended":     bodyExtended,
		"wrapper extended":  wrapperExtended,
		"wrapper reordered": wrapperReordered,
	} {
		if _, err := VerifySidecarIdentityBinding(encoded); !errors.Is(err, ErrSidecarBindingInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A field out of its format is refused even under good signatures, which NewSidecarIdentityBinding will not make.
func TestBindingRefusesFieldsOutOfFormat(t *testing.T) {
	identitySeed, clientKeySeed := testBindingSeeds()
	breaks := map[string]func(binding *SidecarIdentityBinding){
		"no network":      func(binding *SidecarIdentityBinding) { binding.NetworkId = Id{} },
		"no sidecar":      func(binding *SidecarIdentityBinding) { binding.SidecarId = Id{} },
		"no client":       func(binding *SidecarIdentityBinding) { binding.ClientId = Id{} },
		"generation zero": func(binding *SidecarIdentityBinding) { binding.Generation = 0 },
		"no time":         func(binding *SidecarIdentityBinding) { binding.IssuedAt = time.Unix(0, 0) },
		"another identity key": func(binding *SidecarIdentityBinding) {
			binding.IdentityPublicKey = ed25519.NewKeyFromSeed(clientKeySeed).Public().(ed25519.PublicKey)
		},
	}
	for name, edit := range breaks {
		binding := testBindingFields()
		edit(binding)
		if _, err := NewSidecarIdentityBinding(binding, identitySeed, clientKeySeed); !errors.Is(err, ErrSidecarBindingInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// one key as both, signed by it twice, which a hand-made binding could carry
	binding := testBindingFields()
	if _, err := NewSidecarIdentityBinding(binding, identitySeed, identitySeed); !errors.Is(err, ErrSidecarBindingInvalid) {
		t.Errorf("one key as both: %v", err)
	}
	if _, err := VerifySidecarIdentityBinding(nil); !errors.Is(err, ErrSidecarBindingInvalid) {
		t.Errorf("nothing: %v", err)
	}
	if _, err := VerifySidecarIdentityBinding(make([]byte, sidecarBindingMaxByteCount+1)); !errors.Is(err, ErrSidecarBindingInvalid) {
		t.Errorf("past the bound: %v", err)
	}
}

func readBindingVectors(t *testing.T) []bindingVector {
	t.Helper()
	encoded, err := os.ReadFile("testdata/binding/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := []bindingVector{}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	return vectors
}

// The vectors sign to the same bytes on every leg, and verify to their fields.
func TestBindingVectors(t *testing.T) {
	for _, vector := range readBindingVectors(t) {
		decodeHex := func(text string) []byte {
			value, err := hex.DecodeString(text)
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			return value
		}
		parseId := func(text string) Id {
			id, err := ParseId(text)
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			return id
		}
		binding := &SidecarIdentityBinding{
			NetworkId:  parseId(vector.NetworkId),
			SidecarId:  parseId(vector.SidecarId),
			ClientId:   parseId(vector.ClientId),
			Generation: vector.Generation,
			IssuedAt:   time.UnixMilli(vector.IssuedAtMs),
		}
		signedBinding, err := NewSidecarIdentityBinding(binding, decodeHex(vector.IdentitySeed), decodeHex(vector.ClientKeySeed))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if hex.EncodeToString(signedBinding) != vector.SignedBinding {
			t.Errorf("%s: signs to other bytes", vector.Name)
		}
		verified, err := VerifySidecarIdentityBinding(decodeHex(vector.SignedBinding))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		if hex.EncodeToString(verified.IdentityPublicKey) != vector.IdentityPublicKey ||
			hex.EncodeToString(verified.ClientPublicKey) != vector.ClientPublicKey || verified.Generation != vector.Generation ||
			verified.IssuedAt.UnixMilli() != vector.IssuedAtMs || verified.ClientId != binding.ClientId {
			t.Errorf("%s: verifies to other fields", vector.Name)
		}
	}
}

// The first vector is the synthetic binding, so the file is not stale.
func TestBindingVectorsAreTheSyntheticBinding(t *testing.T) {
	if readBindingVectors(t)[0].SignedBinding != hex.EncodeToString(testSignedBinding(t)) {
		t.Fatal("testdata/binding/vectors.json is not the synthetic binding")
	}
}

// No input panics, and anything accepted is canonical: its body and wrapper re-encode to the same bytes, so one
// binding has one byte string.
func FuzzVerifySidecarIdentityBinding(f *testing.F) {
	identitySeed, clientKeySeed := testBindingSeeds()
	signedBinding, _ := NewSidecarIdentityBinding(testBindingFields(), identitySeed, clientKeySeed)
	f.Add(signedBinding)
	f.Add([]byte{})
	f.Add(signedBinding[:len(signedBinding)/2])
	f.Add(append(bytes.Clone(signedBinding), 0x78, 0x01))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		binding, err := VerifySidecarIdentityBinding(encoded)
		if err != nil {
			if binding != nil {
				t.Fatal("a binding beside an error")
			}
			return
		}
		signed := &bridge.SignedSidecarIdentityBinding{}
		if proto.Unmarshal(encoded, signed) != nil {
			t.Fatal("accepted bytes that do not decode")
		}
		canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil || !bytes.Equal(canonical, encoded) {
			t.Fatal("accepted a wrapper that is not canonical")
		}
		if bytes.Equal(binding.ClientPublicKey, binding.IdentityPublicKey) {
			t.Fatal("accepted one key as both")
		}
	})
}
