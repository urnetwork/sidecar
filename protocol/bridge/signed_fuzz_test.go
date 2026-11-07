// §22.6's typed Signed target, and the countersign check's own. Seeds in testdata/fuzz/ and each target's f.Add run as
// ordinary tests under go test (owner decision 101), so they hold even though nothing fuzzes continuously.

package bridge

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Every value SignedType's descriptor holds, 0 included, so a value an owner adds joins by being declared.
func testDescriptorTypes() []SignedType {
	values := SignedType(0).Descriptor().Values()
	signedTypes := make([]SignedType, values.Len())
	for i := range signedTypes {
		signedTypes[i] = SignedType(values.Get(i).Number())
	}
	return signedTypes
}

// A GrantRevoke whose encoding is an OwnerConfirm's too. protocol's OwnerConfirm is out of this package's reach (§4.4),
// so this writes its two fields by hand and holds the bodies equal; protocol/statement_test.go has the real message.
func testGrantRevokeBody(t testing.TB) []byte {
	header := &StatementHeader{
		NetworkId:  bytes.Repeat([]byte{0x01}, 16),
		At:         &AuthPin{Version: 7, Chain: bytes.Repeat([]byte{0x02}, 32)},
		Nonce:      bytes.Repeat([]byte{0x03}, 16),
		NotAfterMs: 1,
	}
	id := bytes.Repeat([]byte{0x04}, 16)
	body, err := proto.Marshal(&GrantRevoke{Header: header, GrantId: id})
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader, err := proto.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var ownerConfirm []byte
	ownerConfirm = protowire.AppendTag(ownerConfirm, 1, protowire.BytesType)
	ownerConfirm = protowire.AppendBytes(ownerConfirm, encodedHeader)
	ownerConfirm = protowire.AppendTag(ownerConfirm, 2, protowire.BytesType)
	ownerConfirm = protowire.AppendBytes(ownerConfirm, id)
	if !bytes.Equal(body, ownerConfirm) {
		t.Fatal("the two statements must encode alike, or this seed proves nothing")
	}
	return body
}

// §22.6: whatever the body, a statement signed under one type passes as that type alone. It is refused as every other
// value the descriptor holds, by the type check, and when a relay also rewrites Signed.type to the one expected, which
// leaves the type check nothing to see, by the signature, or for a countersignature by the leaf that covers the type.
// The body a seed holds may parse as a statement of both types, which is the case the rule exists for.
func FuzzSignedTypeConfusion(f *testing.F) {
	signedTypes := testDescriptorTypes()
	for i, signedType := range signedTypes {
		f.Add(testBody, int32(signedType), int32(signedTypes[(i+1)%len(signedTypes)]))
	}
	grantRevokeBody := testGrantRevokeBody(f)
	grantRevoke := int32(SignedType_SIGNED_GRANT_REVOKE)
	ownerConfirm := int32(SignedType_SIGNED_OWNER_CONFIRM)
	f.Add(grantRevokeBody, grantRevoke, ownerConfirm)
	f.Add(grantRevokeBody, ownerConfirm, grantRevoke)

	purpose := "acl"
	publicKey := testEd25519Public()
	profiles := testPresenceProfiles(f)
	registered := func(signedType SignedType) bool {
		return signedType != SignedType_SIGNED_TYPE_NONE && slices.Contains(signedTypes, signedType)
	}

	f.Fuzz(func(t *testing.T, body []byte, signedAs int32, presentedAs int32) {
		signedType := SignedType(signedAs)
		presentedType := SignedType(presentedAs)

		signed := testSignEd25519(purpose, signedType, body)
		err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, publicKey)
		if registered(signedType) && err != nil {
			t.Fatalf("%d as itself: %v", signedAs, err)
		}
		if !registered(signedType) && !errors.Is(err, ErrSignedTypeUnknown) {
			t.Fatalf("%d as itself: %v", signedAs, err)
		}

		refuseAs := func(expected SignedType) {
			if expected == signedType {
				return
			}
			want := ErrSignedTypeMismatch
			if !registered(expected) {
				want = ErrSignedTypeUnknown
			}
			err := VerifySigned(signed, purpose, expected, SignedKeyAlgEd25519, publicKey)
			if !errors.Is(err, want) {
				t.Fatalf("%d as %d: %v", signedAs, int32(expected), err)
			}
		}
		for _, expected := range signedTypes {
			refuseAs(expected)
		}
		refuseAs(presentedType)

		if presentedType != signedType {
			rewritten := proto.CloneOf(signed)
			rewritten.Type = uint32(presentedType)
			want := ErrSignedSignature
			if !registered(presentedType) {
				want = ErrSignedTypeUnknown
			}
			err := VerifySigned(rewritten, purpose, presentedType, SignedKeyAlgEd25519, publicKey)
			if !errors.Is(err, want) {
				t.Fatalf("%d rewritten to %d: %v", signedAs, presentedAs, err)
			}
		}

		statements := []*testActStatement{{purpose: purpose, signedType: signedType, body: body}}
		for _, profile := range profiles {
			countersigned := testCountersignedAct(t, statements, profile.check)[0]
			err := VerifyPresenceCountersign(countersigned, purpose, profile.alg, profile.publicKey)
			if registered(signedType) && err != nil {
				t.Fatalf("%s %d countersigned: %v", profile.name, signedAs, err)
			}
			if !registered(signedType) && !errors.Is(err, ErrSignedTypeUnknown) {
				t.Fatalf("%s %d countersigned: %v", profile.name, signedAs, err)
			}

			if presentedType == signedType {
				continue
			}
			rewritten := proto.CloneOf(countersigned)
			rewritten.Type = uint32(presentedType)
			err = VerifyPresenceCountersign(rewritten, purpose, profile.alg, profile.publicKey)
			if registered(presentedType) && !profile.refusesOtherBytes(err) {
				t.Fatalf("%s %d rewritten to %d: %v", profile.name, signedAs, presentedAs, err)
			}
			if !registered(presentedType) && !errors.Is(err, ErrSignedTypeUnknown) {
				t.Fatalf("%s %d rewritten to %d: %v", profile.name, signedAs, presentedAs, err)
			}
		}
	})
}

// Decoding and the countersign check are total on arbitrary input under every algorithm, and a nil means a statement
// of the fixed act at its own index, by its own signer, whatever a mutation did to the rest of the Signed. The seeds
// start past every branch: each act's statements, and a countersign refusal stopping at each kind of check.
func FuzzVerifyPresenceCountersign(f *testing.F) {
	statements := testActStatements(5)
	profiles := testPresenceProfiles(f)
	for _, profile := range profiles {
		for i, signed := range testCountersignedAct(f, statements, profile.check) {
			encoded, err := proto.Marshal(signed)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(encoded, statements[i].purpose, int(profile.alg))
			f.Add(encoded[:len(encoded)/2], statements[i].purpose, int(profile.alg))
		}
		for _, vector := range testBuildRefusalVectors(f, profile) {
			f.Add(testFromHex(f, vector.Signed), vector.Purpose, int(profile.alg))
		}
	}
	f.Add([]byte{}, "authority", 0)

	publicKey := profiles[0].publicKey
	f.Fuzz(func(t *testing.T, encoded []byte, purpose string, alg int) {
		signed := &Signed{}
		if proto.Unmarshal(encoded, signed) != nil {
			return
		}
		keyAlg := SignedKeyAlg(alg)
		// A key record is input too, so this must not panic, whatever it answers: an input may hold its own key.
		_ = VerifyPresenceCountersign(signed, purpose, keyAlg, signed.GetWebauthn().GetKeyId())

		if err := VerifyPresenceCountersign(signed, purpose, keyAlg, publicKey); err != nil {
			return
		}
		evidence := signed.GetWebauthn()
		if evidence.GetActSize() != uint32(len(statements)) || int(evidence.GetActIndex()) >= len(statements) {
			t.Fatalf("verified index %d of %d", evidence.GetActIndex(), evidence.GetActSize())
		}
		statement := statements[evidence.GetActIndex()]
		if purpose != statement.purpose || signed.GetType() != uint32(statement.signedType) ||
			!bytes.Equal(signed.GetBody(), statement.body) || !bytes.Equal(signed.GetSignerId(), testSignerId) {
			t.Fatalf("verified purpose %q, type %d, body %x, signer %x", purpose, signed.GetType(), signed.GetBody(), signed.GetSignerId())
		}
	})
}
