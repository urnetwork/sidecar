// UrMlsCredential's one encoding and its signature over the received bytes (QD-440): a credential with a wrong
// suite, algorithm, signature or field order is refused, and so is every other way off the one form.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A credential's arguments for signer's sidecar.
func mlsTestCredentialArgs(signer *gkmTestSigner) *UrMlsCredentialArgs {
	signatureKey := ed25519.NewKeyFromSeed(gkmTestBytes("mls signature key", ed25519.SeedSize))
	return &UrMlsCredentialArgs{
		SidecarId:             signer.sidecarId,
		IdentityPublicKey:     signer.publicKey(),
		MlsSignaturePublicKey: signatureKey.Public().(ed25519.PublicKey),
		NotAfter:              gkmTestTime.Add(90 * 24 * time.Hour),
		AdmissionSha256:       gkmTestBytes("admission", gkmDigestByteCount),
	}
}

// One field, as the credential's encoder writes it.
type mlsTestCredentialField struct {
	number   protowire.Number
	wireType protowire.Type
	value    []byte
	varint   uint64
}

// A credential's fields as written, so a test can reorder, drop or add one and sign the result.
func mlsTestCredentialFields(args *UrMlsCredentialArgs) []mlsTestCredentialField {
	return []mlsTestCredentialField{
		{number: 1, wireType: protowire.BytesType, value: args.SidecarId.Bytes()},
		{number: 2, wireType: protowire.BytesType, value: args.IdentityPublicKey},
		{number: 3, wireType: protowire.BytesType, value: []byte("ed25519")},
		{number: 4, wireType: protowire.BytesType, value: args.MlsSignaturePublicKey},
		{number: 5, wireType: protowire.VarintType, varint: 0x0010},
		{number: 6, wireType: protowire.VarintType, varint: uint64(args.NotAfter.UnixMilli())},
		{number: 7, wireType: protowire.BytesType, value: args.AdmissionSha256},
	}
}

// fields encoded in order, then a valid signature over exactly those bytes, so only the form is wrong.
func mlsTestSignedCredential(t *testing.T, signer *gkmTestSigner, fields []mlsTestCredentialField) []byte {
	t.Helper()
	var body []byte
	for _, field := range fields {
		body = protowire.AppendTag(body, field.number, field.wireType)
		if field.wireType == protowire.VarintType {
			body = protowire.AppendVarint(body, field.varint)
		} else {
			body = protowire.AppendBytes(body, field.value)
		}
	}
	signed, err := signer.sign("mls-credential", bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded := protowire.AppendTag(body, 8, protowire.BytesType)
	return protowire.AppendBytes(encoded, signed.GetSignature())
}

func TestUrMlsCredentialRoundTrip(t *testing.T) {
	signer := newGkmTestSigner("device")
	args := mlsTestCredentialArgs(signer)
	encoded, err := SignUrMlsCredential(args, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := CheckUrMlsCredential(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(credential.GetSidecarId(), args.SidecarId.Bytes()) ||
		!bytes.Equal(credential.GetIdentityPublicKey(), args.IdentityPublicKey) ||
		credential.GetIdentityAlg() != "ed25519" ||
		!bytes.Equal(credential.GetMlsSignaturePublicKey(), args.MlsSignaturePublicKey) ||
		credential.GetCipherSuite() != 0x0010 ||
		credential.GetNotAfter() != args.NotAfter.UnixMilli() ||
		!bytes.Equal(credential.GetAdmissionSha256(), args.AdmissionSha256) ||
		len(credential.GetIdentitySignature()) != ed25519.SignatureSize {
		t.Errorf("fields %v", credential)
	}

	// The one form is protobuf's own: what protobuf reads of it, it writes back byte for byte.
	parsed := &protocol.UrMlsCredential{}
	if err := proto.Unmarshal(encoded, parsed); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(parsed, credential) {
		t.Error("protobuf reads other fields")
	}
	remarshaled, err := proto.MarshalOptions{Deterministic: true}.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remarshaled, encoded) {
		t.Error("protobuf writes the one form otherwise")
	}
	// The hand encoder writes it too, so every refusal below differs from it in one rule.
	if again := mlsTestSignedCredential(t, signer, mlsTestCredentialFields(args)); !bytes.Equal(again, encoded) {
		t.Error("the test's encoding is not the signer's")
	}
}

// The signature covers the received bytes before field 8: any byte of them changed refuses.
func TestUrMlsCredentialVerifiesTheReceivedBytes(t *testing.T) {
	signer := newGkmTestSigner("device")
	encoded, err := SignUrMlsCredential(mlsTestCredentialArgs(signer), signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	signedByteCount := len(encoded) - 2 - ed25519.SignatureSize
	for index := 0; index < len(encoded); index += 1 {
		changed := bytes.Clone(encoded)
		changed[index] ^= 0x01
		if _, err := CheckUrMlsCredential(changed); err == nil {
			t.Errorf("byte %d changed passed", index)
		} else if signedByteCount+2 <= index && !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("signature byte %d changed: %v", index, err)
		}
	}
}

func TestUrMlsCredentialRefusesEveryOtherForm(t *testing.T) {
	signer := newGkmTestSigner("device")
	args := mlsTestCredentialArgs(signer)
	fields := func(change func(fields []mlsTestCredentialField) []mlsTestCredentialField) []byte {
		return mlsTestSignedCredential(t, signer, change(mlsTestCredentialFields(args)))
	}
	encoded, err := SignUrMlsCredential(args, signer.sign)
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(bytes.Clone(encoded), 0x48, 0x01)
	// field 8 with a two-byte length header for 64 bytes, which one byte holds
	overlong := bytes.Clone(encoded[:len(encoded)-1-ed25519.SignatureSize])
	overlong = append(overlong, 0xc0, 0x00)
	overlong = append(overlong, encoded[len(encoded)-ed25519.SignatureSize:]...)
	otherSigner := newGkmTestSigner("another device")

	refusals := map[string][]byte{
		"cipher suite 0x0001": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[4].varint = 0x0001
			return fields
		}),
		"alg ed448": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[2].value = []byte("ed448")
			return fields
		}),
		"fields 2 and 3 swapped": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[1], fields[2] = fields[2], fields[1]
			return fields
		}),
		"field 7 first": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			return append([]mlsTestCredentialField{fields[6]}, fields[:6]...)
		}),
		"field 6 left out": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			return append(fields[:5:5], fields[6])
		}),
		"field 1 twice": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			return append([]mlsTestCredentialField{fields[0]}, fields...)
		}),
		"an unknown field 9 before field 8": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			return append(fields, mlsTestCredentialField{number: 9, wireType: protowire.BytesType, value: []byte{1}})
		}),
		"cipher suite as bytes": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[4] = mlsTestCredentialField{number: 5, wireType: protowire.BytesType, value: []byte{0x10}}
			return fields
		}),
		"a short sidecar_id": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[0].value = fields[0].value[:15]
			return fields
		}),
		"a short identity key": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[1].value = fields[1].value[:31]
			return fields
		}),
		"a short signature key": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[3].value = fields[3].value[:31]
			return fields
		}),
		"a short admission hash": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[6].value = fields[6].value[:31]
			return fields
		}),
		"not_after 0": fields(func(fields []mlsTestCredentialField) []mlsTestCredentialField {
			fields[5].varint = 0
			return fields
		}),
		"bytes after field 8":    trailing,
		"an overlong length":     overlong,
		"empty":                  {},
		"another identity's key": mlsTestSignedCredential(t, otherSigner, mlsTestCredentialFields(args)),
	}
	for name, credential := range refusals {
		_, err := CheckUrMlsCredential(credential)
		if !errors.Is(err, ErrGkmMalformed) && !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := CheckUrMlsCredential(refusals["another identity's key"]); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("signed by another identity key: %v", err)
	}

	// A signature under the right key and the wrong type, or purpose, never verifies as a credential.
	body := encoded[:len(encoded)-2-ed25519.SignatureSize]
	for name, signature := range map[string][]byte{
		"another type":    ed25519.Sign(signer.privateKey, bridge.SignedBytes("mls-credential", bridge.SignedType_SIGNED_READER_KEY, body)),
		"another purpose": ed25519.Sign(signer.privateKey, bridge.SignedBytes("reader-key", bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL, body)),
	} {
		credential := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(body), 8, protowire.BytesType), signature)
		if _, err := CheckUrMlsCredential(credential); !errors.Is(err, ErrGkmAuthentication) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUrMlsCredentialSignRefusesAnotherKey(t *testing.T) {
	signer := newGkmTestSigner("device")
	other := newGkmTestSigner("another device")
	if _, err := SignUrMlsCredential(mlsTestCredentialArgs(signer), other.sign); !errors.Is(err, ErrGkmAuthentication) {
		t.Errorf("signed by another key: %v", err)
	}
	args := mlsTestCredentialArgs(signer)
	args.NotAfter = time.Time{}
	if _, err := SignUrMlsCredential(args, signer.sign); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("no not_after: %v", err)
	}
	if _, err := SignUrMlsCredential(nil, signer.sign); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("no arguments: %v", err)
	}
	lying := func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		signed, err := signer.sign(purpose, signedType, append(bytes.Clone(body), 0), agentId)
		return signed, err
	}
	if _, err := SignUrMlsCredential(mlsTestCredentialArgs(signer), lying); !errors.Is(err, ErrGkmMalformed) {
		t.Errorf("a signer that signed other bytes: %v", err)
	}
}
