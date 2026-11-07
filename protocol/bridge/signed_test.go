// VerifySigned's and VerifyRecoverySigned's refusals, and what names a statement. Each refusal asserts why, so a test
// cannot pass on an unrelated failure, such as a type-confusion case that only ever met a bad key. Keys are fixed
// synthetic values, and the signatures are deterministic.

package bridge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	testPurpose      = "bridge"
	testOtherPurpose = "acl"
)

var (
	testBody       = []byte("a synthetic statement body")
	testEd25519Key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	testP256Scalar = bytes.Repeat([]byte{0x22}, 32)
)

// The verifying half of testEd25519Key, as a key record would hold it.
func testEd25519Public() []byte {
	return testEd25519Key.Public().(ed25519.PublicKey)
}

// Signs as a sidecar would, so every refusal below starts from a statement that verifies.
func testSignEd25519(purpose string, signedType SignedType, body []byte) *Signed {
	return &Signed{
		Body:      body,
		SignerId:  []byte("synthetic-signer"),
		KeyId:     []byte("synthetic-key"),
		Signature: ed25519.Sign(testEd25519Key, SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}
}

// The fixed P-256 key, with its public half as VerifySigned takes it: a SEC 1 uncompressed point.
func testP256Key(t testing.TB) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), testP256Scalar)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return key, publicKey
}

// A nil rand makes the signature RFC 6979 deterministic.
func testSignDigest(t testing.TB, key *ecdsa.PrivateKey, digest []byte) []byte {
	signature, err := key.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// Signs as ecdsa-p256-sha256 does: a DER signature over the signed bytes' SHA-256 (§16.6).
func testSignP256(t testing.TB, key *ecdsa.PrivateKey, purpose string, signedType SignedType, body []byte) *Signed {
	digest := sha256.Sum256(SignedBytes(purpose, signedType, body))
	return &Signed{
		Body:      body,
		Signature: testSignDigest(t, key, digest[:]),
		Type:      uint32(signedType),
	}
}

// What a platform authenticator would produce, with each input a test may spoil.
type testWebAuthnAssertion struct {
	rpId            string
	flags           byte
	clientType      string
	challenge       string
	clientDataJson  []byte
	authData        func(authenticatorData []byte) []byte // rewrites the data before it is signed
	signSignedBytes bool
}

// An assertion every check passes, for a test to spoil one input of.
func testGoodWebAuthnAssertion(purpose string, signedType SignedType, body []byte) *testWebAuthnAssertion {
	challenge := sha256.Sum256(SignedBytes(purpose, signedType, body))
	return &testWebAuthnAssertion{
		rpId:       webAuthnRpId,
		flags:      webAuthnFlagUserPresent | webAuthnFlagUserVerified,
		clientType: webAuthnClientDataTypeGet,
		challenge:  base64.RawURLEncoding.EncodeToString(challenge[:]),
	}
}

// The Signed this assertion makes, its signature valid over whatever was spoiled, so a refusal comes from the check
// a test aims at and not from the signature.
func (self *testWebAuthnAssertion) sign(
	t testing.TB,
	key *ecdsa.PrivateKey,
	purpose string,
	signedType SignedType,
	body []byte,
) *Signed {
	rpIdHash := sha256.Sum256([]byte(self.rpId))
	authenticatorData := append(rpIdHash[:], self.flags, 0x00, 0x00, 0x00, 0x07)
	if self.authData != nil {
		authenticatorData = self.authData(authenticatorData)
	}
	clientDataJson := self.clientDataJson
	if clientDataJson == nil {
		clientDataJson = fmt.Appendf(
			nil,
			`{"type":%q,"challenge":%q,"origin":"https://app.example"}`,
			self.clientType,
			self.challenge,
		)
	}
	clientDataHash := sha256.Sum256(clientDataJson)
	digest := sha256.New()
	digest.Write(authenticatorData)
	digest.Write(clientDataHash[:])
	message := digest.Sum(nil)
	if self.signSignedBytes {
		signedDigest := sha256.Sum256(SignedBytes(purpose, signedType, body))
		message = signedDigest[:]
	}
	return &Signed{
		Body:      body,
		Signature: testSignDigest(t, key, message),
		Webauthn: &WebAuthnEvidence{
			AuthenticatorData: authenticatorData,
			ClientDataJson:    clientDataJson,
		},
		Type: uint32(signedType),
	}
}

// Every value but 0, from the enum itself, so a value an owner adds joins each pair test by being declared.
func testRegisteredTypes() []SignedType {
	signedTypes := make([]SignedType, 0, len(SignedType_name))
	for number := range SignedType_name {
		if number != 0 {
			signedTypes = append(signedTypes, SignedType(number))
		}
	}
	slices.Sort(signedTypes)
	return signedTypes
}

// A vector's bytes.
func testFromHex(t testing.TB, value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// Pins §6.9's layout byte by byte: every signer and verifier on every leg must produce exactly this.
func TestSignedBytesLayout(t *testing.T) {
	want := []byte("urnetwork-sidecar-v1/bridge\x00\x00\x00\x19\x07a synthetic statement body")
	got := SignedBytes(testPurpose, SignedType_SIGNED_BRIDGE_WITHDRAW, testBody)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed bytes %x, want %x", got, want)
	}
}

// Fixed vectors, so a change to the layout or a primitive cannot pass by changing signer and verifier
// together.
func TestVerifySignedFixedVectors(t *testing.T) {
	cases := []struct {
		alg       SignedKeyAlg
		publicKey string
		signature string
		evidence  *WebAuthnEvidence
	}{
		{
			alg:       SignedKeyAlgEd25519,
			publicKey: "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
			signature: "7be88830ddc0cb0462f0f79f11c92a5204d570662387dde958194a071905f4f5" +
				"3012e611406a373ca8561dd39419b960f3bbbbfca14153e5a22e9e65685bec0c",
		},
		{
			alg: SignedKeyAlgEcdsaP256,
			publicKey: "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3" +
				"50185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285",
			signature: "3045022066287e1ad9db490faa0f181d3023c99829363da0dade5434d9989b887470bd38" +
				"022100f2e90469fb031b3464e663c8778437b07d04f8dde95b02fc404d577d8447c182",
		},
		{
			alg: SignedKeyAlgWebAuthnEs256,
			publicKey: "04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf3" +
				"50185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285",
			signature: "30450220376cb2453793faf17a218313aaebf8dfba4c6542d25c032fa3aefba94ac23fee" +
				"022100dffbf01157c58666a03259dfe9b473f4dd74f1b5d5a83cf42c750a0754acea7d",
			evidence: &WebAuthnEvidence{
				AuthenticatorData: testFromHex(t, "b70e6f0e528a7b4e942210fb178091e069f512f53fb3ea0c8eb1702ddefcec7d0500000007"),
				ClientDataJson: []byte(`{"type":"webauthn.get",` +
					`"challenge":"Wgf1L4DyViZmREZLUP7fKmjcUFWB9BsnogEEUW0v6fs",` +
					`"origin":"https://app.example"}`),
			},
		},
	}
	for _, c := range cases {
		signed := &Signed{
			Body:      testBody,
			Signature: testFromHex(t, c.signature),
			Webauthn:  c.evidence,
			Type:      uint32(SignedType_SIGNED_BRIDGE_WITHDRAW),
		}
		err := VerifySigned(
			signed,
			testPurpose,
			SignedType_SIGNED_BRIDGE_WITHDRAW,
			c.alg,
			testFromHex(t, c.publicKey),
		)
		if err != nil {
			t.Errorf("alg %d: %v", c.alg, err)
		}
	}
}

// §22.6: every registered type pair is refused as another type.
func TestVerifySignedRefusesEveryOtherType(t *testing.T) {
	publicKey := testEd25519Public()
	signedTypes := testRegisteredTypes()
	for _, signedType := range signedTypes {
		signed := testSignEd25519(testPurpose, signedType, testBody)
		if err := VerifySigned(signed, testPurpose, signedType, SignedKeyAlgEd25519, publicKey); err != nil {
			t.Fatalf("%s as itself: %v", signedType, err)
		}
		for _, otherType := range signedTypes {
			if otherType == signedType {
				continue
			}
			err := VerifySigned(signed, testPurpose, otherType, SignedKeyAlgEd25519, publicKey)
			if !errors.Is(err, ErrSignedTypeMismatch) {
				t.Errorf("%s as %s: %v", signedType, otherType, err)
			}
		}
	}
}

// The other half of the same rule: a relay rewrites Signed.type to what the verifier expects. Nothing
// but the signed bytes can catch this, because Signed.type is outside the signature's field.
func TestVerifySignedRefusesRewrittenType(t *testing.T) {
	publicKey := testEd25519Public()
	signedTypes := testRegisteredTypes()
	for _, signedType := range signedTypes {
		signed := testSignEd25519(testPurpose, signedType, testBody)
		for _, otherType := range signedTypes {
			if otherType == signedType {
				continue
			}
			rewritten := &Signed{Body: signed.Body, Signature: signed.Signature, Type: uint32(otherType)}
			err := VerifySigned(rewritten, testPurpose, otherType, SignedKeyAlgEd25519, publicKey)
			if !errors.Is(err, ErrSignedSignature) {
				t.Errorf("%s rewritten to %s: %v", signedType, otherType, err)
			}
		}
	}
}

// §6.11: a verifier refuses 0 and an unknown value. Each statement really is signed under that value, so
// only the enum can refuse it.
func TestVerifySignedRefusesUnknownTypes(t *testing.T) {
	publicKey := testEd25519Public()
	for _, signedType := range []SignedType{0, 1, 0x1100, 0x12FF, 0x14FF, 0x7FFFFFFF, -1} {
		signed := testSignEd25519(testPurpose, signedType, testBody)
		err := VerifySigned(signed, testPurpose, signedType, SignedKeyAlgEd25519, publicKey)
		if !errors.Is(err, ErrSignedTypeUnknown) {
			t.Errorf("type %d: %v", signedType, err)
		}
	}
}

// A statement carrying 0 is a statement with no type, whatever the caller expects.
func TestVerifySignedRefusesZeroTypeOnTheWire(t *testing.T) {
	signed := testSignEd25519(testPurpose, SignedType_SIGNED_BRIDGE_WITHDRAW, testBody)
	signed.Type = 0
	err := VerifySigned(
		signed,
		testPurpose,
		SignedType_SIGNED_BRIDGE_WITHDRAW,
		SignedKeyAlgEd25519,
		testEd25519Public(),
	)
	if !errors.Is(err, ErrSignedTypeMismatch) {
		t.Fatal(err)
	}
}

// A type above int32's range must not wrap onto a registered value.
func TestVerifySignedRefusesTypeAboveInt32(t *testing.T) {
	signed := testSignEd25519(testPurpose, SignedType_SIGNED_BRIDGE_WITHDRAW, testBody)
	signed.Type = uint32(SignedType_SIGNED_BRIDGE_WITHDRAW) | 0x80000000
	err := VerifySigned(
		signed,
		testPurpose,
		SignedType_SIGNED_BRIDGE_WITHDRAW,
		SignedKeyAlgEd25519,
		testEd25519Public(),
	)
	if !errors.Is(err, ErrSignedTypeMismatch) {
		t.Fatal(err)
	}
}

// Each statement is signed under the purpose it is presented with, so only this rule refuses it.
// presence-act would otherwise put VerifySigned's input in the countersigned bytes' domain, and a 0x00 in a
// purpose would let two purposes and types encode alike.
func TestVerifySignedRefusesUnusablePurposes(t *testing.T) {
	publicKey := testEd25519Public()
	signedType := SignedType_SIGNED_SIDECAR_REVOKE
	for _, purpose := range []string{
		"",
		"presence-act",
		"\x00",
		"authority\x00",
		"authority\x00\x00\x00\x12\x06",
	} {
		signed := testSignEd25519(purpose, signedType, testBody)
		err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, publicKey)
		if !errors.Is(err, ErrSignedPurpose) {
			t.Errorf("purpose %q: %v", purpose, err)
		}
	}
}

// Purpose is in the signed bytes, so a statement signed for one purpose never verifies under another,
// whatever the type.
func TestVerifySignedRefusesSignatureFromAnotherPurpose(t *testing.T) {
	publicKey := testEd25519Public()
	for _, signedType := range testRegisteredTypes() {
		signed := testSignEd25519(testPurpose, signedType, testBody)
		err := VerifySigned(signed, testOtherPurpose, signedType, SignedKeyAlgEd25519, publicKey)
		if !errors.Is(err, ErrSignedSignature) {
			t.Errorf("%s: %v", signedType, err)
		}
	}
}

// A type mismatch answers before the signature runs, as §6.9 orders the two.
func TestVerifySignedChecksTypeBeforeSignature(t *testing.T) {
	signed := &Signed{
		Body:      testBody,
		Signature: []byte("not a signature"),
		Type:      uint32(SignedType_SIGNED_SUSPEND),
	}
	err := VerifySigned(
		signed,
		testOtherPurpose,
		SignedType_SIGNED_UNSUSPEND,
		SignedKeyAlgEd25519,
		testEd25519Public(),
	)
	if !errors.Is(err, ErrSignedTypeMismatch) {
		t.Fatal(err)
	}
}

// A caller that lost its statement gets a refusal and no panic.
func TestVerifySignedRefusesNilSigned(t *testing.T) {
	err := VerifySigned(
		nil,
		testPurpose,
		SignedType_SIGNED_BRIDGE_WITHDRAW,
		SignedKeyAlgEd25519,
		testEd25519Public(),
	)
	if !errors.Is(err, ErrSignedMissing) {
		t.Fatal(err)
	}
}

// Every bit of the body and of the signature is covered, on both plain algorithms.
func TestVerifySignedRefusesEveryBitFlip(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	p256Key, p256Public := testP256Key(t)
	cases := []struct {
		alg       SignedKeyAlg
		publicKey []byte
		signed    *Signed
	}{
		{alg: SignedKeyAlgEd25519, publicKey: testEd25519Public(), signed: testSignEd25519(purpose, signedType, testBody)},
		{alg: SignedKeyAlgEcdsaP256, publicKey: p256Public, signed: testSignP256(t, p256Key, purpose, signedType, testBody)},
	}
	for _, c := range cases {
		if err := VerifySigned(c.signed, purpose, signedType, c.alg, c.publicKey); err != nil {
			t.Fatalf("alg %d: %v", c.alg, err)
		}
		for _, field := range [][]byte{c.signed.Body, c.signed.Signature} {
			for i := range field {
				for bit := range 8 {
					field[i] ^= 1 << bit
					if VerifySigned(c.signed, purpose, signedType, c.alg, c.publicKey) == nil {
						t.Errorf("alg %d: byte %d bit %d flipped and still verified", c.alg, i, bit)
					}
					field[i] ^= 1 << bit
				}
			}
		}
	}
}

// A good signature under a key other than the record's is refused on both plain algorithms.
func TestVerifySignedRefusesAnotherKey(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	otherEd25519 := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	err := VerifySigned(
		testSignEd25519(purpose, signedType, testBody),
		purpose,
		signedType,
		SignedKeyAlgEd25519,
		otherEd25519.Public().(ed25519.PublicKey),
	)
	if !errors.Is(err, ErrSignedSignature) {
		t.Errorf("ed25519: %v", err)
	}

	p256Key, _ := testP256Key(t)
	otherP256, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherP256Public, err := otherP256.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifySigned(
		testSignP256(t, p256Key, purpose, signedType, testBody),
		purpose,
		signedType,
		SignedKeyAlgEcdsaP256,
		otherP256Public,
	)
	if !errors.Is(err, ErrSignedSignature) {
		t.Errorf("p256: %v", err)
	}
}

// ed25519.Verify panics on a key of the wrong length, and a key record is input: a malformed one must be
// a refusal, never a crash of the verifier.
func TestVerifySignedRefusesMalformedEd25519Keys(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	signed := testSignEd25519(purpose, signedType, testBody)
	for _, size := range []int{0, 1, 31, 33, 64} {
		err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, make([]byte, size))
		if !errors.Is(err, ErrSignedKey) {
			t.Errorf("key of %d bytes: %v", size, err)
		}
	}
	if err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, nil); !errors.Is(err, ErrSignedKey) {
		t.Errorf("nil key: %v", err)
	}
}

// Anything but an uncompressed point on the curve is a refusal for both P-256 algorithms, before any signature runs.
func TestVerifySignedRefusesMalformedP256Keys(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	p256Key, p256Public := testP256Key(t)

	compressed := elliptic.MarshalCompressed(elliptic.P256(), p256Key.X, p256Key.Y)
	offCurve := bytes.Clone(p256Public)
	offCurve[len(offCurve)-1] ^= 0x01
	wrongPrefix := bytes.Clone(p256Public)
	wrongPrefix[0] = 0x05
	publicKeys := [][]byte{nil, {}, {0x00}, compressed, offCurve, wrongPrefix, p256Public[1:], testEd25519Public()}

	signed := testSignP256(t, p256Key, purpose, signedType, testBody)
	assertion := testGoodWebAuthnAssertion(purpose, signedType, testBody)
	webAuthnSigned := assertion.sign(t, p256Key, purpose, signedType, testBody)
	for i, publicKey := range publicKeys {
		err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEcdsaP256, publicKey)
		if !errors.Is(err, ErrSignedKey) {
			t.Errorf("ecdsa key %d: %v", i, err)
		}
		err = VerifySigned(webAuthnSigned, purpose, signedType, SignedKeyAlgWebAuthnEs256, publicKey)
		if !errors.Is(err, ErrSignedKey) {
			t.Errorf("webauthn key %d: %v", i, err)
		}
	}
}

// Zero is unset, so a caller that forgot to read the key record fails closed.
func TestVerifySignedRefusesUnknownAlg(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	signed := testSignEd25519(purpose, signedType, testBody)
	for _, alg := range []SignedKeyAlg{0, 4, -1} {
		err := VerifySigned(signed, purpose, signedType, alg, testEd25519Public())
		if !errors.Is(err, ErrSignedKey) {
			t.Errorf("alg %d: %v", alg, err)
		}
	}
}

// §16.6 fixes DER. A raw r || s, or DER with anything after it, is not a signature here.
func TestVerifySignedRefusesNonDerEcdsaSignatures(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	p256Key, p256Public := testP256Key(t)
	good := testSignP256(t, p256Key, purpose, signedType, testBody)

	raw := make([]byte, 64)
	copy(raw, good.Signature[4:36])
	trailing := append(bytes.Clone(good.Signature), 0x00)

	for i, signature := range [][]byte{nil, {}, raw, trailing, {0x30, 0x00}} {
		signed := &Signed{Body: testBody, Signature: signature, Type: uint32(signedType)}
		err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEcdsaP256, p256Public)
		if !errors.Is(err, ErrSignedSignature) {
			t.Errorf("signature %d: %v", i, err)
		}
	}
}

// §6.9's rule: evidence without its key_id only for a webauthn-es256 signer, and with it, a
// countersignature, only beside an identity key's signature.
func TestVerifySignedEvidenceMustFit(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	p256Key, p256Public := testP256Key(t)
	ed25519Signed := func(evidence *WebAuthnEvidence) *Signed {
		signed := testSignEd25519(purpose, signedType, testBody)
		signed.Webauthn = evidence
		return signed
	}
	p256Signed := func(evidence *WebAuthnEvidence) *Signed {
		signed := testSignP256(t, p256Key, purpose, signedType, testBody)
		signed.Webauthn = evidence
		return signed
	}
	webAuthnSigned := func(mutate func(evidence *WebAuthnEvidence)) *Signed {
		assertion := testGoodWebAuthnAssertion(purpose, signedType, testBody)
		signed := assertion.sign(t, p256Key, purpose, signedType, testBody)
		if mutate != nil {
			mutate(signed.Webauthn)
		}
		return signed
	}
	countersignature := &WebAuthnEvidence{KeyId: []byte("synthetic-presence-key")}

	cases := []struct {
		name      string
		signed    *Signed
		alg       SignedKeyAlg
		publicKey []byte
		want      error
	}{
		{
			name:      "ed25519 alone",
			signed:    ed25519Signed(nil),
			alg:       SignedKeyAlgEd25519,
			publicKey: testEd25519Public(),
		},
		{
			name:      "ed25519 with a countersignature",
			signed:    ed25519Signed(countersignature),
			alg:       SignedKeyAlgEd25519,
			publicKey: testEd25519Public(),
		},
		{
			name:      "ed25519 with empty evidence",
			signed:    ed25519Signed(&WebAuthnEvidence{}),
			alg:       SignedKeyAlgEd25519,
			publicKey: testEd25519Public(),
			want:      ErrSignedEvidence,
		},
		{
			name:      "ed25519 with an assertion but no key_id",
			signed:    ed25519Signed(webAuthnSigned(nil).Webauthn),
			alg:       SignedKeyAlgEd25519,
			publicKey: testEd25519Public(),
			want:      ErrSignedEvidence,
		},
		{
			name:      "ecdsa alone",
			signed:    p256Signed(nil),
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: p256Public,
		},
		{
			name:      "ecdsa with a countersignature",
			signed:    p256Signed(countersignature),
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name:      "ecdsa with empty evidence",
			signed:    p256Signed(&WebAuthnEvidence{}),
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name:      "webauthn with its assertion",
			signed:    webAuthnSigned(nil),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
		},
		{
			name: "webauthn with no evidence",
			signed: func() *Signed {
				signed := webAuthnSigned(nil)
				signed.Webauthn = nil
				return signed
			}(),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name: "webauthn with a key_id",
			signed: webAuthnSigned(func(evidence *WebAuthnEvidence) {
				evidence.KeyId = []byte("synthetic-presence-key")
			}),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name: "webauthn with a countersignature's signature",
			signed: webAuthnSigned(func(evidence *WebAuthnEvidence) {
				evidence.Signature = []byte{0x30}
			}),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name: "webauthn with an act size",
			signed: webAuthnSigned(func(evidence *WebAuthnEvidence) {
				evidence.ActSize = 1
			}),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name: "webauthn with an act index",
			signed: webAuthnSigned(func(evidence *WebAuthnEvidence) {
				evidence.ActIndex = 1
			}),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
		{
			name: "webauthn with an act path",
			signed: webAuthnSigned(func(evidence *WebAuthnEvidence) {
				evidence.ActPath = [][]byte{make([]byte, sha256.Size)}
			}),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: p256Public,
			want:      ErrSignedEvidence,
		},
	}
	for _, c := range cases {
		err := VerifySigned(c.signed, purpose, signedType, c.alg, c.publicKey)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// §7.9: a countersignature its presence row does not require is ignored, so a garbage one must not refuse
// the statement. The other side of that is why VerifySigned's comment tells a caller the presence row
// covers to check it apart: a nil here says nothing about the countersignature.
func TestVerifySignedLeavesCountersignatureUnchecked(t *testing.T) {
	purpose := "authority"
	signedType := SignedType_SIGNED_SIDECAR_REVOKE
	signed := testSignEd25519(purpose, signedType, testBody)
	signed.Webauthn = &WebAuthnEvidence{
		KeyId:     []byte("synthetic-presence-key"),
		Signature: []byte("not a signature"),
		ActSize:   7,
		ActIndex:  9,
		ActPath:   [][]byte{[]byte("short")},
	}
	if err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, testEd25519Public()); err != nil {
		t.Fatal(err)
	}
}

// Every clause of §16.6's per-use profile that needs no state, each spoiled before signing, so the
// signature itself stays valid and only the clause can refuse it.
func TestVerifySignedWebAuthnProfile(t *testing.T) {
	purpose := "approval"
	signedType := SignedType_SIGNED_APPROVAL_DECISION
	otherBytes := sha256.Sum256(SignedBytes(purpose, SignedType_SIGNED_APPROVAL_CANCEL, testBody))
	body := sha256.Sum256(testBody)
	good := testGoodWebAuthnAssertion(purpose, signedType, testBody)

	cases := []struct {
		name   string
		mutate func(assertion *testWebAuthnAssertion)
		want   error
	}{
		{
			name: "good",
		},
		{
			name: "other flags set too",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.flags |= 0x08 | 0x40
			},
		},
		{
			name: "another rp id",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.rpId = "rp.example"
			},
			want: ErrSignedEvidence,
		},
		{
			name: "user present unset",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.flags = webAuthnFlagUserVerified
			},
			want: ErrSignedEvidence,
		},
		{
			name: "user verified unset",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.flags = webAuthnFlagUserPresent
			},
			want: ErrSignedEvidence,
		},
		{
			name: "no flags",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.flags = 0
			},
			want: ErrSignedEvidence,
		},
		{
			name: "webauthn.create",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientType = "webauthn.create"
			},
			want: ErrSignedEvidence,
		},
		{
			name: "no client type",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientType = ""
			},
			want: ErrSignedEvidence,
		},
		{
			name: "client type that only begins webauthn.get",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientType = "webauthn.get.other"
			},
			want: ErrSignedEvidence,
		},
		{
			name: "client type that only ends webauthn.get",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientType = "other.webauthn.get"
			},
			want: ErrSignedEvidence,
		},
		{
			name: "challenge of another type's signed bytes",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.challenge = base64.RawURLEncoding.EncodeToString(otherBytes[:])
			},
			want: ErrSignedEvidence,
		},
		{
			name: "challenge of the body alone",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.challenge = base64.RawURLEncoding.EncodeToString(body[:])
			},
			want: ErrSignedEvidence,
		},
		{
			name: "padded challenge",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.challenge = good.challenge + "="
			},
			want: ErrSignedEvidence,
		},
		{
			name: "no challenge",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.challenge = ""
			},
			want: ErrSignedEvidence,
		},
		{
			name: "client data not json",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientDataJson = []byte(`{"type":"webauthn.get"`)
			},
			want: ErrSignedEvidence,
		},
		{
			name: "client data empty",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientDataJson = []byte{}
			},
			want: ErrSignedEvidence,
		},
		{
			name: "client data json of the wrong shape",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.clientDataJson = []byte(`["webauthn.get"]`)
			},
			want: ErrSignedEvidence,
		},
		{
			name: "signature over the signed bytes, not the evidence",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.signSignedBytes = true
			},
			want: ErrSignedSignature,
		},
	}
	p256Key, p256Public := testP256Key(t)
	for _, c := range cases {
		assertion := testGoodWebAuthnAssertion(purpose, signedType, testBody)
		if c.mutate != nil {
			c.mutate(assertion)
		}
		signed := assertion.sign(t, p256Key, purpose, signedType, testBody)
		err := VerifySigned(signed, purpose, signedType, SignedKeyAlgWebAuthnEs256, p256Public)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// WebAuthn §6.1's fixed head is the rp id hash's 32 bytes, a flags byte and a 4-byte counter, and §16.6's caller reads
// signCount at bytes 33 to 37, so 37 is the least that passes. The sizes are written here, not read from the constant
// under test, and every assertion is validly signed, so only the size can refuse it. What follows the counter is
// extension data, which nothing here reads.
func TestVerifySignedWebAuthnAuthenticatorDataFloor(t *testing.T) {
	purpose := "approval"
	signedType := SignedType_SIGNED_APPROVAL_DECISION
	p256Key, p256Public := testP256Key(t)
	signedOfSize := func(size int) *Signed {
		assertion := testGoodWebAuthnAssertion(purpose, signedType, testBody)
		assertion.authData = func(authenticatorData []byte) []byte {
			return append(authenticatorData, make([]byte, 64)...)[:size]
		}
		return assertion.sign(t, p256Key, purpose, signedType, testBody)
	}
	for size := range 37 {
		err := VerifySigned(signedOfSize(size), purpose, signedType, SignedKeyAlgWebAuthnEs256, p256Public)
		if !errors.Is(err, ErrSignedEvidence) {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
	for _, size := range []int{37, 38, 64} {
		err := VerifySigned(signedOfSize(size), purpose, signedType, SignedKeyAlgWebAuthnEs256, p256Public)
		if err != nil {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
}

// The evidence is what the signature covers, so changing it after signing is a signature failure, and
// the challenge in it is what ties it to this statement.
func TestVerifySignedWebAuthnEvidenceIsSigned(t *testing.T) {
	purpose := "approval"
	signedType := SignedType_SIGNED_APPROVAL_DECISION
	p256Key, p256Public := testP256Key(t)
	signed := testGoodWebAuthnAssertion(purpose, signedType, testBody).sign(t, p256Key, purpose, signedType, testBody)

	// The counter sits past every field the profile reads, so only the signature can see it change.
	counter := len(signed.Webauthn.AuthenticatorData) - 1
	signed.Webauthn.AuthenticatorData[counter] ^= 0x01
	err := VerifySigned(signed, purpose, signedType, SignedKeyAlgWebAuthnEs256, p256Public)
	if !errors.Is(err, ErrSignedSignature) {
		t.Errorf("counter: %v", err)
	}
	signed.Webauthn.AuthenticatorData[counter] ^= 0x01

	signed.Webauthn.ClientDataJson = bytes.Replace(signed.Webauthn.ClientDataJson, []byte("app.example"), []byte("rp2.example"), 1)
	err = VerifySigned(signed, purpose, signedType, SignedKeyAlgWebAuthnEs256, p256Public)
	if !errors.Is(err, ErrSignedSignature) {
		t.Errorf("origin: %v", err)
	}
}

// §6.9: WebAuthn's challenge is the SHA-256 of the signed bytes, so it covers the type. A statement
// rewritten to another type carries a challenge for the wrong bytes.
func TestVerifySignedWebAuthnChallengeCoversType(t *testing.T) {
	purpose := "approval"
	signedType := SignedType_SIGNED_APPROVAL_DECISION
	otherType := SignedType_SIGNED_APPROVAL_CANCEL
	p256Key, p256Public := testP256Key(t)
	signed := testGoodWebAuthnAssertion(purpose, signedType, testBody).sign(t, p256Key, purpose, signedType, testBody)
	signed.Type = uint32(otherType)
	err := VerifySigned(signed, purpose, otherType, SignedKeyAlgWebAuthnEs256, p256Public)
	if !errors.Is(err, ErrSignedEvidence) {
		t.Fatal(err)
	}
}

// §22.6: signatures verify over the received bytes, never a re-marshal. The body here is an AuthPin with
// its fields reversed and a non-minimal varint, which proto.Unmarshal takes and proto.Marshal would rewrite.
func TestVerifySignedCoversReceivedBytesNeverAReMarshal(t *testing.T) {
	purpose := "authority"
	signedType := SignedType_SIGNED_RECOVERY_VETO
	var body []byte
	body = protowire.AppendTag(body, 2, protowire.BytesType)
	body = protowire.AppendBytes(body, []byte("synthetic chain"))
	body = protowire.AppendTag(body, 1, protowire.VarintType)
	body = append(body, 0x87, 0x80, 0x00)

	signed := testSignEd25519(purpose, signedType, body)
	if err := VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, testEd25519Public()); err != nil {
		t.Fatal(err)
	}

	pin := &AuthPin{}
	if err := proto.Unmarshal(body, pin); err != nil {
		t.Fatal(err)
	}
	if pin.GetVersion() != 7 {
		t.Fatalf("version %d", pin.GetVersion())
	}
	reMarshalled, err := proto.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reMarshalled, body) {
		t.Fatal("the fixture must not survive a re-marshal, or this proves nothing")
	}
	signed.Body = reMarshalled
	err = VerifySigned(signed, purpose, signedType, SignedKeyAlgEd25519, testEd25519Public())
	if !errors.Is(err, ErrSignedSignature) {
		t.Fatal(err)
	}
}

// A Signed crosses the wire and still verifies, an unknown field in the wrapper included, because the
// signature covers only purpose, type and body and §6.4 skips what it does not know. That same openness is why a
// Signed's own hash names no statement (TestSignedBytesSha256NamesEveryRewrittenSigned).
func TestVerifySignedAfterWireRoundTrip(t *testing.T) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	encoded, err := proto.Marshal(testSignEd25519(purpose, signedType, testBody))
	if err != nil {
		t.Fatal(err)
	}
	encoded = protowire.AppendTag(encoded, 100, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, []byte("a later field"))

	decoded := &Signed{}
	if err := proto.Unmarshal(encoded, decoded); err != nil {
		t.Fatal(err)
	}
	if err := VerifySigned(decoded, purpose, signedType, SignedKeyAlgEd25519, testEd25519Public()); err != nil {
		t.Fatal(err)
	}
}

// Pins the hash against the fixed vector's WebAuthn challenge, which §6.9 defines as this value, so it cannot change
// with SignedBytes unnoticed.
func TestSignedBytesSha256FixedVector(t *testing.T) {
	want := testFromHex(t, "5a07f52f80f256266644464b50fedf2a68dc505581f41b27a20104516d2fe9fb")
	got := SignedBytesSha256(testPurpose, SignedType_SIGNED_BRIDGE_WITHDRAW, testBody)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

// One RepoGrant written every way a relay can write it. Each form encodes apart and verifies, so a replay check
// keyed on the hash of what arrived, §7.9's as written, takes each for a statement it has not seen, and a server
// could carry the grant again after its RepoRevoke. The signed bytes' hash is the same for all of them, so a check
// keyed on it refuses every one after the first.
func TestSignedBytesSha256NamesEveryRewrittenSigned(t *testing.T) {
	purpose := testOtherPurpose
	signedType := SignedType_SIGNED_REPO_GRANT
	p256Key, p256Public := testP256Key(t)
	marshal := func(signed *Signed) []byte {
		encoded, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	plain := marshal(testSignEd25519(purpose, signedType, testBody))
	unknownField := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(plain), 100, protowire.BytesType), []byte("x"))
	repeatedBody := protowire.AppendBytes(protowire.AppendTag(bytes.Clone(plain), 1, protowire.BytesType), testBody)
	countersigned := testSignEd25519(purpose, signedType, testBody)
	countersigned.Webauthn = &WebAuthnEvidence{KeyId: []byte("not a key"), Signature: []byte("not a signature")}
	otherIds := testSignEd25519(purpose, signedType, testBody)
	otherIds.SignerId, otherIds.KeyId = otherIds.KeyId, otherIds.SignerId

	p256Signed := testSignP256(t, p256Key, purpose, signedType, testBody)
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(p256Signed.Signature, &rs); err != nil {
		t.Fatal(err)
	}
	rs.S.Sub(elliptic.P256().Params().N, rs.S)
	otherSignature, err := asn1.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	p256Other := &Signed{Body: testBody, Signature: otherSignature, Type: uint32(signedType)}

	cases := []struct {
		name      string
		encoded   []byte
		alg       SignedKeyAlg
		publicKey []byte
	}{
		{name: "as signed", encoded: plain, alg: SignedKeyAlgEd25519, publicKey: testEd25519Public()},
		{name: "an unknown field", encoded: unknownField, alg: SignedKeyAlgEd25519, publicKey: testEd25519Public()},
		{name: "the body twice", encoded: repeatedBody, alg: SignedKeyAlgEd25519, publicKey: testEd25519Public()},
		{
			name:      "a countersignature no row asks for",
			encoded:   marshal(countersigned),
			alg:       SignedKeyAlgEd25519,
			publicKey: testEd25519Public(),
		},
		{name: "other ids", encoded: marshal(otherIds), alg: SignedKeyAlgEd25519, publicKey: testEd25519Public()},
		{name: "ecdsa's (r, s)", encoded: marshal(p256Signed), alg: SignedKeyAlgEcdsaP256, publicKey: p256Public},
		{name: "ecdsa's (r, n - s)", encoded: marshal(p256Other), alg: SignedKeyAlgEcdsaP256, publicKey: p256Public},
	}

	want := SignedBytesSha256(purpose, signedType, testBody)
	encodingNames := map[[sha256.Size]byte]string{}
	for _, c := range cases {
		decoded := &Signed{}
		if err := proto.Unmarshal(c.encoded, decoded); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if err := VerifySigned(decoded, purpose, signedType, c.alg, c.publicKey); err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		// Two forms alike would prove less than this claims.
		encoding := sha256.Sum256(c.encoded)
		if other, ok := encodingNames[encoding]; ok {
			t.Errorf("%s encodes as %s does", c.name, other)
		}
		encodingNames[encoding] = c.name
		if got := SignedBytesSha256(purpose, SignedType(decoded.GetType()), decoded.GetBody()); got != want {
			t.Errorf("%s: got %x, want %x", c.name, got, want)
		}
	}
}

// What the signature covers is what the hash covers, so two statements never share one.
func TestSignedBytesSha256CoversPurposeTypeAndBody(t *testing.T) {
	signedType := SignedType_SIGNED_REPO_GRANT
	statement := SignedBytesSha256(testOtherPurpose, signedType, testBody)
	for name, other := range map[string][sha256.Size]byte{
		"purpose": SignedBytesSha256(testPurpose, signedType, testBody),
		"type":    SignedBytesSha256(testOtherPurpose, SignedType_SIGNED_REPO_REVOKE, testBody),
		"body":    SignedBytesSha256(testOtherPurpose, signedType, []byte("another synthetic body")),
	} {
		if other == statement {
			t.Errorf("another %s hashes alike", name)
		}
	}
}

// Signs as a recovered device does: the member in signer_id and the key itself in key_id (§7.9's Recovery).
func testSignRecovery(key ed25519.PrivateKey, purpose string, signedType SignedType, body []byte) *Signed {
	return &Signed{
		Body:      body,
		SignerId:  []byte("synthetic-member"),
		KeyId:     key.Public().(ed25519.PublicKey),
		Signature: ed25519.Sign(key, SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}
}

// The fixed vector's Ed25519 key standing as a recovery key, with the hash a RecoveryBind shows for it written out,
// so the match is SHA-256 of the 32 key bytes on every leg.
func TestVerifyRecoverySignedFixedVector(t *testing.T) {
	signed := &Signed{
		Body:     testBody,
		SignerId: []byte("synthetic-member"),
		KeyId:    testFromHex(t, "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"),
		Signature: testFromHex(t, "7be88830ddc0cb0462f0f79f11c92a5204d570662387dde958194a071905f4f5"+
			"3012e611406a373ca8561dd39419b960f3bbbbfca14153e5a22e9e65685bec0c"),
		Type: uint32(SignedType_SIGNED_BRIDGE_WITHDRAW),
	}
	recoveryKeySha256 := testFromHex(t, "10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d")
	err := VerifyRecoverySigned(signed, testPurpose, SignedType_SIGNED_BRIDGE_WITHDRAW, recoveryKeySha256)
	if err != nil {
		t.Fatal(err)
	}
}

// §7.9 has api and readers match the carried key to the row's hash. Each key below signs for itself, so a verifier
// that took the carried key on trust would pass it, and only the match refuses.
func TestVerifyRecoverySignedRefusesKeysItsRowDoesNotBind(t *testing.T) {
	purpose := "authority"
	signedType := SignedType_SIGNED_AUTHORITY_COSIGN
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	keySha256 := sha256.Sum256(key.Public().(ed25519.PublicKey))
	signed := testSignRecovery(key, purpose, signedType, testBody)
	if err := VerifyRecoverySigned(signed, purpose, signedType, keySha256[:]); err != nil {
		t.Fatal(err)
	}

	otherSigned := testSignRecovery(otherKey, purpose, signedType, testBody)
	if err := VerifyRecoverySigned(otherSigned, purpose, signedType, keySha256[:]); !errors.Is(err, ErrSignedKey) {
		t.Errorf("another key: %v", err)
	}
	// A member with no binding has no hash to match, whatever signs.
	for _, noBinding := range [][]byte{nil, {}} {
		if err := VerifyRecoverySigned(signed, purpose, signedType, noBinding); !errors.Is(err, ErrSignedKey) {
			t.Errorf("no binding %v: %v", noBinding, err)
		}
	}
	// The hash in key_id, as a share key's would be, carries no key to verify under.
	hashed := testSignRecovery(key, purpose, signedType, testBody)
	hashed.KeyId = keySha256[:]
	if err := VerifyRecoverySigned(hashed, purpose, signedType, keySha256[:]); !errors.Is(err, ErrSignedKey) {
		t.Errorf("the key's hash: %v", err)
	}
	for _, size := range []int{0, 31, 33, 64} {
		malformed := testSignRecovery(key, purpose, signedType, testBody)
		malformed.KeyId = make([]byte, size)
		malformedSha256 := sha256.Sum256(malformed.KeyId)
		if err := VerifyRecoverySigned(malformed, purpose, signedType, malformedSha256[:]); !errors.Is(err, ErrSignedKey) {
			t.Errorf("key of %d bytes: %v", size, err)
		}
	}
	if err := VerifyRecoverySigned(nil, purpose, signedType, keySha256[:]); !errors.Is(err, ErrSignedMissing) {
		t.Errorf("nil: %v", err)
	}
}

// A bound key is one more Ed25519 signer: VerifySigned's rules hold it as they hold any other.
func TestVerifyRecoverySignedKeepsVerifySignedsRules(t *testing.T) {
	purpose := "authority"
	signedType := SignedType_SIGNED_AUTHORITY_PROPOSAL
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	keySha256 := sha256.Sum256(key.Public().(ed25519.PublicKey))

	cases := []struct {
		name         string
		mutate       func(signed *Signed)
		purpose      string
		expectedType SignedType
		want         error
	}{
		{name: "good", purpose: purpose, expectedType: signedType},
		{
			name:         "as another type",
			purpose:      purpose,
			expectedType: SignedType_SIGNED_ADMIN_SET,
			want:         ErrSignedTypeMismatch,
		},
		{
			name:         "as another purpose",
			purpose:      testOtherPurpose,
			expectedType: signedType,
			want:         ErrSignedSignature,
		},
		{name: "a refused purpose", purpose: presenceActPurpose, expectedType: signedType, want: ErrSignedPurpose},
		{
			name: "another body",
			mutate: func(signed *Signed) {
				signed.Body = []byte("another synthetic body")
			},
			purpose:      purpose,
			expectedType: signedType,
			want:         ErrSignedSignature,
		},
		{
			name: "an assertion beside an ed25519 signature",
			mutate: func(signed *Signed) {
				signed.Webauthn = &WebAuthnEvidence{}
			},
			purpose:      purpose,
			expectedType: signedType,
			want:         ErrSignedEvidence,
		},
	}
	for _, c := range cases {
		signed := testSignRecovery(key, purpose, signedType, testBody)
		if c.mutate != nil {
			c.mutate(signed)
		}
		err := VerifyRecoverySigned(signed, c.purpose, c.expectedType, keySha256[:])
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// One input for FuzzVerifySigned, with what VerifySigned must answer for it.
type testFuzzSeed struct {
	name     string
	encoded  []byte
	expected SignedType
	alg      SignedKeyAlg
	want     error
}

// The statement every fuzz input is judged against.
const testFuzzType = SignedType_SIGNED_BRIDGE_WITHDRAW

// The key FuzzVerifySigned verifies under for each algorithm, so each algorithm's checks are in reach of an input.
func testFuzzPublicKeys(t testing.TB) map[SignedKeyAlg][]byte {
	_, p256Public := testP256Key(t)
	return map[SignedKeyAlg][]byte{
		SignedKeyAlgEd25519:       testEd25519Public(),
		SignedKeyAlgEcdsaP256:     p256Public,
		SignedKeyAlgWebAuthnEs256: p256Public,
	}
}

// A statement that verifies on each algorithm, and one that stops at each kind of check after it, so the corpus starts
// past every branch rather than hoping a mutation finds a valid signature.
func testFuzzSeeds(t testing.TB) []testFuzzSeed {
	purpose := testPurpose
	p256Key, _ := testP256Key(t)
	marshal := func(signed *Signed) []byte {
		encoded, err := proto.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	ed25519Good := marshal(testSignEd25519(purpose, testFuzzType, testBody))
	countersigned := testSignEd25519(purpose, testFuzzType, testBody)
	countersigned.Webauthn = &WebAuthnEvidence{KeyId: []byte("synthetic-presence-key")}

	p256Signed := testSignP256(t, p256Key, purpose, testFuzzType, testBody)
	p256Good := marshal(p256Signed)
	p256Signed.Signature[len(p256Signed.Signature)-1] ^= 0x01
	p256Spoiled := marshal(p256Signed)

	webAuthn := func(mutate func(assertion *testWebAuthnAssertion)) []byte {
		assertion := testGoodWebAuthnAssertion(purpose, testFuzzType, testBody)
		if mutate != nil {
			mutate(assertion)
		}
		return marshal(assertion.sign(t, p256Key, purpose, testFuzzType, testBody))
	}
	webAuthnGood := webAuthn(nil)
	withAssertion := testSignEd25519(purpose, testFuzzType, testBody)
	withAssertion.Webauthn = &WebAuthnEvidence{AuthenticatorData: []byte("not an assertion")}
	webAuthnEvidence := func(mutate func(evidence *WebAuthnEvidence)) []byte {
		signed := testGoodWebAuthnAssertion(purpose, testFuzzType, testBody).sign(t, p256Key, purpose, testFuzzType, testBody)
		mutate(signed.Webauthn)
		return marshal(signed)
	}

	return []testFuzzSeed{
		{name: "ed25519", encoded: ed25519Good, expected: testFuzzType, alg: SignedKeyAlgEd25519},
		{
			name:     "ed25519 with a countersignature",
			encoded:  marshal(countersigned),
			expected: testFuzzType,
			alg:      SignedKeyAlgEd25519,
		},
		{
			name:     "ed25519 with an assertion",
			encoded:  marshal(withAssertion),
			expected: testFuzzType,
			alg:      SignedKeyAlgEd25519,
			want:     ErrSignedEvidence,
		},
		{
			name:     "ed25519 as another type",
			encoded:  ed25519Good,
			expected: SignedType_SIGNED_BRIDGE_MAP,
			alg:      SignedKeyAlgEd25519,
			want:     ErrSignedTypeMismatch,
		},
		{name: "no type", encoded: ed25519Good, alg: SignedKeyAlgEd25519, want: ErrSignedTypeUnknown},
		{name: "no algorithm", encoded: ed25519Good, expected: testFuzzType, want: ErrSignedKey},
		{
			name:     "ed25519 as ecdsa",
			encoded:  ed25519Good,
			expected: testFuzzType,
			alg:      SignedKeyAlgEcdsaP256,
			want:     ErrSignedSignature,
		},
		{
			name:     "ed25519 as webauthn",
			encoded:  ed25519Good,
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{name: "ecdsa", encoded: p256Good, expected: testFuzzType, alg: SignedKeyAlgEcdsaP256},
		{
			name:     "ecdsa, spoiled",
			encoded:  p256Spoiled,
			expected: testFuzzType,
			alg:      SignedKeyAlgEcdsaP256,
			want:     ErrSignedSignature,
		},
		{
			name:     "ecdsa as ed25519",
			encoded:  p256Good,
			expected: testFuzzType,
			alg:      SignedKeyAlgEd25519,
			want:     ErrSignedSignature,
		},
		{name: "webauthn", encoded: webAuthnGood, expected: testFuzzType, alg: SignedKeyAlgWebAuthnEs256},
		{
			name:     "webauthn as ecdsa",
			encoded:  webAuthnGood,
			expected: testFuzzType,
			alg:      SignedKeyAlgEcdsaP256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn with a countersignature's key_id",
			encoded: webAuthnEvidence(func(evidence *WebAuthnEvidence) {
				evidence.KeyId = []byte("synthetic-presence-key")
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn with a countersignature's fields",
			encoded: webAuthnEvidence(func(evidence *WebAuthnEvidence) {
				evidence.ActSize = 1
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, short authenticator data",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.authData = func(authenticatorData []byte) []byte {
					return authenticatorData[:len(authenticatorData)-1]
				}
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, another rp id",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.rpId = "rp.example"
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, user not verified",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.flags = webAuthnFlagUserPresent
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, client data not json",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.clientDataJson = []byte(`{"type":"webauthn.get"`)
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, another client type",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.clientType = "webauthn.create"
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, another challenge",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.challenge = "c3ludGhldGlj"
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedEvidence,
		},
		{
			name: "webauthn, signature over the signed bytes",
			encoded: webAuthn(func(assertion *testWebAuthnAssertion) {
				assertion.signSignedBytes = true
			}),
			expected: testFuzzType,
			alg:      SignedKeyAlgWebAuthnEs256,
			want:     ErrSignedSignature,
		},
	}
}

// Holds the corpus to its purpose: if a change to a seed or to the target left an algorithm's verifier out of reach,
// as a single Ed25519 key once did, its seeds would stop answering as written here.
func TestFuzzSeedsReachEveryCheck(t *testing.T) {
	publicKeys := testFuzzPublicKeys(t)
	for _, seed := range testFuzzSeeds(t) {
		signed := &Signed{}
		if err := proto.Unmarshal(seed.encoded, signed); err != nil {
			t.Fatalf("%s: %v", seed.name, err)
		}
		err := VerifySigned(signed, testPurpose, seed.expected, seed.alg, publicKeys[seed.alg])
		if !errors.Is(err, seed.want) {
			t.Errorf("%s: got %v, want %v", seed.name, err, seed.want)
		}
	}
}

// Decoding and verifying are total on arbitrary input under every algorithm, and only the fixed statement's own bytes
// pass: whatever a mutation does to a Signed, a nil result means the body and type are the ones that were signed.
func FuzzVerifySigned(f *testing.F) {
	seeds := testFuzzSeeds(f)
	for _, seed := range seeds {
		f.Add(seed.encoded, int32(seed.expected), int(seed.alg))
	}
	good := seeds[0].encoded
	f.Add(good[:len(good)/2], int32(testFuzzType), int(SignedKeyAlgEd25519))
	f.Add([]byte{}, int32(testFuzzType), 0)

	publicKeys := testFuzzPublicKeys(f)
	f.Fuzz(func(t *testing.T, encoded []byte, expected int32, alg int) {
		signed := &Signed{}
		if proto.Unmarshal(encoded, signed) != nil {
			return
		}
		expectedType := SignedType(expected)
		keyAlg := SignedKeyAlg(alg)
		// A key record is input too, so this must not panic, whatever it answers: an input may hold its own key.
		_ = VerifySigned(signed, testPurpose, expectedType, keyAlg, signed.GetKeyId())

		err := VerifySigned(signed, testPurpose, expectedType, keyAlg, publicKeys[keyAlg])
		if err != nil {
			return
		}
		if expectedType != testFuzzType || !bytes.Equal(signed.GetBody(), testBody) {
			t.Fatalf("verified type %d with body %x", expected, signed.GetBody())
		}
	})
}

// key_id is input here, the one place a key comes from the message, so a nil result must also mean it is the bound key.
func FuzzVerifyRecoverySigned(f *testing.F) {
	purpose := "authority"
	signedType := SignedType_SIGNED_AUTHORITY_COSIGN
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	publicKeySha256 := sha256.Sum256(publicKey)
	otherKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))

	for _, signed := range []*Signed{
		testSignRecovery(key, purpose, signedType, testBody),
		testSignRecovery(otherKey, purpose, signedType, testBody),
	} {
		encoded, err := proto.Marshal(signed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded, int32(signedType))
		f.Add(encoded, int32(SignedType_SIGNED_SIDECAR_ADMIT))
		f.Add(encoded[:len(encoded)/2], int32(signedType))
	}
	f.Add([]byte{}, int32(signedType))

	f.Fuzz(func(t *testing.T, encoded []byte, expected int32) {
		signed := &Signed{}
		if proto.Unmarshal(encoded, signed) != nil {
			return
		}
		expectedType := SignedType(expected)
		err := VerifyRecoverySigned(signed, purpose, expectedType, publicKeySha256[:])
		if err != nil {
			return
		}
		if !bytes.Equal(signed.GetKeyId(), publicKey) || expectedType != signedType ||
			!bytes.Equal(signed.GetBody(), testBody) {
			t.Fatalf("verified type %d with key %x and body %x", expected, signed.GetKeyId(), signed.GetBody())
		}
	})
}
