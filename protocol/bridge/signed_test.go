// VerifySigned's refusals. Each asserts why a statement is refused, so a test cannot pass on an unrelated
// failure, such as a type-confusion case that only ever met a bad key. Keys are fixed synthetic values,
// and the signatures are deterministic.

package bridge

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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
	shortAuthData   bool
	signSignedBytes bool
}

func testGoodWebAuthnAssertion(purpose string, signedType SignedType, body []byte) *testWebAuthnAssertion {
	challenge := sha256.Sum256(SignedBytes(purpose, signedType, body))
	return &testWebAuthnAssertion{
		rpId:       webAuthnRpId,
		flags:      webAuthnFlagUserPresent | webAuthnFlagUserVerified,
		clientType: webAuthnClientDataTypeGet,
		challenge:  base64.RawURLEncoding.EncodeToString(challenge[:]),
	}
}

func (self *testWebAuthnAssertion) sign(
	t testing.TB,
	key *ecdsa.PrivateKey,
	purpose string,
	signedType SignedType,
	body []byte,
) *Signed {
	rpIdHash := sha256.Sum256([]byte(self.rpId))
	authenticatorData := append(rpIdHash[:], self.flags, 0x00, 0x00, 0x00, 0x07)
	if self.shortAuthData {
		authenticatorData = authenticatorData[:webAuthnAuthenticatorDataMinSize-1]
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
			name: "authenticator data too short",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.shortAuthData = true
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
// signature covers only purpose, type and body.
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

// Decoding and verifying are total on arbitrary input, and only the fixed statement's own bytes pass:
// whatever a mutation does to a Signed, a nil result means the body and type are the ones that were signed.
func FuzzVerifySigned(f *testing.F) {
	purpose := testPurpose
	signedType := SignedType_SIGNED_BRIDGE_WITHDRAW
	good, err := proto.Marshal(testSignEd25519(purpose, signedType, testBody))
	if err != nil {
		f.Fatal(err)
	}
	countersigned := testSignEd25519(purpose, signedType, testBody)
	countersigned.Webauthn = &WebAuthnEvidence{KeyId: []byte("synthetic-presence-key")}
	withEvidence, err := proto.Marshal(countersigned)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good, int32(signedType), int(SignedKeyAlgEd25519))
	f.Add(withEvidence, int32(signedType), int(SignedKeyAlgEd25519))
	f.Add(good, int32(SignedType_SIGNED_BRIDGE_MAP), int(SignedKeyAlgEd25519))
	f.Add(good, int32(0), int(SignedKeyAlgEd25519))
	f.Add(good[:len(good)/2], int32(signedType), int(SignedKeyAlgEd25519))
	f.Add(good, int32(signedType), int(SignedKeyAlgEcdsaP256))
	f.Add(good, int32(signedType), int(SignedKeyAlgWebAuthnEs256))
	f.Add([]byte{}, int32(signedType), 0)

	publicKey := testEd25519Public()
	f.Fuzz(func(t *testing.T, encoded []byte, expected int32, alg int) {
		signed := &Signed{}
		if proto.Unmarshal(encoded, signed) != nil {
			return
		}
		expectedType := SignedType(expected)
		err := VerifySigned(signed, purpose, expectedType, SignedKeyAlg(alg), publicKey)
		if err != nil {
			return
		}
		if expectedType != signedType || !bytes.Equal(signed.GetBody(), testBody) {
			t.Fatalf("verified type %d with body %x", expected, signed.GetBody())
		}
	})
}
