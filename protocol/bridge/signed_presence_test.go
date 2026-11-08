// VerifyPresenceCountersign's refusals, an act's tree against RFC 9162, and where the countersigned bytes' domain ends.
// As in signed_test.go, each refusal asserts why and spoils one input of a countersignature that verifies, so a test
// cannot pass on an unrelated failure. Both §16.6 profiles run every rule they share, and keys are fixed synthetic
// values.

package bridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Names the fixture presence key, as its KeyRegister would.
var testPresenceKeyId = []byte("synthetic-presence-key")

// The signer testSignEd25519 writes, which an act's countersigned bytes name.
var testSignerId = []byte("synthetic-signer")

// The most an act holds, written here and not read from the constant under test.
const testActMaxSize = 65535

// One statement of an act, before it is signed.
type testActStatement struct {
	purpose    string
	signedType SignedType
	body       []byte
}

// An act of size statements of several purposes and types, so a leaf that dropped either would show.
func testActStatements(size int) []*testActStatement {
	kinds := []testActStatement{
		{purpose: "authority", signedType: SignedType_SIGNED_SIDECAR_REVOKE},
		{purpose: "acl", signedType: SignedType_SIGNED_SUSPEND},
		{purpose: "authority", signedType: SignedType_SIGNED_KEY_REVOKE},
		{purpose: "authority", signedType: SignedType_SIGNED_RECOVERY_VETO},
		{purpose: "acl", signedType: SignedType_SIGNED_OWNER_CONFIRM},
	}
	statements := make([]*testActStatement, size)
	for i := range statements {
		kind := kinds[i%len(kinds)]
		statements[i] = &testActStatement{
			purpose:    kind.purpose,
			signedType: kind.signedType,
			body:       fmt.Appendf(nil, "synthetic statement %d", i),
		}
	}
	return statements
}

// Each statement's d_i, in act order.
func testActDigests(statements []*testActStatement) [][sha256.Size]byte {
	statementDigests := make([][sha256.Size]byte, len(statements))
	for i, statement := range statements {
		statementDigests[i] = SignedBytesSha256(statement.purpose, statement.signedType, statement.body)
	}
	return statementDigests
}

// Fixed digests for an act too large to write out, by the statement rule the vectors state.
func testRuleDigests(size int) [][sha256.Size]byte {
	statementDigests := make([][sha256.Size]byte, size)
	for i := range statementDigests {
		body := binary.BigEndian.AppendUint32(nil, uint32(i))
		statementDigests[i] = SignedBytesSha256("authority", SignedType_SIGNED_SIDECAR_REVOKE, body)
	}
	return statementDigests
}

// A presence key's one check, over an act's countersigned bytes: what the key returns, before the act's fields join it.
type testPresenceCheck func(countersignedBytes []byte) *WebAuthnEvidence

// ecdsa-p256-sha256's check by key.
func testEcdsaPresenceCheck(t testing.TB, key *ecdsa.PrivateKey) testPresenceCheck {
	return func(countersignedBytes []byte) *WebAuthnEvidence {
		digest := sha256.Sum256(countersignedBytes)
		return &WebAuthnEvidence{KeyId: testPresenceKeyId, Signature: testSignDigest(t, key, digest[:])}
	}
}

// An assertion every countersign check passes against the fixture origins, for a test to spoil one input of.
func testGoodCountersignAssertion(t testing.TB, countersignedBytes []byte) *testWebAuthnAssertion {
	challenge := sha256.Sum256(countersignedBytes)
	return &testWebAuthnAssertion{
		rpId:       webAuthnRpId,
		flags:      webAuthnFlagUserPresent | webAuthnFlagUserVerified,
		clientType: webAuthnClientDataTypeGet,
		challenge:  base64.RawURLEncoding.EncodeToString(challenge[:]),
		origin:     testFixtureOrigins(t)[0],
	}
}

// webauthn-es256's check, with mutate spoiling one input of the assertion before it is signed.
func testWebAuthnPresenceCheck(
	t testing.TB,
	key *ecdsa.PrivateKey,
	mutate func(assertion *testWebAuthnAssertion),
) testPresenceCheck {
	return func(countersignedBytes []byte) *WebAuthnEvidence {
		assertion := testGoodCountersignAssertion(t, countersignedBytes)
		if mutate != nil {
			mutate(assertion)
		}
		evidence, signature := assertion.assert(t, key, countersignedBytes)
		evidence.KeyId = testPresenceKeyId
		evidence.Signature = signature
		return evidence
	}
}

// One §16.6 profile, for the rules both share.
type testPresenceProfile struct {
	name      string
	alg       SignedKeyAlg
	publicKey []byte
	check     testPresenceCheck
}

// Whether err is how this profile refuses a countersignature over other bytes than the ones it signed: a signature
// that fails, or, since it comes first, a challenge that differs.
func (self *testPresenceProfile) refusesOtherBytes(err error) bool {
	if self.alg == SignedKeyAlgEcdsaP256 {
		return errors.Is(err, ErrSignedSignature)
	}
	return errors.Is(err, ErrSignedEvidence) && strings.Contains(err.Error(), "challenge")
}

// Both profiles over the fixed P-256 key.
func testPresenceProfiles(t testing.TB) []*testPresenceProfile {
	key, publicKey := testP256Key(t)
	return []*testPresenceProfile{
		{
			name:      "ecdsa-p256-sha256",
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: publicKey,
			check:     testEcdsaPresenceCheck(t, key),
		},
		{
			name:      "webauthn-es256",
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: publicKey,
			check:     testWebAuthnPresenceCheck(t, key, nil),
		},
	}
}

// A second P-256 key, as a key the signer never registered would be.
func testOtherP256Key(t testing.TB) (*ecdsa.PrivateKey, []byte) {
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return key, publicKey
}

// An act as a device builds one (§7.9's act): every statement signed, one check over the act's root, and that one
// countersignature on each statement with its own index and path.
func testCountersignedAct(t testing.TB, statements []*testActStatement, check testPresenceCheck) []*Signed {
	statementDigests := testActDigests(statements)
	root, err := PresenceActRoot(statementDigests)
	if err != nil {
		t.Fatal(err)
	}
	evidence := check(PresenceActBytes(testSignerId, uint32(len(statements)), root))
	act := make([]*Signed, len(statements))
	for i, statement := range statements {
		actPath, err := PresenceActPath(statementDigests, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		signed := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		signed.Webauthn = proto.CloneOf(evidence)
		signed.Webauthn.ActSize = uint32(len(statements))
		signed.Webauthn.ActIndex = uint32(i)
		signed.Webauthn.ActPath = actPath
		act[i] = signed
	}
	return act
}

// Pins §7.9's layout byte by byte: every signer and verifier on every leg must produce exactly this.
func TestPresenceActBytesLayout(t *testing.T) {
	root := [sha256.Size]byte{}
	for i := range root {
		root[i] = byte(i)
	}
	want := slices.Concat(
		[]byte("urnetwork-sidecar-v1/presence-act\x00synthetic-signer\x00\x00\x00\x05"),
		root[:],
	)
	got := PresenceActBytes(testSignerId, 5, root)
	if !bytes.Equal(got, want) {
		t.Fatalf("countersigned bytes %x, want %x", got, want)
	}
}

// §7.9: one check covers the act, and each statement verifies alone by its own path, whichever of the act's
// statements land and in whatever order, with its identity signature beside it. Each crosses the wire first, as it
// does in fact, with an unknown field a later release might add.
func TestVerifyPresenceCountersignFiveStatementAct(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	for _, profile := range testPresenceProfiles(t) {
		act := testCountersignedAct(t, statements, profile.check)
		for _, i := range []int{3, 0, 4, 2, 1} {
			encoded, err := proto.Marshal(act[i])
			if err != nil {
				t.Fatal(err)
			}
			encoded = protowire.AppendTag(encoded, 100, protowire.BytesType)
			encoded = protowire.AppendBytes(encoded, []byte("a later field"))
			signed := &Signed{}
			if err := proto.Unmarshal(encoded, signed); err != nil {
				t.Fatal(err)
			}
			statement := statements[i]
			err = VerifySigned(signed, statement.purpose, statement.signedType, SignedKeyAlgEd25519, testEd25519Public())
			if err != nil {
				t.Errorf("%s statement %d: identity signature: %v", profile.name, i, err)
			}
			err = verifyPresenceCountersign(signed, statement.purpose, profile.alg, profile.publicKey, origins)
			if err != nil {
				t.Errorf("%s statement %d: %v", profile.name, i, err)
			}
		}
	}
}

// An act of one has no path, and its root is its leaf hash.
func TestVerifyPresenceCountersignActOfOne(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(1)
	for _, profile := range testPresenceProfiles(t) {
		signed := testCountersignedAct(t, statements, profile.check)[0]
		if len(signed.GetWebauthn().GetActPath()) != 0 {
			t.Fatalf("%s: a path of %d hashes", profile.name, len(signed.GetWebauthn().GetActPath()))
		}
		err := verifyPresenceCountersign(signed, statements[0].purpose, profile.alg, profile.publicKey, origins)
		if err != nil {
			t.Errorf("%s: %v", profile.name, err)
		}
	}
}

// §16.6: a countersign check does not compare signCount, because a verifier of one statement holds no counter, so a
// counter that ran backward or sits at 0 is no fault. Nothing here reads the counter, so any value passes.
func TestVerifyPresenceCountersignIgnoresSignCount(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(3)
	key, publicKey := testP256Key(t)
	for _, signCount := range []uint32{0, 1, 7, 0x7FFFFFFF, 0xFFFFFFFF} {
		check := testWebAuthnPresenceCheck(t, key, func(assertion *testWebAuthnAssertion) {
			assertion.authData = func(authenticatorData []byte) []byte {
				binary.BigEndian.PutUint32(authenticatorData[33:], signCount)
				return authenticatorData
			}
		})
		for i, signed := range testCountersignedAct(t, statements, check) {
			err := verifyPresenceCountersign(signed, statements[i].purpose, SignedKeyAlgWebAuthnEs256, publicKey, origins)
			if err != nil {
				t.Errorf("signCount %d statement %d: %v", signCount, i, err)
			}
		}
	}
}

// A caller that holds no statement, and a statement with no countersignature or an empty one, get a refusal and no
// panic. A statement with webauthn evidence but no key_id is no countersignature at all, whatever else it holds.
func TestVerifyPresenceCountersignRefusesNoCountersignature(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	statement := statements[2]
	_, publicKey := testP256Key(t)
	for _, profile := range testPresenceProfiles(t) {
		err := verifyPresenceCountersign(nil, statement.purpose, profile.alg, publicKey, origins)
		if !errors.Is(err, ErrSignedMissing) {
			t.Errorf("%s nil: %v", profile.name, err)
		}

		bare := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		err = verifyPresenceCountersign(bare, statement.purpose, profile.alg, publicKey, origins)
		if !errors.Is(err, ErrSignedEvidence) {
			t.Errorf("%s no evidence: %v", profile.name, err)
		}

		empty := proto.CloneOf(bare)
		empty.Webauthn = &WebAuthnEvidence{}
		err = verifyPresenceCountersign(empty, statement.purpose, profile.alg, publicKey, origins)
		if !errors.Is(err, ErrSignedEvidence) {
			t.Errorf("%s empty evidence: %v", profile.name, err)
		}

		noKeyId := proto.CloneOf(testCountersignedAct(t, statements, profile.check)[2])
		noKeyId.Webauthn.KeyId = nil
		err = verifyPresenceCountersign(noKeyId, statement.purpose, profile.alg, publicKey, origins)
		if !errors.Is(err, ErrSignedEvidence) {
			t.Errorf("%s no key_id: %v", profile.name, err)
		}
	}
}

// An act is one signer's, and countersigned bytes with no signer in them would be nobody's.
func TestVerifyPresenceCountersignRefusesNoSignerId(t *testing.T) {
	origins := testFixtureOrigins(t)
	statement := testActStatements(1)[0]
	for _, profile := range testPresenceProfiles(t) {
		leaf := presenceActLeafHash(SignedBytesSha256(statement.purpose, statement.signedType, statement.body))
		signed := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		signed.SignerId = nil
		signed.Webauthn = profile.check(PresenceActBytes(nil, 1, leaf))
		signed.Webauthn.ActSize = 1
		err := verifyPresenceCountersign(signed, statement.purpose, profile.alg, profile.publicKey, origins)
		if !errors.Is(err, ErrSignedEvidence) {
			t.Errorf("%s: %v", profile.name, err)
		}
	}
}

// §6.11's refusals hold here as in VerifySigned, even with no type to expect. Each statement really is countersigned
// under that value, so only the enum can refuse it, and a value above int32's range must not wrap onto a registered one.
func TestVerifyPresenceCountersignRefusesUnknownTypes(t *testing.T) {
	origins := testFixtureOrigins(t)
	purpose := "authority"
	for _, profile := range testPresenceProfiles(t) {
		for _, number := range []uint32{0, 1, 0x1100, 0x12FF, 0x7FFFFFFF, 0x80001206, 0xFFFFFFFF} {
			statements := []*testActStatement{{purpose: purpose, signedType: SignedType(number), body: testBody}}
			signed := testCountersignedAct(t, statements, profile.check)[0]
			signed.Type = number
			err := verifyPresenceCountersign(signed, purpose, profile.alg, profile.publicKey, origins)
			if !errors.Is(err, ErrSignedTypeUnknown) {
				t.Errorf("%s type %#x: %v", profile.name, number, err)
			}
		}
	}
}

// A purpose VerifySigned refuses is refused here, or a leaf could be built from the countersigned bytes' own domain.
// Each act really is countersigned under that purpose, so only the rule can refuse it.
func TestVerifyPresenceCountersignRefusesUnusablePurposes(t *testing.T) {
	origins := testFixtureOrigins(t)
	for _, profile := range testPresenceProfiles(t) {
		for _, purpose := range []string{"", "presence-act", "\x00", "authority\x00", "authority\x00\x00\x00\x12\x06"} {
			statements := []*testActStatement{
				{purpose: purpose, signedType: SignedType_SIGNED_SIDECAR_REVOKE, body: testBody},
			}
			signed := testCountersignedAct(t, statements, profile.check)[0]
			err := verifyPresenceCountersign(signed, purpose, profile.alg, profile.publicKey, origins)
			if !errors.Is(err, ErrSignedPurpose) {
				t.Errorf("%s purpose %q: %v", profile.name, purpose, err)
			}
		}
	}
}

// The purpose a statement was signed under is in its leaf, so one presented under another reaches another root.
func TestVerifyPresenceCountersignRefusesAnotherPurpose(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	for _, profile := range testPresenceProfiles(t) {
		for i, signed := range testCountersignedAct(t, statements, profile.check) {
			otherPurpose := "bridge"
			err := verifyPresenceCountersign(signed, otherPurpose, profile.alg, profile.publicKey, origins)
			if !profile.refusesOtherBytes(err) {
				t.Errorf("%s statement %d: %v", profile.name, i, err)
			}
		}
	}
}

// A path that misses its leaf, each way a relay can write one: other bytes under the path, or a path that walks
// somewhere else. Where the path could be an act's, only the signature over the root can refuse it.
func TestVerifyPresenceCountersignRefusesAPathThatMissesItsLeaf(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	statement := statements[2]
	cases := []struct {
		name   string
		mutate func(signed *Signed)
		// refused for its shape; the rest reach the signature over another root
		shape bool
	}{
		{
			name: "another body",
			mutate: func(signed *Signed) {
				signed.Body = append(signed.Body, 0x00)
			},
		},
		{
			name: "another statement's body",
			mutate: func(signed *Signed) {
				signed.Body = statements[1].body
			},
		},
		{
			name: "another type",
			mutate: func(signed *Signed) {
				signed.Type = uint32(SignedType_SIGNED_MEMBER_REVOKE)
			},
		},
		{
			name: "first hash spoiled",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActPath[0][0] ^= 0x01
			},
		},
		{
			name: "last hash spoiled",
			mutate: func(signed *Signed) {
				path := signed.Webauthn.ActPath
				path[len(path)-1][sha256.Size-1] ^= 0x80
			},
		},
		{
			name: "hashes swapped",
			mutate: func(signed *Signed) {
				path := signed.Webauthn.ActPath
				path[0], path[1] = path[1], path[0]
			},
		},
		{
			name: "index one below",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActIndex -= 1
			},
		},
		{
			name: "index one above",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActIndex += 1
			},
		},
		{
			name: "size one above, which walks the same path to the same root",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActSize += 1
			},
		},
		{
			name: "size one below",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActSize -= 1
			},
			shape: true,
		},
		{
			name: "no path",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActPath = nil
			},
			shape: true,
		},
		{
			name: "last hash missing",
			mutate: func(signed *Signed) {
				path := signed.Webauthn.ActPath
				signed.Webauthn.ActPath = path[:len(path)-1]
			},
			shape: true,
		},
		{
			name: "one hash more",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActPath = append(signed.Webauthn.ActPath, make([]byte, sha256.Size))
			},
			shape: true,
		},
		{
			name: "a hash a byte short",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActPath[1] = signed.Webauthn.ActPath[1][:sha256.Size-1]
			},
			shape: true,
		},
		{
			name: "a hash a byte long",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActPath[1] = append(signed.Webauthn.ActPath[1], 0x00)
			},
			shape: true,
		},
		{
			name: "an empty hash",
			mutate: func(signed *Signed) {
				signed.Webauthn.ActPath[0] = []byte{}
			},
			shape: true,
		},
	}
	for _, profile := range testPresenceProfiles(t) {
		act := testCountersignedAct(t, statements, profile.check)
		for _, c := range cases {
			signed := proto.CloneOf(act[2])
			c.mutate(signed)
			err := verifyPresenceCountersign(signed, statement.purpose, profile.alg, profile.publicKey, origins)
			if c.shape {
				if !errors.Is(err, ErrSignedAct) {
					t.Errorf("%s %s: %v", profile.name, c.name, err)
				}
			} else if !profile.refusesOtherBytes(err) {
				t.Errorf("%s %s: %v", profile.name, c.name, err)
			}
		}
	}
}

// Neither half of two acts makes a third: a statement keeps its own path, but the check that signed another act's root
// rides it, and the other way a statement rides another act's path and check whole.
func TestVerifyPresenceCountersignRefusesAnotherActsRoot(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	otherStatements := testActStatements(5)
	for _, statement := range otherStatements {
		statement.body = append(statement.body, []byte(" of another act")...)
	}
	for _, profile := range testPresenceProfiles(t) {
		act := testCountersignedAct(t, statements, profile.check)
		otherAct := testCountersignedAct(t, otherStatements, profile.check)

		signed := proto.CloneOf(act[1])
		signed.Webauthn.Signature = otherAct[1].Webauthn.Signature
		signed.Webauthn.AuthenticatorData = otherAct[1].Webauthn.AuthenticatorData
		signed.Webauthn.ClientDataJson = otherAct[1].Webauthn.ClientDataJson
		err := verifyPresenceCountersign(signed, statements[1].purpose, profile.alg, profile.publicKey, origins)
		if !profile.refusesOtherBytes(err) {
			t.Errorf("%s another act's check: %v", profile.name, err)
		}

		signed = proto.CloneOf(act[1])
		signed.Webauthn = proto.CloneOf(otherAct[1].Webauthn)
		err = verifyPresenceCountersign(signed, statements[1].purpose, profile.alg, profile.publicKey, origins)
		if !profile.refusesOtherBytes(err) {
			t.Errorf("%s another act's path and check: %v", profile.name, err)
		}
	}
}

// signer_id is in the countersigned bytes though no identity signature covers it, so a check one signer ran stands for
// no other, and a relay cannot move it.
func TestVerifyPresenceCountersignRefusesAnotherSignersAct(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	for _, profile := range testPresenceProfiles(t) {
		for i, signed := range testCountersignedAct(t, statements, profile.check) {
			moved := proto.CloneOf(signed)
			moved.SignerId = []byte("another-synthetic-signer")
			err := verifyPresenceCountersign(moved, statements[i].purpose, profile.alg, profile.publicKey, origins)
			if !profile.refusesOtherBytes(err) {
				t.Errorf("%s statement %d: %v", profile.name, i, err)
			}
		}
	}
}

// A key_id resolves to a key record, so a check by any other key meets the record's key and fails. The caller resolves
// the id, which is why this takes the key and not the id.
func TestVerifyPresenceCountersignRefusesAnotherKey(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(3)
	key, _ := testP256Key(t)
	_, otherPublic := testOtherP256Key(t)
	for _, profile := range []*testPresenceProfile{
		{name: "ecdsa-p256-sha256", alg: SignedKeyAlgEcdsaP256, check: testEcdsaPresenceCheck(t, key)},
		{name: "webauthn-es256", alg: SignedKeyAlgWebAuthnEs256, check: testWebAuthnPresenceCheck(t, key, nil)},
	} {
		for i, signed := range testCountersignedAct(t, statements, profile.check) {
			err := verifyPresenceCountersign(signed, statements[i].purpose, profile.alg, otherPublic, origins)
			if !errors.Is(err, ErrSignedSignature) {
				t.Errorf("%s statement %d: %v", profile.name, i, err)
			}
		}
	}
}

// Every bit of the signature and of each path hash is covered, on both profiles, and for webauthn-es256 every bit of
// the signed evidence. The walk runs before the signature, so a flip in a path reaches another root.
func TestVerifyPresenceCountersignRefusesEveryBitFlip(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(5)
	statement := statements[3]
	for _, profile := range testPresenceProfiles(t) {
		act := testCountersignedAct(t, statements, profile.check)
		good := act[3]

		refuseFlips := func(name string, field func(signed *Signed) []byte) {
			signed := proto.CloneOf(good)
			verify := func() error {
				return verifyPresenceCountersign(signed, statement.purpose, profile.alg, profile.publicKey, origins)
			}
			target := field(signed)
			for i := range target {
				for bit := range 8 {
					target[i] ^= 1 << bit
					if verify() == nil {
						t.Errorf("%s %s bit %d of byte %d verified", profile.name, name, bit, i)
					}
					target[i] ^= 1 << bit
				}
			}
			if err := verify(); err != nil {
				t.Errorf("%s %s restored: %v", profile.name, name, err)
			}
		}
		refuseFlips("signature", func(signed *Signed) []byte { return signed.Webauthn.Signature })
		refuseFlips("body", func(signed *Signed) []byte { return signed.Body })
		refuseFlips("signer_id", func(signed *Signed) []byte { return signed.SignerId })
		for hashIndex := range good.Webauthn.ActPath {
			refuseFlips(
				fmt.Sprintf("path hash %d", hashIndex),
				func(signed *Signed) []byte { return signed.Webauthn.ActPath[hashIndex] },
			)
		}
		if profile.alg == SignedKeyAlgWebAuthnEs256 {
			refuseFlips("authenticator data", func(signed *Signed) []byte { return signed.Webauthn.AuthenticatorData })
			refuseFlips("client data", func(signed *Signed) []byte { return signed.Webauthn.ClientDataJson })
		}
	}
}

// §7.9's bounds, each against a countersignature that is otherwise whole, so only the bound can refuse it. A presence
// key signs what its client gives it, so an act past the bounds can carry a real signature.
func TestVerifyPresenceCountersignBoundsAnAct(t *testing.T) {
	origins := testFixtureOrigins(t)
	statement := testActStatements(1)[0]
	leafDigest := SignedBytesSha256(statement.purpose, statement.signedType, statement.body)

	for _, profile := range testPresenceProfiles(t) {
		// an act one over the most an act holds, with this statement a real leaf of it
		overDigests := testRuleDigests(testActMaxSize + 1)
		overDigests[5] = leafDigest
		leafHashes := make([][sha256.Size]byte, len(overDigests))
		for i, statementDigest := range overDigests {
			leafHashes[i] = presenceActLeafHash(statementDigest)
		}
		over := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		over.Webauthn = profile.check(PresenceActBytes(testSignerId, testActMaxSize+1, presenceActTreeHash(leafHashes)))
		over.Webauthn.ActSize = testActMaxSize + 1
		over.Webauthn.ActIndex = 5
		over.Webauthn.ActPath = presenceActTreePath(leafHashes, 5)
		if len(over.Webauthn.ActPath) != 16 {
			t.Fatalf("a path of %d hashes", len(over.Webauthn.ActPath))
		}
		err := verifyPresenceCountersign(over, statement.purpose, profile.alg, profile.publicKey, origins)
		if !errors.Is(err, ErrSignedAct) {
			t.Errorf("%s an act of 65,536: %v", profile.name, err)
		}

		// an act of none, whose empty path would otherwise walk nowhere
		leaf := presenceActLeafHash(leafDigest)
		none := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		none.Webauthn = profile.check(PresenceActBytes(testSignerId, 0, leaf))
		err = verifyPresenceCountersign(none, statement.purpose, profile.alg, profile.publicKey, origins)
		if !errors.Is(err, ErrSignedAct) {
			t.Errorf("%s an act of 0: %v", profile.name, err)
		}

		// index past the end of an act of one, whose path is empty, so the walk alone would pass it
		past := proto.CloneOf(testCountersignedAct(t, []*testActStatement{statement}, profile.check)[0])
		past.Webauthn.ActIndex = 1
		err = verifyPresenceCountersign(past, statement.purpose, profile.alg, profile.publicKey, origins)
		if !errors.Is(err, ErrSignedAct) {
			t.Errorf("%s index 1 of 1: %v", profile.name, err)
		}
		past.Webauthn.ActIndex = 0xFFFFFFFF
		err = verifyPresenceCountersign(past, statement.purpose, profile.alg, profile.publicKey, origins)
		if !errors.Is(err, ErrSignedAct) {
			t.Errorf("%s the highest index: %v", profile.name, err)
		}

		// 17 hashes, the deepest act's 16 and one more
		statementDigests := testRuleDigests(testActMaxSize)
		statementDigests[0] = leafDigest
		seventeen := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		root, err := PresenceActRoot(statementDigests)
		if err != nil {
			t.Fatal(err)
		}
		seventeen.Webauthn = profile.check(PresenceActBytes(testSignerId, testActMaxSize, root))
		seventeen.Webauthn.ActSize = testActMaxSize
		seventeen.Webauthn.ActPath, err = PresenceActPath(statementDigests, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(seventeen.Webauthn.ActPath) != 16 {
			t.Fatalf("a path of %d hashes", len(seventeen.Webauthn.ActPath))
		}
		err = verifyPresenceCountersign(seventeen, statement.purpose, profile.alg, profile.publicKey, origins)
		if err != nil {
			t.Errorf("%s the deepest act: %v", profile.name, err)
		}
		seventeen.Webauthn.ActPath = append(seventeen.Webauthn.ActPath, make([]byte, sha256.Size))
		err = verifyPresenceCountersign(seventeen, statement.purpose, profile.alg, profile.publicKey, origins)
		if !errors.Is(err, ErrSignedAct) || !strings.Contains(err.Error(), "17 hashes") {
			t.Errorf("%s 17 hashes: %v", profile.name, err)
		}
	}
}

// Every clause of §16.6's countersign check over a webauthn-es256 assertion, each spoiled before signing, so the
// signature stays valid and only the clause can refuse it. The origin clause is VerifySigned's too, and a refused origin
// names itself.
func TestVerifyPresenceCountersignWebAuthnProfile(t *testing.T) {
	statements := testActStatements(3)
	statement := statements[0]
	signedBytes := sha256.Sum256(SignedBytes(statement.purpose, statement.signedType, statement.body))
	body := sha256.Sum256(statement.body)
	origins := testFixtureOrigins(t)

	cases := []struct {
		name   string
		mutate func(assertion *testWebAuthnAssertion)
		want   error
		reason string
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
			name: "the statement's own challenge, a per-use assertion's",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.challenge = base64.RawURLEncoding.EncodeToString(signedBytes[:])
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
				assertion.challenge += "="
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
			name: "the other listed origin, an android one",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin = origins[1]
			},
		},
		{
			name: "an unlisted origin",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin = "https://app.example"
			},
			want:   ErrSignedEvidence,
			reason: "origin",
		},
		{
			name: "no origin",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin = ""
			},
			want:   ErrSignedEvidence,
			reason: "origin",
		},
		{
			name: "an origin that only begins a listed one",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin += ".example"
			},
			want:   ErrSignedEvidence,
			reason: "origin",
		},
		{
			name: "an origin that only ends a listed one",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin = strings.Replace(assertion.origin, "https://", "https://sub.", 1)
			},
			want:   ErrSignedEvidence,
			reason: "origin",
		},
		{
			name: "a listed origin's host over another scheme",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin = strings.Replace(assertion.origin, "https://", "http://", 1)
			},
			want:   ErrSignedEvidence,
			reason: "origin",
		},
		{
			name: "a debug-signed android build",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.origin = testDebugBuildOrigin()
			},
			want:   ErrSignedEvidence,
			reason: "origin",
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
			name: "signature over the countersigned bytes, not the evidence",
			mutate: func(assertion *testWebAuthnAssertion) {
				assertion.signSignedBytes = true
			},
			want: ErrSignedSignature,
		},
	}
	key, publicKey := testP256Key(t)
	for _, c := range cases {
		signed := testCountersignedAct(t, statements, testWebAuthnPresenceCheck(t, key, c.mutate))[0]
		err := verifyPresenceCountersign(signed, statement.purpose, SignedKeyAlgWebAuthnEs256, publicKey, origins)
		if !errors.Is(err, c.want) || (c.reason != "" && !strings.Contains(err.Error(), c.reason)) {
			t.Errorf("%s: got %v, want %v for %q", c.name, err, c.want, c.reason)
		}
	}
}

// The exported checks read webAuthnOrigins and refuse every other origin alike (QD-073), the fixture origins included,
// so no test passes against the release by way of a fixture. The one test that reads the table: each of its entries
// verifies per use and as a countersignature, and every other origin, each validly signed, is refused by both.
func TestVerifiersReadTheReleaseOriginTable(t *testing.T) {
	statements := testActStatements(1)
	statement := statements[0]
	key, publicKey := testP256Key(t)
	// the per-use answer, then the countersignature's
	verifyBoth := func(origin string) []error {
		perUse := testGoodWebAuthnAssertion(t, statement.purpose, statement.signedType, statement.body)
		perUse.origin = origin
		signed := perUse.sign(t, key, statement.purpose, statement.signedType, statement.body)
		check := testWebAuthnPresenceCheck(t, key, func(assertion *testWebAuthnAssertion) {
			assertion.origin = origin
		})
		countersigned := testCountersignedAct(t, statements, check)[0]
		return []error{
			VerifySigned(signed, statement.purpose, statement.signedType, SignedKeyAlgWebAuthnEs256, publicKey),
			VerifyPresenceCountersign(countersigned, statement.purpose, SignedKeyAlgWebAuthnEs256, publicKey),
		}
	}

	if len(webAuthnOrigins) == 0 {
		t.Fatal("no origin is listed, so every passkey would be refused")
	}
	for i, origin := range webAuthnOrigins {
		for _, err := range verifyBoth(origin) {
			if err != nil {
				t.Errorf("listed origin %d: %v", i, err)
			}
		}
	}
	refusedOrigins := append(testFixtureOrigins(t), "https://phish.example", testDebugBuildOrigin(), "")
	for _, origin := range refusedOrigins {
		for _, err := range verifyBoth(origin) {
			if !errors.Is(err, ErrSignedEvidence) || !strings.Contains(err.Error(), "origin") {
				t.Errorf("%q: %v", origin, err)
			}
		}
	}
}

// The same floor as a per-use assertion's, sizes written here and each assertion validly signed, so only the size can
// refuse it.
func TestVerifyPresenceCountersignAuthenticatorDataFloor(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(1)
	key, publicKey := testP256Key(t)
	verifyOfSize := func(size int) error {
		check := testWebAuthnPresenceCheck(t, key, func(assertion *testWebAuthnAssertion) {
			assertion.authData = func(authenticatorData []byte) []byte {
				return append(authenticatorData, make([]byte, 64)...)[:size]
			}
		})
		signed := testCountersignedAct(t, statements, check)[0]
		return verifyPresenceCountersign(signed, statements[0].purpose, SignedKeyAlgWebAuthnEs256, publicKey, origins)
	}
	for size := range 37 {
		err := verifyOfSize(size)
		if !errors.Is(err, ErrSignedEvidence) {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
	for _, size := range []int{37, 38, 64} {
		err := verifyOfSize(size)
		if err != nil {
			t.Errorf("%d bytes: %v", size, err)
		}
	}
}

// The key record fixes the algorithm, never the message: a countersignature of one profile refuses under the other, and
// nothing but a P-256 presence profile countersigns (§16.6).
func TestVerifyPresenceCountersignEvidenceMustFit(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(3)
	statement := statements[1]
	key, publicKey := testP256Key(t)
	ecdsaSigned := testCountersignedAct(t, statements, testEcdsaPresenceCheck(t, key))[1]
	webAuthnSigned := testCountersignedAct(t, statements, testWebAuthnPresenceCheck(t, key, nil))[1]

	cases := []struct {
		name      string
		signed    *Signed
		alg       SignedKeyAlg
		publicKey []byte
		want      error
	}{
		{
			name:      "an es256 assertion as ecdsa-p256-sha256",
			signed:    webAuthnSigned,
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: publicKey,
			want:      ErrSignedEvidence,
		},
		{
			name: "only authenticator data beside ecdsa-p256-sha256",
			signed: func() *Signed {
				signed := proto.CloneOf(ecdsaSigned)
				signed.Webauthn.AuthenticatorData = []byte{0x00}
				return signed
			}(),
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: publicKey,
			want:      ErrSignedEvidence,
		},
		{
			name: "only client data beside ecdsa-p256-sha256",
			signed: func() *Signed {
				signed := proto.CloneOf(ecdsaSigned)
				signed.Webauthn.ClientDataJson = []byte("{}")
				return signed
			}(),
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: publicKey,
			want:      ErrSignedEvidence,
		},
		{
			name:      "ecdsa-p256-sha256 as webauthn-es256, with no assertion",
			signed:    ecdsaSigned,
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: publicKey,
			want:      ErrSignedEvidence,
		},
		{
			name:      "an identity key's algorithm",
			signed:    ecdsaSigned,
			alg:       SignedKeyAlgEd25519,
			publicKey: testEd25519Public(),
			want:      ErrSignedKey,
		},
		{
			name:      "no algorithm",
			signed:    ecdsaSigned,
			publicKey: publicKey,
			want:      ErrSignedKey,
		},
		{
			name:      "an algorithm past the last",
			signed:    ecdsaSigned,
			alg:       SignedKeyAlgWebAuthnEs256 + 1,
			publicKey: publicKey,
			want:      ErrSignedKey,
		},
		{
			name:      "ecdsa-p256-sha256 with no key",
			signed:    ecdsaSigned,
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: nil,
			want:      ErrSignedKey,
		},
		{
			name:      "ecdsa-p256-sha256 with a compressed point",
			signed:    ecdsaSigned,
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: append([]byte{0x02 | publicKey[64]&0x01}, publicKey[1:33]...),
			want:      ErrSignedKey,
		},
		{
			name:      "webauthn-es256 with a point off the curve",
			signed:    webAuthnSigned,
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: append(slices.Clone(publicKey[:64]), publicKey[64]^0x01),
			want:      ErrSignedKey,
		},
		{
			name: "no signature",
			signed: func() *Signed {
				signed := proto.CloneOf(ecdsaSigned)
				signed.Webauthn.Signature = nil
				return signed
			}(),
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: publicKey,
			want:      ErrSignedSignature,
		},
		{
			name: "Signed's signature where the countersignature's belongs",
			signed: func() *Signed {
				signed := proto.CloneOf(webAuthnSigned)
				signed.Signature, signed.Webauthn.Signature = signed.Webauthn.Signature, signed.Signature
				return signed
			}(),
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: publicKey,
			want:      ErrSignedSignature,
		},
		{
			name:      "ecdsa-p256-sha256 fits",
			signed:    ecdsaSigned,
			alg:       SignedKeyAlgEcdsaP256,
			publicKey: publicKey,
		},
		{
			name:      "webauthn-es256 fits",
			signed:    webAuthnSigned,
			alg:       SignedKeyAlgWebAuthnEs256,
			publicKey: publicKey,
		},
	}
	for _, c := range cases {
		err := verifyPresenceCountersign(c.signed, statement.purpose, c.alg, c.publicKey, origins)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

// A key signs an act's countersigned bytes and nothing near them: its signature over the statement's own bytes, the
// leaf, those bytes cut short, another size or the layout with no size in it is refused, each with the act fields whole,
// and only the bytes themselves pass.
func TestVerifyPresenceCountersignSignsTheActsBytesAlone(t *testing.T) {
	origins := testFixtureOrigins(t)
	statement := testActStatements(1)[0]
	signedBytes := SignedBytes(statement.purpose, statement.signedType, statement.body)
	leaf := presenceActLeafHash(sha256.Sum256(signedBytes))
	actBytes := PresenceActBytes(testSignerId, 1, leaf)
	for _, profile := range testPresenceProfiles(t) {
		for _, message := range [][]byte{
			signedBytes,
			leaf[:],
			actBytes[:len(actBytes)-1],
			PresenceActBytes(testSignerId, 2, leaf),
			slices.Concat([]byte("urnetwork-sidecar-v1/presence-act\x00"), testSignerId, leaf[:]),
		} {
			signed := testSignEd25519(statement.purpose, statement.signedType, statement.body)
			signed.Webauthn = profile.check(message)
			signed.Webauthn.ActSize = 1
			err := verifyPresenceCountersign(signed, statement.purpose, profile.alg, profile.publicKey, origins)
			if !profile.refusesOtherBytes(err) {
				t.Errorf("%s over %x: %v", profile.name, message, err)
			}
		}
		signed := testSignEd25519(statement.purpose, statement.signedType, statement.body)
		signed.Webauthn = profile.check(actBytes)
		signed.Webauthn.ActSize = 1
		err := verifyPresenceCountersign(signed, statement.purpose, profile.alg, profile.publicKey, origins)
		if err != nil {
			t.Errorf("%s over the act's bytes: %v", profile.name, err)
		}
	}
}

// §7.9's "presence-act" is no §6.11 purpose: a signer_id can make SignedBytes under that purpose equal an act's bytes
// exactly, so if VerifySigned took the purpose, a presence key's countersignature would verify as a statement of its
// own by that key. The purpose rule is the only thing that stops it.
func TestCountersignedBytesNeverVerifyAsAStatement(t *testing.T) {
	origins := testFixtureOrigins(t)
	signedType := SignedType_SIGNED_SIDECAR_REVOKE
	signerId := binary.BigEndian.AppendUint32(nil, uint32(signedType))
	signerId = append(signerId, []byte("rest of a synthetic signer id")...)
	root := [sha256.Size]byte{0x01}
	actBytes := PresenceActBytes(signerId, 7, root)
	body := slices.Concat(signerId[4:], []byte{0x00, 0x00, 0x00, 0x07}, root[:])
	if !bytes.Equal(SignedBytes(presenceActPurpose, signedType, body), actBytes) {
		t.Fatal("the fixture must make the two encodings meet, or this proves nothing")
	}

	key, publicKey := testP256Key(t)
	digest := sha256.Sum256(actBytes)
	signed := &Signed{Body: body, Signature: testSignDigest(t, key, digest[:]), Type: uint32(signedType)}
	err := VerifySigned(signed, presenceActPurpose, signedType, SignedKeyAlgEcdsaP256, publicKey)
	if !errors.Is(err, ErrSignedPurpose) {
		t.Fatal(err)
	}

	assertion := testGoodCountersignAssertion(t, actBytes)
	evidence, signature := assertion.assert(t, key, actBytes)
	signed = &Signed{Body: body, Signature: signature, Webauthn: evidence, Type: uint32(signedType)}
	err = verifySigned(signed, presenceActPurpose, signedType, SignedKeyAlgWebAuthnEs256, publicKey, origins)
	if !errors.Is(err, ErrSignedPurpose) {
		t.Fatal(err)
	}
}

// Each check's assertion stands for its own message: a per-use assertion over a statement's signed bytes is no
// countersignature of it, and a countersignature's assertion, its act fields gone, is no per-use signature.
func TestAssertionsDoNotCrossBetweenChecks(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(1)
	statement := statements[0]
	key, publicKey := testP256Key(t)

	perUse := testGoodWebAuthnAssertion(t, statement.purpose, statement.signedType, statement.body)
	signed := perUse.sign(t, key, statement.purpose, statement.signedType, statement.body)
	err := verifySigned(signed, statement.purpose, statement.signedType, SignedKeyAlgWebAuthnEs256, publicKey, origins)
	if err != nil {
		t.Fatal(err)
	}
	signed.SignerId = testSignerId
	signed.Webauthn.KeyId = testPresenceKeyId
	signed.Webauthn.Signature = signed.Signature
	signed.Webauthn.ActSize = 1
	err = verifyPresenceCountersign(signed, statement.purpose, SignedKeyAlgWebAuthnEs256, publicKey, origins)
	if !errors.Is(err, ErrSignedEvidence) || !strings.Contains(err.Error(), "challenge") {
		t.Errorf("a per-use assertion as a countersignature: %v", err)
	}

	countersigned := testCountersignedAct(t, statements, testWebAuthnPresenceCheck(t, key, nil))[0]
	reused := &Signed{
		Body:      countersigned.Body,
		Signature: countersigned.Webauthn.Signature,
		Webauthn: &WebAuthnEvidence{
			AuthenticatorData: countersigned.Webauthn.AuthenticatorData,
			ClientDataJson:    countersigned.Webauthn.ClientDataJson,
		},
		Type: countersigned.Type,
	}
	err = verifySigned(reused, statement.purpose, statement.signedType, SignedKeyAlgWebAuthnEs256, publicKey, origins)
	if !errors.Is(err, ErrSignedEvidence) || !strings.Contains(err.Error(), "challenge") {
		t.Errorf("a countersignature as a per-use assertion: %v", err)
	}
}

// What VerifySigned's evidence rule makes of a statement that carries one: the identity signature stands apart from
// the countersignature, so a bad one refuses here and not there, and a good one vouches for no identity signature.
func TestCountersignatureAndIdentitySignatureAreApart(t *testing.T) {
	origins := testFixtureOrigins(t)
	statements := testActStatements(3)
	statement := statements[0]
	for _, profile := range testPresenceProfiles(t) {
		act := testCountersignedAct(t, statements, profile.check)

		spoiled := proto.CloneOf(act[0])
		spoiled.Webauthn.Signature[len(spoiled.Webauthn.Signature)-1] ^= 0x01
		err := VerifySigned(spoiled, statement.purpose, statement.signedType, SignedKeyAlgEd25519, testEd25519Public())
		if err != nil {
			t.Errorf("%s a spoiled countersignature in VerifySigned: %v", profile.name, err)
		}
		err = verifyPresenceCountersign(spoiled, statement.purpose, profile.alg, profile.publicKey, origins)
		if err == nil {
			t.Errorf("%s a spoiled countersignature verified", profile.name)
		}

		forged := proto.CloneOf(act[0])
		forged.Signature = ed25519.Sign(
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize)),
			SignedBytes(statement.purpose, statement.signedType, statement.body),
		)
		err = VerifySigned(forged, statement.purpose, statement.signedType, SignedKeyAlgEd25519, testEd25519Public())
		if !errors.Is(err, ErrSignedSignature) {
			t.Errorf("%s another identity's signature: %v", profile.name, err)
		}
		err = verifyPresenceCountersign(forged, statement.purpose, profile.alg, profile.publicKey, origins)
		if err != nil {
			t.Errorf("%s the countersignature beside it: %v", profile.name, err)
		}
	}
}

// §2.1.1's tree against answers no code here produced, Certificate Transparency's published ones, at the sizes that
// take each shape of right edge. Those leaves are arbitrary where an act's are 32 bytes, so they enter below
// PresenceActRoot, as leaf hashes.
func TestPresenceActTreeKnownAnswers(t *testing.T) {
	leaves := []string{
		"",
		"00",
		"10",
		"2021",
		"3031",
		"40414243",
		"5051525354555657",
		"606162636465666768696a6b6c6d6e6f",
	}
	leafHashes := make([][sha256.Size]byte, len(leaves))
	for i, leaf := range leaves {
		leafHashes[i] = sha256.Sum256(append([]byte{0x00}, testFromHex(t, leaf)...))
	}
	roots := []string{
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for i, root := range roots {
		size := i + 1
		want := testFromHex(t, root)
		got := presenceActTreeHash(leafHashes[:size])
		if !bytes.Equal(got[:], want) {
			t.Errorf("size %d: root %x, want %x", size, got, want)
		}
		// §2.1.3.2 reaches the same answer by another algorithm, from every leaf.
		for index := range size {
			path := presenceActTreePath(leafHashes[:size], index)
			walked, err := presenceActPathRoot(leafHashes[index], uint32(index), uint32(size), path)
			if err != nil {
				t.Errorf("size %d index %d: %v", size, index, err)
			} else if !bytes.Equal(walked[:], want) {
				t.Errorf("size %d index %d: walked to %x, want %x", size, index, walked, want)
			}
		}
	}
}

// A leaf is the statement digest's leaf hash, so an act's root is not MTH over the digests read as leaf hashes: the
// 0x00 prefix is what keeps a node from passing as a statement.
func TestPresenceActRootHashesItsLeaves(t *testing.T) {
	statementDigests := testRuleDigests(3)
	got, err := PresenceActRoot(statementDigests)
	if err != nil {
		t.Fatal(err)
	}
	leafHash := func(i int) []byte {
		hash := sha256.Sum256(append([]byte{0x00}, statementDigests[i][:]...))
		return hash[:]
	}
	node := func(left []byte, right []byte) []byte {
		hash := sha256.Sum256(slices.Concat([]byte{0x01}, left, right))
		return hash[:]
	}
	want := node(node(leafHash(0), leafHash(1)), leafHash(2))
	if !bytes.Equal(got[:], want) {
		t.Fatalf("root %x, want %x", got, want)
	}
	if bytes.Equal(got[:], node(node(statementDigests[0][:], statementDigests[1][:]), statementDigests[2][:])) {
		t.Fatal("the digests were read as leaf hashes")
	}
}

// Every leaf of every act up to 70 statements, past each power of two that shapes a right edge: its path walks to the
// root, and it stands for no other leaf. No index but its own reaches the root from this leaf by this path, the
// off-by-one cases included, nor does the next leaf reach it by this path.
func TestPresenceActPathsWalkOnlyFromTheirOwnLeaf(t *testing.T) {
	for size := 1; size <= 70; size++ {
		statementDigests := testRuleDigests(size)
		root, err := PresenceActRoot(statementDigests)
		if err != nil {
			t.Fatal(err)
		}
		for index := range size {
			path, err := PresenceActPath(statementDigests, uint32(index))
			if err != nil {
				t.Fatal(err)
			}
			leaf := presenceActLeafHash(statementDigests[index])
			walked, err := presenceActPathRoot(leaf, uint32(index), uint32(size), path)
			if err != nil {
				t.Fatalf("size %d index %d: %v", size, index, err)
			}
			if walked != root {
				t.Errorf("size %d index %d: walked to %x, want %x", size, index, walked, root)
			}
			for otherIndex := range size + 1 {
				if otherIndex == index {
					continue
				}
				walked, err := presenceActPathRoot(leaf, uint32(otherIndex), uint32(size), path)
				if err == nil && walked == root {
					t.Errorf("size %d index %d reached the root as index %d", size, index, otherIndex)
				}
			}
			if index+1 < size {
				otherLeaf := presenceActLeafHash(statementDigests[index+1])
				walked, err := presenceActPathRoot(otherLeaf, uint32(index), uint32(size), path)
				if err == nil && walked == root {
					t.Errorf("size %d: leaf %d reached the root by leaf %d's path", size, index+1, index)
				}
			}
		}
	}
}

// §7.9's largest act: the deepest leaves take 16 hashes, the right edge fewer, one more hash is refused, and an index
// one either way misses the root.
func TestPresenceActPathsAtTheLargestAct(t *testing.T) {
	statementDigests := testRuleDigests(testActMaxSize)
	root, err := PresenceActRoot(statementDigests)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		index int
		size  int
	}{
		{index: 0, size: 16},
		{index: 1, size: 16},
		{index: 32767, size: 16},
		{index: 32768, size: 16},
		{index: 65532, size: 16},
		{index: 65533, size: 16},
		// an odd last leaf has no sibling at the bottom level, so its path is one shorter
		{index: 65534, size: 15},
	}
	for _, c := range cases {
		path, err := PresenceActPath(statementDigests, uint32(c.index))
		if err != nil {
			t.Fatal(err)
		}
		if len(path) != c.size {
			t.Errorf("index %d: a path of %d hashes, want %d", c.index, len(path), c.size)
		}
		leaf := presenceActLeafHash(statementDigests[c.index])
		walked, err := presenceActPathRoot(leaf, uint32(c.index), testActMaxSize, path)
		if err != nil {
			t.Errorf("index %d: %v", c.index, err)
		} else if walked != root {
			t.Errorf("index %d: walked to %x, want %x", c.index, walked, root)
		}
		for _, otherIndex := range []int{c.index - 1, c.index + 1} {
			if otherIndex < 0 {
				continue
			}
			walked, err := presenceActPathRoot(leaf, uint32(otherIndex), testActMaxSize, path)
			if err == nil && walked == root {
				t.Errorf("index %d reached the root as index %d", c.index, otherIndex)
			}
		}
		_, err = presenceActPathRoot(leaf, uint32(c.index), testActMaxSize, append(path, make([]byte, sha256.Size)))
		if !errors.Is(err, ErrSignedAct) {
			t.Errorf("index %d, one hash more: %v", c.index, err)
		}
	}
}

// The builders refuse what no verifier would take, so an act a device builds is always one its verifiers accept.
func TestPresenceActBuildersRefuseWhatVerifiersWould(t *testing.T) {
	_, err := PresenceActRoot(nil)
	if !errors.Is(err, ErrSignedAct) {
		t.Errorf("root of none: %v", err)
	}
	_, err = PresenceActPath(nil, 0)
	if !errors.Is(err, ErrSignedAct) {
		t.Errorf("path of none: %v", err)
	}

	tooMany := make([][sha256.Size]byte, testActMaxSize+1)
	_, err = PresenceActRoot(tooMany)
	if !errors.Is(err, ErrSignedAct) {
		t.Errorf("root of 65,536: %v", err)
	}
	_, err = PresenceActPath(tooMany, 0)
	if !errors.Is(err, ErrSignedAct) {
		t.Errorf("path of 65,536: %v", err)
	}
	_, err = PresenceActRoot(tooMany[:testActMaxSize])
	if err != nil {
		t.Errorf("root of 65,535: %v", err)
	}

	for _, index := range []uint32{3, 4, 0xFFFFFFFF} {
		_, err = PresenceActPath(testRuleDigests(3), index)
		if !errors.Is(err, ErrSignedAct) {
			t.Errorf("index %d of 3: %v", index, err)
		}
	}
}
