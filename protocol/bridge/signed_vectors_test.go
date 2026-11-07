// testdata/signed/vectors.json: fixed vectors for VerifySigned and VerifyPresenceCountersign on both §16.6 profiles,
// which FS-124's verification cases consume. TestSignedVectorsAreByteEqual rebuilds the file on the leg it runs on and
// holds it to the file's bytes, signatures included, since Ed25519 and a nil rand's RFC 6979 ECDSA are deterministic.
// TestSignedVectorsVerify and TestSignedVectorsWalk read the file as any other consumer does, with no key but the
// public ones it holds. So a change to a layout or a primitive cannot pass by changing signer and verifier together,
// and §4.7's legs cannot drift apart. signed_legs_test.go runs these on the sidecar_http leg.
//
// To rewrite the file after a deliberate format change, with its diff reviewed:
//
//	go test ./protocol/bridge -run '^TestSignedVectorsAreByteEqual$' -update-signed-vectors

package bridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
)

// Relative to this package, as go test runs it on every leg.
const testSignedVectorsPath = "../../testdata/signed/vectors.json"

// Rewrites the vector file from this leg in place of comparing it.
var testUpdateSignedVectors = flag.Bool(
	"update-signed-vectors",
	false,
	"rewrite testdata/signed/vectors.json, then read its diff",
)

// The file. Every bytes value is lowercase hex, and each `signed` is a Signed as a verifier receives it, so a consumer
// parses it and verifies over those bytes, never a re-marshal.
type testSignedVectors struct {
	Comment     string                    `json:"comment"`
	SignedBytes []*testSignedBytesVector  `json:"signed_bytes"`
	Statements  []*testStatementVector    `json:"statements"`
	Trees       []*testTreeVector         `json:"trees"`
	Acts        []*testActVector          `json:"acts"`
	Refusals    []*testCountersignRefusal `json:"countersign_refusals"`
}

// §6.9's signed bytes and their SHA-256.
type testSignedBytesVector struct {
	Purpose     string `json:"purpose"`
	Type        uint32 `json:"type"`
	Body        string `json:"body"`
	SignedBytes string `json:"signed_bytes"`
	Sha256      string `json:"sha256"`
}

// One VerifySigned call and its answer: refusal names the error, empty for a statement that verifies.
type testStatementVector struct {
	Name         string `json:"name"`
	KeyAlg       string `json:"key_alg"`
	PublicKey    string `json:"public_key"`
	Purpose      string `json:"purpose"`
	ExpectedType uint32 `json:"expected_type"`
	Signed       string `json:"signed"`
	Refusal      string `json:"refusal"`
}

// An act's tree over rule leaves (the file's comment states the rule), with chosen inclusion paths.
type testTreeVector struct {
	Size  uint32            `json:"size"`
	Root  string            `json:"root"`
	Paths []*testPathVector `json:"paths"`
}

// One leaf's path, nearest the leaf first.
type testPathVector struct {
	Index uint32   `json:"index"`
	Path  []string `json:"path"`
}

// A whole act by one signer, each statement verifying alone under both keys given.
type testActVector struct {
	Name               string                    `json:"name"`
	KeyAlg             string                    `json:"key_alg"`
	PublicKey          string                    `json:"public_key"`
	IdentityPublicKey  string                    `json:"identity_public_key"`
	SignerId           string                    `json:"signer_id"`
	KeyId              string                    `json:"key_id"`
	Size               uint32                    `json:"size"`
	Root               string                    `json:"root"`
	CountersignedBytes string                    `json:"countersigned_bytes"`
	Statements         []*testActStatementVector `json:"statements"`
}

// One statement of an act.
type testActStatementVector struct {
	Purpose string `json:"purpose"`
	Type    uint32 `json:"type"`
	Body    string `json:"body"`
	Digest  string `json:"digest"`
	Signed  string `json:"signed"`
}

// One VerifyPresenceCountersign call that refuses, naming the error.
type testCountersignRefusal struct {
	Name      string `json:"name"`
	KeyAlg    string `json:"key_alg"`
	PublicKey string `json:"public_key"`
	Purpose   string `json:"purpose"`
	Signed    string `json:"signed"`
	Refusal   string `json:"refusal"`
}

// The file's key_alg values, which are §16.6's and §7.9's names for them.
var testVectorKeyAlgs = map[string]SignedKeyAlg{
	"ed25519":           SignedKeyAlgEd25519,
	"ecdsa-p256-sha256": SignedKeyAlgEcdsaP256,
	"webauthn-es256":    SignedKeyAlgWebAuthnEs256,
}

// The file's refusal values.
var testVectorRefusals = map[string]error{
	"":                      nil,
	"ErrSignedTypeUnknown":  ErrSignedTypeUnknown,
	"ErrSignedPurpose":      ErrSignedPurpose,
	"ErrSignedTypeMismatch": ErrSignedTypeMismatch,
	"ErrSignedEvidence":     ErrSignedEvidence,
	"ErrSignedAct":          ErrSignedAct,
	"ErrSignedKey":          ErrSignedKey,
	"ErrSignedSignature":    ErrSignedSignature,
}

// What a consumer reads off the wire.
func testHexSigned(t testing.TB, signed *Signed) string {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(encoded)
}

// The leg's own answers, built from fixed keys: everything but the key material a consumer never needs.
func testBuildSignedVectors(t testing.TB) *testSignedVectors {
	vectors := &testSignedVectors{
		Comment: "Fixed vectors for sidecar/protocol/bridge's VerifySigned and VerifyPresenceCountersign (§6.9, §7.9, " +
			"§16.6; FS-124). All keys are synthetic. Bytes are lowercase hex. Each trees entry is over the leaves " +
			"d_i = SHA-256(signed bytes of purpose authority, type 0x1206, body u32be(i)); an act's root is RFC 9162's " +
			"MTH over its statements' digests in act order, so a leaf hash is SHA-256(0x00 || d_i).",
	}

	for _, statement := range []*testActStatement{
		{purpose: "bridge", signedType: SignedType_SIGNED_BRIDGE_WITHDRAW, body: testBody},
		{purpose: "authority", signedType: SignedType_SIGNED_SIDECAR_REVOKE, body: []byte{}},
		{purpose: "acl", signedType: SignedType_SIGNED_GRANT_REVOKE, body: []byte{0x00, 0x01, 0xFF}},
	} {
		digest := SignedBytesSha256(statement.purpose, statement.signedType, statement.body)
		vectors.SignedBytes = append(vectors.SignedBytes, &testSignedBytesVector{
			Purpose:     statement.purpose,
			Type:        uint32(statement.signedType),
			Body:        hex.EncodeToString(statement.body),
			SignedBytes: hex.EncodeToString(SignedBytes(statement.purpose, statement.signedType, statement.body)),
			Sha256:      hex.EncodeToString(digest[:]),
		})
	}

	key, publicKey := testP256Key(t)
	purpose := "authority"
	signedType := SignedType_SIGNED_SIDECAR_REVOKE
	otherType := SignedType_SIGNED_KEY_REVOKE
	ed25519Public := hex.EncodeToString(testEd25519Public())
	p256Public := hex.EncodeToString(publicKey)

	ed25519Signed := testSignEd25519(purpose, signedType, testBody)
	ecdsaSigned := testSignP256(t, key, purpose, signedType, testBody)
	assertion := testGoodWebAuthnAssertion(purpose, signedType, testBody)
	webAuthnSigned := assertion.sign(t, key, purpose, signedType, testBody)
	countersigned := testCountersignedAct(t, testActStatements(3), testEcdsaPresenceCheck(t, key))[0]
	withAssertion := proto.CloneOf(ed25519Signed)
	withAssertion.Webauthn = proto.CloneOf(webAuthnSigned.Webauthn)
	rewritten := proto.CloneOf(ed25519Signed)
	rewritten.Type = uint32(otherType)

	vectors.Statements = []*testStatementVector{
		{
			Name: "ed25519", KeyAlg: "ed25519", PublicKey: ed25519Public, Purpose: purpose,
			ExpectedType: uint32(signedType), Signed: testHexSigned(t, ed25519Signed),
		},
		{
			Name: "ecdsa-p256-sha256", KeyAlg: "ecdsa-p256-sha256", PublicKey: p256Public, Purpose: purpose,
			ExpectedType: uint32(signedType), Signed: testHexSigned(t, ecdsaSigned),
		},
		{
			Name: "webauthn-es256", KeyAlg: "webauthn-es256", PublicKey: p256Public, Purpose: purpose,
			ExpectedType: uint32(signedType), Signed: testHexSigned(t, webAuthnSigned),
		},
		{
			Name: "ed25519 with a countersignature, which this check does not read", KeyAlg: "ed25519",
			PublicKey: ed25519Public, Purpose: testActStatements(1)[0].purpose,
			ExpectedType: uint32(testActStatements(1)[0].signedType), Signed: testHexSigned(t, countersigned),
		},
		{
			Name: "another type expected", KeyAlg: "ed25519", PublicKey: ed25519Public, Purpose: purpose,
			ExpectedType: uint32(otherType), Signed: testHexSigned(t, ed25519Signed),
			Refusal: "ErrSignedTypeMismatch",
		},
		{
			Name: "type rewritten to the one expected", KeyAlg: "ed25519", PublicKey: ed25519Public, Purpose: purpose,
			ExpectedType: uint32(otherType), Signed: testHexSigned(t, rewritten), Refusal: "ErrSignedSignature",
		},
		{
			Name: "type 0 expected", KeyAlg: "ed25519", PublicKey: ed25519Public, Purpose: purpose,
			ExpectedType: 0, Signed: testHexSigned(t, ed25519Signed), Refusal: "ErrSignedTypeUnknown",
		},
		{
			Name: "an unregistered type expected", KeyAlg: "ed25519", PublicKey: ed25519Public, Purpose: purpose,
			ExpectedType: 0x12FF, Signed: testHexSigned(t, ed25519Signed), Refusal: "ErrSignedTypeUnknown",
		},
		{
			Name: "the countersigned bytes' purpose", KeyAlg: "ed25519", PublicKey: ed25519Public,
			Purpose: "presence-act", ExpectedType: uint32(signedType), Signed: testHexSigned(t, ed25519Signed),
			Refusal: "ErrSignedPurpose",
		},
		{
			Name: "another purpose", KeyAlg: "ed25519", PublicKey: ed25519Public, Purpose: "bridge",
			ExpectedType: uint32(signedType), Signed: testHexSigned(t, ed25519Signed), Refusal: "ErrSignedSignature",
		},
		{
			Name: "an assertion with no key_id beside an identity key's signature", KeyAlg: "ed25519",
			PublicKey: ed25519Public, Purpose: purpose, ExpectedType: uint32(signedType),
			Signed: testHexSigned(t, withAssertion), Refusal: "ErrSignedEvidence",
		},
		{
			Name: "an es256 assertion as ecdsa-p256-sha256", KeyAlg: "ecdsa-p256-sha256", PublicKey: p256Public,
			Purpose: purpose, ExpectedType: uint32(signedType), Signed: testHexSigned(t, webAuthnSigned),
			Refusal: "ErrSignedEvidence",
		},
	}

	for _, size := range []int{1, 2, 3, 7, testActMaxSize} {
		statementDigests := testRuleDigests(size)
		root, err := PresenceActRoot(statementDigests)
		if err != nil {
			t.Fatal(err)
		}
		tree := &testTreeVector{Size: uint32(size), Root: hex.EncodeToString(root[:])}
		indexes := []int{}
		if size <= 7 {
			for index := range size {
				indexes = append(indexes, index)
			}
		} else {
			indexes = []int{0, 1, 32767, 32768, 65533, 65534}
		}
		for _, index := range indexes {
			actPath, err := PresenceActPath(statementDigests, uint32(index))
			if err != nil {
				t.Fatal(err)
			}
			path := &testPathVector{Index: uint32(index), Path: []string{}}
			for _, hash := range actPath {
				path.Path = append(path.Path, hex.EncodeToString(hash))
			}
			tree.Paths = append(tree.Paths, path)
		}
		vectors.Trees = append(vectors.Trees, tree)
	}

	for _, profile := range testPresenceProfiles(t) {
		for _, size := range []int{1, 5} {
			statements := testActStatements(size)
			statementDigests := testActDigests(statements)
			root, err := PresenceActRoot(statementDigests)
			if err != nil {
				t.Fatal(err)
			}
			act := &testActVector{
				Name:               fmt.Sprintf("%d statements, %s", size, profile.name),
				KeyAlg:             profile.name,
				PublicKey:          hex.EncodeToString(profile.publicKey),
				IdentityPublicKey:  hex.EncodeToString(testEd25519Public()),
				SignerId:           hex.EncodeToString(testSignerId),
				KeyId:              hex.EncodeToString(testPresenceKeyId),
				Size:               uint32(size),
				Root:               hex.EncodeToString(root[:]),
				CountersignedBytes: hex.EncodeToString(PresenceActBytes(testSignerId, uint32(size), root)),
			}
			for i, signed := range testCountersignedAct(t, statements, profile.check) {
				act.Statements = append(act.Statements, &testActStatementVector{
					Purpose: statements[i].purpose,
					Type:    uint32(statements[i].signedType),
					Body:    hex.EncodeToString(statements[i].body),
					Digest:  hex.EncodeToString(statementDigests[i][:]),
					Signed:  testHexSigned(t, signed),
				})
			}
			vectors.Acts = append(vectors.Acts, act)
		}
		vectors.Refusals = append(vectors.Refusals, testBuildRefusalVectors(t, profile)...)
	}
	return vectors
}

// One profile's refusals, each a statement of a five-statement act with one input spoiled. For a webauthn-es256 check
// spoiled before it was signed, the signature still holds and only the clause can refuse it.
func testBuildRefusalVectors(t testing.TB, profile *testPresenceProfile) []*testCountersignRefusal {
	statements := testActStatements(5)
	statement := statements[2]
	act := testCountersignedAct(t, statements, profile.check)
	otherBytesRefusal := "ErrSignedSignature"
	if profile.alg == SignedKeyAlgWebAuthnEs256 {
		otherBytesRefusal = "ErrSignedEvidence"
	}
	otherKey, _ := testOtherP256Key(t)

	refusal := func(name string, want string, signed *Signed) *testCountersignRefusal {
		return &testCountersignRefusal{
			Name:      name + ", " + profile.name,
			KeyAlg:    profile.name,
			PublicKey: hex.EncodeToString(profile.publicKey),
			Purpose:   statement.purpose,
			Signed:    testHexSigned(t, signed),
			Refusal:   want,
		}
	}
	spoiled := func(mutate func(signed *Signed)) *Signed {
		signed := proto.CloneOf(act[2])
		mutate(signed)
		return signed
	}

	otherStatements := testActStatements(5)
	for _, otherStatement := range otherStatements {
		otherStatement.body = append(otherStatement.body, []byte(" of another act")...)
	}
	otherAct := testCountersignedAct(t, otherStatements, profile.check)

	var otherKeyCheck testPresenceCheck
	if profile.alg == SignedKeyAlgEcdsaP256 {
		otherKeyCheck = testEcdsaPresenceCheck(t, otherKey)
	} else {
		otherKeyCheck = testWebAuthnPresenceCheck(t, otherKey, nil)
	}

	refusals := []*testCountersignRefusal{
		refusal(
			"no countersignature",
			"ErrSignedEvidence",
			testSignEd25519(statement.purpose, statement.signedType, statement.body),
		),
		refusal("another key", "ErrSignedSignature", testCountersignedAct(t, statements, otherKeyCheck)[2]),
		refusal("another act's root", otherBytesRefusal, spoiled(func(signed *Signed) {
			signed.Webauthn.Signature = otherAct[2].Webauthn.Signature
			signed.Webauthn.AuthenticatorData = otherAct[2].Webauthn.AuthenticatorData
			signed.Webauthn.ClientDataJson = otherAct[2].Webauthn.ClientDataJson
		})),
		refusal("another signer's act", otherBytesRefusal, spoiled(func(signed *Signed) {
			signed.SignerId = []byte("another-synthetic-signer")
		})),
		refusal("a path that misses its leaf", otherBytesRefusal, spoiled(func(signed *Signed) {
			signed.Webauthn.ActPath[0][0] ^= 0x01
		})),
		refusal("index off by one", otherBytesRefusal, spoiled(func(signed *Signed) {
			signed.Webauthn.ActIndex += 1
		})),
		refusal("size off by one", otherBytesRefusal, spoiled(func(signed *Signed) {
			signed.Webauthn.ActSize += 1
		})),
		refusal("a path too short", "ErrSignedAct", spoiled(func(signed *Signed) {
			signed.Webauthn.ActPath = signed.Webauthn.ActPath[:1]
		})),
		refusal("17 hashes", "ErrSignedAct", spoiled(func(signed *Signed) {
			for len(signed.Webauthn.ActPath) < 17 {
				signed.Webauthn.ActPath = append(signed.Webauthn.ActPath, make([]byte, sha256.Size))
			}
		})),
		refusal("an act of 0", "ErrSignedAct", spoiled(func(signed *Signed) {
			signed.Webauthn.ActSize = 0
		})),
		refusal("an act of 65,536", "ErrSignedAct", spoiled(func(signed *Signed) {
			signed.Webauthn.ActSize = 65536
		})),
		refusal("the index past the act", "ErrSignedAct", spoiled(func(signed *Signed) {
			signed.Webauthn.ActIndex = signed.Webauthn.ActSize
		})),
	}

	if profile.alg == SignedKeyAlgWebAuthnEs256 {
		key, _ := testP256Key(t)
		spoiledCheck := func(mutate func(assertion *testWebAuthnAssertion)) *Signed {
			return testCountersignedAct(t, statements, testWebAuthnPresenceCheck(t, key, mutate))[2]
		}
		refusals = append(
			refusals,
			refusal("UV clear", "ErrSignedEvidence", spoiledCheck(func(assertion *testWebAuthnAssertion) {
				assertion.flags = webAuthnFlagUserPresent
			})),
			refusal("UP clear", "ErrSignedEvidence", spoiledCheck(func(assertion *testWebAuthnAssertion) {
				assertion.flags = webAuthnFlagUserVerified
			})),
			refusal("another rp id", "ErrSignedEvidence", spoiledCheck(func(assertion *testWebAuthnAssertion) {
				assertion.rpId = "rp.example"
			})),
			refusal("an unlisted origin", "ErrSignedEvidence", spoiledCheck(func(assertion *testWebAuthnAssertion) {
				assertion.origin = "https://app.example"
			})),
			refusal("another client data type", "ErrSignedEvidence", spoiledCheck(func(assertion *testWebAuthnAssertion) {
				assertion.clientType = "webauthn.create"
			})),
			refusal("another challenge", "ErrSignedEvidence", spoiledCheck(func(assertion *testWebAuthnAssertion) {
				digest := SignedBytesSha256(statement.purpose, statement.signedType, statement.body)
				assertion.challenge = base64.RawURLEncoding.EncodeToString(digest[:])
			})),
			refusal("tampered client data", "ErrSignedSignature", spoiled(func(signed *Signed) {
				clientDataJson := signed.Webauthn.ClientDataJson
				signed.Webauthn.ClientDataJson = bytes.Replace(clientDataJson, []byte(`"origin"`), []byte(`"origin" `), 1)
			})),
		)
	}
	return refusals
}

// The file as it stands.
func testReadSignedVectors(t testing.TB) *testSignedVectors {
	encoded, err := os.ReadFile(testSignedVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testSignedVectors{}
	if err := json.Unmarshal(encoded, vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// §22's byte-equal rule: this leg's signed bytes, trees, countersigned bytes, signatures and encodings are the file's,
// to the byte.
func TestSignedVectorsAreByteEqual(t *testing.T) {
	built, err := json.MarshalIndent(testBuildSignedVectors(t), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	built = append(built, '\n')
	if *testUpdateSignedVectors {
		if err := os.WriteFile(testSignedVectorsPath, built, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.ReadFile(testSignedVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(built, file) {
		first := 0
		for first < len(built) && first < len(file) && built[first] == file[first] {
			first += 1
		}
		t.Fatalf("this leg differs from the file at byte %d: %q", first, built[first:min(first+80, len(built))])
	}
}

// A vector's Signed, as it comes off the wire.
func testParseVectorSigned(t testing.TB, value string) *Signed {
	signed := &Signed{}
	if err := proto.Unmarshal(testFromHex(t, value), signed); err != nil {
		t.Fatal(err)
	}
	return signed
}

// The file as a consumer reads it: every statement answers as it says, and every act verifies statement by statement
// from nothing but public keys, each in a different order from its build.
func TestSignedVectorsVerify(t *testing.T) {
	vectors := testReadSignedVectors(t)

	for _, vector := range vectors.SignedBytes {
		body := testFromHex(t, vector.Body)
		signedBytes := SignedBytes(vector.Purpose, SignedType(vector.Type), body)
		if hex.EncodeToString(signedBytes) != vector.SignedBytes {
			t.Errorf("%s %#x: signed bytes %x", vector.Purpose, vector.Type, signedBytes)
		}
		digest := SignedBytesSha256(vector.Purpose, SignedType(vector.Type), body)
		if hex.EncodeToString(digest[:]) != vector.Sha256 {
			t.Errorf("%s %#x: sha256 %x", vector.Purpose, vector.Type, digest)
		}
	}

	for _, vector := range vectors.Statements {
		err := VerifySigned(
			testParseVectorSigned(t, vector.Signed),
			vector.Purpose,
			SignedType(vector.ExpectedType),
			testVectorKeyAlgs[vector.KeyAlg],
			testFromHex(t, vector.PublicKey),
		)
		if !errors.Is(err, testVectorRefusals[vector.Refusal]) {
			t.Errorf("%s: got %v, want %s", vector.Name, err, vector.Refusal)
		}
	}

	for _, vector := range vectors.Acts {
		root := [sha256.Size]byte(testFromHex(t, vector.Root))
		countersignedBytes := PresenceActBytes(testFromHex(t, vector.SignerId), vector.Size, root)
		if hex.EncodeToString(countersignedBytes) != vector.CountersignedBytes {
			t.Errorf("%s: countersigned bytes %x", vector.Name, countersignedBytes)
		}
		statementDigests := [][sha256.Size]byte{}
		for _, statement := range vector.Statements {
			statementDigests = append(statementDigests, [sha256.Size]byte(testFromHex(t, statement.Digest)))
		}
		builtRoot, err := PresenceActRoot(statementDigests)
		if err != nil {
			t.Fatal(err)
		}
		if builtRoot != root {
			t.Errorf("%s: root %x", vector.Name, builtRoot)
		}
		for _, statement := range slices.Backward(vector.Statements) {
			signed := testParseVectorSigned(t, statement.Signed)
			err := VerifySigned(
				signed,
				statement.Purpose,
				SignedType(statement.Type),
				SignedKeyAlgEd25519,
				testFromHex(t, vector.IdentityPublicKey),
			)
			if err != nil {
				t.Errorf("%s statement: identity signature: %v", vector.Name, err)
			}
			err = VerifyPresenceCountersign(
				signed,
				statement.Purpose,
				testVectorKeyAlgs[vector.KeyAlg],
				testFromHex(t, vector.PublicKey),
			)
			if err != nil {
				t.Errorf("%s statement: %v", vector.Name, err)
			}
		}
	}

	for _, vector := range vectors.Refusals {
		err := VerifyPresenceCountersign(
			testParseVectorSigned(t, vector.Signed),
			vector.Purpose,
			testVectorKeyAlgs[vector.KeyAlg],
			testFromHex(t, vector.PublicKey),
		)
		if err == nil || !errors.Is(err, testVectorRefusals[vector.Refusal]) {
			t.Errorf("%s: got %v, want %s", vector.Name, err, vector.Refusal)
		}
	}
}

// RFC 9162 path vectors at each of the task's sizes: every path walks from its leaf to the file's root, an index one
// either way misses, one hash more than the path holds is refused, and 17 hashes are refused whatever the size.
func TestSignedVectorsWalk(t *testing.T) {
	sizes := []uint32{}
	for _, tree := range testReadSignedVectors(t).Trees {
		sizes = append(sizes, tree.Size)
		root := [sha256.Size]byte(testFromHex(t, tree.Root))
		for _, vector := range tree.Paths {
			actPath := [][]byte{}
			for _, hash := range vector.Path {
				actPath = append(actPath, testFromHex(t, hash))
			}
			statementDigest := SignedBytesSha256(
				"authority",
				SignedType_SIGNED_SIDECAR_REVOKE,
				binary.BigEndian.AppendUint32(nil, vector.Index),
			)
			leaf := presenceActLeafHash(statementDigest)
			walked, err := presenceActPathRoot(leaf, vector.Index, tree.Size, actPath)
			if err != nil {
				t.Errorf("size %d index %d: %v", tree.Size, vector.Index, err)
			} else if walked != root {
				t.Errorf("size %d index %d: walked to %x", tree.Size, vector.Index, walked)
			}
			for _, otherIndex := range []uint32{vector.Index - 1, vector.Index + 1} {
				walked, err := presenceActPathRoot(leaf, otherIndex, tree.Size, actPath)
				if err == nil && walked == root {
					t.Errorf("size %d index %d reached the root as index %d", tree.Size, vector.Index, otherIndex)
				}
			}
			_, err = presenceActPathRoot(leaf, vector.Index, tree.Size, append(actPath, make([]byte, sha256.Size)))
			if !errors.Is(err, ErrSignedAct) {
				t.Errorf("size %d index %d, one hash more: %v", tree.Size, vector.Index, err)
			}
			seventeen := append(actPath, make([][]byte, 17-len(actPath))...)
			for i := len(actPath); i < 17; i++ {
				seventeen[i] = make([]byte, sha256.Size)
			}
			_, err = presenceActPathRoot(leaf, vector.Index, tree.Size, seventeen)
			if !errors.Is(err, ErrSignedAct) {
				t.Errorf("size %d index %d, 17 hashes: %v", tree.Size, vector.Index, err)
			}
		}
	}
	if !slices.Equal(sizes, []uint32{1, 2, 3, 7, testActMaxSize}) {
		t.Errorf("trees at %v", sizes)
	}
}
