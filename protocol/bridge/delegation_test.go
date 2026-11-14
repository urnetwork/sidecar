// VerifyWindowDelegation and WindowDelegationSigned (§17.9's sign and verify rows, D-BRIDGE-17): each mismatch alone
// beside a positive twin, a share certificate presented as a delegation (§22.6's type confusion), and
// testdata/bridge/delegation/vectors.json, fixed vectors a verifier on any leg reads as a consumer does.
// TestWindowDelegationVectorsAreByteEqual rebuilds the file, whose Ed25519 signatures are deterministic, and holds it to
// its bytes, so a change to the layout cannot pass by changing signer and verifier together.
//
// To rewrite the file after a deliberate format change, with its diff reviewed:
//
//	go test ./protocol/bridge -run '^TestWindowDelegationVectorsAreByteEqual$' -update-delegation-vectors

package bridge

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Relative to this package, as go test runs it on every leg.
const testDelegationVectorsPath = "../../testdata/bridge/delegation/vectors.json"

// Rewrites the vector file from this leg in place of comparing it.
var testUpdateDelegationVectors = flag.Bool(
	"update-delegation-vectors",
	false,
	"rewrite testdata/bridge/delegation/vectors.json, then read its diff",
)

// The host's time in every case, and a week, a window client's longest life (§7.4).
const (
	testDelegationNowMs  = 1_800_000_000_000
	testDelegationWeekMs = 7 * 24 * 60 * 60 * 1000
)

// Synthetic ids and keys, each a repeated byte (CODESTYLE's test data rule).
var (
	testDelegationNetworkId    = bytes.Repeat([]byte{0x0d}, 16)
	testDelegationSubjectId    = bytes.Repeat([]byte{0x5a}, 16)
	testDelegationWindowId     = bytes.Repeat([]byte{0xc0}, 16)
	testDelegationTargetId     = bytes.Repeat([]byte{0x7a}, 16)
	testDelegationOtherId      = bytes.Repeat([]byte{0x3b}, 16)
	testDelegationSubjectKey   = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	testDelegationWindowKey    = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xc1}, ed25519.SeedSize))
	testDelegationOtherKey     = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
	testDelegationOtherNetwork = bytes.Repeat([]byte{0x0e}, 16)
)

// The delegation every case starts from, valid against testDelegationCheck.
func testDelegation() *WindowDelegation {
	return &WindowDelegation{
		NetworkId:             testDelegationNetworkId,
		SubjectSidecarId:      testDelegationSubjectId,
		WindowClientId:        testDelegationWindowId,
		WindowClientPublicKey: testDelegationWindowKey.Public().(ed25519.PublicKey),
		TargetSidecarId:       testDelegationTargetId,
		NotAfterMs:            testDelegationNowMs + testDelegationWeekMs,
	}
}

// The host's check: the subject is the one admitted identity.
func testDelegationCheck() *WindowDelegationCheck {
	return &WindowDelegationCheck{
		NetworkId:             testDelegationNetworkId,
		WindowClientId:        testDelegationWindowId,
		WindowClientPublicKey: testDelegationWindowKey.Public().(ed25519.PublicKey),
		TargetSidecarId:       testDelegationTargetId,
		NowMs:                 testDelegationNowMs,
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			if bytes.Equal(sidecarId, testDelegationSubjectId) {
				return testDelegationSubjectKey.Public().(ed25519.PublicKey), true
			}
			return nil, false
		},
	}
}

// A Signed's bytes over body as signedType, by key under signerId.
func testDelegationSign(t testing.TB, key ed25519.PrivateKey, signerId []byte, signedType SignedType, body []byte) []byte {
	t.Helper()
	signed := &Signed{
		Body:      body,
		SignerId:  signerId,
		Signature: ed25519.Sign(key, SignedBytes(SignedPurposeWindowDelegation, signedType, body)),
		Type:      uint32(signedType),
	}
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return signedBytes
}

// The delegation's body, encoded deterministically.
func testDelegationBody(t testing.TB, delegation *WindowDelegation) []byte {
	t.Helper()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A delegation signed as its subject signs one.
func testDelegationSigned(t testing.TB, delegation *WindowDelegation) []byte {
	t.Helper()
	return testDelegationSign(t, testDelegationSubjectKey, testDelegationSubjectId, SignedType_SIGNED_WINDOW_DELEGATION,
		testDelegationBody(t, delegation))
}

// The refusal an error names, as the vector file writes it.
func testDelegationRefusal(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrWindowDelegationMalformed):
		return "malformed"
	case errors.Is(err, ErrWindowDelegationSigner):
		return "signer"
	case errors.Is(err, ErrWindowDelegationMismatch):
		return "mismatch"
	case errors.Is(err, ErrWindowDelegationExpired):
		return "expired"
	case errors.Is(err, ErrWindowDelegationShare):
		return "share"
	case errors.Is(err, ErrSignedTypeMismatch):
		return "type"
	case errors.Is(err, ErrSignedSignature):
		return "signature"
	default:
		return "other: " + err.Error()
	}
}

// One case: a delegation's bytes as a contract carries them, and what the check answers.
type testDelegationCase struct {
	Name    string `json:"name"`
	Signed  string `json:"signed"`
	Refusal string `json:"refusal"`
}

// The file. Every bytes value is lowercase hex.
type testDelegationVectors struct {
	Comment string `json:"comment"`
	NowMs   int64  `json:"now_ms"`
	// the one admitted subject, by sidecar_id, and its identity key
	SubjectSidecarId string                `json:"subject_sidecar_id"`
	SubjectPublicKey string                `json:"subject_public_key"`
	NetworkId        string                `json:"network_id"`
	WindowClientId   string                `json:"window_client_id"`
	WindowClientKey  string                `json:"window_client_public_key"`
	TargetSidecarId  string                `json:"target_sidecar_id"`
	Cases            []*testDelegationCase `json:"cases"`
}

// The cases, built from fixed seeds: the positive twin first, then each fault alone.
func testDelegationVectorCases(t testing.TB) []*testDelegationCase {
	t.Helper()
	cases := []*testDelegationCase{}
	add := func(name string, signedBytes []byte, refusal string) {
		cases = append(cases, &testDelegationCase{Name: name, Signed: hex.EncodeToString(signedBytes), Refusal: refusal})
	}
	mutated := func(mutate func(delegation *WindowDelegation)) []byte {
		delegation := testDelegation()
		mutate(delegation)
		return testDelegationSigned(t, delegation)
	}

	add("valid", testDelegationSigned(t, testDelegation()), "")
	add("window client key mismatched", mutated(func(delegation *WindowDelegation) {
		delegation.WindowClientPublicKey = testDelegationOtherKey.Public().(ed25519.PublicKey)
	}), "mismatch")
	add("expired", mutated(func(delegation *WindowDelegation) {
		delegation.NotAfterMs = testDelegationNowMs
	}), "expired")
	add("wrong target", mutated(func(delegation *WindowDelegation) {
		delegation.TargetSidecarId = testDelegationOtherId
	}), "mismatch")
	add("wrong network", mutated(func(delegation *WindowDelegation) {
		delegation.NetworkId = testDelegationOtherNetwork
	}), "mismatch")
	add("wrong source", mutated(func(delegation *WindowDelegation) {
		delegation.WindowClientId = testDelegationOtherId
	}), "mismatch")
	add("share certificate type", testDelegationSign(t, testDelegationSubjectKey, testDelegationSubjectId,
		SignedType_SIGNED_SHARE_CERT, testDelegationBody(t, testDelegation())), "type")

	badSignature := &Signed{}
	if err := proto.Unmarshal(testDelegationSigned(t, testDelegation()), badSignature); err != nil {
		t.Fatal(err)
	}
	badSignature.Signature[0] ^= 0x01
	add("bad signature", testDelegationMarshal(t, badSignature), "signature")

	add("another key under the subject's id", testDelegationSign(t, testDelegationOtherKey, testDelegationSubjectId,
		SignedType_SIGNED_WINDOW_DELEGATION, testDelegationBody(t, testDelegation())), "signature")

	relabeled := &Signed{}
	if err := proto.Unmarshal(testDelegationSign(t, testDelegationSubjectKey, testDelegationSubjectId,
		SignedType_SIGNED_SHARE_CERT, testDelegationBody(t, testDelegation())), relabeled); err != nil {
		t.Fatal(err)
	}
	relabeled.Type = uint32(SignedType_SIGNED_WINDOW_DELEGATION)
	add("share certificate relabeled as a delegation", testDelegationMarshal(t, relabeled), "signature")

	unknownSigner := testDelegation()
	unknownSigner.SubjectSidecarId = testDelegationOtherId
	add("a subject not admitted", testDelegationSign(t, testDelegationOtherKey, testDelegationOtherId,
		SignedType_SIGNED_WINDOW_DELEGATION, testDelegationBody(t, unknownSigner)), "signer")

	add("signed by another than its subject", mutated(func(delegation *WindowDelegation) {
		delegation.SubjectSidecarId = testDelegationOtherId
	}), "signer")
	add("a share", mutated(func(delegation *WindowDelegation) {
		delegation.ShareId = testDelegationOtherId
	}), "share")

	withKeyId := &Signed{}
	if err := proto.Unmarshal(testDelegationSigned(t, testDelegation()), withKeyId); err != nil {
		t.Fatal(err)
	}
	withKeyId.KeyId = bytes.Repeat([]byte{0x4b}, 32)
	add("a share signer's key_id", testDelegationMarshal(t, withKeyId), "share")

	unknownField := protowire.AppendTag(testDelegationBody(t, testDelegation()), 99, protowire.VarintType)
	unknownField = protowire.AppendVarint(unknownField, 1)
	add("a field the verifier does not know", testDelegationSign(t, testDelegationSubjectKey, testDelegationSubjectId,
		SignedType_SIGNED_WINDOW_DELEGATION, unknownField), "malformed")
	return cases
}

// A message's deterministic bytes.
func testDelegationMarshal(t testing.TB, message proto.Message) []byte {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// The whole file's bytes, built on this leg.
func testDelegationVectorBytes(t testing.TB) []byte {
	t.Helper()
	check := testDelegationCheck()
	vectors := &testDelegationVectors{
		Comment: "WindowDelegation vectors (sidecar design §17.9, D-BRIDGE-17): each case's signed is the Signed bytes " +
			"a contract carries, verified against the host's view below, subject_sidecar_id being the one admitted " +
			"identity, at now_ms; refusal names the check that refuses it, empty for one that verifies. Synthetic " +
			"ids and keys from fixed seeds.",
		NowMs:            check.NowMs,
		SubjectSidecarId: hex.EncodeToString(testDelegationSubjectId),
		SubjectPublicKey: hex.EncodeToString(testDelegationSubjectKey.Public().(ed25519.PublicKey)),
		NetworkId:        hex.EncodeToString(check.NetworkId),
		WindowClientId:   hex.EncodeToString(check.WindowClientId),
		WindowClientKey:  hex.EncodeToString(check.WindowClientPublicKey),
		TargetSidecarId:  hex.EncodeToString(check.TargetSidecarId),
		Cases:            testDelegationVectorCases(t),
	}
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func TestWindowDelegationVectorsAreByteEqual(t *testing.T) {
	built := testDelegationVectorBytes(t)
	if *testUpdateDelegationVectors {
		if err := os.WriteFile(testDelegationVectorsPath, built, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	held, err := os.ReadFile(testDelegationVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(built, held) {
		t.Fatalf("%s differs from what this leg builds; rewrite it with -update-delegation-vectors and read the diff", testDelegationVectorsPath)
	}
}

// The file read as a consumer reads it, with the public keys it holds and nothing else.
func TestWindowDelegationVectorsVerify(t *testing.T) {
	held, err := os.ReadFile(testDelegationVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testDelegationVectors{}
	if err := json.Unmarshal(held, vectors); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	subjectId, subjectKey := decode(vectors.SubjectSidecarId), decode(vectors.SubjectPublicKey)
	check := &WindowDelegationCheck{
		NetworkId:             decode(vectors.NetworkId),
		WindowClientId:        decode(vectors.WindowClientId),
		WindowClientPublicKey: decode(vectors.WindowClientKey),
		TargetSidecarId:       decode(vectors.TargetSidecarId),
		NowMs:                 vectors.NowMs,
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			return subjectKey, bytes.Equal(sidecarId, subjectId)
		},
	}
	if len(vectors.Cases) < 2 || vectors.Cases[0].Refusal != "" {
		t.Fatal("the file holds no positive twin first")
	}
	for _, testCase := range vectors.Cases {
		delegation, err := VerifyWindowDelegation(decode(testCase.Signed), check)
		if got := testDelegationRefusal(err); got != testCase.Refusal {
			t.Errorf("%s: refusal %q, want %q", testCase.Name, got, testCase.Refusal)
		}
		if (err == nil) != (delegation != nil) {
			t.Errorf("%s: a delegation beside the error %v", testCase.Name, err)
		}
	}
}

// The positive twin: every field checked, and the delegation returned as signed.
func TestVerifyWindowDelegationPasses(t *testing.T) {
	delegation, err := VerifyWindowDelegation(testDelegationSigned(t, testDelegation()), testDelegationCheck())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(delegation, testDelegation()) {
		t.Fatalf("returned %v", delegation)
	}
}

// Each value the check holds, changed alone, refuses with its own error, and the twin of each passes.
func TestVerifyWindowDelegationRefusesEachMismatchAlone(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(check *WindowDelegationCheck)
		refusal error
	}{
		{name: "network", mutate: func(check *WindowDelegationCheck) { check.NetworkId = testDelegationOtherNetwork }, refusal: ErrWindowDelegationMismatch},
		{name: "unsealed network", mutate: func(check *WindowDelegationCheck) { check.NetworkId = make([]byte, 16) }, refusal: ErrWindowDelegationMismatch},
		{name: "source", mutate: func(check *WindowDelegationCheck) { check.WindowClientId = testDelegationOtherId }, refusal: ErrWindowDelegationMismatch},
		{name: "session key", mutate: func(check *WindowDelegationCheck) {
			check.WindowClientPublicKey = testDelegationOtherKey.Public().(ed25519.PublicKey)
		}, refusal: ErrWindowDelegationMismatch},
		{name: "no session key", mutate: func(check *WindowDelegationCheck) { check.WindowClientPublicKey = nil }, refusal: ErrWindowDelegationMismatch},
		{name: "target", mutate: func(check *WindowDelegationCheck) { check.TargetSidecarId = testDelegationOtherId }, refusal: ErrWindowDelegationMismatch},
		{name: "expired at its not_after", mutate: func(check *WindowDelegationCheck) {
			check.NowMs = testDelegationNowMs + testDelegationWeekMs
		}, refusal: ErrWindowDelegationExpired},
		{name: "revoked or suspended subject", mutate: func(check *WindowDelegationCheck) {
			check.IdentityKey = func(sidecarId []byte) ([]byte, bool) { return nil, false }
		}, refusal: ErrWindowDelegationSigner},
		{name: "another pinned key", mutate: func(check *WindowDelegationCheck) {
			check.IdentityKey = func(sidecarId []byte) ([]byte, bool) {
				return testDelegationOtherKey.Public().(ed25519.PublicKey), true
			}
		}, refusal: ErrSignedSignature},
	}
	signedBytes := testDelegationSigned(t, testDelegation())
	for _, testCase := range cases {
		check := testDelegationCheck()
		testCase.mutate(check)
		if _, err := VerifyWindowDelegation(signedBytes, check); !errors.Is(err, testCase.refusal) {
			t.Errorf("%s: %v, want %v", testCase.name, err, testCase.refusal)
		}
		// the twin: the same check, unchanged, passes
		if _, err := VerifyWindowDelegation(signedBytes, testDelegationCheck()); err != nil {
			t.Errorf("%s's twin: %v", testCase.name, err)
		}
	}
}

// §22.6's type confusion: a share certificate's Signed, of type 0x1909 under the same purpose, is never a delegation,
// whether presented as it is or with its type field rewritten.
func TestWindowDelegationRefusesAShareCertificate(t *testing.T) {
	shareCert := testDelegationMarshal(t, &ShareCert{
		ShareId:          testDelegationOtherId,
		ConfigGeneration: 3,
		SignerPublicKey:  testDelegationOtherKey.Public().(ed25519.PublicKey),
		NotAfterMs:       testDelegationNowMs + testDelegationWeekMs,
	})
	asCert := testDelegationSign(t, testDelegationSubjectKey, testDelegationSubjectId, SignedType_SIGNED_SHARE_CERT, shareCert)
	if _, err := VerifyWindowDelegation(asCert, testDelegationCheck()); !errors.Is(err, ErrSignedTypeMismatch) {
		t.Fatalf("a share certificate as itself: %v", err)
	}
	relabeled := &Signed{}
	if err := proto.Unmarshal(asCert, relabeled); err != nil {
		t.Fatal(err)
	}
	relabeled.Type = uint32(SignedType_SIGNED_WINDOW_DELEGATION)
	if _, err := VerifyWindowDelegation(testDelegationMarshal(t, relabeled), testDelegationCheck()); !errors.Is(err, ErrSignedSignature) {
		t.Fatalf("a share certificate relabeled: %v", err)
	}
}

// Bytes that are no Signed delegation refuse before any key is looked up.
func TestVerifyWindowDelegationRefusesWhatIsNoDelegation(t *testing.T) {
	lookups := 0
	check := testDelegationCheck()
	identityKey := check.IdentityKey
	check.IdentityKey = func(sidecarId []byte) ([]byte, bool) {
		lookups += 1
		return identityKey(sidecarId)
	}
	oversize := bytes.Repeat([]byte{0x0a}, DefaultWindowDelegationSettings().MaxByteCount+1)
	shortSigner := &Signed{}
	if err := proto.Unmarshal(testDelegationSigned(t, testDelegation()), shortSigner); err != nil {
		t.Fatal(err)
	}
	shortSigner.SignerId = shortSigner.SignerId[:8]
	cases := []struct {
		name    string
		signed  []byte
		refusal error
	}{
		{name: "none", signed: nil, refusal: ErrWindowDelegationMalformed},
		{name: "past the bound", signed: oversize, refusal: ErrWindowDelegationMalformed},
		{name: "garbage", signed: []byte{0xff, 0xff, 0xff}, refusal: ErrWindowDelegationMalformed},
		{name: "a short signer_id", signed: testDelegationMarshal(t, shortSigner), refusal: ErrWindowDelegationMalformed},
	}
	for _, testCase := range cases {
		if _, err := VerifyWindowDelegation(testCase.signed, check); !errors.Is(err, testCase.refusal) {
			t.Errorf("%s: %v", testCase.name, err)
		}
	}
	if lookups != 0 {
		t.Fatalf("%d key lookups for bytes that are no delegation", lookups)
	}
	if _, err := VerifyWindowDelegation(testDelegationSigned(t, testDelegation()), nil); !errors.Is(err, ErrWindowDelegationMismatch) {
		t.Fatalf("no check: %v", err)
	}
}

// What WindowDelegationSigned writes verifies, and it refuses a delegation it would write wrongly or a signer that
// hands back another statement.
func TestWindowDelegationSignedRoundTrips(t *testing.T) {
	sign := func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		return &Signed{
			Body:      body,
			SignerId:  testDelegationSubjectId,
			Signature: ed25519.Sign(testDelegationSubjectKey, SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
	signedBytes, err := WindowDelegationSigned(testDelegation(), sign, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signedBytes, testDelegationSigned(t, testDelegation())) {
		t.Fatal("not the bytes a subject's Sign writes")
	}
	if _, err := VerifyWindowDelegation(signedBytes, testDelegationCheck()); err != nil {
		t.Fatal(err)
	}

	otherType := func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		signed, err := sign(purpose, signedType, body)
		signed.Type = uint32(SignedType_SIGNED_SHARE_CERT)
		return signed, err
	}
	otherBody := func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		return sign(purpose, signedType, append(bytes.Clone(body), 0x00))
	}
	for name, signer := range map[string]func(string, SignedType, []byte) (*Signed, error){
		"another type": otherType, "another body": otherBody,
	} {
		if _, err := WindowDelegationSigned(testDelegation(), signer, nil); !errors.Is(err, ErrWindowDelegationMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	malformed := []func(delegation *WindowDelegation){
		func(delegation *WindowDelegation) { delegation.NetworkId = nil },
		func(delegation *WindowDelegation) {
			delegation.WindowClientPublicKey = delegation.WindowClientPublicKey[:31]
		},
		func(delegation *WindowDelegation) { delegation.NotAfterMs = 0 },
	}
	for i, mutate := range malformed {
		delegation := testDelegation()
		mutate(delegation)
		if _, err := WindowDelegationSigned(delegation, sign, nil); !errors.Is(err, ErrWindowDelegationMalformed) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	withShare := testDelegation()
	withShare.ShareId = testDelegationOtherId
	if _, err := WindowDelegationSigned(withShare, sign, nil); !errors.Is(err, ErrWindowDelegationShare) {
		t.Fatalf("a share: %v", err)
	}
}
