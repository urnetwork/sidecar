// VerifyWindowDelegation's forwarding path (§17.9's verify row, D-BRIDGE-17, owner decision 197; DESIGN-DETAILS
// 4.2.2): a delegation whose signer_id is a 32-byte delegation_id verifies only under the forwarding key the host's
// state lists for that id, for the sidecar it is listed under, with key_id that key's SHA-256. Each mismatch alone
// refuses beside its positive twin, the path is chosen by the signer's length and never by trying keys (QD-093), and
// testdata/bridge/delegation/forwarding_vectors.json holds fixed vectors a verifier on any leg reads as a consumer
// does.
//
// To rewrite the file after a deliberate format change, with its diff reviewed:
//
//	go test ./protocol/bridge -run '^TestForwardingDelegationVectorsAreByteEqual$' -update-delegation-vectors

package bridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"google.golang.org/protobuf/proto"
)

// Relative to this package, as go test runs it on every leg.
const testForwardVectorsPath = "../../testdata/bridge/delegation/forwarding_vectors.json"

// Synthetic forwarding Delegations: the subject's live one, another sidecar's live one, and one the state lists
// nowhere, as a superseded or revoked one is.
var (
	testForwardDelegationId      = bytes.Repeat([]byte{0xf1}, sha256.Size)
	testForwardKey               = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xf2}, ed25519.SeedSize))
	testForwardOtherDelegationId = bytes.Repeat([]byte{0xe1}, sha256.Size)
	testForwardOtherKey          = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xe2}, ed25519.SeedSize))
	testForwardGoneDelegationId  = bytes.Repeat([]byte{0xd1}, sha256.Size)
	testForwardGoneKey           = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xd2}, ed25519.SeedSize))
)

// The host's check with the subject's and another sidecar's forwarding Delegations live.
func testForwardCheck() *WindowDelegationCheck {
	check := testDelegationCheck()
	check.ForwardingKey = func(delegationId []byte) ([]byte, []byte, bool) {
		switch {
		case bytes.Equal(delegationId, testForwardDelegationId):
			return testDelegationSubjectId, testForwardKey.Public().(ed25519.PublicKey), true
		case bytes.Equal(delegationId, testForwardOtherDelegationId):
			return testDelegationOtherId, testForwardOtherKey.Public().(ed25519.PublicKey), true
		default:
			return nil, nil, false
		}
	}
	return check
}

// A Signed's bytes over body as signedType, by key, as a forwarding signer writes one: signer_id the Delegation's id
// and key_id the SHA-256 of keyIdOf.
func testForwardSign(t testing.TB, key ed25519.PrivateKey, delegationId []byte, keyIdOf ed25519.PublicKey, signedType SignedType, body []byte) []byte {
	t.Helper()
	keyId := sha256.Sum256(keyIdOf)
	return testDelegationMarshal(t, &Signed{
		Body:      body,
		SignerId:  delegationId,
		KeyId:     keyId[:],
		Signature: ed25519.Sign(key, SignedBytes(SignedPurposeWindowDelegation, signedType, body)),
		Type:      uint32(signedType),
	})
}

// A delegation signed by the subject's live forwarding key.
func testForwardSigned(t testing.TB, delegation *WindowDelegation) []byte {
	t.Helper()
	return testForwardSign(t, testForwardKey, testForwardDelegationId, testForwardKey.Public().(ed25519.PublicKey),
		SignedType_SIGNED_WINDOW_DELEGATION, testDelegationBody(t, delegation))
}

// The file. Every bytes value is lowercase hex.
type testForwardVectors struct {
	Comment string `json:"comment"`
	NowMs   int64  `json:"now_ms"`
	// the one admitted subject, its identity key, and the forwarding Delegation the state lists live for it
	SubjectSidecarId    string                `json:"subject_sidecar_id"`
	SubjectPublicKey    string                `json:"subject_public_key"`
	ForwardDelegationId string                `json:"forward_delegation_id"`
	ForwardPublicKey    string                `json:"forward_public_key"`
	NetworkId           string                `json:"network_id"`
	WindowClientId      string                `json:"window_client_id"`
	WindowClientKey     string                `json:"window_client_public_key"`
	TargetSidecarId     string                `json:"target_sidecar_id"`
	Cases               []*testDelegationCase `json:"cases"`
}

// The cases, built from fixed seeds: the positive twin first, then each fault alone. The file's host lists one
// forwarding Delegation, the subject's, so another sidecar's and a superseded or revoked one are ids it does not list.
func testForwardVectorCases(t testing.TB) []*testDelegationCase {
	t.Helper()
	cases := []*testDelegationCase{}
	add := func(name string, signedBytes []byte, refusal string) {
		cases = append(cases, &testDelegationCase{Name: name, Signed: hex.EncodeToString(signedBytes), Refusal: refusal})
	}
	forwardPublicKey := testForwardKey.Public().(ed25519.PublicKey)
	body := testDelegationBody(t, testDelegation())

	add("valid under the forwarding key", testForwardSigned(t, testDelegation()), "")
	add("a forwarding Delegation the state does not list", testForwardSign(t, testForwardGoneKey, testForwardGoneDelegationId,
		testForwardGoneKey.Public().(ed25519.PublicKey), SignedType_SIGNED_WINDOW_DELEGATION, body), "signer")
	add("another key under the forwarding Delegation's id", testForwardSign(t, testForwardGoneKey, testForwardDelegationId,
		forwardPublicKey, SignedType_SIGNED_WINDOW_DELEGATION, body), "signature")
	add("a key_id that is another key's", testForwardSign(t, testForwardKey, testForwardDelegationId,
		testForwardGoneKey.Public().(ed25519.PublicKey), SignedType_SIGNED_WINDOW_DELEGATION, body), "signer")
	add("the identity key under the forwarding Delegation's id", testForwardSign(t, testDelegationSubjectKey, testForwardDelegationId,
		forwardPublicKey, SignedType_SIGNED_WINDOW_DELEGATION, body), "signature")
	add("the forwarding key under the subject's sidecar_id", testDelegationSign(t, testForwardKey, testDelegationSubjectId,
		SignedType_SIGNED_WINDOW_DELEGATION, body), "signature")
	add("share certificate type", testForwardSign(t, testForwardKey, testForwardDelegationId, forwardPublicKey,
		SignedType_SIGNED_SHARE_CERT, body), "type")

	shortKeyId := &Signed{}
	if err := proto.Unmarshal(testForwardSigned(t, testDelegation()), shortKeyId); err != nil {
		t.Fatal(err)
	}
	shortKeyId.KeyId = shortKeyId.KeyId[:16]
	add("a 32-byte signer with a 16-byte key_id", testDelegationMarshal(t, shortKeyId), "malformed")

	noKeyId := &Signed{}
	if err := proto.Unmarshal(testForwardSigned(t, testDelegation()), noKeyId); err != nil {
		t.Fatal(err)
	}
	noKeyId.KeyId = nil
	add("a 32-byte signer with no key_id", testDelegationMarshal(t, noKeyId), "malformed")

	otherSubject := testDelegation()
	otherSubject.SubjectSidecarId = testDelegationOtherId
	add("another subject than the forwarding Delegation's sidecar", testForwardSigned(t, otherSubject), "signer")

	expired := testDelegation()
	expired.NotAfterMs = testDelegationNowMs
	add("expired", testForwardSigned(t, expired), "expired")

	wrongTarget := testDelegation()
	wrongTarget.TargetSidecarId = testDelegationOtherId
	add("wrong target", testForwardSigned(t, wrongTarget), "mismatch")

	share := testDelegation()
	share.ShareId = testDelegationOtherId
	add("a share", testForwardSigned(t, share), "share")
	return cases
}

// The whole file's bytes, built on this leg.
func testForwardVectorBytes(t testing.TB) []byte {
	t.Helper()
	check := testDelegationCheck()
	vectors := &testForwardVectors{
		Comment: "WindowDelegation vectors for the forwarding path (sidecar design §17.9, D-BRIDGE-17, owner decision " +
			"197): each case's signed is the Signed bytes a contract carries, verified against the host's view below at " +
			"now_ms, where subject_sidecar_id is the one admitted identity and forward_delegation_id the one forwarding " +
			"Delegation the state lists live, for that subject, with forward_public_key; refusal names the check that " +
			"refuses it, empty for one that verifies. Synthetic ids and keys from fixed seeds.",
		NowMs:               check.NowMs,
		SubjectSidecarId:    hex.EncodeToString(testDelegationSubjectId),
		SubjectPublicKey:    hex.EncodeToString(testDelegationSubjectKey.Public().(ed25519.PublicKey)),
		ForwardDelegationId: hex.EncodeToString(testForwardDelegationId),
		ForwardPublicKey:    hex.EncodeToString(testForwardKey.Public().(ed25519.PublicKey)),
		NetworkId:           hex.EncodeToString(check.NetworkId),
		WindowClientId:      hex.EncodeToString(check.WindowClientId),
		WindowClientKey:     hex.EncodeToString(check.WindowClientPublicKey),
		TargetSidecarId:     hex.EncodeToString(check.TargetSidecarId),
		Cases:               testForwardVectorCases(t),
	}
	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}

func TestForwardingDelegationVectorsAreByteEqual(t *testing.T) {
	built := testForwardVectorBytes(t)
	if *testUpdateDelegationVectors {
		if err := os.WriteFile(testForwardVectorsPath, built, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	held, err := os.ReadFile(testForwardVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(built, held) {
		t.Fatalf("%s differs from what this leg builds; rewrite it with -update-delegation-vectors and read the diff", testForwardVectorsPath)
	}
}

// The file read as a consumer reads it, with the public keys it holds and nothing else.
func TestForwardingDelegationVectorsVerify(t *testing.T) {
	held, err := os.ReadFile(testForwardVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	vectors := &testForwardVectors{}
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
	forwardDelegationId, forwardKey := decode(vectors.ForwardDelegationId), decode(vectors.ForwardPublicKey)
	check := &WindowDelegationCheck{
		NetworkId:             decode(vectors.NetworkId),
		WindowClientId:        decode(vectors.WindowClientId),
		WindowClientPublicKey: decode(vectors.WindowClientKey),
		TargetSidecarId:       decode(vectors.TargetSidecarId),
		NowMs:                 vectors.NowMs,
		IdentityKey: func(sidecarId []byte) ([]byte, bool) {
			return subjectKey, bytes.Equal(sidecarId, subjectId)
		},
		ForwardingKey: func(delegationId []byte) ([]byte, []byte, bool) {
			return subjectId, forwardKey, bytes.Equal(delegationId, forwardDelegationId)
		},
	}
	if len(vectors.Cases) < 2 || vectors.Cases[0].Refusal != "" {
		t.Fatal("the file holds no positive twin first")
	}
	for _, testCase := range vectors.Cases {
		admission, err := VerifyWindowDelegationAdmission(decode(testCase.Signed), check)
		if got := testDelegationRefusal(err); got != testCase.Refusal {
			t.Errorf("%s: refusal %q, want %q", testCase.Name, got, testCase.Refusal)
		}
		if (err == nil) != (admission != nil) {
			t.Errorf("%s: an admission beside the error %v", testCase.Name, err)
		}
		if admission != nil && !bytes.Equal(admission.ForwardDelegationId, forwardDelegationId) {
			t.Errorf("%s: admitted without naming the forwarding Delegation", testCase.Name)
		}
	}
}

// The positive twin: the delegation as signed, and the forwarding Delegation whose key admitted it. The identity path
// names none.
func TestVerifyForwardingDelegationPasses(t *testing.T) {
	admission, err := VerifyWindowDelegationAdmission(testForwardSigned(t, testDelegation()), testForwardCheck())
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(admission.Delegation, testDelegation()) || !bytes.Equal(admission.ForwardDelegationId, testForwardDelegationId) {
		t.Fatalf("admitted %v under %x", admission.Delegation, admission.ForwardDelegationId)
	}
	identity, err := VerifyWindowDelegationAdmission(testDelegationSigned(t, testDelegation()), testForwardCheck())
	if err != nil {
		t.Fatal(err)
	}
	if len(identity.ForwardDelegationId) != 0 {
		t.Fatalf("an identity-key delegation named the forwarding Delegation %x", identity.ForwardDelegationId)
	}
}

// Each fault of the forwarding path alone refuses with its own error, and the twin of each passes: another sidecar's
// forwarding key, a superseded or revoked one, which the state lists nowhere, a host that admits no forwarding key, a
// share certificate's type, and a 32-byte signer with a 16-byte key_id.
func TestVerifyForwardingDelegationRefusesEachMismatchAlone(t *testing.T) {
	forwardPublicKey := testForwardKey.Public().(ed25519.PublicKey)
	otherPublicKey := testForwardOtherKey.Public().(ed25519.PublicKey)
	body := testDelegationBody(t, testDelegation())
	valid := testForwardSigned(t, testDelegation())
	shortKeyId := &Signed{}
	if err := proto.Unmarshal(valid, shortKeyId); err != nil {
		t.Fatal(err)
	}
	shortKeyId.KeyId = shortKeyId.KeyId[:16]
	cases := []struct {
		name    string
		signed  []byte
		mutate  func(check *WindowDelegationCheck)
		refusal error
	}{
		{
			// its Delegation is live, for the other sidecar, and it names this subject
			name: "another sidecar's forwarding key",
			signed: testForwardSign(t, testForwardOtherKey, testForwardOtherDelegationId, otherPublicKey,
				SignedType_SIGNED_WINDOW_DELEGATION, body),
			refusal: ErrWindowDelegationSigner,
		},
		{
			name: "another sidecar's forwarding key under the subject's Delegation",
			signed: testForwardSign(t, testForwardOtherKey, testForwardDelegationId, forwardPublicKey,
				SignedType_SIGNED_WINDOW_DELEGATION, body),
			refusal: ErrSignedSignature,
		},
		{
			name: "a superseded forwarding key",
			signed: testForwardSign(t, testForwardGoneKey, testForwardGoneDelegationId, testForwardGoneKey.Public().(ed25519.PublicKey),
				SignedType_SIGNED_WINDOW_DELEGATION, body),
			refusal: ErrWindowDelegationSigner,
		},
		{
			name:   "a revoked forwarding key",
			signed: valid,
			mutate: func(check *WindowDelegationCheck) {
				check.ForwardingKey = func(delegationId []byte) ([]byte, []byte, bool) { return nil, nil, false }
			},
			refusal: ErrWindowDelegationSigner,
		},
		{
			name:    "a host that admits no forwarding key",
			signed:  valid,
			mutate:  func(check *WindowDelegationCheck) { check.ForwardingKey = nil },
			refusal: ErrWindowDelegationSigner,
		},
		{
			name: "a share certificate's type",
			signed: testForwardSign(t, testForwardKey, testForwardDelegationId, forwardPublicKey,
				SignedType_SIGNED_SHARE_CERT, body),
			refusal: ErrSignedTypeMismatch,
		},
		{
			name:    "a 32-byte signer with a 16-byte key_id",
			signed:  testDelegationMarshal(t, shortKeyId),
			refusal: ErrWindowDelegationMalformed,
		},
		{
			name: "a key_id that is not the listed key's",
			signed: testForwardSign(t, testForwardKey, testForwardDelegationId, otherPublicKey,
				SignedType_SIGNED_WINDOW_DELEGATION, body),
			refusal: ErrWindowDelegationSigner,
		},
		{
			name:   "a listed key of the wrong length",
			signed: valid,
			mutate: func(check *WindowDelegationCheck) {
				check.ForwardingKey = func(delegationId []byte) ([]byte, []byte, bool) {
					return testDelegationSubjectId, forwardPublicKey[:16], true
				}
			},
			refusal: ErrWindowDelegationSigner,
		},
	}
	for _, testCase := range cases {
		check := testForwardCheck()
		if testCase.mutate != nil {
			testCase.mutate(check)
		}
		if _, err := VerifyWindowDelegationAdmission(testCase.signed, check); !errors.Is(err, testCase.refusal) {
			t.Errorf("%s: %v, want %v", testCase.name, err, testCase.refusal)
		}
		// the twin: the subject's own forwarding key, against the same host unchanged
		if _, err := VerifyWindowDelegationAdmission(valid, testForwardCheck()); err != nil {
			t.Errorf("%s's twin: %v", testCase.name, err)
		}
	}
}

// QD-093: the path is the signer_id's length. A 16-byte signer asks only for an identity key and a 32-byte one only
// for a forwarding key, whatever either would have answered, and each is asked once.
func TestWindowDelegationPathIsBySignerLength(t *testing.T) {
	identityLookups, forwardLookups := 0, 0
	check := testForwardCheck()
	identityKey, forwardingKey := check.IdentityKey, check.ForwardingKey
	check.IdentityKey = func(sidecarId []byte) ([]byte, bool) {
		identityLookups += 1
		return identityKey(sidecarId)
	}
	check.ForwardingKey = func(delegationId []byte) ([]byte, []byte, bool) {
		forwardLookups += 1
		return forwardingKey(delegationId)
	}
	if _, err := VerifyWindowDelegationAdmission(testForwardSigned(t, testDelegation()), check); err != nil {
		t.Fatal(err)
	}
	if identityLookups != 0 || forwardLookups != 1 {
		t.Fatalf("a 32-byte signer made %d identity and %d forwarding lookups", identityLookups, forwardLookups)
	}
	identityLookups, forwardLookups = 0, 0
	// the forwarding key under the subject's sidecar_id: the identity key alone is tried, and refuses it
	crossed := testDelegationSign(t, testForwardKey, testDelegationSubjectId, SignedType_SIGNED_WINDOW_DELEGATION,
		testDelegationBody(t, testDelegation()))
	if _, err := VerifyWindowDelegationAdmission(crossed, check); !errors.Is(err, ErrSignedSignature) {
		t.Fatalf("the forwarding key under a sidecar_id: %v", err)
	}
	if identityLookups != 1 || forwardLookups != 0 {
		t.Fatalf("a 16-byte signer made %d identity and %d forwarding lookups", identityLookups, forwardLookups)
	}
}

// What WindowDelegationSigned writes for a forwarding signer verifies, and it refuses a signer whose ids no verifier
// reads.
func TestWindowDelegationSignedByAForwardingKey(t *testing.T) {
	keyId := sha256.Sum256(testForwardKey.Public().(ed25519.PublicKey))
	sign := func(signerId []byte, keyId []byte) func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
		return func(purpose string, signedType SignedType, body []byte) (*Signed, error) {
			return &Signed{
				Body:      body,
				SignerId:  signerId,
				KeyId:     keyId,
				Signature: ed25519.Sign(testForwardKey, SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		}
	}
	signedBytes, err := WindowDelegationSigned(testDelegation(), sign(testForwardDelegationId, keyId[:]), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signedBytes, testForwardSigned(t, testDelegation())) {
		t.Fatal("not the bytes a forwarding signer writes")
	}
	if _, err := VerifyWindowDelegationAdmission(signedBytes, testForwardCheck()); err != nil {
		t.Fatal(err)
	}
	refused := []struct {
		name     string
		signerId []byte
		keyId    []byte
	}{
		{name: "a 32-byte signer with no key_id", signerId: testForwardDelegationId},
		{name: "a 32-byte signer with a 16-byte key_id", signerId: testForwardDelegationId, keyId: keyId[:16]},
		{name: "a 16-byte signer with a key_id", signerId: testDelegationSubjectId, keyId: keyId[:]},
		{name: "a signer of another length", signerId: testForwardDelegationId[:20], keyId: keyId[:]},
	}
	for _, testCase := range refused {
		if _, err := WindowDelegationSigned(testDelegation(), sign(testCase.signerId, testCase.keyId), nil); !errors.Is(err, ErrWindowDelegationMalformed) {
			t.Errorf("%s: %v", testCase.name, err)
		}
	}
	// a format limit below what a delegation takes refuses it, at the signer and at the verifier
	small := &WindowDelegationSettings{MaxByteCount: 64}
	if _, err := WindowDelegationSigned(testDelegation(), sign(testForwardDelegationId, keyId[:]), small); !errors.Is(err, ErrWindowDelegationMalformed) {
		t.Fatalf("past the signer's bound: %v", err)
	}
	check := testForwardCheck()
	check.Settings = small
	if _, err := VerifyWindowDelegationAdmission(signedBytes, check); !errors.Is(err, ErrWindowDelegationMalformed) {
		t.Fatalf("past the verifier's bound: %v", err)
	}
}
