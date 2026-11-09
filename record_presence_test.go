// §22.7's presence row at the root (FS-124; D-MCP-19): VerifyPresenceUse, VerifyPresenceCountersignature and
// VerifyPresenceRegistration from a key's row, each refusal spoiling one input of something that verifies, so a test
// cannot pass on an unrelated failure. Both §16.6 profiles run every rule they share.
//
// The root verifies against the release's origin table, which these tests cannot replace, so every assertion here
// reports https://ur.io, QD-073's origin for iOS, macOS, Windows and every CTAP client; the keys are fixed synthetic
// values no network registers, so their assertions verify under no real row. testdata/presence/vectors.json holds the
// fixed inputs and the exact bytes they give, embedded, since a Worker has no file system. A format change regenerates
// it:
//
//	go test -run TestPresenceVectors . -args -update-presence-vectors
//
// which is a format change, and is read as one in review.

package sidecar

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

//go:embed testdata/presence/vectors.json
var presenceVectorsJson []byte

var updatePresenceVectors = flag.Bool("update-presence-vectors", false, "rewrite testdata/presence/vectors.json")

// QD-073's origin for every host but Android, the one the release table holds.
const testPresenceOrigin = "https://ur.io"

// What sidecartest.FixturePresenceKey derives a key's scalar and key_id from, so the two derivations agree on a seed and
// its test can hold them to these vectors.
const (
	testPresenceScalarDomain = "urnetwork-sidecar-test/presence-key"
	testPresenceKeyIdDomain  = "urnetwork-sidecar-test/presence-key-id"
)

// A presence key of one profile, from a seed.
type testPresenceKey struct {
	seed       string
	alg        bridge.KeyAlg
	keyId      []byte
	privateKey *ecdsa.PrivateKey
	publicKey  []byte
}

// The key of seed for alg: its scalar is SHA-256(domain || seed), its key_id the first 16 bytes of SHA-256(domain ||
// seed), its public key a SEC 1 uncompressed point (QD-445).
func newTestPresenceKey(t testing.TB, seed string, alg bridge.KeyAlg) *testPresenceKey {
	scalar := sha256.Sum256([]byte(testPresenceScalarDomain + seed))
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	keyIdHash := sha256.Sum256([]byte(testPresenceKeyIdDomain + seed))
	return &testPresenceKey{
		seed:       seed,
		alg:        alg,
		keyId:      keyIdHash[:16],
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// The row a member device's state holds for the key once its KeyRegister applies.
func (self *testPresenceKey) row() *bridge.KeyRow {
	return &bridge.KeyRow{
		KeyId:     bytes.Clone(self.keyId),
		MemberId:  bytes.Repeat([]byte{0x4d}, 16),
		Alg:       self.alg,
		PublicKey: bytes.Clone(self.publicKey),
		Purpose:   bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		Signer:    bytes.Repeat([]byte{0x5d}, 16),
		At:        7,
	}
}

// A DER signature over digest; a nil rand makes it RFC 6979 deterministic, so vectors are fixed.
func (self *testPresenceKey) signDigest(t testing.TB, digest []byte) []byte {
	signature, err := self.privateKey.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// What a webauthn-es256 authenticator reports, each input one a test may spoil.
type testPresenceAssertion struct {
	rpId       string
	flags      byte
	signCount  uint32
	clientType string
	origin     string
	// The message whose SHA-256 is the challenge, when it is not the one signed.
	challengeMessage []byte
}

// What every check passes: rp id ur.io, UP and UV, webauthn.get and the release origin.
func testGoodPresenceAssertion() *testPresenceAssertion {
	return &testPresenceAssertion{
		rpId:       "ur.io",
		flags:      0x01 | 0x04,
		signCount:  7,
		clientType: "webauthn.get",
		origin:     testPresenceOrigin,
	}
}

// The evidence and DER signature the key's assertion makes over message.
func (self *testPresenceKey) assert(t testing.TB, assertion *testPresenceAssertion, message []byte) (*bridge.WebAuthnEvidence, []byte) {
	rpIdHash := sha256.Sum256([]byte(assertion.rpId))
	authenticatorData := append(rpIdHash[:], assertion.flags)
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, assertion.signCount)
	challengeMessage := message
	if assertion.challengeMessage != nil {
		challengeMessage = assertion.challengeMessage
	}
	challenge := sha256.Sum256(challengeMessage)
	clientDataJson := fmt.Appendf(
		nil,
		`{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":false}`,
		assertion.clientType,
		base64.RawURLEncoding.EncodeToString(challenge[:]),
		assertion.origin,
	)
	clientDataHash := sha256.Sum256(clientDataJson)
	digest := sha256.Sum256(append(bytes.Clone(authenticatorData), clientDataHash[:]...))
	evidence := &bridge.WebAuthnEvidence{AuthenticatorData: authenticatorData, ClientDataJson: clientDataJson}
	return evidence, self.signDigest(t, digest[:])
}

// The key's own Signed of a statement (§16.6's per use): for webauthn-es256 an assertion over the signed bytes, for
// ecdsa-p256-sha256 a DER signature over their SHA-256. assertion is ignored for ecdsa-p256-sha256.
func (self *testPresenceKey) sign(
	t testing.TB,
	assertion *testPresenceAssertion,
	purpose string,
	signedType bridge.SignedType,
	body []byte,
) *bridge.Signed {
	signedBytes := bridge.SignedBytes(purpose, signedType, body)
	signed := &bridge.Signed{Body: bytes.Clone(body), KeyId: bytes.Clone(self.keyId), Type: uint32(signedType)}
	switch self.alg {
	case bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256:
		signed.Webauthn, signed.Signature = self.assert(t, assertion, signedBytes)
	default:
		digest := sha256.Sum256(signedBytes)
		signed.Signature = self.signDigest(t, digest[:])
	}
	return signed
}

// One statement of an act, as its signer built it.
type testPresenceActStatement struct {
	purpose string
	signed  *bridge.Signed
}

// Puts the key's countersignature over the act of statements, in act order, on each (§7.9's act), as signer_id
// signerId: the act's root over each statement's signed bytes, one check over the countersigned bytes, and each
// statement's index and path.
func (self *testPresenceKey) countersign(t testing.TB, assertion *testPresenceAssertion, signerId []byte, statements []*testPresenceActStatement) {
	statementDigests := make([][sha256.Size]byte, len(statements))
	for i, statement := range statements {
		statement.signed.SignerId = bytes.Clone(signerId)
		statementDigests[i] = bridge.SignedBytesSha256(
			statement.purpose,
			bridge.SignedType(statement.signed.GetType()),
			statement.signed.GetBody(),
		)
	}
	root, err := bridge.PresenceActRoot(statementDigests)
	if err != nil {
		t.Fatal(err)
	}
	countersignedBytes := bridge.PresenceActBytes(signerId, uint32(len(statements)), root)
	var assertionEvidence *bridge.WebAuthnEvidence
	var signature []byte
	switch self.alg {
	case bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256:
		assertionEvidence, signature = self.assert(t, assertion, countersignedBytes)
	default:
		digest := sha256.Sum256(countersignedBytes)
		signature = self.signDigest(t, digest[:])
	}
	for i, statement := range statements {
		path, err := bridge.PresenceActPath(statementDigests, uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		statement.signed.Webauthn = &bridge.WebAuthnEvidence{
			AuthenticatorData: assertionEvidence.GetAuthenticatorData(),
			ClientDataJson:    assertionEvidence.GetClientDataJson(),
			KeyId:             bytes.Clone(self.keyId),
			Signature:         signature,
			ActSize:           uint32(len(statements)),
			ActIndex:          uint32(i),
			ActPath:           path,
		}
	}
}

// A KeyRegister body that registers the key, with its own proof (QD-086): the deterministic encoding of fields 1 to 8,
// then field 9's DER signature and, for webauthn-es256, field 10's evidence, over the key-proof signed bytes of the
// fields before them.
func (self *testPresenceKey) registerBody(t testing.TB, assertion *testPresenceAssertion, notAfter int64) []byte {
	register := &protocol.KeyRegister{
		Header: &bridge.StatementHeader{
			NetworkId:  bytes.Repeat([]byte{0x4e}, 16),
			At:         &bridge.AuthPin{Version: 6, Chain: bytes.Repeat([]byte{0xc6}, 32)},
			Nonce:      bytes.Repeat([]byte{0x6e}, 16),
			NotAfterMs: 1767225600000,
		},
		MemberId:  bytes.Repeat([]byte{0x4d}, 16),
		KeyId:     bytes.Clone(self.keyId),
		Alg:       self.alg,
		PublicKey: bytes.Clone(self.publicKey),
		Purpose:   bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		NotAfter:  notAfter,
	}
	prefix, err := proto.MarshalOptions{Deterministic: true}.Marshal(register)
	if err != nil {
		t.Fatal(err)
	}
	proof := self.sign(t, assertion, PresenceKeyProofPurpose, bridge.SignedType_SIGNED_KEY_REGISTER, prefix)
	body := protowire.AppendTag(bytes.Clone(prefix), 9, protowire.BytesType)
	body = protowire.AppendBytes(body, proof.GetSignature())
	if proof.GetWebauthn() != nil {
		evidence, err := proto.MarshalOptions{Deterministic: true}.Marshal(proof.GetWebauthn())
		if err != nil {
			t.Fatal(err)
		}
		body = protowire.AppendTag(body, 10, protowire.BytesType)
		body = protowire.AppendBytes(body, evidence)
	}
	return body
}

// The KeyRegister statement around body, as its registering device's identity key would carry it; the identity
// signature is not this file's to check, so it is a placeholder.
func testPresenceRegisterSigned(body []byte) *bridge.Signed {
	return &bridge.Signed{
		Body:      body,
		SignerId:  bytes.Repeat([]byte{0x5d}, 16),
		Signature: []byte("an identity signature this file does not check"),
		Type:      uint32(bridge.SignedType_SIGNED_KEY_REGISTER),
	}
}

// body parsed as ParseConfigStatement parses a KeyRegister.
func testPresenceParseRegister(t testing.TB, body []byte) *protocol.KeyRegister {
	message, err := ParseConfigStatement(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REGISTER, body)
	if err != nil {
		t.Fatal(err)
	}
	return message.(*protocol.KeyRegister)
}

// A counter store in memory, the shape a daemon's durable one takes.
type testPresenceCounter struct {
	stateLock   sync.Mutex
	keyIdCounts map[string]uint32
}

func newTestPresenceCounter() *testPresenceCounter {
	return &testPresenceCounter{keyIdCounts: map[string]uint32{}}
}

func (self *testPresenceCounter) UpdatePresenceCount(keyId []byte, update func(storedCount uint32) (uint32, error)) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	signCount, err := update(self.keyIdCounts[string(keyId)])
	if err != nil {
		return err
	}
	self.keyIdCounts[string(keyId)] = signCount
	return nil
}

func (self *testPresenceCounter) count(keyId []byte) uint32 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keyIdCounts[string(keyId)]
}

// The two profiles' keys, fixed.
func testPresenceKeys(t testing.TB) []*testPresenceKey {
	return []*testPresenceKey{
		newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256),
		newTestPresenceKey(t, "ecdsa-p256-sha256 key a", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256),
	}
}

// A decision's body, as a presence decision carries one: what the key signs per use.
var testPresenceDecisionBody = []byte("a synthetic approval decision")

// The action a decision over testPresenceDecisionBody does not approve.
var testPresenceOtherDecisionBody = []byte("a synthetic approval decision for another action")

// Each profile's positive vector, with and without a counter: the counter stores a webauthn-es256 signCount, and
// ecdsa-p256-sha256 has none to store.
func TestVerifyPresenceUsePasses(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
		if err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil); err != nil {
			t.Errorf("%s without a counter: %v", key.alg, err)
		}
		counter := newTestPresenceCounter()
		if err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), counter); err != nil {
			t.Errorf("%s with a counter: %v", key.alg, err)
		}
		wantCount := uint32(0)
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			wantCount = 7
		}
		if count := counter.count(key.keyId); count != wantCount {
			t.Errorf("%s: stored count %d, want %d", key.alg, count, wantCount)
		}
	}
}

// A row the per-use and countersign checks refuse before reading the statement: none, another purpose, revoked, or
// an algorithm no presence profile has.
func TestPresenceKeyAlgRefusesRows(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
	sshsig := key.row()
	sshsig.Purpose = bridge.KeyPurpose_KEY_PURPOSE_SSHSIG
	noPurpose := key.row()
	noPurpose.Purpose = bridge.KeyPurpose_KEY_PURPOSE_UNSPECIFIED
	revoked := key.row()
	revoked.RevokedAt = 9
	sshAlg := key.row()
	sshAlg.Alg = bridge.KeyAlg_KEY_ALG_SSH_ED25519
	noAlg := key.row()
	noAlg.Alg = bridge.KeyAlg_KEY_ALG_UNSPECIFIED
	unknownAlg := key.row()
	unknownAlg.Alg = bridge.KeyAlg(99)
	for _, row := range []*bridge.KeyRow{nil, sshsig, noPurpose, revoked, sshAlg, noAlg, unknownAlg} {
		err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, nil)
		if !errors.Is(err, ErrPresenceKey) {
			t.Errorf("per use under %v: %v", row, err)
		}
		if err := VerifyPresenceCountersignature(signed, ApprovalPurpose, row); !errors.Is(err, ErrPresenceKey) {
			t.Errorf("countersignature under %v: %v", row, err)
		}
	}
}

// Another key's row: the same statement verified under it fails the signature.
func TestVerifyPresenceUseRefusesAWrongKey(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		other := newTestPresenceKey(t, "another key", key.alg)
		signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
		err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, other.row(), nil)
		if !errors.Is(err, bridge.ErrSignedSignature) {
			t.Errorf("%s: %v", key.alg, err)
		}
	}
}

// An assertion made for another statement, carried with this one: its challenge is the other's, and for
// ecdsa-p256-sha256 its signature is over the other's bytes.
func TestVerifyPresenceUseRefusesAReplayedChallenge(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		other := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceOtherDecisionBody)
		replayed := proto.Clone(other).(*bridge.Signed)
		replayed.Body = bytes.Clone(testPresenceDecisionBody)
		err := VerifyPresenceUse(replayed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil)
		want := bridge.ErrSignedSignature
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			want = bridge.ErrSignedEvidence
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", key.alg, err, want)
		}
	}
	// and a challenge over another message under an assertion signed whole
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	assertion := testGoodPresenceAssertion()
	assertion.challengeMessage = bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceOtherDecisionBody)
	signed := key.sign(t, assertion, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
	err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil)
	if !errors.Is(err, bridge.ErrSignedEvidence) {
		t.Errorf("another message's challenge: %v", err)
	}
}

// The same assertion twice to one store: the second is a counter regression, and the stored count stays.
func TestVerifyPresenceUseRefusesAReplayToItsCounter(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
	counter := newTestPresenceCounter()
	if err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), counter); err != nil {
		t.Fatal(err)
	}
	err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), counter)
	if !errors.Is(err, ErrPresenceCounter) {
		t.Errorf("the replay: %v", err)
	}
	if count := counter.count(key.keyId); count != 7 {
		t.Errorf("stored count %d after the replay, want 7", count)
	}
}

// signCount above the stored one when either is non-zero, and both zero passing; a refusal stores nothing.
func TestVerifyPresenceUseComparesTheCounter(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	cases := []struct {
		storedCount uint32
		signCount   uint32
		pass        bool
	}{
		{storedCount: 0, signCount: 0, pass: true},
		{storedCount: 0, signCount: 1, pass: true},
		{storedCount: 9, signCount: 10, pass: true},
		{storedCount: 9, signCount: 9, pass: false},
		{storedCount: 9, signCount: 7, pass: false},
		{storedCount: 5, signCount: 0, pass: false},
		{storedCount: 0xffffffff, signCount: 0xffffffff, pass: false},
	}
	for _, c := range cases {
		assertion := testGoodPresenceAssertion()
		assertion.signCount = c.signCount
		signed := key.sign(t, assertion, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
		counter := newTestPresenceCounter()
		counter.keyIdCounts[string(key.keyId)] = c.storedCount
		err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), counter)
		wantCount := c.storedCount
		if c.pass {
			wantCount = c.signCount
			if err != nil {
				t.Errorf("stored %d, signed %d: %v", c.storedCount, c.signCount, err)
			}
		} else if !errors.Is(err, ErrPresenceCounter) {
			t.Errorf("stored %d, signed %d: %v, want a counter regression", c.storedCount, c.signCount, err)
		}
		if count := counter.count(key.keyId); count != wantCount {
			t.Errorf("stored %d, signed %d: count %d, want %d", c.storedCount, c.signCount, count, wantCount)
		}
		// a verifier with no store compares nothing
		if err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil); err != nil {
			t.Errorf("stored %d, signed %d, no counter: %v", c.storedCount, c.signCount, err)
		}
	}
}

// A store's own failure refuses the use, so a verifier that cannot record a count does not accept one.
func TestVerifyPresenceUseRefusesWhenItsCounterFails(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
	storeFailed := errors.New("a store that cannot write")
	counter := testPresenceFailingCounter{err: storeFailed}
	err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), counter)
	if !errors.Is(err, storeFailed) {
		t.Errorf("%v", err)
	}
}

// A store that fails every update.
type testPresenceFailingCounter struct {
	err error
}

func (self testPresenceFailingCounter) UpdatePresenceCount(keyId []byte, update func(storedCount uint32) (uint32, error)) error {
	return self.err
}

// Each webauthn-es256 input the profile fixes, spoiled alone: UP or UV clear, another rp id, a create assertion's type,
// and an origin off the release table, Android's among them until its hash lands (QD-073).
func TestVerifyPresenceUseRefusesSpoiledAssertions(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	androidHash := sha256.Sum256([]byte("synthetic release signing certificate"))
	cases := []struct {
		name  string
		spoil func(assertion *testPresenceAssertion)
	}{
		{name: "UP clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x04 }},
		{name: "UV clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x01 }},
		{name: "UP and UV clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x00 }},
		{name: "another rp", spoil: func(assertion *testPresenceAssertion) { assertion.rpId = "presence.example" }},
		{name: "a subdomain's rp", spoil: func(assertion *testPresenceAssertion) { assertion.rpId = "app.ur.io" }},
		{name: "a create", spoil: func(assertion *testPresenceAssertion) { assertion.clientType = "webauthn.create" }},
		{name: "a fixture origin", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "https://presence.example" }},
		{name: "a subdomain origin", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "https://app.ur.io" }},
		{name: "a port", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "https://ur.io:8443" }},
		{name: "plain http", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "http://ur.io" }},
		{
			name: "an android origin",
			spoil: func(assertion *testPresenceAssertion) {
				assertion.origin = "android:apk-key-hash:" + base64.RawURLEncoding.EncodeToString(androidHash[:])
			},
		},
	}
	for _, c := range cases {
		assertion := testGoodPresenceAssertion()
		c.spoil(assertion)
		signed := key.sign(t, assertion, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
		counter := newTestPresenceCounter()
		err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), counter)
		if !errors.Is(err, bridge.ErrSignedEvidence) {
			t.Errorf("%s: %v", c.name, err)
		}
		if count := counter.count(key.keyId); count != 0 {
			t.Errorf("%s: a refused use stored count %d", c.name, count)
		}
	}
}

// An ES256 assertion presented to a key the row says is ecdsa-p256-sha256: with its evidence it is refused as evidence
// beside that algorithm, and stripped of it the signature, over the evidence and not the signed bytes, fails.
func TestVerifyPresenceUseRefusesAnEs256AssertionAsEcdsa(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
	asEcdsa := key.row()
	asEcdsa.Alg = bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256
	err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, asEcdsa, nil)
	if !errors.Is(err, bridge.ErrSignedEvidence) {
		t.Errorf("with its evidence: %v", err)
	}
	stripped := proto.Clone(signed).(*bridge.Signed)
	stripped.Webauthn = nil
	err = VerifyPresenceUse(stripped, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, asEcdsa, nil)
	if !errors.Is(err, bridge.ErrSignedSignature) {
		t.Errorf("stripped: %v", err)
	}
	// and the other way: an ecdsa-p256-sha256 signature to a webauthn-es256 row has no evidence
	ecdsaKey := newTestPresenceKey(t, "ecdsa-p256-sha256 key a", bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256)
	ecdsaSigned := ecdsaKey.sign(t, nil, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceDecisionBody)
	asWebAuthn := ecdsaKey.row()
	asWebAuthn.Alg = bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256
	err = VerifyPresenceUse(ecdsaSigned, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, asWebAuthn, nil)
	if !errors.Is(err, bridge.ErrSignedEvidence) {
		t.Errorf("ecdsa as webauthn: %v", err)
	}
}

// A presence key's signature over another action's decision, carried as this one's, and one statement read as another
// type or purpose: what the key signed names the action, its type and its purpose.
func TestVerifyPresenceUseRefusesAnotherActionsBytes(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		signed := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testPresenceOtherDecisionBody)
		moved := proto.Clone(signed).(*bridge.Signed)
		moved.Body = bytes.Clone(testPresenceDecisionBody)
		if err := VerifyPresenceUse(moved, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil); err == nil {
			t.Errorf("%s: another action's signature passed", key.alg)
		}
		cancel := proto.Clone(signed).(*bridge.Signed)
		cancel.Type = uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL)
		if err := VerifyPresenceUse(cancel, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, key.row(), nil); err == nil {
			t.Errorf("%s: a decision read as a cancel passed", key.alg)
		}
		if err := VerifyPresenceUse(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil); err == nil {
			t.Errorf("%s: a decision read under another purpose passed", key.alg)
		}
	}
}

// A countersignature where the key's own signature belongs is refused, and so is a countersign check run per use.
func TestVerifyPresenceUseRefusesACountersignature(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		signed := &bridge.Signed{Body: bytes.Clone(testPresenceDecisionBody), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION)}
		key.countersign(t, testGoodPresenceAssertion(), []byte("synthetic-signer"), []*testPresenceActStatement{{purpose: ApprovalPurpose, signed: signed}})
		signed.Signature = bytes.Clone(signed.GetWebauthn().GetSignature())
		err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key.row(), nil)
		if !errors.Is(err, bridge.ErrSignedEvidence) {
			t.Errorf("%s: %v", key.alg, err)
		}
	}
}

// Five statements of several purposes and types, as §7.9's act gives them.
func testPresenceActStatements() []*testPresenceActStatement {
	kinds := []struct {
		purpose    string
		signedType bridge.SignedType
	}{
		{purpose: bridge.SignedPurposeAuthority, signedType: bridge.SignedType_SIGNED_SIDECAR_REVOKE},
		{purpose: bridge.SignedPurposeAcl, signedType: bridge.SignedType_SIGNED_SUSPEND},
		{purpose: bridge.SignedPurposeAuthority, signedType: bridge.SignedType_SIGNED_KEY_REVOKE},
		{purpose: bridge.SignedPurposeAuthority, signedType: bridge.SignedType_SIGNED_RECOVERY_VETO},
		{purpose: bridge.SignedPurposeAcl, signedType: bridge.SignedType_SIGNED_OWNER_CONFIRM},
	}
	statements := make([]*testPresenceActStatement, len(kinds))
	for i, kind := range kinds {
		statements[i] = &testPresenceActStatement{
			purpose: kind.purpose,
			signed: &bridge.Signed{
				Body:      fmt.Appendf(nil, "synthetic covered statement %d", i),
				Signature: []byte("an identity signature this file does not check"),
				Type:      uint32(kind.signedType),
			},
		}
	}
	return statements
}

// A five-statement act passes each statement alone, in any order, from the key's row, for both profiles; a
// countersignature's signCount, low or zero, is never compared.
func TestVerifyPresenceCountersignatureFiveStatementAct(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		for _, signCount := range []uint32{7, 0} {
			assertion := testGoodPresenceAssertion()
			assertion.signCount = signCount
			statements := testPresenceActStatements()
			key.countersign(t, assertion, []byte("synthetic-signer"), statements)
			for _, i := range []int{3, 0, 4, 2, 1} {
				statement := statements[i]
				if err := VerifyPresenceCountersignature(statement.signed, statement.purpose, key.row()); err != nil {
					t.Errorf("%s, signCount %d, statement %d: %v", key.alg, signCount, i, err)
				}
			}
		}
	}
}

// The countersign check refuses what the per-use check does but a counter regression, and what only an act has: a
// path that misses its leaf, another act's root, another signer's act and a size over 65,535.
func TestVerifyPresenceCountersignatureRefuses(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		other := newTestPresenceKey(t, "another key", key.alg)
		fresh := func(assertion *testPresenceAssertion) []*testPresenceActStatement {
			statements := testPresenceActStatements()
			key.countersign(t, assertion, []byte("synthetic-signer"), statements)
			return statements
		}
		// countersigned bytes other than the key's: webauthn-es256's challenge, checked first, misses them, and an
		// ecdsa-p256-sha256 signature fails over them
		wantOtherBytes := bridge.ErrSignedSignature
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			wantOtherBytes = bridge.ErrSignedEvidence
		}
		cases := []struct {
			name  string
			spoil func() (*testPresenceActStatement, *bridge.KeyRow)
			want  error
		}{
			{
				name: "another key's row",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					row := other.row()
					row.KeyId = bytes.Clone(key.keyId)
					return fresh(testGoodPresenceAssertion())[1], row
				},
				want: bridge.ErrSignedSignature,
			},
			{
				name: "evidence naming another key",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					statement := fresh(testGoodPresenceAssertion())[1]
					statement.signed.Webauthn.KeyId = bytes.Clone(other.keyId)
					return statement, key.row()
				},
				want: bridge.ErrSignedEvidence,
			},
			{
				name: "a path that misses its leaf",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					statements := fresh(testGoodPresenceAssertion())
					statements[1].signed.Webauthn.ActPath = statements[2].signed.GetWebauthn().GetActPath()
					return statements[1], key.row()
				},
				want: wantOtherBytes,
			},
			{
				// the statement is not in the act whose evidence it carries, so its leaf walks to no root the key
				// signed
				name: "another act's root",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					statements := fresh(testGoodPresenceAssertion())
					others := testPresenceActStatements()
					others[1].signed.Body = []byte("a statement of another act")
					key.countersign(t, testGoodPresenceAssertion(), []byte("synthetic-signer"), others)
					statements[1].signed.Webauthn = others[1].signed.GetWebauthn()
					return statements[1], key.row()
				},
				want: wantOtherBytes,
			},
			{
				name: "another signer's act",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					statement := fresh(testGoodPresenceAssertion())[1]
					statement.signed.SignerId = []byte("another-synthetic-signer")
					return statement, key.row()
				},
				want: wantOtherBytes,
			},
			{
				name: "an act over 65,535",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					statement := fresh(testGoodPresenceAssertion())[1]
					statement.signed.Webauthn.ActSize = 65536
					return statement, key.row()
				},
				want: bridge.ErrSignedAct,
			},
		}
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			for _, spoiled := range []struct {
				name  string
				spoil func(assertion *testPresenceAssertion)
			}{
				{name: "UV clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x01 }},
				{name: "UP clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x04 }},
				{name: "another rp", spoil: func(assertion *testPresenceAssertion) { assertion.rpId = "presence.example" }},
				{name: "an unlisted origin", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "https://presence.example" }},
				{
					name: "a replayed challenge",
					spoil: func(assertion *testPresenceAssertion) {
						assertion.challengeMessage = []byte("another act's countersigned bytes")
					},
				},
			} {
				cases = append(cases, struct {
					name  string
					spoil func() (*testPresenceActStatement, *bridge.KeyRow)
					want  error
				}{
					name: spoiled.name,
					spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
						assertion := testGoodPresenceAssertion()
						spoiled.spoil(assertion)
						return fresh(assertion)[1], key.row()
					},
					want: bridge.ErrSignedEvidence,
				})
			}
			cases = append(cases, struct {
				name  string
				spoil func() (*testPresenceActStatement, *bridge.KeyRow)
				want  error
			}{
				name: "an ES256 countersignature as ecdsa-p256-sha256",
				spoil: func() (*testPresenceActStatement, *bridge.KeyRow) {
					row := key.row()
					row.Alg = bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256
					return fresh(testGoodPresenceAssertion())[1], row
				},
				want: bridge.ErrSignedEvidence,
			})
		}
		for _, c := range cases {
			statement, row := c.spoil()
			err := VerifyPresenceCountersignature(statement.signed, statement.purpose, row)
			if !errors.Is(err, c.want) {
				t.Errorf("%s, %s: %v, want %v", key.alg, c.name, err, c.want)
			}
		}
	}
}

// Each profile's KeyRegister with its own proof passes, parsed as the log parses it.
func TestVerifyPresenceRegistrationPasses(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		body := key.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
		signed := testPresenceRegisterSigned(body)
		if err := VerifyPresenceRegistration(testPresenceParseRegister(t, body), signed); err != nil {
			t.Errorf("%s: %v", key.alg, err)
		}
	}
}

// What a registration's proof refuses: each a body that differs from a passing one in one way.
func TestVerifyPresenceRegistrationRefuses(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		good := key.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
		prefixSize, keySignature, keyWebAuthn, err := presenceRegistrationProof(good)
		if err != nil {
			t.Fatal(err)
		}
		prefix := good[:prefixSize]
		appendField := func(body []byte, number protowire.Number, value []byte) []byte {
			body = protowire.AppendTag(bytes.Clone(body), number, protowire.BytesType)
			return protowire.AppendBytes(body, value)
		}
		other := newTestPresenceKey(t, "another key", key.alg)
		otherBody := other.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
		_, otherSignature, otherWebAuthn, err := presenceRegistrationProof(otherBody)
		if err != nil {
			t.Fatal(err)
		}

		cases := []struct {
			name string
			body []byte
		}{
			{name: "no proof", body: prefix},
			{name: "an empty key_signature", body: appendField(appendField(prefix, 9, nil), 10, keyWebAuthn)},
			{name: "field 10 first", body: appendField(appendField(prefix, 10, keyWebAuthn), 9, keySignature)},
			{name: "field 10 alone", body: appendField(prefix, 10, keyWebAuthn)},
			{name: "a field after the proof", body: appendField(good, 11, []byte("trailing"))},
			{name: "field 9 twice", body: appendField(good, 9, keySignature)},
			{name: "a header after the proof", body: appendField(good, 1, nil)},
			{name: "another key's proof", body: appendField(appendField(prefix, 9, otherSignature), 10, otherWebAuthn)},
			{
				name: "field 9 as a varint",
				body: protowire.AppendVarint(protowire.AppendTag(bytes.Clone(prefix), 9, protowire.VarintType), 1),
			},
			{name: "a truncated proof", body: good[:len(good)-1]},
		}
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			cases = append(cases, struct {
				name string
				body []byte
			}{name: "no evidence", body: appendField(prefix, 9, keySignature)})
			for _, spoiled := range []struct {
				name  string
				spoil func(assertion *testPresenceAssertion)
			}{
				{name: "UV clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x01 }},
				{name: "UP clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x04 }},
				{name: "another rp", spoil: func(assertion *testPresenceAssertion) { assertion.rpId = "presence.example" }},
				{name: "an unlisted origin", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "https://presence.example" }},
			} {
				assertion := testGoodPresenceAssertion()
				spoiled.spoil(assertion)
				cases = append(cases, struct {
					name string
					body []byte
				}{name: spoiled.name, body: key.registerBody(t, assertion, 1798761600000)})
			}
			// evidence a countersignature would carry is no registration's
			evidence := &bridge.WebAuthnEvidence{}
			if err := proto.Unmarshal(keyWebAuthn, evidence); err != nil {
				t.Fatal(err)
			}
			evidence.KeyId = bytes.Clone(key.keyId)
			countersignShaped, err := proto.Marshal(evidence)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, struct {
				name string
				body []byte
			}{name: "a countersignature's evidence", body: appendField(appendField(prefix, 9, keySignature), 10, countersignShaped)})
		} else {
			cases = append(cases, struct {
				name string
				body []byte
			}{name: "evidence beside ecdsa-p256-sha256", body: appendField(good, 10, []byte{})})
		}
		for _, c := range cases {
			register := &protocol.KeyRegister{}
			if err := proto.Unmarshal(c.body, register); err != nil {
				// a body proto cannot parse is refused before the proof: the prefix's register stands in
				register = testPresenceParseRegister(t, good)
			}
			err := VerifyPresenceRegistration(register, testPresenceRegisterSigned(c.body))
			if !errors.Is(err, ErrPresenceRegistration) {
				t.Errorf("%s, %s: %v", key.alg, c.name, err)
			}
		}
	}
}

// The proof covers the bytes as received: a prefix that parses alike but encodes otherwise, a key read from another
// body, another statement type or another purpose's proof fails.
func TestVerifyPresenceRegistrationCoversTheBytes(t *testing.T) {
	for _, key := range testPresenceKeys(t) {
		good := key.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
		prefixSize, _, _, err := presenceRegistrationProof(good)
		if err != nil {
			t.Fatal(err)
		}
		proof := good[prefixSize:]

		// not_after again at the prefix's end: proto reads the same message, and the key signed other bytes
		register := testPresenceParseRegister(t, good)
		notAfter := protowire.AppendTag(nil, 8, protowire.VarintType)
		notAfter = protowire.AppendVarint(notAfter, uint64(register.GetNotAfter()))
		reencoded := append(append(bytes.Clone(good[:prefixSize]), notAfter...), proof...)
		if !proto.Equal(testPresenceParseRegister(t, reencoded), register) {
			t.Fatal("the re-encoded body parses as another register")
		}
		if err := VerifyPresenceRegistration(register, testPresenceRegisterSigned(reencoded)); !errors.Is(err, ErrPresenceRegistration) {
			t.Errorf("%s, re-encoded: %v", key.alg, err)
		}

		// a register that is not the statement's body
		other := newTestPresenceKey(t, "another key", key.alg)
		otherRegister := testPresenceParseRegister(t, other.registerBody(t, testGoodPresenceAssertion(), 1798761600000))
		if err := VerifyPresenceRegistration(otherRegister, testPresenceRegisterSigned(good)); !errors.Is(err, ErrPresenceRegistration) {
			t.Errorf("%s, another register: %v", key.alg, err)
		}

		// another type around the body
		wrongType := testPresenceRegisterSigned(good)
		wrongType.Type = uint32(bridge.SignedType_SIGNED_KEY_REVOKE)
		if err := VerifyPresenceRegistration(register, wrongType); !errors.Is(err, ErrPresenceRegistration) {
			t.Errorf("%s, another type: %v", key.alg, err)
		}

		// a proof the key made under the statement's own purpose rather than key-proof
		misdirected := key.sign(t, testGoodPresenceAssertion(), bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REGISTER, good[:prefixSize])
		body := protowire.AppendTag(bytes.Clone(good[:prefixSize]), 9, protowire.BytesType)
		body = protowire.AppendBytes(body, misdirected.GetSignature())
		if misdirected.GetWebauthn() != nil {
			evidence, err := proto.Marshal(misdirected.GetWebauthn())
			if err != nil {
				t.Fatal(err)
			}
			body = protowire.AppendTag(body, 10, protowire.BytesType)
			body = protowire.AppendBytes(body, evidence)
		}
		if err := VerifyPresenceRegistration(register, testPresenceRegisterSigned(body)); !errors.Is(err, ErrPresenceRegistration) {
			t.Errorf("%s, purpose authority: %v", key.alg, err)
		}
	}
}

// A KeyRegister that is no presence key's carries no proof to check: sshsig, and algorithms no profile has.
func TestVerifyPresenceRegistrationRefusesOtherKeys(t *testing.T) {
	key := newTestPresenceKey(t, "webauthn-es256 key a", bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256)
	body := key.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
	for _, spoil := range []func(register *protocol.KeyRegister){
		func(register *protocol.KeyRegister) { register.Purpose = bridge.KeyPurpose_KEY_PURPOSE_SSHSIG },
		func(register *protocol.KeyRegister) { register.Alg = bridge.KeyAlg_KEY_ALG_SSH_ED25519 },
		func(register *protocol.KeyRegister) { register.Alg = bridge.KeyAlg_KEY_ALG_UNSPECIFIED },
	} {
		register := testPresenceParseRegister(t, body)
		spoil(register)
		if err := VerifyPresenceRegistration(register, testPresenceRegisterSigned(body)); !errors.Is(err, ErrPresenceRegistration) {
			t.Errorf("%v: %v", register, err)
		}
	}
	if err := VerifyPresenceRegistration(nil, testPresenceRegisterSigned(body)); !errors.Is(err, ErrPresenceRegistration) {
		t.Errorf("no register: %v", err)
	}
	if err := VerifyPresenceRegistration(testPresenceParseRegister(t, body), nil); !errors.Is(err, ErrPresenceRegistration) {
		t.Errorf("no statement: %v", err)
	}
}

// One key of the vectors.
type presenceKeyVector struct {
	Name      string   `json:"name"`
	Seed      string   `json:"seed"`
	Alg       string   `json:"alg"`
	KeyId     hexBytes `json:"key_id"`
	PublicKey hexBytes `json:"public_key"`
}

// One per-use check: the Signed, as encoded, under the key's row, from a stored count, and what it gives.
type presenceUseVector struct {
	Name        string   `json:"name"`
	Key         string   `json:"key"`
	Purpose     string   `json:"purpose"`
	Type        uint32   `json:"type"`
	Signed      hexBytes `json:"signed"`
	StoredCount uint32   `json:"stored_count"`
	// The count stored after, which a refusal leaves as it was.
	CountAfter uint32 `json:"count_after"`
	Refusal    string `json:"refusal"`
}

// One countersignature: a statement of an act, as encoded, under the key's row.
type presenceCountersignVector struct {
	Name    string   `json:"name"`
	Key     string   `json:"key"`
	Purpose string   `json:"purpose"`
	Signed  hexBytes `json:"signed"`
	Refusal string   `json:"refusal"`
}

// One KeyRegister statement's body with its proof.
type presenceRegistrationVector struct {
	Name    string   `json:"name"`
	Key     string   `json:"key"`
	Body    hexBytes `json:"body"`
	Refusal string   `json:"refusal"`
}

// The file's shape.
type presenceVectorFile struct {
	Comment           string                        `json:"comment"`
	Keys              []*presenceKeyVector          `json:"keys"`
	Uses              []*presenceUseVector          `json:"uses"`
	Countersignatures []*presenceCountersignVector  `json:"countersignatures"`
	Registrations     []*presenceRegistrationVector `json:"registrations"`
}

// What a refusal names, so a vector says which error and not only that one came.
var presenceRefusals = map[string]error{
	"presence_key":          ErrPresenceKey,
	"presence_counter":      ErrPresenceCounter,
	"presence_registration": ErrPresenceRegistration,
	"signed_evidence":       bridge.ErrSignedEvidence,
	"signed_signature":      bridge.ErrSignedSignature,
	"signed_act":            bridge.ErrSignedAct,
}

// The vectors this leg computes from fixed inputs.
func testPresenceVectorFile(t *testing.T) *presenceVectorFile {
	t.Helper()
	marshal := func(signed *bridge.Signed) hexBytes {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	file := &presenceVectorFile{
		Comment: "Fixed vectors for the root's VerifyPresenceUse, VerifyPresenceCountersignature and " +
			"VerifyPresenceRegistration (§16.6's profiles, §7.9's presence row; D-MCP-19, FS-124, QD-086). Keys are " +
			"synthetic: a key's P-256 scalar is SHA-256(\"" + testPresenceScalarDomain + "\" || seed) and its key_id " +
			"the first 16 bytes of SHA-256(\"" + testPresenceKeyIdDomain + "\" || seed), as sidecartest.FixturePresenceKey " +
			"derives them; public keys are SEC 1 uncompressed. Signatures are RFC 6979 deterministic. Every assertion " +
			"reports origin https://ur.io, QD-073's for every host but Android, which the release table holds. A use is " +
			"checked from stored_count, and count_after is what a counter holds after. Bytes are lowercase hex. go test " +
			"-run TestPresenceVectors -update-presence-vectors rewrites this file, which is a format change.",
	}
	keyNames := map[*testPresenceKey]string{}
	keys := testPresenceKeys(t)
	for _, key := range keys {
		name := "webauthn-es256"
		if key.alg == bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256 {
			name = "ecdsa-p256-sha256"
		}
		keyNames[key] = name
		file.Keys = append(file.Keys, &presenceKeyVector{
			Name:      name,
			Seed:      key.seed,
			Alg:       name,
			KeyId:     key.keyId,
			PublicKey: key.publicKey,
		})
	}

	decision := bridge.SignedType_SIGNED_APPROVAL_DECISION
	for _, key := range keys {
		name := keyNames[key]
		good := key.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, decision, testPresenceDecisionBody)
		use := func(vector *presenceUseVector) {
			vector.Key = name
			if vector.Purpose == "" {
				vector.Purpose = ApprovalPurpose
			}
			if vector.Type == 0 {
				vector.Type = uint32(decision)
			}
			file.Uses = append(file.Uses, vector)
		}
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			use(&presenceUseVector{Name: name + " passes", Signed: marshal(good), CountAfter: 7})
			use(&presenceUseVector{Name: name + " above its stored count", Signed: marshal(good), StoredCount: 6, CountAfter: 7})
			use(&presenceUseVector{
				Name: name + " replayed to its counter", Signed: marshal(good), StoredCount: 7, CountAfter: 7,
				Refusal: "presence_counter",
			})
			use(&presenceUseVector{
				Name: name + " a counter regression", Signed: marshal(good), StoredCount: 9, CountAfter: 9,
				Refusal: "presence_counter",
			})
			noCounter := testGoodPresenceAssertion()
			noCounter.signCount = 0
			use(&presenceUseVector{
				Name:   name + " with no counter",
				Signed: marshal(key.sign(t, noCounter, ApprovalPurpose, decision, testPresenceDecisionBody)),
			})
			for _, spoiled := range []struct {
				name  string
				spoil func(assertion *testPresenceAssertion)
			}{
				{name: "UP clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x04 }},
				{name: "UV clear", spoil: func(assertion *testPresenceAssertion) { assertion.flags = 0x01 }},
				{name: "another rp", spoil: func(assertion *testPresenceAssertion) { assertion.rpId = "presence.example" }},
				{name: "an unlisted origin", spoil: func(assertion *testPresenceAssertion) { assertion.origin = "https://presence.example" }},
				{
					name: "a replayed challenge",
					spoil: func(assertion *testPresenceAssertion) {
						assertion.challengeMessage = bridge.SignedBytes(ApprovalPurpose, decision, testPresenceOtherDecisionBody)
					},
				},
			} {
				assertion := testGoodPresenceAssertion()
				spoiled.spoil(assertion)
				use(&presenceUseVector{
					Name:    name + " " + spoiled.name,
					Signed:  marshal(key.sign(t, assertion, ApprovalPurpose, decision, testPresenceDecisionBody)),
					Refusal: "signed_evidence",
				})
			}
		} else {
			use(&presenceUseVector{Name: name + " passes", Signed: marshal(good)})
			replayed := key.sign(t, nil, ApprovalPurpose, decision, testPresenceOtherDecisionBody)
			replayed.Body = bytes.Clone(testPresenceDecisionBody)
			use(&presenceUseVector{Name: name + " another action's signature", Signed: marshal(replayed), Refusal: "signed_signature"})
		}
		other := newTestPresenceKey(t, "another key", key.alg)
		use(&presenceUseVector{
			Name:    name + " by another key",
			Signed:  marshal(other.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, decision, testPresenceDecisionBody)),
			Refusal: "signed_signature",
		})
	}
	// an ES256 assertion presented to an ecdsa-p256-sha256 row: the webauthn-es256 key's statement, under the ecdsa key's
	// name, whose row is the ecdsa key's but for the public key; written as the webauthn key's evidence beside a row
	// that says ecdsa-p256-sha256
	webAuthnKey := keys[0]
	asEcdsa := webAuthnKey.sign(t, testGoodPresenceAssertion(), ApprovalPurpose, decision, testPresenceDecisionBody)
	file.Uses = append(file.Uses, &presenceUseVector{
		Name:    "an es256 assertion as ecdsa-p256-sha256",
		Key:     "webauthn-es256 as ecdsa-p256-sha256",
		Purpose: ApprovalPurpose,
		Type:    uint32(decision),
		Signed:  marshal(asEcdsa),
		Refusal: "signed_evidence",
	})

	for _, key := range keys {
		name := keyNames[key]
		// webauthn-es256's challenge misses other countersigned bytes before its signature is read
		otherBytesRefusal := "signed_signature"
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			otherBytesRefusal = "signed_evidence"
		}
		statements := testPresenceActStatements()
		key.countersign(t, testGoodPresenceAssertion(), []byte("synthetic-signer"), statements)
		for i, statement := range statements {
			file.Countersignatures = append(file.Countersignatures, &presenceCountersignVector{
				Name:    fmt.Sprintf("%s act of five, statement %d", name, i),
				Key:     name,
				Purpose: statement.purpose,
				Signed:  marshal(statement.signed),
			})
		}
		missed := proto.Clone(statements[1].signed).(*bridge.Signed)
		missed.Webauthn.ActPath = statements[2].signed.GetWebauthn().GetActPath()
		file.Countersignatures = append(file.Countersignatures, &presenceCountersignVector{
			Name: name + " a path that misses its leaf", Key: name, Purpose: statements[1].purpose,
			Signed: marshal(missed), Refusal: otherBytesRefusal,
		})
		otherSigner := proto.Clone(statements[1].signed).(*bridge.Signed)
		otherSigner.SignerId = []byte("another-synthetic-signer")
		file.Countersignatures = append(file.Countersignatures, &presenceCountersignVector{
			Name: name + " another signer's act", Key: name, Purpose: statements[1].purpose,
			Signed: marshal(otherSigner), Refusal: otherBytesRefusal,
		})
		oversized := proto.Clone(statements[1].signed).(*bridge.Signed)
		oversized.Webauthn.ActSize = 65536
		file.Countersignatures = append(file.Countersignatures, &presenceCountersignVector{
			Name: name + " an act over 65,535", Key: name, Purpose: statements[1].purpose,
			Signed: marshal(oversized), Refusal: "signed_act",
		})
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			noUv := testGoodPresenceAssertion()
			noUv.flags = 0x01
			spoiled := testPresenceActStatements()
			key.countersign(t, noUv, []byte("synthetic-signer"), spoiled)
			file.Countersignatures = append(file.Countersignatures, &presenceCountersignVector{
				Name: name + " UV clear", Key: name, Purpose: spoiled[1].purpose,
				Signed: marshal(spoiled[1].signed), Refusal: "signed_evidence",
			})
		}
	}

	for _, key := range keys {
		name := keyNames[key]
		file.Registrations = append(file.Registrations, &presenceRegistrationVector{
			Name: name + " registers", Key: name, Body: key.registerBody(t, testGoodPresenceAssertion(), 1798761600000),
		})
		other := newTestPresenceKey(t, "another key", key.alg)
		good := key.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
		prefixSize, _, _, err := presenceRegistrationProof(good)
		if err != nil {
			t.Fatal(err)
		}
		otherBody := other.registerBody(t, testGoodPresenceAssertion(), 1798761600000)
		otherPrefixSize, _, _, err := presenceRegistrationProof(otherBody)
		if err != nil {
			t.Fatal(err)
		}
		file.Registrations = append(file.Registrations, &presenceRegistrationVector{
			Name: name + " another key's proof", Key: name,
			Body:    append(bytes.Clone(good[:prefixSize]), otherBody[otherPrefixSize:]...),
			Refusal: "presence_registration",
		})
		file.Registrations = append(file.Registrations, &presenceRegistrationVector{
			Name: name + " no proof", Key: name, Body: bytes.Clone(good[:prefixSize]), Refusal: "presence_registration",
		})
		if key.alg == bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
			noUv := testGoodPresenceAssertion()
			noUv.flags = 0x01
			file.Registrations = append(file.Registrations, &presenceRegistrationVector{
				Name: name + " UV clear", Key: name, Body: key.registerBody(t, noUv, 1798761600000),
				Refusal: "presence_registration",
			})
		}
	}
	return file
}

// The row a vector's key name gives.
func testPresenceVectorRow(t *testing.T, file *presenceVectorFile, name string) *bridge.KeyRow {
	t.Helper()
	keyName := name
	asEcdsa := name == "webauthn-es256 as ecdsa-p256-sha256"
	if asEcdsa {
		keyName = "webauthn-es256"
	}
	for _, key := range file.Keys {
		if key.Name != keyName {
			continue
		}
		alg := bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256
		if key.Alg == "ecdsa-p256-sha256" || asEcdsa {
			alg = bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256
		}
		return &bridge.KeyRow{
			KeyId:     key.KeyId,
			Alg:       alg,
			PublicKey: key.PublicKey,
			Purpose:   bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		}
	}
	t.Fatalf("no key %q", name)
	return nil
}

// Checks err against a vector's refusal name.
func testPresenceVectorVerdict(t *testing.T, name string, refusal string, err error) {
	t.Helper()
	if refusal == "" {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		return
	}
	want, ok := presenceRefusals[refusal]
	if !ok {
		t.Fatalf("%s: no refusal named %q", name, refusal)
	}
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", name, err, want)
	}
}

// The file as checked in, with what this leg computes from the same inputs beside it.
func TestPresenceVectorsAreByteEqual(t *testing.T) {
	encoded, err := json.MarshalIndent(testPresenceVectorFile(t), "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *updatePresenceVectors {
		if err := os.WriteFile("testdata/presence/vectors.json", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(encoded, presenceVectorsJson) {
		t.Error("a vector moved: this leg computes other bytes than testdata/presence/vectors.json holds")
	}
}

// Each checked-in vector gets its verdict from the bytes alone, with every refusal named.
func TestPresenceVectorsVerify(t *testing.T) {
	file := &presenceVectorFile{}
	if err := json.Unmarshal(presenceVectorsJson, file); err != nil {
		t.Fatal(err)
	}
	if len(file.Keys) != 2 || len(file.Uses) == 0 || len(file.Countersignatures) == 0 || len(file.Registrations) == 0 {
		t.Fatalf("the file holds %d keys, %d uses, %d countersignatures, %d registrations",
			len(file.Keys), len(file.Uses), len(file.Countersignatures), len(file.Registrations))
	}
	refusalNames := map[string]bool{}
	for _, vector := range file.Uses {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(vector.Signed, signed); err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		row := testPresenceVectorRow(t, file, vector.Key)
		counter := newTestPresenceCounter()
		counter.keyIdCounts[string(row.GetKeyId())] = vector.StoredCount
		err := VerifyPresenceUse(signed, vector.Purpose, bridge.SignedType(vector.Type), row, counter)
		testPresenceVectorVerdict(t, vector.Name, vector.Refusal, err)
		if count := counter.count(row.GetKeyId()); count != vector.CountAfter {
			t.Errorf("%s: count %d after, want %d", vector.Name, count, vector.CountAfter)
		}
		refusalNames[vector.Refusal] = true
	}
	for _, vector := range file.Countersignatures {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(vector.Signed, signed); err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		err := VerifyPresenceCountersignature(signed, vector.Purpose, testPresenceVectorRow(t, file, vector.Key))
		testPresenceVectorVerdict(t, vector.Name, vector.Refusal, err)
		refusalNames[vector.Refusal] = true
	}
	for _, vector := range file.Registrations {
		register := &protocol.KeyRegister{}
		if err := proto.Unmarshal(vector.Body, register); err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		err := VerifyPresenceRegistration(register, testPresenceRegisterSigned(vector.Body))
		testPresenceVectorVerdict(t, vector.Name, vector.Refusal, err)
		refusalNames[vector.Refusal] = true
	}
	for _, name := range []string{"", "presence_counter", "presence_registration", "signed_evidence", "signed_signature", "signed_act"} {
		if !refusalNames[name] {
			t.Errorf("no vector of verdict %q", name)
		}
	}
	// the two keys are the two profiles, each a 65-byte point
	algs := []string{}
	for _, key := range file.Keys {
		algs = append(algs, key.Alg)
		if len(key.PublicKey) != 65 || key.PublicKey[0] != 0x04 {
			t.Errorf("%s: public key of %d bytes", key.Name, len(key.PublicKey))
		}
	}
	slices.Sort(algs)
	if !slices.Equal(algs, []string{"ecdsa-p256-sha256", "webauthn-es256"}) {
		t.Errorf("profiles %v", algs)
	}
}
