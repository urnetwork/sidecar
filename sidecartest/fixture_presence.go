// Presence keys of both §16.6 profiles, from fixed seeds, for the cases that need a person's key without a person:
// TEAM-M2-06's countersignature rule and FS-124 at api and member devices, CORE's acts, and the spend check's presence
// decisions. A FixturePresenceKey signs per use, countersigns an act (§7.9's presence row) and registers itself with its
// own proof (QD-086), each in the bytes a real authenticator's evidence takes, so what it makes verifies through the
// root's VerifyPresenceUse, VerifyPresenceCountersignature and VerifyPresenceRegistration, which the tests hold to.
//
// A key's scalar is SHA-256("urnetwork-sidecar-test/presence-key" || seed) and its key_id the first 16 bytes of
// SHA-256("urnetwork-sidecar-test/presence-key-id" || seed), the derivation testdata/presence/vectors.json states, so
// a seed gives the same key here and in the root's vectors. Signatures are RFC 6979 deterministic.
//
// webauthn-es256 assertions report rp id ur.io, UP and UV, webauthn.get and origin https://ur.io, QD-073's for every
// host but Android, because a verifier reads the release's origin table and a test cannot replace it. The keys are
// synthetic and no network registers them, so an assertion here verifies under no real row. A test spoils one input
// through the exported fields before signing, as an authenticator that failed a check would.
//
// A FixturePresenceKey is not safe for concurrent use while a test changes its fields.

package sidecartest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The domains testdata/presence/vectors.json states for a seed's scalar and key_id.
const (
	fixturePresenceScalarDomain = "urnetwork-sidecar-test/presence-key"
	fixturePresenceKeyIdDomain  = "urnetwork-sidecar-test/presence-key-id"
)

// WebAuthn's flags (WebAuthn §6.1): user present and user verified.
const (
	FixturePresenceFlagUserPresent  byte = 0x01
	FixturePresenceFlagUserVerified byte = 0x04
)

// The origin a fixture assertion reports by default: QD-073's for iOS, macOS, Windows and every CTAP client.
const FixturePresenceOrigin = "https://ur.io"

// One presence key of one profile, and what its next webauthn-es256 assertion reports.
type FixturePresenceKey struct {
	// The seed it derives from.
	Seed string
	// webauthn-es256 or ecdsa-p256-sha256.
	Alg bridge.KeyAlg
	// KeyRegister's and KeyRow's key_id, which a countersignature's evidence names.
	KeyId []byte
	// A SEC 1 uncompressed point, 65 bytes (QD-445).
	PublicKey []byte

	// What the next webauthn-es256 assertion reports. NewFixturePresenceKey sets each to what verifies; a test clears
	// a flag or moves a value to spoil one. Ignored by ecdsa-p256-sha256.
	RpId      string
	Flags     byte
	SignCount uint32
	Origin    string

	privateKey *ecdsa.PrivateKey
}

// The key of seed for alg, webauthn-es256 or ecdsa-p256-sha256. Panics on any other algorithm, or on a seed whose hash
// is no P-256 scalar, which no fixed seed of a test is.
func NewFixturePresenceKey(seed string, alg bridge.KeyAlg) *FixturePresenceKey {
	if alg != bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 && alg != bridge.KeyAlg_KEY_ALG_ECDSA_P256_SHA256 {
		panic(fmt.Sprintf("no presence profile for %s", alg))
	}
	scalar := sha256.Sum256([]byte(fixturePresenceScalarDomain + seed))
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar[:])
	if err != nil {
		panic(err)
	}
	publicKey, err := privateKey.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	keyIdHash := sha256.Sum256([]byte(fixturePresenceKeyIdDomain + seed))
	return &FixturePresenceKey{
		Seed:       seed,
		Alg:        alg,
		KeyId:      keyIdHash[:16],
		PublicKey:  publicKey,
		RpId:       "ur.io",
		Flags:      FixturePresenceFlagUserPresent | FixturePresenceFlagUserVerified,
		SignCount:  1,
		Origin:     FixturePresenceOrigin,
		privateKey: privateKey,
	}
}

// The row a state holds once the key's KeyRegister, signed by signerId for memberId, applies at position at.
func (self *FixturePresenceKey) KeyRow(memberId []byte, signerId []byte, at uint64) *bridge.KeyRow {
	return &bridge.KeyRow{
		KeyId:     bytes.Clone(self.KeyId),
		MemberId:  bytes.Clone(memberId),
		Alg:       self.Alg,
		PublicKey: bytes.Clone(self.PublicKey),
		Purpose:   bridge.KeyPurpose_KEY_PURPOSE_PRESENCE,
		Signer:    bytes.Clone(signerId),
		At:        at,
	}
}

// What the key's evidence and signature are over message: for webauthn-es256, an assertion whose challenge is
// message's SHA-256, then SignCount moves on by one, as an authenticator's does; for ecdsa-p256-sha256, a DER
// signature over message's SHA-256 and no evidence.
func (self *FixturePresenceKey) Assert(message []byte) (*bridge.WebAuthnEvidence, []byte) {
	if self.Alg != bridge.KeyAlg_KEY_ALG_WEBAUTHN_ES256 {
		digest := sha256.Sum256(message)
		return nil, self.signDigest(digest[:])
	}
	rpIdHash := sha256.Sum256([]byte(self.RpId))
	authenticatorData := append(rpIdHash[:], self.Flags)
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, self.SignCount)
	self.SignCount += 1
	challenge := sha256.Sum256(message)
	clientDataJson := fmt.Appendf(
		nil,
		`{"type":"webauthn.get","challenge":%q,"origin":%q,"crossOrigin":false}`,
		base64.RawURLEncoding.EncodeToString(challenge[:]),
		self.Origin,
	)
	clientDataHash := sha256.Sum256(clientDataJson)
	digest := sha256.Sum256(append(bytes.Clone(authenticatorData), clientDataHash[:]...))
	evidence := &bridge.WebAuthnEvidence{AuthenticatorData: authenticatorData, ClientDataJson: clientDataJson}
	return evidence, self.signDigest(digest[:])
}

// A DER signature over digest, RFC 6979 deterministic for a nil rand.
func (self *FixturePresenceKey) signDigest(digest []byte) []byte {
	signature, err := self.privateKey.Sign(nil, digest, crypto.SHA256)
	if err != nil {
		panic(err)
	}
	return signature
}

// The key's own Signed of body as signedType under purpose (§16.6's per use), a presence decision's among them:
// key_id the key's, and for webauthn-es256 the assertion beside the signature.
func (self *FixturePresenceKey) Sign(purpose string, signedType bridge.SignedType, body []byte) *bridge.Signed {
	evidence, signature := self.Assert(bridge.SignedBytes(purpose, signedType, body))
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		KeyId:     bytes.Clone(self.KeyId),
		Signature: signature,
		Webauthn:  evidence,
		Type:      uint32(signedType),
	}
}

// One statement of an act: the Signed its signer built, and the purpose its type is signed under.
type FixturePresenceStatement struct {
	Purpose string
	Signed  *bridge.Signed
}

// Puts the key's countersignature on each statement of one act (§7.9's act), in act order: sets each Signed's
// signer_id to signerId, takes one check over the act's countersigned bytes, and gives each statement its index and
// inclusion path. The identity signatures are the caller's, before or after, since the countersignature covers each
// statement's purpose, type and body and nothing else of it.
func (self *FixturePresenceKey) Countersign(signerId []byte, statements []*FixturePresenceStatement) error {
	statementDigests := make([][sha256.Size]byte, len(statements))
	for i, statement := range statements {
		statementDigests[i] = bridge.SignedBytesSha256(
			statement.Purpose,
			bridge.SignedType(statement.Signed.GetType()),
			statement.Signed.GetBody(),
		)
	}
	root, err := bridge.PresenceActRoot(statementDigests)
	if err != nil {
		return err
	}
	evidence, signature := self.Assert(bridge.PresenceActBytes(signerId, uint32(len(statements)), root))
	for i, statement := range statements {
		path, err := bridge.PresenceActPath(statementDigests, uint32(i))
		if err != nil {
			return err
		}
		statement.Signed.SignerId = bytes.Clone(signerId)
		statement.Signed.Webauthn = &bridge.WebAuthnEvidence{
			AuthenticatorData: evidence.GetAuthenticatorData(),
			ClientDataJson:    evidence.GetClientDataJson(),
			KeyId:             bytes.Clone(self.KeyId),
			Signature:         signature,
			ActSize:           uint32(len(statements)),
			ActIndex:          uint32(i),
			ActPath:           path,
		}
	}
	return nil
}

// The body of a KeyRegister that registers this key, with its own proof (QD-086): register's fields 1 to 8 with key_id,
// alg, public key and purpose presence set from the key, deterministically encoded, then field 9's DER signature and,
// for webauthn-es256, field 10's evidence, over the key-proof signed bytes of what precedes them. register itself is
// not changed. The caller signs the body with the registering device's identity key and, where §7.9's presence row
// covers it, countersigns it.
func (self *FixturePresenceKey) RegisterBody(register *protocol.KeyRegister) ([]byte, error) {
	prefixRegister := proto.Clone(register).(*protocol.KeyRegister)
	prefixRegister.KeyId = bytes.Clone(self.KeyId)
	prefixRegister.Alg = self.Alg
	prefixRegister.PublicKey = bytes.Clone(self.PublicKey)
	prefixRegister.Purpose = bridge.KeyPurpose_KEY_PURPOSE_PRESENCE
	prefixRegister.KeySignature = nil
	prefixRegister.KeyWebauthn = nil
	prefix, err := proto.MarshalOptions{Deterministic: true}.Marshal(prefixRegister)
	if err != nil {
		return nil, err
	}
	evidence, signature := self.Assert(
		bridge.SignedBytes(sidecar.PresenceKeyProofPurpose, bridge.SignedType_SIGNED_KEY_REGISTER, prefix),
	)
	body := protowire.AppendTag(prefix, 9, protowire.BytesType)
	body = protowire.AppendBytes(body, signature)
	if evidence != nil {
		evidenceBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(evidence)
		if err != nil {
			return nil, err
		}
		body = protowire.AppendTag(body, 10, protowire.BytesType)
		body = protowire.AppendBytes(body, evidenceBytes)
	}
	return body, nil
}

// A PresenceCounter in memory: what a daemon's durable store keeps, without the durability, for tests. Safe for
// concurrent use.
type FakePresenceCounter struct {
	stateLock   sync.Mutex
	keyIdCounts map[string]uint32
	// Failing every update, when set: a store that cannot write.
	err error
}

// An empty store: every key's count 0.
func NewFakePresenceCounter() *FakePresenceCounter {
	return &FakePresenceCounter{keyIdCounts: map[string]uint32{}}
}

func (self *FakePresenceCounter) UpdatePresenceCount(keyId []byte, update func(storedCount uint32) (uint32, error)) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	signCount, err := update(self.keyIdCounts[string(keyId)])
	if err != nil {
		return err
	}
	self.keyIdCounts[string(keyId)] = signCount
	return nil
}

// The count stored for keyId, 0 when none is.
func (self *FakePresenceCounter) Count(keyId []byte) uint32 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.keyIdCounts[string(keyId)]
}

// Sets the count stored for keyId, as a store a restart reloaded would hold it.
func (self *FakePresenceCounter) SetCount(keyId []byte, signCount uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keyIdCounts[string(keyId)] = signCount
}

// Makes every later update fail with err, nil restoring the store.
func (self *FakePresenceCounter) SetErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.err = err
}
