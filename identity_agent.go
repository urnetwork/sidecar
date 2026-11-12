//go:build !ios_extension

// Agent subkeys (§5.5, D-CORE-6, R-CORE-8, I-7; QD-159, QD-232; CORE-M6-03). An agent stays an attribution label on
// this sidecar (agent_asserted), and from v1 each agent registration, its agent_id, may also carry an Ed25519 subkey:
// the daemon draws it, keeps it in the network's keychain.ur and never hands it to the agent (I-7), signs sealed
// provenance with it on the agent's behalf, and has its identity key vouch for it in an AgentCert:
//
//	cert     Signed{purpose agent-cert, type SIGNED_AGENT_CERT, signer_id the sidecar_id} over AgentCert{sidecar_id,
//	         agent_id, public_key, not_after_ms}, not_after at most AgentSubkeys.MaxLifetime (30 days) after its
//	         signing. It rides inside the sealed provenance it vouches for, RECORD.md 5.3's AgentSignedBody and §11.6's
//	         sealed push metadata, and never in a statement, a config record or anything a server stores or verifies,
//	         so no server sees an agent id (D-CORE-6, §6.9). Sign has no path to it.
//	sign     "urnetwork-sidecar-v1/" || purpose || 0x00 || message, purpose one of the provenance purposes alone,
//	         key_id SHA-256(public_key) (§6.9's algorithm row). Sign keeps the identity key for every statement,
//	         whatever agent it names, so a subkey signs nothing a server reads.
//	renew    a subkey with under RenewBefore left is replaced, under a new certificate, at its next use, so no
//	         signature is made with one past its not_after
//	revoke   AgentRevoke is a local act, not a record (QD-232): the agent's record keeps a tombstone in place of its
//	         key, so this daemon signs nothing more for that agent_id and never mints it another subkey; a new
//	         registration is a new agent_id. Readers bound what was signed before by not_after. A compromised daemon
//	         is a SidecarRevoke for compromise, from whose since_n on readers take its provenance as unattributed,
//	         which they decide before they call VerifyAgentProvenance.
//	read     VerifyAgentProvenance: the certificate under the identity key of the sidecar that signed the carrying
//	         entry, naming that sidecar and the entry's agent; the entry's time before not_after and no further than
//	         MaxLifetime before it; then the subkey's signature over the purpose and message. An absent certificate
//	         reads agent_asserted; anything else that fails is refused, and the caller alarms (QD-159).
//
// Each subkey reaches testHookSecret where it is drawn and where it is read. Not on the forwarding leg, which signs no
// provenance: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The identity key's purpose over an AgentCert (QD-159).
const AgentCertPurpose = "agent-cert"

// RECORD.md 5.3's version-2 entry body: the subkey signs log_id || entry_id || body under this purpose.
const AgentProvenancePurposeRecord = "record-agent"

// The provenance purposes a subkey signs, and nothing else: each names sealed bytes its format defines. §11.6's push
// metadata joins with the purpose EVS1-M6-02 gives its bytes.
var agentProvenancePurposes = []string{AgentProvenancePurposeRecord}

// What every provenance signature's bytes begin with, as §6.9's signed bytes do.
const agentProvenanceSignedPrefix = "urnetwork-sidecar-v1/"

// An agent's record in the core's namespace of keychain.ur: magic, version, state, and while live the subkey's seed
// and the marshalled Signed AgentCert with its length, integers big endian.
const (
	sidecarAgentRecordPrefix  = "agent/"
	sidecarAgentRecordMagic   = "URAG"
	sidecarAgentRecordVersion = 1
	sidecarAgentRecordLive    = 1
	sidecarAgentRecordRevoked = 2
)

var (
	// The agent's subkey was revoked here (AgentRevoke): this daemon signs nothing more for that agent_id, and a new
	// registration takes a new one.
	ErrAgentSubkeyRevoked = errors.New("this agent's subkey was revoked: register the agent again")
	// The purpose is not one of the provenance purposes, so a subkey does not sign it: subkeys sign only sealed
	// provenance, never a statement (D-CORE-6).
	ErrAgentProvenancePurpose = errors.New("an agent subkey signs only sealed provenance")
	// No agent, or an argument a subkey cannot take.
	ErrAgentSubkeyArgs = errors.New("an agent subkey needs an agent id")
	// The provenance names a certificate that does not verify, a time past its life, or a signature that does not
	// verify under its subkey: never attributed, and the reader alarms (QD-159).
	ErrAgentProvenanceInvalid = errors.New("agent provenance does not verify")
	// The agent record does not decode: a failure, never absence (D-CORE-15).
	errSidecarAgentRecordFormat = fmt.Errorf("%w: an agent subkey record does not decode", ErrSidecarStoreFailed)
)

// An agent subkey's certificate as its sidecar holds it, with no private key, so it may go anywhere an id may.
type AgentSubkeyCert struct {
	AgentId Id
	// The subkey's Ed25519 public key.
	PublicKey []byte
	// SHA-256(PublicKey): a signature's key_id.
	KeyId []byte
	// The certificate's end: no provenance this subkey signs is dated at or past it.
	NotAfter time.Time
	// The marshalled Signed AgentCert, which rides inside the sealed provenance it vouches for.
	Cert []byte
}

// One provenance signature by an agent's subkey, with the certificate a reader checks it under: what RECORD.md 5.3's
// AgentSignedBody and §11.6's sealed metadata carry.
type AgentProvenanceSignature struct {
	AgentId   Id
	KeyId     []byte
	Signature []byte
	Cert      []byte
}

// An agent's record as keychain.ur holds it. The seed is the caller's to zero.
type sidecarAgentRecord struct {
	revoked bool
	// the subkey's Ed25519 seed, live only
	seed []byte
	// the marshalled Signed AgentCert, live only
	cert []byte
}

// The record's name in the core's namespace: the agent id as 32 lowercase hex.
func sidecarAgentRecordName(agentId Id) string {
	return sidecarAgentRecordPrefix + hex.EncodeToString(agentId[:])
}

// The record's bytes: a tombstone holds no seed and no certificate.
func (self *sidecarAgentRecord) encode() []byte {
	encoded := make([]byte, 0, len(sidecarAgentRecordMagic)+2+ed25519.SeedSize+4+len(self.cert))
	encoded = append(encoded, sidecarAgentRecordMagic...)
	encoded = append(encoded, sidecarAgentRecordVersion)
	if self.revoked {
		return append(encoded, sidecarAgentRecordRevoked)
	}
	encoded = append(encoded, sidecarAgentRecordLive)
	encoded = append(encoded, self.seed...)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(self.cert)))
	return append(encoded, self.cert...)
}

// Exactly one record of this version: a tombstone, or a live seed with a certificate. Anything else is
// errSidecarAgentRecordFormat, which never repeats the bytes.
func decodeSidecarAgentRecord(encoded []byte) (*sidecarAgentRecord, error) {
	cursor := &wrapCursor{remaining: encoded}
	magic := cursor.take(len(sidecarAgentRecordMagic))
	version := cursor.takeUint8()
	state := cursor.takeUint8()
	if cursor.failed || string(magic) != sidecarAgentRecordMagic || version != sidecarAgentRecordVersion {
		return nil, errSidecarAgentRecordFormat
	}
	switch state {
	case sidecarAgentRecordRevoked:
		if !cursor.finished() {
			return nil, errSidecarAgentRecordFormat
		}
		return &sidecarAgentRecord{revoked: true}, nil
	case sidecarAgentRecordLive:
	default:
		return nil, errSidecarAgentRecordFormat
	}
	seed := cursor.take(ed25519.SeedSize)
	certByteCount := cursor.takeUint32()
	if cursor.failed || certByteCount == 0 || uint32(len(cursor.remaining)) != certByteCount {
		return nil, errSidecarAgentRecordFormat
	}
	cert := cursor.take(int(certByteCount))
	if !cursor.finished() {
		return nil, errSidecarAgentRecordFormat
	}
	record := &sidecarAgentRecord{seed: bytes.Clone(seed), cert: bytes.Clone(cert)}
	testHookSecret("agent_subkey", record.seed)
	return record, nil
}

// The certificate's fields, checked as this sidecar wrote them: its own sidecar and the agent, a 32-byte key and a
// positive not_after.
func parseAgentSubkeyCert(certBytes []byte, sidecarId Id, agentId Id) (*AgentSubkeyCert, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(certBytes, signed); err != nil {
		return nil, errSidecarAgentRecordFormat
	}
	cert := &protocol.AgentCert{}
	if err := proto.Unmarshal(signed.GetBody(), cert); err != nil {
		return nil, errSidecarAgentRecordFormat
	}
	if !bytes.Equal(cert.GetSidecarId(), sidecarId.Bytes()) || !bytes.Equal(cert.GetAgentId(), agentId.Bytes()) ||
		len(cert.GetPublicKey()) != ed25519.PublicKeySize || cert.GetNotAfterMs() <= 0 {
		return nil, errSidecarAgentRecordFormat
	}
	keyId := sha256.Sum256(cert.GetPublicKey())
	return &AgentSubkeyCert{
		AgentId:   agentId,
		PublicKey: bytes.Clone(cert.GetPublicKey()),
		KeyId:     keyId[:],
		NotAfter:  time.UnixMilli(cert.GetNotAfterMs()),
		Cert:      bytes.Clone(certBytes),
	}, nil
}

// The core's namespace and this sidecar's identity, or why an agent subkey cannot be used now: Locked, Revoked, or
// no identity yet.
func (self *Sidecar) agentSubkeySecrets() (SidecarSecrets, *SidecarIdentity, error) {
	var state SidecarState
	var secrets SidecarSecrets
	var identity *SidecarIdentity
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state = self.lifecycle.state
		secrets = self.coreSecrets
		if self.identity != nil {
			identity = self.identity.clone()
		}
	}()
	switch state {
	case SidecarStateLocked:
		return nil, nil, fmt.Errorf("agent subkey: %w", ErrSidecarStoreLocked)
	case SidecarStateRevoked:
		return nil, nil, fmt.Errorf("%w: this sidecar is revoked", ErrSidecarSignRefused)
	}
	if secrets == nil || identity == nil {
		return nil, nil, fmt.Errorf("agent subkey: %w", ErrSidecarNoIdentity)
	}
	return secrets, identity, nil
}

// The agent's live subkey, minted when it has none and renewed when under RenewBefore is left: its record, whose seed
// the caller zeroes, and its certificate. Refuses a revoked agent. Runs under agentSubkeyLock.
func (self *Sidecar) liveAgentSubkeyWithLock(agentId Id) (*sidecarAgentRecord, *AgentSubkeyCert, error) {
	if agentId == (Id{}) {
		return nil, nil, ErrAgentSubkeyArgs
	}
	secrets, identity, err := self.agentSubkeySecrets()
	if err != nil {
		return nil, nil, err
	}
	settings := self.settings.AgentSubkeys
	now := self.clock.Now()
	name := sidecarAgentRecordName(agentId)
	encoded, err := secrets.Get(name)
	switch {
	case err == nil:
		record, decodeErr := decodeSidecarAgentRecord(encoded)
		clear(encoded)
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		if record.revoked {
			return nil, nil, ErrAgentSubkeyRevoked
		}
		cert, certErr := parseAgentSubkeyCert(record.cert, identity.SidecarId, agentId)
		if certErr != nil {
			clear(record.seed)
			return nil, nil, certErr
		}
		if now.Add(settings.RenewBefore).Before(cert.NotAfter) {
			return record, cert, nil
		}
		// too near its end: a new subkey under a new certificate takes its place
		clear(record.seed)
	case errors.Is(err, ErrSidecarStoreAbsent):
	default:
		return nil, nil, err
	}
	return self.mintAgentSubkeyWithLock(secrets, identity, agentId, now)
}

// A new subkey for agentId under a certificate the identity key signs, written over whatever the record held. Runs
// under agentSubkeyLock.
func (self *Sidecar) mintAgentSubkeyWithLock(secrets SidecarSecrets, identity *SidecarIdentity, agentId Id,
	now time.Time) (*sidecarAgentRecord, *AgentSubkeyCert, error) {
	settings := self.settings.AgentSubkeys
	// what the identity key may not sign on this device it does not certify either (identity_readonly.go,
	// identity_recover.go)
	if err := self.checkReadOnlySign(bridge.SignedType_SIGNED_AGENT_CERT, nil); err != nil {
		return nil, nil, err
	}
	if err := self.checkRecoveryAnchorSign(secrets, bridge.SignedType_SIGNED_AGENT_CERT, nil); err != nil {
		return nil, nil, err
	}
	identityRecord, err := loadSidecarIdentity(secrets)
	if err != nil {
		return nil, nil, fmt.Errorf("agent subkey: %w", err)
	}
	defer identityRecord.keys.erase()
	if identityRecord.identity.SidecarId != identity.SidecarId {
		return nil, nil, fmt.Errorf("agent subkey: %w", errSidecarIdentityFormat)
	}
	seed, err := newSidecarKeySeed(rand.Reader, "agent_subkey")
	if err != nil {
		return nil, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			clear(seed)
		}
	}()
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	lifetime := min(settings.Lifetime, settings.MaxLifetime)
	body, err := proto.Marshal(&protocol.AgentCert{
		SidecarId:  identity.SidecarId.Bytes(),
		AgentId:    agentId.Bytes(),
		PublicKey:  publicKey,
		NotAfterMs: now.Add(lifetime).UnixMilli(),
	})
	if err != nil {
		return nil, nil, err
	}
	identityKey := ed25519.NewKeyFromSeed(identityRecord.keys.identitySeed)
	defer clear(identityKey)
	certBytes, err := proto.Marshal(&bridge.Signed{
		Body:      body,
		SignerId:  identity.SidecarId.Bytes(),
		Signature: ed25519.Sign(identityKey, bridge.SignedBytes(AgentCertPurpose, bridge.SignedType_SIGNED_AGENT_CERT, body)),
		Type:      uint32(bridge.SignedType_SIGNED_AGENT_CERT),
	})
	if err != nil {
		return nil, nil, err
	}
	record := &sidecarAgentRecord{seed: seed, cert: certBytes}
	encoded := record.encode()
	defer clear(encoded)
	hookKey := agentId.String()
	testHookBarrier("identity.agent_subkey.mint.before", hookKey)
	err = secrets.Put(sidecarAgentRecordName(agentId), encoded)
	testHookBarrier("identity.agent_subkey.mint.after", hookKey)
	if err != nil {
		return nil, nil, err
	}
	cert, err := parseAgentSubkeyCert(certBytes, identity.SidecarId, agentId)
	if err != nil {
		return nil, nil, err
	}
	keep = true
	return record, cert, nil
}

// The agent's subkey certificate, minting the subkey on the registration's first use and renewing it when under
// RenewBefore is left: what an entry's writer seals beside a provenance signature, and never the key itself, which
// stays in keychain.ur (I-7). ErrAgentSubkeyRevoked once AgentRevoke ran for the agent.
func (self *Sidecar) AgentSubkey(agentId Id) (*AgentSubkeyCert, error) {
	self.agentSubkeyLock.Lock()
	defer self.agentSubkeyLock.Unlock()
	record, cert, err := self.liveAgentSubkeyWithLock(agentId)
	if err != nil {
		return nil, err
	}
	clear(record.seed)
	return cert, nil
}

// "urnetwork-sidecar-v1/" || purpose || 0x00 || message: what a provenance signature covers, for signer and reader
// alike.
func AgentProvenanceSignedBytes(purpose string, message []byte) []byte {
	signedBytes := make([]byte, 0, len(agentProvenanceSignedPrefix)+len(purpose)+1+len(message))
	signedBytes = append(signedBytes, agentProvenanceSignedPrefix...)
	signedBytes = append(signedBytes, purpose...)
	signedBytes = append(signedBytes, 0x00)
	return append(signedBytes, message...)
}

// Whether a subkey signs under purpose: one of the provenance purposes, never a statement's or agent-cert itself.
func agentProvenancePurposeKnown(purpose string) bool {
	return slices.Contains(agentProvenancePurposes, purpose)
}

// Signs message as sealed provenance under purpose with the agent's subkey, minted or renewed as due, and answers the
// signature with the certificate a reader checks it under. Only the provenance purposes sign
// (ErrAgentProvenancePurpose): a subkey never signs a statement, which Sign keeps for the identity key (D-CORE-6).
// ErrAgentSubkeyRevoked once AgentRevoke ran for the agent.
func (self *Sidecar) SignProvenance(agentId Id, purpose string, message []byte) (*AgentProvenanceSignature, error) {
	if !agentProvenancePurposeKnown(purpose) {
		return nil, fmt.Errorf("%w: %q", ErrAgentProvenancePurpose, purpose)
	}
	self.agentSubkeyLock.Lock()
	defer self.agentSubkeyLock.Unlock()
	record, cert, err := self.liveAgentSubkeyWithLock(agentId)
	if err != nil {
		return nil, err
	}
	defer clear(record.seed)
	subkey := ed25519.NewKeyFromSeed(record.seed)
	defer clear(subkey)
	return &AgentProvenanceSignature{
		AgentId:   agentId,
		KeyId:     bytes.Clone(cert.KeyId),
		Signature: ed25519.Sign(subkey, AgentProvenanceSignedBytes(purpose, message)),
		Cert:      bytes.Clone(cert.Cert),
	}, nil
}

// QD-232's AgentRevoke: deletes the agent's subkey from keychain.ur, leaving a tombstone, so this daemon signs nothing
// more for agentId and never mints it another subkey. An agent with no subkey yet gets the tombstone all the same.
// What it signed before stays checkable by its certificate until not_after.
func (self *Sidecar) AgentRevoke(agentId Id) error {
	if agentId == (Id{}) {
		return ErrAgentSubkeyArgs
	}
	self.agentSubkeyLock.Lock()
	defer self.agentSubkeyLock.Unlock()
	secrets, _, err := self.agentSubkeySecrets()
	if err != nil {
		return err
	}
	hookKey := agentId.String()
	testHookBarrier("identity.agent_subkey.revoke.before", hookKey)
	err = secrets.Put(sidecarAgentRecordName(agentId), (&sidecarAgentRecord{revoked: true}).encode())
	testHookBarrier("identity.agent_subkey.revoke.after", hookKey)
	return err
}

// What a reader makes of an agent's provenance (QD-159).
type AgentProvenance int

const (
	// No certificate: the agent is the writer's word, agent_asserted (§5.5).
	AgentProvenanceAsserted AgentProvenance = 1
	// The certificate verified under the writing sidecar's identity key and named the entry's agent, the entry fell
	// inside its life, and the subkey's signature verified.
	AgentProvenanceVerified AgentProvenance = 2
)

// One provenance signature as a reader holds it, with what its carrying entry vouches for.
type AgentProvenanceCheck struct {
	// The sidecar whose identity key signed the carrying entry, and that key as the reader pins it (§6.9).
	SidecarId         Id
	IdentityPublicKey []byte
	// The carrying entry's signed time.
	EntryTime time.Time
	// The agent the entry names.
	AgentId Id
	// What the entry seals beside it: the marshalled Signed AgentCert, empty for none, and the key id and signature.
	Cert      []byte
	KeyId     []byte
	Signature []byte
	// What was signed.
	Purpose string
	Message []byte
	// The bound the reader holds certificates to: AgentSubkeys of its settings.
	Settings *SidecarAgentSubkeySettings
}

// A reader's check of an agent's provenance (QD-159): AgentProvenanceAsserted with no certificate,
// AgentProvenanceVerified once the certificate, the entry's time and the subkey's signature all hold, and otherwise
// an error wrapping ErrAgentProvenanceInvalid, which the caller alarms on and never attributes. A caller that holds the
// writer revoked for compromise at or before the entry's position reads it unattributed and does not call this.
func VerifyAgentProvenance(check *AgentProvenanceCheck) (AgentProvenance, error) {
	if check == nil || check.Settings == nil {
		return 0, fmt.Errorf("%w: nothing to check", ErrAgentProvenanceInvalid)
	}
	if len(check.Cert) == 0 {
		return AgentProvenanceAsserted, nil
	}
	refused := func(why string) (AgentProvenance, error) {
		return 0, fmt.Errorf("%w: %s", ErrAgentProvenanceInvalid, why)
	}
	if !agentProvenancePurposeKnown(check.Purpose) {
		return refused("not a provenance purpose")
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(check.Cert, signed); err != nil {
		return refused("the certificate does not parse")
	}
	if !bytes.Equal(signed.GetSignerId(), check.SidecarId.Bytes()) || len(signed.GetKeyId()) != 0 {
		return refused("the certificate's signer is not the entry's")
	}
	err := bridge.VerifySigned(signed, AgentCertPurpose, bridge.SignedType_SIGNED_AGENT_CERT, bridge.SignedKeyAlgEd25519,
		check.IdentityPublicKey)
	if err != nil {
		return refused("the certificate's signature")
	}
	cert := &protocol.AgentCert{}
	if err := proto.Unmarshal(signed.GetBody(), cert); err != nil {
		return refused("the certificate's body")
	}
	if !bytes.Equal(cert.GetSidecarId(), check.SidecarId.Bytes()) || !bytes.Equal(cert.GetAgentId(), check.AgentId.Bytes()) {
		return refused("the certificate names another sidecar or agent")
	}
	if len(cert.GetPublicKey()) != ed25519.PublicKeySize {
		return refused("the certificate's key")
	}
	entryMillis := check.EntryTime.UnixMilli()
	notAfterMillis := cert.GetNotAfterMs()
	if notAfterMillis <= entryMillis {
		return refused("the entry is past the certificate's life")
	}
	if check.Settings.MaxLifetime.Milliseconds() < notAfterMillis-entryMillis {
		return refused("the certificate runs past the format's most")
	}
	keyId := sha256.Sum256(cert.GetPublicKey())
	if !bytes.Equal(check.KeyId, keyId[:]) {
		return refused("the key id is not the certificate's key")
	}
	if !ed25519.Verify(ed25519.PublicKey(cert.GetPublicKey()), AgentProvenanceSignedBytes(check.Purpose, check.Message), check.Signature) {
		return refused("the subkey's signature")
	}
	return AgentProvenanceVerified, nil
}
