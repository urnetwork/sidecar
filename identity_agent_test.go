//go:build !ios_extension

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A sidecar with an identity on a clock the test moves, and its identity key's seed.
func newAgentTestSidecar(t *testing.T) (*Sidecar, *identityTestClock, *sidecarIdentityKeys) {
	t.Helper()
	sidecar, _, keys := newIdentityTestSidecar(t)
	clock := newIdentityTestClock()
	sidecar.clock = clock
	return sidecar, clock, keys
}

// What a reader checks a signature with, as it would find it in an entry the sidecar signed at entryTime.
func agentTestCheck(sidecar *Sidecar, signature *AgentProvenanceSignature, entryTime time.Time, message []byte) *AgentProvenanceCheck {
	identity := sidecar.currentIdentity()
	return &AgentProvenanceCheck{
		SidecarId:         identity.SidecarId,
		IdentityPublicKey: identity.IdentityPublicKey,
		EntryTime:         entryTime,
		AgentId:           signature.AgentId,
		Cert:              signature.Cert,
		KeyId:             signature.KeyId,
		Signature:         signature.Signature,
		Purpose:           AgentProvenancePurposeRecord,
		Message:           message,
		Settings:          DefaultSidecarAgentSubkeySettings(),
	}
}

// A certificate the identity key signs by hand, as a writer that ignored the format's most would, and the subkey's
// seed.
func agentTestForgedCert(t *testing.T, sidecar *Sidecar, keys *sidecarIdentityKeys, agentId Id, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	identity := sidecar.currentIdentity()
	body, err := proto.Marshal(&protocol.AgentCert{
		SidecarId:  identity.SidecarId.Bytes(),
		AgentId:    agentId.Bytes(),
		PublicKey:  ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey),
		NotAfterMs: notAfter.UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := proto.Marshal(&bridge.Signed{
		Body:     body,
		SignerId: identity.SidecarId.Bytes(),
		Signature: ed25519.Sign(ed25519.NewKeyFromSeed(keys.identitySeed),
			bridge.SignedBytes(AgentCertPurpose, bridge.SignedType_SIGNED_AGENT_CERT, body)),
		Type: uint32(bridge.SignedType_SIGNED_AGENT_CERT),
	})
	if err != nil {
		t.Fatal(err)
	}
	return cert, seed
}

// A subkey's certificate runs at most 30 days from its signing, whatever Lifetime asks, and a reader attributes
// nothing to a certificate that runs further past the entry it rides in. Near its end the subkey is replaced.
func TestSubkeyNotAfterAtMostThirtyDays(t *testing.T) {
	sidecar, clock, keys := newAgentTestSidecar(t)
	maxLifetime := 30 * 24 * time.Hour
	agentId := NewId()
	cert, err := sidecar.AgentSubkey(agentId)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(clock.Now().Add(maxLifetime)) {
		t.Fatalf("a default certificate runs to %s", cert.NotAfter)
	}
	if sum := sha256.Sum256(cert.PublicKey); !bytes.Equal(cert.KeyId, sum[:]) {
		t.Fatal("the key id is not the key's SHA-256")
	}

	// a Lifetime past the format's most mints at the most
	sidecar.settings.AgentSubkeys.Lifetime = 40 * 24 * time.Hour
	longer, err := sidecar.AgentSubkey(NewId())
	if err != nil {
		t.Fatal(err)
	}
	if !longer.NotAfter.Equal(clock.Now().Add(maxLifetime)) {
		t.Fatalf("a 40-day Lifetime minted to %s", longer.NotAfter)
	}

	// the reader's half: 30 days past the entry verifies, a millisecond more does not
	entryTime := clock.Now()
	message := []byte("synthetic log_id || entry_id || body")
	for _, c := range []struct {
		notAfter time.Time
		verified bool
	}{
		{notAfter: entryTime.Add(maxLifetime), verified: true},
		{notAfter: entryTime.Add(maxLifetime + time.Millisecond), verified: false},
		{notAfter: entryTime.Add(365 * 24 * time.Hour), verified: false},
	} {
		forgedCert, seed := agentTestForgedCert(t, sidecar, keys, agentId, c.notAfter)
		publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		keyId := sha256.Sum256(publicKey)
		signature := &AgentProvenanceSignature{
			AgentId:   agentId,
			KeyId:     keyId[:],
			Signature: ed25519.Sign(ed25519.NewKeyFromSeed(seed), AgentProvenanceSignedBytes(AgentProvenancePurposeRecord, message)),
			Cert:      forgedCert,
		}
		provenance, err := VerifyAgentProvenance(agentTestCheck(sidecar, signature, entryTime, message))
		if c.verified && (err != nil || provenance != AgentProvenanceVerified) {
			t.Errorf("not_after %s: %v", c.notAfter.Sub(entryTime), err)
		}
		if !c.verified && !errors.Is(err, ErrAgentProvenanceInvalid) {
			t.Errorf("not_after %s attributed: %v", c.notAfter.Sub(entryTime), err)
		}
	}

	// within RenewBefore of its end the next use draws a new subkey under a new certificate
	clock.advance(maxLifetime - sidecar.settings.AgentSubkeys.RenewBefore + time.Second)
	renewed, err := sidecar.AgentSubkey(agentId)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(renewed.PublicKey, cert.PublicKey) || !renewed.NotAfter.Equal(clock.Now().Add(maxLifetime)) {
		t.Fatal("a subkey near its end was not replaced")
	}
	again, err := sidecar.AgentSubkey(agentId)
	if err != nil || !bytes.Equal(again.PublicKey, renewed.PublicKey) {
		t.Fatalf("a fresh subkey was replaced again: %v", err)
	}
}

// D-CORE-6: a subkey signs only sealed provenance. Every purpose a statement takes, and agent-cert itself, is refused
// before any key is read; Sign keeps the identity key whatever agent it names, and never certifies a subkey.
func TestSubkeyCannotSignStatement(t *testing.T) {
	sidecar, _, keys := newAgentTestSidecar(t)
	agentId := NewId()
	statementPurposes := []string{AgentCertPurpose, "", "presence-act", "binding-client", "binding-identity"}
	for number := range bridge.SignedType_name {
		if purpose, ok := sidecarIdentitySignedPurpose(bridge.SignedType(number)); ok {
			statementPurposes = append(statementPurposes, purpose)
		}
	}
	for _, purpose := range statementPurposes {
		signature, err := sidecar.SignProvenance(agentId, purpose, []byte("synthetic"))
		if !errors.Is(err, ErrAgentProvenancePurpose) || signature != nil {
			t.Errorf("a subkey signed under %q: %v", purpose, err)
		}
	}
	if _, err := sidecar.Sign(AgentCertPurpose, bridge.SignedType_SIGNED_AGENT_CERT, []byte("synthetic"), &agentId); !errors.Is(err, ErrSidecarSignRefused) {
		t.Fatalf("Sign certified a subkey: %v", err)
	}

	cert, err := sidecar.AgentSubkey(agentId)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("synthetic statement")
	signed, err := sidecar.Sign(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REVOKE, body, &agentId)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REVOKE, bridge.SignedKeyAlgEd25519, keys.identityPublicKey()); err != nil {
		t.Fatalf("a statement naming an agent is not the identity key's: %v", err)
	}
	if err := bridge.VerifySigned(signed, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REVOKE, bridge.SignedKeyAlgEd25519, cert.PublicKey); err == nil {
		t.Fatal("a statement verifies under the agent's subkey")
	}

	// a provenance signature is no statement's: its bytes never verify as one under the subkey
	provenance, err := sidecar.SignProvenance(agentId, AgentProvenancePurposeRecord, body)
	if err != nil {
		t.Fatal(err)
	}
	asStatement := &bridge.Signed{Body: body, Signature: provenance.Signature, Type: uint32(bridge.SignedType_SIGNED_KEY_REVOKE)}
	if err := bridge.VerifySigned(asStatement, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_KEY_REVOKE, bridge.SignedKeyAlgEd25519, cert.PublicKey); err == nil {
		t.Fatal("a provenance signature verifies as a statement")
	}
}

// QD-232's AgentRevoke: the daemon signs nothing more for the agent and mints it no new subkey, keychain.ur keeps no
// key for it, and readers refuse provenance whose certificate does not check or whose entry is past its life. What was
// signed before stays checkable by its certificate until not_after.
func TestRevokedSubkeyProvenanceRefused(t *testing.T) {
	sidecar, clock, keys := newAgentTestSidecar(t)
	agentId := NewId()
	message := []byte("synthetic log_id || entry_id || body")
	entryTime := clock.Now()
	signature, err := sidecar.SignProvenance(agentId, AgentProvenancePurposeRecord, message)
	if err != nil {
		t.Fatal(err)
	}
	if provenance, err := VerifyAgentProvenance(agentTestCheck(sidecar, signature, entryTime, message)); err != nil || provenance != AgentProvenanceVerified {
		t.Fatalf("a fresh signature: %v", err)
	}

	if err := sidecar.AgentRevoke(agentId); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.SignProvenance(agentId, AgentProvenancePurposeRecord, message); !errors.Is(err, ErrAgentSubkeyRevoked) {
		t.Fatalf("a revoked agent signed: %v", err)
	}
	if _, err := sidecar.AgentSubkey(agentId); !errors.Is(err, ErrAgentSubkeyRevoked) {
		t.Fatalf("a revoked agent was minted a subkey: %v", err)
	}
	encoded, err := sidecar.coreSecrets.Get(sidecarAgentRecordName(agentId))
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeSidecarAgentRecord(encoded)
	if err != nil || !record.revoked || record.seed != nil || record.cert != nil {
		t.Fatalf("keychain.ur keeps more than a tombstone: %v", err)
	}
	// an agent never minted is tombstoned all the same
	unminted := NewId()
	if err := sidecar.AgentRevoke(unminted); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.SignProvenance(unminted, AgentProvenancePurposeRecord, message); !errors.Is(err, ErrAgentSubkeyRevoked) {
		t.Fatalf("an agent revoked before its first use signed: %v", err)
	}

	// readers: the earlier signature within its life, and every way it can fail
	check := agentTestCheck(sidecar, signature, entryTime, message)
	if provenance, err := VerifyAgentProvenance(check); err != nil || provenance != AgentProvenanceVerified {
		t.Fatalf("a signature made before the revocation: %v", err)
	}
	refusals := map[string]func(check *AgentProvenanceCheck){
		"past not_after": func(check *AgentProvenanceCheck) { check.EntryTime = entryTime.Add(30 * 24 * time.Hour) },
		"another agent":  func(check *AgentProvenanceCheck) { check.AgentId = NewId() },
		"another sidecar": func(check *AgentProvenanceCheck) {
			check.SidecarId = NewId()
		},
		"another identity key": func(check *AgentProvenanceCheck) {
			otherKeys, err := newSidecarIdentityKeys(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			check.IdentityPublicKey = otherKeys.identityPublicKey()
		},
		"a changed message": func(check *AgentProvenanceCheck) { check.Message = []byte("synthetic other body") },
		"a bad signature": func(check *AgentProvenanceCheck) {
			check.Signature = bytes.Clone(check.Signature)
			check.Signature[0] ^= 1
		},
		"another key id":     func(check *AgentProvenanceCheck) { check.KeyId = make([]byte, sha256.Size) },
		"another purpose":    func(check *AgentProvenanceCheck) { check.Purpose = bridge.SignedPurposeAuthority },
		"a cert in pieces":   func(check *AgentProvenanceCheck) { check.Cert = check.Cert[:len(check.Cert)/2] },
		"the identity's key": func(check *AgentProvenanceCheck) { check.IdentityPublicKey = keys.clientPublicKey() },
	}
	for name, change := range refusals {
		check := agentTestCheck(sidecar, signature, entryTime, message)
		change(check)
		if provenance, err := VerifyAgentProvenance(check); !errors.Is(err, ErrAgentProvenanceInvalid) || provenance != 0 {
			t.Errorf("%s: %v, %d", name, err, provenance)
		}
	}

	// no certificate at all reads agent_asserted, never verified
	asserted := agentTestCheck(sidecar, signature, entryTime, message)
	asserted.Cert = nil
	if provenance, err := VerifyAgentProvenance(asserted); err != nil || provenance != AgentProvenanceAsserted {
		t.Fatalf("an absent certificate: %v, %d", err, provenance)
	}
}

// A subkey is held in keychain.ur and never leaves the daemon: a locked keychain signs nothing, a record that does not
// decode is a failure rather than absence, and nothing a caller gets back holds the seed.
func TestAgentSubkeyStaysInTheKeychain(t *testing.T) {
	sidecar, _, _ := newAgentTestSidecar(t)
	agentId := NewId()
	signature, err := sidecar.SignProvenance(agentId, AgentProvenancePurposeRecord, []byte("synthetic"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := sidecar.coreSecrets.Get(sidecarAgentRecordName(agentId))
	if err != nil {
		t.Fatal(err)
	}
	record, err := decodeSidecarAgentRecord(encoded)
	if err != nil || record.revoked || len(record.seed) != ed25519.SeedSize {
		t.Fatalf("the live record: %v", err)
	}
	for _, held := range [][]byte{signature.Cert, signature.Signature, signature.KeyId} {
		if bytes.Contains(held, record.seed) {
			t.Fatal("a reply holds the subkey's seed")
		}
	}

	if err := sidecar.coreSecrets.Put(sidecarAgentRecordName(agentId), append(encoded, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.SignProvenance(agentId, AgentProvenancePurposeRecord, []byte("synthetic")); !errors.Is(err, ErrSidecarStoreFailed) {
		t.Fatalf("a record that does not decode: %v", err)
	}

	locked := newSidecarBase(nil, cheapKeychainSettings())
	if _, err := locked.SignProvenance(agentId, AgentProvenancePurposeRecord, []byte("synthetic")); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("a locked sidecar signed: %v", err)
	}
	if _, err := locked.AgentSubkey(Id{}); !errors.Is(err, ErrAgentSubkeyArgs) {
		t.Fatalf("no agent: %v", err)
	}
}
