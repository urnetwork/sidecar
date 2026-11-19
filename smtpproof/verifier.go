package smtpproof

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// What the root's interfaces get: cli/ injects a Prover and server a Verifier (§14.9), each over the key
// sets it holds. Until keys exist for a part, both refuse it, so an injected module with no keys sends
// and passes no mail.

var (
	_ sidecar.SmtpProver        = (*Prover)(nil)
	_ sidecar.SmtpProofVerifier = (*Verifier)(nil)
	_ sidecar.SmtpProofSession  = (*edgeSession)(nil)
)

// How a Verifier behaves. Start from DefaultVerifierSettings.
type VerifierSettings struct {
	// The proofs' catalog and limits, which the prover's must equal (DESIGN-DETAILS 3.2.8).
	Proof *ProofSettings
	// Client octets held for a part still proving.
	MaxHeldBytes int
	// Server octets kept for parts to cover.
	MaxServerBytes int
	// Handshake octets accepted.
	MaxHandshakeBytes int
	// Key sets a Verifier holds at most: 4, the set a release pins and the ones before it that hosts
	// still prove under (DESIGN-DETAILS 3.2.7).
	KeySetMaxCount int
}

func DefaultVerifierSettings() *VerifierSettings {
	settings := defaultEdgeSettings()
	return &VerifierSettings{
		Proof:             settings.proof,
		MaxHeldBytes:      settings.maxHeldBytes,
		MaxServerBytes:    settings.maxServerBytes,
		MaxHandshakeBytes: settings.maxHandshakeBytes,
		KeySetMaxCount:    4,
	}
}

// A key set an edge accepts, as smtpedge.yml's proof_key_sets lists it (DESIGN-DETAILS 3.2.7).
type VerifierKeySet struct {
	// As OpenKeySet opened it, against its id.
	KeySet *KeySet
	// When the edge stops accepting it; zero for never. A set already past it is dropped at start.
	NotAfter time.Time
}

// One key set a Verifier holds: its catalog's settings and a backend over its verifying keys.
type verifierKeySet struct {
	id       []byte
	notAfter time.Time
	proof    *ProofSettings
	backend  partVerifier
}

// Implements sidecar.SmtpProofVerifier. Safe for concurrent use.
type Verifier struct {
	settings *VerifierSettings
	// Tests give a fake clock.
	now func() time.Time
	// By id in hex.
	keySets map[string]*verifierKeySet
}

// A Verifier holding the edge's key sets, each set's verifying keys checked against its keyset.json. A
// session verifies under the one set its preamble names, for its whole life. With no set it holds none
// and answers every preamble ErrSmtpProofKeySet, which is what server gets until a production setup
// exists.
func NewVerifier(settings *VerifierSettings, keySets []*VerifierKeySet) (*Verifier, error) {
	return newVerifierAt(settings, keySets, time.Now)
}

func newVerifierAt(settings *VerifierSettings, keySets []*VerifierKeySet, now func() time.Time) (*Verifier, error) {
	if settings.KeySetMaxCount < len(keySets) {
		return nil, fmt.Errorf("smtpproof: %d key sets, past the %d a verifier holds", len(keySets), settings.KeySetMaxCount)
	}
	verifier := &Verifier{settings: settings, now: now, keySets: map[string]*verifierKeySet{}}
	for _, keySet := range keySets {
		if keySet == nil || keySet.KeySet == nil {
			return nil, errors.New("smtpproof: a key set entry holds no key set")
		}
		key := hex.EncodeToString(keySet.KeySet.id)
		if _, ok := verifier.keySets[key]; ok {
			return nil, fmt.Errorf("smtpproof: key set %s is listed twice", key)
		}
		if !keySet.NotAfter.IsZero() && !now().Before(keySet.NotAfter) {
			continue
		}
		keys, err := keySet.KeySet.verifyingKeys()
		if err != nil {
			return nil, err
		}
		backend := newGroth16Backend(keySet.KeySet.proof)
		for _, shapeKeys := range keys {
			backend.addKeys(shapeKeys)
		}
		verifier.keySets[key] = &verifierKeySet{
			id:       bytes.Clone(keySet.KeySet.id),
			notAfter: keySet.NotAfter,
			proof:    keySet.KeySet.proof,
			backend:  backend,
		}
	}
	return verifier, nil
}

// The key set an id names, if the verifier accepts it now.
func (self *Verifier) keySet(id []byte) *verifierKeySet {
	keySet, ok := self.keySets[hex.EncodeToString(id)]
	if !ok || (!keySet.notAfter.IsZero() && !self.now().Before(keySet.notAfter)) {
		return nil
	}
	return keySet
}

// HoldsKeySet of sidecar.SmtpProofVerifier: a set this verifier was given and whose not_after has not
// passed. A preamble that names none names no set this verifier holds.
func (self *Verifier) HoldsKeySet(keySet []byte) bool {
	return self.keySet(keySet) != nil
}

// NewSmtpProofSession of sidecar.SmtpProofVerifier.
func (self *Verifier) NewSmtpProofSession(preamble *sidecar.SmtpProofPreamble) (sidecar.SmtpProofSession, error) {
	if preamble == nil || preamble.MxHost == "" {
		return nil, errors.New("smtpproof: preamble lacks the edge's own values")
	}
	keySet := self.keySet(preamble.ProofKeySet)
	if keySet == nil {
		return nil, sidecar.ErrSmtpProofKeySet
	}
	session := newSessionPreamble(preamble, keySet.proof)
	if err := checkSessionPreamble(session); err != nil {
		return nil, fmt.Errorf("smtpproof: %w", err)
	}
	settings := &edgeSettings{
		proof:             keySet.proof,
		maxHeldBytes:      self.settings.MaxHeldBytes,
		maxServerBytes:    self.settings.MaxServerBytes,
		maxHandshakeBytes: self.settings.MaxHandshakeBytes,
	}
	edge := newEdgeSession(settings, session, preamble.MxHost, keySet.backend)
	// a session verifies under the set its preamble names, for its whole life
	edge.keySet = bytes.Clone(keySet.id)
	return edge, nil
}

// A Prover over the key sets a release pins, newest first (DESIGN-DETAILS 3.2.7). directory holds keys/,
// each set's fetched files, and cache/, what this host's own checks produced. Nothing is checked here:
// PrepareKeys does it at idle, one shape at a time, and until a family is ready in a pinned set the
// Prover names no key set and refuses every job, and a host with it queues its mail (D-SMTP-18). With no
// pin it never names one. Every set's proofs load their shapes through one loader, within the settings'
// memory budget (DESIGN-DETAILS 3.2.8).
func NewProver(settings *ProverSettings, keySettings *KeySettings, pins [][]byte, directory string) *Prover {
	keys := newProverKeys(settings.Proof, keySettings, pins, directory, productionKeySetCircuits(settings.Proof), settings.SuiteOrder)
	keys.host.loader = newProverLoader(settings, sidecar.RealClock{})
	return &Prover{settings: settings, backend: &proverKeysBackend{keys: keys}, keys: keys}
}
