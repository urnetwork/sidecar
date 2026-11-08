package smtpproof

import (
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// What the root's interfaces get: cli/ injects a Prover and server a Verifier (§14.9), each over a
// KeySet. Until keys exist for a part, both refuse it, so an injected module with no keys sends and
// passes no mail.

var (
	_ sidecar.SmtpProver        = (*Prover)(nil)
	_ sidecar.SmtpProofVerifier = (*Verifier)(nil)
	_ sidecar.SmtpProofSession  = (*edgeSession)(nil)
)

// How a Verifier behaves. Start from DefaultVerifierSettings.
type VerifierSettings struct {
	// Client octets held for a part still proving.
	MaxHeldBytes int
	// Server octets kept for parts to cover.
	MaxServerBytes int
	// Handshake octets accepted.
	MaxHandshakeBytes int
}

func DefaultVerifierSettings() *VerifierSettings {
	settings := defaultEdgeSettings()
	return &VerifierSettings{
		MaxHeldBytes:      settings.maxHeldBytes,
		MaxServerBytes:    settings.maxServerBytes,
		MaxHandshakeBytes: settings.maxHandshakeBytes,
	}
}

// Implements sidecar.SmtpProofVerifier. Safe for concurrent use.
type Verifier struct {
	settings *VerifierSettings
	backend  partVerifier
}

// A Verifier holding a KeySet's verifying keys. With no KeySet it holds none and refuses every part,
// which is what server gets until a production setup exists.
func NewVerifier(settings *VerifierSettings, keySet *KeySet) (*Verifier, error) {
	backend := newGroth16Backend()
	if keySet != nil {
		keys, err := keySet.verifyingKeys()
		if err != nil {
			return nil, err
		}
		for _, shapeKeys := range keys {
			backend.addKeys(shapeKeys)
		}
	}
	return &Verifier{settings: settings, backend: backend}, nil
}

// A Prover whose proving keys come from cacheDirectory, where KeySet.VerifyProvingKeys leaves each
// key it verified. Until a shape is verified its parts are refused. With no KeySet the Prover refuses
// every part, and a host that has one queues its mail instead (D-SMTP-18).
func NewProver(settings *ProverSettings, keySet *KeySet, cacheDirectory string) *Prover {
	backend := newGroth16Backend()
	if keySet != nil {
		backend.source = newCachedProvingKeys(keySet, cacheDirectory)
	}
	return &Prover{settings: settings, backend: backend}
}

// NewSmtpProofSession of sidecar.SmtpProofVerifier.
func (self *Verifier) NewSmtpProofSession(preamble *sidecar.SmtpProofPreamble) (sidecar.SmtpProofSession, error) {
	if preamble == nil || preamble.MxHost == "" {
		return nil, errors.New("smtpproof: preamble lacks the edge's own values")
	}
	session := newSessionPreamble(preamble)
	if err := checkSessionPreamble(session); err != nil {
		return nil, fmt.Errorf("smtpproof: %w", err)
	}
	settings := &edgeSettings{
		maxHeldBytes:      self.settings.MaxHeldBytes,
		maxServerBytes:    self.settings.MaxServerBytes,
		maxHandshakeBytes: self.settings.MaxHandshakeBytes,
	}
	return newEdgeSession(settings, session, preamble.MxHost, self.backend), nil
}
