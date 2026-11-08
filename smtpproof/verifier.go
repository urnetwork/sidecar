package smtpproof

import (
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar"
)

// What the root's interfaces get: cli/ injects a Prover and server a Verifier (§14.9). Until keys
// exist for a part, both refuse it, so an injected module with no keys sends and passes no mail.

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

// A Verifier holding no keys, which refuses every part until keys are loaded. Loading them is not
// built yet: see SPEC.md section 12.
func NewVerifier(settings *VerifierSettings) *Verifier {
	return &Verifier{settings: settings, backend: newGroth16Backend()}
}

// A Prover holding no keys, which refuses every part until keys are loaded, likewise.
func NewProver(settings *ProverSettings) *Prover {
	return &Prover{settings: settings, backend: newGroth16Backend()}
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
