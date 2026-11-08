// A bridge from this package's private fixtures to the external tests in checker_agreement_test.go,
// which hold smtpproof/checker against the gate and the relation. It is compiled only into this
// package's tests, and nothing outside a test reaches it.

package smtpproof

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One thing the edge saw, as the external tests read it. Exactly one field is set.
type ExportedEvent struct {
	ClientRecord []byte
	ServerRecord []byte
	Shts         []byte
	Part         *sidecar.SmtpProofPart
}

// A part's witness, as plain octets.
type ExportedWitness struct {
	HandshakeSecret  []byte
	MasterSecret     []byte
	ClientKey        []byte
	ClientIv         []byte
	ServerKey        []byte
	ServerIv         []byte
	ClientPlaintexts [][]byte
	ServerPlaintexts [][]byte
}

// An honest connection, every event in the order an edge could see it, and each part's witness by its
// event's position.
type ExportedCapture struct {
	Preamble  *sidecar.SmtpProofPreamble
	Events    []*ExportedEvent
	Witnesses map[int]*ExportedWitness
}

// Captures an honest send on one leg, BDAT or DATA, with several DATA parts.
func ExportCapture(t *testing.T, legIndex int, data bool) *ExportedCapture {
	t.Helper()
	leg := testTlsLegs()[legIndex%len(testTlsLegs())]
	settings := DefaultProverSettings()
	job := testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol")
	if data {
		settings.ForceData = true
		settings.DataPartBytes = 12
	}
	send := testRunSend(t, leg, testMxDefaults(), settings, job)
	testExpectOneTransaction(t, leg, send, job)
	fixture := &testGateFixture{leg: leg, preamble: newSessionPreamble(job.Preamble), trace: send.edge.trace, parts: send.edge.parts}
	if len(send.backend.proved) != len(fixture.parts) {
		t.Fatalf("%d witnesses for %d parts", len(send.backend.proved), len(fixture.parts))
	}
	capture := &ExportedCapture{Preamble: job.Preamble, Witnesses: map[int]*ExportedWitness{}}
	for i, event := range testReplayEvents(fixture) {
		exported := &ExportedEvent{Shts: event.shts}
		switch {
		case event.part != 0:
			exported.Part = fixture.parts[event.part-1]
			witness := send.backend.proved[event.part-1]
			capture.Witnesses[i] = &ExportedWitness{
				HandshakeSecret:  witness.handshakeSecret,
				MasterSecret:     witness.masterSecret,
				ClientKey:        witness.clientKey,
				ClientIv:         witness.clientIv,
				ServerKey:        witness.serverKey,
				ServerIv:         witness.serverIv,
				ClientPlaintexts: witness.clientPlaintexts,
				ServerPlaintexts: witness.serverPlaintexts,
			}
		case event.shts != nil:
		case event.fromClient:
			exported.ClientRecord = event.record
		default:
			exported.ServerRecord = event.record
		}
		capture.Events = append(capture.Events, exported)
	}
	return capture
}

// Verifies each part by relationCheckPart over the capture's witness for it, and keeps the checks
// that failed, so the gate's refusal can be named by the relation's own checks.
type exportedVerifier struct {
	witness  *partWitness
	failures []string
}

func (self *exportedVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	if self.witness == nil {
		self.failures = []string{string(checkZ1)}
		return errors.New("no witness")
	}
	for _, failure := range relationCheckPart(statement, self.witness) {
		if !slices.Contains(self.failures, string(failure.check)) {
			self.failures = append(self.failures, string(failure.check))
		}
	}
	if 0 < len(self.failures) {
		return errors.New("the relation refuses the part")
	}
	return nil
}

// What smtpproof itself says of a capture: replayed into a fresh gate whose verifier is the relation,
// the checks failing where the gate first refuses, or none. A preamble refused before the gate opens
// is "preamble".
func ExportGateVerdict(capture *ExportedCapture) []string {
	preamble := newSessionPreamble(capture.Preamble)
	if err := checkSessionPreamble(preamble); err != nil {
		return []string{"preamble"}
	}
	verifier := &exportedVerifier{}
	gate := newEdgeSession(defaultEdgeSettings(), preamble, capture.Preamble.MxHost, verifier)
	for i, event := range capture.Events {
		var err error
		switch {
		case event.Part != nil:
			verifier.witness = nil
			verifier.failures = nil
			if witness := capture.Witnesses[i]; witness != nil {
				verifier.witness = &partWitness{
					handshakeSecret:  witness.HandshakeSecret,
					masterSecret:     witness.MasterSecret,
					clientKey:        witness.ClientKey,
					clientIv:         witness.ClientIv,
					serverKey:        witness.ServerKey,
					serverIv:         witness.ServerIv,
					clientPlaintexts: witness.ClientPlaintexts,
					serverPlaintexts: witness.ServerPlaintexts,
				}
			}
			_, err = gate.VerifyPart(context.Background(), event.Part)
			if err != nil && 0 < len(verifier.failures) {
				return verifier.failures
			}
		case event.Shts != nil:
			_, err = gate.DiscloseShts(event.Shts)
		case event.ClientRecord != nil:
			_, err = gate.ClientRecord(event.ClientRecord)
		default:
			err = gate.ServerRecord(event.ServerRecord)
		}
		if err != nil {
			var failure *relationFailure
			if errors.As(err, &failure) {
				return []string{string(failure.check)}
			}
			return []string{"refused: " + err.Error()}
		}
	}
	return nil
}
