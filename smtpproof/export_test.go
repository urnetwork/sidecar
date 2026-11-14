// A bridge from this package's private fixtures to the external tests in checker_agreement_test.go,
// which hold smtpproof/checker against the gate and the relation. It is compiled only into this
// package's tests, and nothing outside a test reaches it.

package smtpproof

import (
	"context"
	"errors"
	"math/big"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
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
	HandshakeSecret []byte
	MasterSecret    []byte
	ClientKey       []byte
	ClientIv        []byte
	ServerKey       []byte
	ServerIv        []byte
	// rho, big-endian.
	KeyBlind []byte
	// The scan state a hdr or body part starts from (DESIGN-DETAILS 3.2.4), and the blinds of the carry it
	// opens and of its own, big-endian.
	CarryInState     uint32
	CarryInBlind     []byte
	CarryOutBlind    []byte
	ClientPlaintexts [][]byte
	ServerPlaintexts [][]byte
}

// A big.Int's octets, or none for no value.
func exportedBlind(blind *big.Int) []byte {
	if blind == nil {
		return nil
	}
	return blind.Bytes()
}

// A blind from its octets, or no value for none.
func importedBlind(octets []byte) *big.Int {
	if octets == nil {
		return nil
	}
	return new(big.Int).SetBytes(octets)
}

// A part's witness from its export.
func importedWitness(witness *ExportedWitness) *partWitness {
	return &partWitness{
		handshakeSecret:  witness.HandshakeSecret,
		masterSecret:     witness.MasterSecret,
		clientKey:        witness.ClientKey,
		clientIv:         witness.ClientIv,
		serverKey:        witness.ServerKey,
		serverIv:         witness.ServerIv,
		keyBlind:         new(big.Int).SetBytes(witness.KeyBlind),
		carryInState:     scanState(witness.CarryInState),
		carryInBlind:     importedBlind(witness.CarryInBlind),
		carryOutBlind:    importedBlind(witness.CarryOutBlind),
		clientPlaintexts: witness.ClientPlaintexts,
		serverPlaintexts: witness.ServerPlaintexts,
	}
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
	fixture := &testGateFixture{leg: leg, preamble: newSessionPreamble(job.Preamble, DefaultProofSettings()), trace: send.edge.trace, parts: send.edge.parts}
	return exportCapture(t, fixture, job, send.backend)
}

// A capture of a finished send: each event as the edge saw it, and each part's witness by its event.
func exportCapture(t *testing.T, fixture *testGateFixture, job *sidecar.SmtpProofJob, backend *testWitnessBackend) *ExportedCapture {
	t.Helper()
	if len(backend.proved) != len(fixture.parts) {
		t.Fatalf("%d witnesses for %d parts", len(backend.proved), len(fixture.parts))
	}
	capture := &ExportedCapture{Preamble: job.Preamble, Witnesses: map[int]*ExportedWitness{}}
	for i, event := range testReplayEvents(fixture) {
		exported := &ExportedEvent{Shts: event.shts}
		switch {
		case event.part != 0:
			exported.Part = fixture.parts[event.part-1]
			witness := backend.proved[event.part-1]
			capture.Witnesses[i] = &ExportedWitness{
				HandshakeSecret:  witness.handshakeSecret,
				MasterSecret:     witness.masterSecret,
				ClientKey:        witness.clientKey,
				ClientIv:         witness.clientIv,
				ServerKey:        witness.serverKey,
				ServerIv:         witness.serverIv,
				KeyBlind:         witness.keyBlind.Bytes(),
				CarryInState:     uint32(witness.carryInState),
				CarryInBlind:     exportedBlind(witness.carryInBlind),
				CarryOutBlind:    exportedBlind(witness.carryOutBlind),
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

// One of sidecartest's MX legs, as ExportMxCapture takes it.
type ExportedMxLeg struct {
	Name    string
	Version uint16
	Suite   uint16
}

// The legs testMxLegs runs, each named tls13 or tls12 first.
func ExportMxLegs() []*ExportedMxLeg {
	var legs []*ExportedMxLeg
	for _, leg := range testMxLegs() {
		legs = append(legs, &ExportedMxLeg{Name: leg.name, Version: leg.version, Suite: leg.suite})
	}
	return legs
}

// Captures an honest send through one of sidecartest's MXs (SMTP-M9-02) on a leg ExportMxLegs names,
// BDAT or DATA, with several DATA parts, as ExportCapture does through this package's own MX.
func ExportMxCapture(t *testing.T, legName string, data bool, mx sidecartest.MxServer) *ExportedCapture {
	t.Helper()
	var leg *testMxLeg
	for _, candidate := range testMxLegs() {
		if candidate.name == legName {
			leg = candidate
		}
	}
	if leg == nil {
		t.Fatalf("no leg %s", legName)
	}
	job := testJob("one line\r\nanother line\r\nand a third\r\n", "bob", "carol")
	if data {
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
	}
	send := testRunSendToMx(t, leg.suites, mx, testMxModeSettings(data), job)
	if send.err != nil || !send.result.Accepted {
		t.Fatalf("%s: %+v, %v (edge: %v)", legName, send.result, send.err, send.edge.failure())
	}
	fixture := &testGateFixture{leg: &testTlsLeg{name: leg.name}, preamble: newSessionPreamble(job.Preamble, DefaultProofSettings()), trace: send.edge.trace, parts: send.edge.parts}
	return exportCapture(t, fixture, job, send.backend)
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
	preamble := newSessionPreamble(capture.Preamble, DefaultProofSettings())
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
				verifier.witness = importedWitness(witness)
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

// Skips a test that needs a compiled circuit in the leg that compiles none (testNeedCircuits).
func ExportNeedCircuits(t *testing.T) {
	t.Helper()
	testNeedCircuits(t)
}

// Whether this leg compiles circuits (testNeedCircuits), for a test that runs its other halves in
// both legs.
func ExportCircuitsRun() bool {
	return testCircuitsRun
}

// Solves each part's circuit over the edge's own statement and the witness set for the part. A test
// shape sized to the part, with room for a mutation of a few blocks, leaves Z1 out and takes the keys
// as given. With keyed set, pi1 solves on its production shape instead, whose keys come from the
// witness's HS or master secret and the edge's own handshake inputs, so a secret the keys no longer
// follow from is refused where a test shape cannot see it. Later parts keep their test shapes: their
// Z1 is millions of constraints, and pi1's is the same derivation under the same inputs.
type exportedCircuitVerifier struct {
	t       *testing.T
	keyed   bool
	witness *partWitness
	refused bool
}

func (self *exportedCircuitVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	self.refused = true
	if self.witness == nil {
		return errors.New("no witness")
	}
	var shape *partShape
	var err error
	if self.keyed && statement.index == 1 {
		shape, err = partShapeFor(DefaultProofSettings(), statement)
	} else {
		shape, err = testShapeFitting(statement, 0, 8)
	}
	if err != nil {
		return err
	}
	compiled := testCompileShape(self.t, shape)
	circuit, err := partAssignment(shape, statement)
	if err != nil {
		return err
	}
	assignWitness(circuit, statement, self.witness)
	if err := testSolved(self.t, compiled, circuit); err != nil {
		return errors.New("no witness satisfies the part's circuit")
	}
	self.refused = false
	return nil
}

// What the circuits say of a capture: replayed into a fresh gate whose verifier is the constraint
// solver, as ExportGateVerdict's is the relation. The index of the first part whose circuit refuses,
// or 0 if every part's is satisfied, and the gate's own refusal if it refused first for a reason that
// is no part's.
func ExportCircuitVerdict(t *testing.T, capture *ExportedCapture) (uint32, error) {
	t.Helper()
	return exportCircuitVerdict(t, capture, false)
}

// As ExportCircuitVerdict, with Z1 in pi1's circuit (exportedCircuitVerifier).
func ExportKeyedCircuitVerdict(t *testing.T, capture *ExportedCapture) (uint32, error) {
	t.Helper()
	return exportCircuitVerdict(t, capture, true)
}

func exportCircuitVerdict(t *testing.T, capture *ExportedCapture, keyed bool) (uint32, error) {
	t.Helper()
	preamble := newSessionPreamble(capture.Preamble, DefaultProofSettings())
	if err := checkSessionPreamble(preamble); err != nil {
		return 0, err
	}
	verifier := &exportedCircuitVerifier{t: t, keyed: keyed}
	gate := newEdgeSession(defaultEdgeSettings(), preamble, capture.Preamble.MxHost, verifier)
	for i, event := range capture.Events {
		var err error
		switch {
		case event.Part != nil:
			verifier.witness = nil
			verifier.refused = false
			if witness := capture.Witnesses[i]; witness != nil {
				verifier.witness = importedWitness(witness)
			}
			_, err = gate.VerifyPart(context.Background(), event.Part)
			if err != nil && verifier.refused {
				return event.Part.Index, nil
			}
		case event.Shts != nil:
			_, err = gate.DiscloseShts(event.Shts)
		case event.ClientRecord != nil:
			_, err = gate.ClientRecord(event.ClientRecord)
		default:
			err = gate.ServerRecord(event.ServerRecord)
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, nil
}
