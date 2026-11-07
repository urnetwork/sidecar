// E1-E3, each refused on its own (§22.10). Each test replays a real connection's trace into a fresh
// gate and diverges from it at one point, so what is under test is the gate's own decision, with no
// MX or prover able to mask it. The MX-level tests in session_test.go cover the composed path.

package smtpproof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/urnetwork/sidecar"
)

// Accepts or refuses every proof: E1-E3 are under test here, and Z1-Z9 in relation_test.go.
type testFixedVerifier struct {
	err error
}

func (self *testFixedVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	return self.err
}

// What a fresh gate needs to replay a captured connection.
type testGateFixture struct {
	leg      *testTlsLeg
	preamble *sessionPreamble
	trace    []*testTraceEntry
	parts    []*sidecar.SmtpProofPart
}

func testGateCapture(t *testing.T, leg *testTlsLeg, mxSettings *testMxSettings, settings *ProverSettings, job *sidecar.SmtpProofJob) *testGateFixture {
	t.Helper()
	send := testRunSend(t, leg, mxSettings, settings, job)
	testExpectOneTransaction(t, leg, send, job)
	return &testGateFixture{leg: leg, preamble: newSessionPreamble(job.Preamble), trace: send.edge.trace, parts: send.edge.parts}
}

func testBdatGateCapture(t *testing.T, leg *testTlsLeg) *testGateFixture {
	t.Helper()
	return testGateCapture(t, leg, testMxDefaults(), DefaultProverSettings(), testJob(strings.Repeat("a body line\r\n", 8), "bob"))
}

func (self *testGateFixture) version() uint16 {
	if strings.HasPrefix(self.leg.name, "tls13") {
		return tlsVersion13
	}
	return tlsVersion12
}

func (self *testGateFixture) gate(verifier partVerifier) *edgeSession {
	return newEdgeSession(defaultEdgeSettings(), self.preamble, testMxHost, verifier)
}

// Replays the handshake, stopping before the first event once the gate is past it, and returns that
// event's position.
func (self *testGateFixture) replayHandshake(t *testing.T, gate *edgeSession) int {
	t.Helper()
	for i, entry := range self.trace {
		var err error
		switch {
		case entry.shts != nil:
			_, err = gate.DiscloseShts(entry.shts)
		case entry.fromClient:
			_, err = gate.ClientRecord(entry.record)
		default:
			err = gate.ServerRecord(entry.record)
		}
		if err != nil {
			t.Fatalf("%s: replay event %d: %v", self.leg.name, i, err)
		}
		gate.stateLock.Lock()
		done := gate.phase == edgePhaseApplication
		gate.stateLock.Unlock()
		if done {
			return i + 1
		}
	}
	t.Fatalf("%s: the trace never finished its handshake", self.leg.name)
	return 0
}

// The client application records of the trace, in stream order.
func (self *testGateFixture) clientRecords(after int) [][]byte {
	var records [][]byte
	for _, entry := range self.trace[after:] {
		if entry.fromClient {
			records = append(records, entry.record)
		}
	}
	return records
}

func (self *testGateFixture) serverRecords(after int) [][]byte {
	var records [][]byte
	for _, entry := range self.trace[after:] {
		if entry.record != nil && !entry.fromClient {
			records = append(records, entry.record)
		}
	}
	return records
}

func testExpectCheck(t *testing.T, name string, err error, check relationCheck) {
	t.Helper()
	var failure *relationFailure
	if !errors.As(err, &failure) || failure.check != check {
		t.Errorf("%s: want %s to refuse, got %v", name, check, err)
	}
}

func testExpectCut(t *testing.T, name string, err error) {
	t.Helper()
	if !errors.Is(err, sidecar.ErrSmtpRecordCut) {
		t.Errorf("%s: want a record cut, got %v", name, err)
	}
}

// A ClientHello with the given extensions, for E1's refusals.
func testClientHelloRecord(t *testing.T, sessionId []byte, serverName string, extensionIds ...uint16) []byte {
	t.Helper()
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(tlsVersion12)
	builder.AddBytes(make([]byte, tlsRandomBytes))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(sessionId) })
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddUint16(tlsSuiteAes128GcmSha256) })
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddUint8(0) })
	builder.AddUint16LengthPrefixed(func(extensions *cryptobyte.Builder) {
		extensions.AddUint16(tlsExtensionServerName)
		extensions.AddUint16LengthPrefixed(func(names *cryptobyte.Builder) {
			names.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
				list.AddUint8(0)
				list.AddUint16LengthPrefixed(func(name *cryptobyte.Builder) { name.AddBytes([]byte(serverName)) })
			})
		})
		for _, extensionId := range extensionIds {
			extensions.AddUint16(extensionId)
			extensions.AddUint16(0)
		}
	})
	body, err := builder.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return tlsFrameRecord(tlsRecordHandshake, tlsVersion12, tlsHandshakeMessage(tlsHandshakeClientHello, body))
}

func testServerHelloRecord(random []byte, suite uint16, extensions []byte) []byte {
	return tlsFrameRecord(tlsRecordHandshake, tlsVersion12, tlsHandshakeMessage(tlsHandshakeServerHello, testServerHelloBody(random, suite, extensions)))
}

func testEmptyPreamble() *sessionPreamble {
	return &sessionPreamble{}
}

// E1

func TestE1RefusesEveryClientHelloOutsideItsShape(t *testing.T) {
	cases := []struct {
		name   string
		record []byte
	}{
		{name: "psk", record: testClientHelloRecord(t, nil, testMxHost, tlsExtensionPreSharedKey)},
		{name: "early data", record: testClientHelloRecord(t, nil, testMxHost, tlsExtensionEarlyData)},
		{name: "session ticket", record: testClientHelloRecord(t, nil, testMxHost, tlsExtensionSessionTicket)},
		{name: "a session id", record: testClientHelloRecord(t, []byte{1, 2, 3}, testMxHost)},
		{name: "another SNI", record: testClientHelloRecord(t, nil, "other.example")},
		{name: "application data first", record: tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, []byte("EHLO x\r\n"))},
		{name: "a truncated hello", record: tlsFrameRecord(tlsRecordHandshake, tlsVersion12, tlsHandshakeMessage(tlsHandshakeClientHello, []byte{3, 3}))},
	}
	for _, c := range cases {
		gate := newEdgeSession(defaultEdgeSettings(), testEmptyPreamble(), testMxHost, &testFixedVerifier{})
		_, err := gate.ClientRecord(c.record)
		testExpectCheck(t, c.name, err, checkE1)
	}
}

func TestE1RefusesAServerNameAnMxCouldReadAnotherWay(t *testing.T) {
	// E1 compares one name, so a hello that holds a second must not reach an MX that reads the other
	name := func(extensions *cryptobyte.Builder, names ...string) {
		extensions.AddUint16(tlsExtensionServerName)
		extensions.AddUint16LengthPrefixed(func(content *cryptobyte.Builder) {
			content.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
				for _, entry := range names {
					list.AddUint8(0)
					list.AddUint16LengthPrefixed(func(value *cryptobyte.Builder) { value.AddBytes([]byte(entry)) })
				}
			})
		})
	}
	cases := []struct {
		name       string
		extensions func(extensions *cryptobyte.Builder)
	}{
		{name: "a second name in the list", extensions: func(extensions *cryptobyte.Builder) {
			name(extensions, testMxHost, "other.example")
		}},
		{name: "a second server_name extension", extensions: func(extensions *cryptobyte.Builder) {
			name(extensions, "other.example")
			name(extensions, testMxHost)
		}},
		{name: "a repeated extension of any kind", extensions: func(extensions *cryptobyte.Builder) {
			name(extensions, testMxHost)
			extensions.AddUint16(tlsExtensionSupportedGroups)
			extensions.AddUint16(0)
			extensions.AddUint16(tlsExtensionSupportedGroups)
			extensions.AddUint16(0)
		}},
	}
	for _, c := range cases {
		builder := cryptobyte.NewBuilder(nil)
		builder.AddUint16(tlsVersion12)
		builder.AddBytes(make([]byte, tlsRandomBytes))
		builder.AddUint8(0)
		builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddUint16(tlsSuiteAes128GcmSha256) })
		builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddUint8(0) })
		builder.AddUint16LengthPrefixed(c.extensions)
		body, err := builder.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		gate := newEdgeSession(defaultEdgeSettings(), testEmptyPreamble(), testMxHost, &testFixedVerifier{})
		_, err = gate.ClientRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, tlsHandshakeMessage(tlsHandshakeClientHello, body)))
		testExpectCheck(t, c.name, err, checkE1)
	}
}

func TestE1RefusesAServerHelloOutsideItsSuites(t *testing.T) {
	const tlsSuiteAes256GcmSha384 = 0x1302
	supportedVersions13 := []byte{0, 43, 0, 2, 0x03, 0x04}
	presharedKey := []byte{0, 41, 0, 2, 0, 0}
	random := make([]byte, tlsRandomBytes)
	cases := []struct {
		name   string
		record []byte
	}{
		{name: "aes-256 in 1.3", record: testServerHelloRecord(random, tlsSuiteAes256GcmSha384, supportedVersions13)},
		{name: "a 1.2 suite in 1.3", record: testServerHelloRecord(random, tlsSuiteEcdheRsaAes128GcmSha256, supportedVersions13)},
		{name: "a 1.3 suite in 1.2", record: testServerHelloRecord(random, tlsSuiteAes128GcmSha256, nil)},
		{name: "a psk selected", record: testServerHelloRecord(random, tlsSuiteAes128GcmSha256, append(bytes.Clone(supportedVersions13), presharedKey...))},
		{name: "rsa key exchange", record: testServerHelloRecord(random, 0x009c, nil)},
	}
	for _, c := range cases {
		gate := newEdgeSession(defaultEdgeSettings(), testEmptyPreamble(), testMxHost, &testFixedVerifier{})
		if _, err := gate.ClientRecord(testClientHelloRecord(t, nil, testMxHost)); err != nil {
			t.Fatal(err)
		}
		testExpectCheck(t, c.name, gate.ServerRecord(c.record), checkE1)
	}
}

func TestE1TakesAChangeCipherSpecBeforeAClientHelloOnlyAfterARetry(t *testing.T) {
	dummy := tlsFrameRecord(tlsRecordChangeCipherSpec, tlsVersion12, []byte{1})
	gate := newEdgeSession(defaultEdgeSettings(), testEmptyPreamble(), testMxHost, &testFixedVerifier{})
	testExpectCheck(t, "before any hello", gate.ServerRecord(dummy), checkE1)

	gate = newEdgeSession(defaultEdgeSettings(), testEmptyPreamble(), testMxHost, &testFixedVerifier{})
	gate.helloRetried = true
	if err := gate.ServerRecord(dummy); err != nil {
		t.Errorf("after a retry: %v", err)
	}
	testExpectCheck(t, "another length", gate.ServerRecord(tlsFrameRecord(tlsRecordChangeCipherSpec, tlsVersion12, []byte{1, 1})), checkE1)
	testExpectCheck(t, "any other record", gate.ServerRecord(tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 20))), checkE1)
}

func TestE1RefusesAClientFlightOtherThanFinished(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		gate := fixture.gate(&testFixedVerifier{})
		var err error
		for _, entry := range fixture.trace {
			switch {
			case entry.shts != nil:
				_, err = gate.DiscloseShts(entry.shts)
			case entry.fromClient && entry.record[0] == tlsRecordApplicationData:
				// the Finished, with one more octet: a record that could carry something else
				longer := append(bytes.Clone(entry.record), 0)
				longer[4] += 1
				_, err = gate.ClientRecord(longer)
			case entry.fromClient:
				_, err = gate.ClientRecord(entry.record)
			default:
				err = gate.ServerRecord(entry.record)
			}
			if err != nil {
				break
			}
		}
		testExpectCheck(t, leg.name, err, checkE1)
	}
}

// A 1.3 handshake's events up to the two the RPC and the stream do not order, and those two.
func (self *testGateFixture) splitFlight13(t *testing.T) (before []*testTraceEntry, shts []byte, finished []byte) {
	t.Helper()
	for _, entry := range self.trace {
		switch {
		case entry.shts != nil:
			shts = entry.shts
		case entry.fromClient && entry.record[0] == tlsRecordApplicationData:
			finished = entry.record
		default:
			before = append(before, entry)
		}
		if shts != nil && finished != nil {
			return before, shts, finished
		}
	}
	t.Fatalf("%s: no client Finished and SHTS in the trace", self.leg.name)
	return nil, nil, nil
}

func (self *testGateFixture) feed(t *testing.T, gate *edgeSession, entries []*testTraceEntry) {
	t.Helper()
	for _, entry := range entries {
		var err error
		if entry.fromClient {
			_, err = gate.ClientRecord(entry.record)
		} else {
			err = gate.ServerRecord(entry.record)
		}
		if err != nil {
			t.Fatalf("%s: %v", self.leg.name, err)
		}
	}
}

func TestE1RefusesATwoRecordClientFlight(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		before, _, finished := fixture.splitFlight13(t)
		gate := fixture.gate(&testFixedVerifier{})
		fixture.feed(t, gate, before)
		if forwarded, err := gate.ClientRecord(finished); err != nil || len(forwarded) != 0 {
			t.Fatalf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		// a second record behind Finished, before any part exists
		_, err := gate.ClientRecord(finished)
		testExpectCheck(t, leg.name, err, checkE1)
	}
}

func TestE1RefusesRenegotiationIn12(t *testing.T) {
	leg := testTlsLegs()[2]
	fixture := testBdatGateCapture(t, leg)

	gate := fixture.gate(&testFixedVerifier{})
	fixture.replayHandshake(t, gate)
	_, err := gate.ClientRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, make([]byte, 40)))
	testExpectCheck(t, "client", err, checkE1)

	gate = fixture.gate(&testFixedVerifier{})
	fixture.replayHandshake(t, gate)
	testExpectCheck(t, "server", gate.ServerRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, make([]byte, 40))), checkE1)
}

func TestE1RefusesASecondClientKeyExchangeIn12(t *testing.T) {
	leg := testTlsLegs()[2]
	fixture := testBdatGateCapture(t, leg)
	gate := fixture.gate(&testFixedVerifier{})
	for i, entry := range fixture.trace {
		if !entry.fromClient {
			if err := gate.ServerRecord(entry.record); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := gate.ClientRecord(entry.record); err != nil {
			t.Fatal(err)
		}
		if 0 < i && entry.record[0] == tlsRecordHandshake {
			// S_ckx is the state after exactly one
			_, err := gate.ClientRecord(entry.record)
			testExpectCheck(t, leg.name, err, checkE1)
			return
		}
	}
	t.Fatal("the trace held no ClientKeyExchange")
}

func TestE1RefusesAFlightOutOfOrderIn12(t *testing.T) {
	leg := testTlsLegs()[2]
	fixture := testBdatGateCapture(t, leg)
	gate := fixture.gate(&testFixedVerifier{})
	if _, err := gate.ClientRecord(fixture.trace[0].record); err != nil {
		t.Fatal(err)
	}
	// the ServerHello, then a ServerHelloDone where the Certificate belongs
	if err := gate.ServerRecord(fixture.trace[1].record[:]); err != nil {
		testExpectCheck(t, "hello", err, checkE1)
	}
	err := gate.ServerRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, tlsHandshakeMessage(tlsHandshakeServerHelloDone, nil)))
	testExpectCheck(t, "done", err, checkE1)
}

// E2

func TestE2RefusesAnSHTSThatDoesNotOpenTheFlight(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		gate := fixture.gate(&testFixedVerifier{})
		var err error
		for _, entry := range fixture.trace {
			switch {
			case entry.shts != nil:
				wrong := bytes.Clone(entry.shts)
				wrong[0] ^= 1
				_, err = gate.DiscloseShts(wrong)
			case entry.fromClient:
				_, err = gate.ClientRecord(entry.record)
			default:
				err = gate.ServerRecord(entry.record)
			}
			if err != nil {
				break
			}
		}
		testExpectCheck(t, leg.name, err, checkE2)
	}
}

// Replays a 1.3 handshake with one message of the flight changed and the flight sealed again under
// SHTS, as a colluding MX could. That isolates E2's checks from the record's own tag.
func testE2FlightMutation(t *testing.T, fixture *testGateFixture, handshakeType uint8, mutate func(message []byte)) error {
	t.Helper()
	var shts []byte
	for _, entry := range fixture.trace {
		if entry.shts != nil {
			shts = entry.shts
		}
	}
	suite := fixture.leg.suites[0]
	key, iv := tls13TrafficKeys(suite, shts)
	opener, err := newTlsCipher(tlsVersion13, suite, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := newTlsCipher(tlsVersion13, suite, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	gate := fixture.gate(&testFixedVerifier{})
	serverHelloDone := false
	finishedSeen := false
	for _, entry := range fixture.trace {
		switch {
		case entry.shts != nil:
			_, err = gate.DiscloseShts(entry.shts)
			return err
		case entry.fromClient:
			if _, err = gate.ClientRecord(entry.record); err != nil {
				return err
			}
		default:
			record := entry.record
			if serverHelloDone && record[0] == tlsRecordApplicationData && !finishedSeen {
				_, content, err := opener.open(record)
				if err != nil {
					t.Fatal(err)
				}
				buffer := &tlsHandshakeBuffer{}
				buffer.add(content)
				var rebuilt []byte
				for {
					message := buffer.next()
					if message == nil {
						break
					}
					if message[0] == handshakeType {
						mutate(message)
					}
					finishedSeen = finishedSeen || message[0] == tlsHandshakeFinished
					rebuilt = append(rebuilt, message...)
				}
				if record, err = sealer.seal(tlsRecordHandshake, rebuilt); err != nil {
					t.Fatal(err)
				}
			}
			if record[0] == tlsRecordHandshake {
				serverHelloDone = true
			}
			if err = gate.ServerRecord(record); err != nil {
				return err
			}
		}
	}
	t.Fatal("the trace disclosed no SHTS")
	return nil
}

func TestE2RefusesAnSHTSOfAnotherLength(t *testing.T) {
	// HMAC pads a short key with zeros, so SHTS with a zero octet added opens the same flight. Z1 would
	// fail it later; the length is refused here, and before any key is derived from it
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		before, shts, _ := fixture.splitFlight13(t)
		for _, disclosed := range [][]byte{nil, shts[:len(shts)-1], append(bytes.Clone(shts), 0)} {
			gate := fixture.gate(&testFixedVerifier{})
			fixture.feed(t, gate, before)
			_, err := gate.DiscloseShts(disclosed)
			testExpectCheck(t, leg.name, err, checkE2)
		}
	}
}

func TestE2RefusesABadServerSignature(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		err := testE2FlightMutation(t, fixture, tlsHandshakeCertificateVerify, func(message []byte) {
			message[len(message)-1] ^= 1
		})
		testExpectCheck(t, leg.name, err, checkE2)
	}
}

func TestE2RefusesABadServerFinished(t *testing.T) {
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		err := testE2FlightMutation(t, fixture, tlsHandshakeFinished, func(message []byte) {
			message[len(message)-1] ^= 1
		})
		testExpectCheck(t, leg.name, err, checkE2)
	}
}

func TestE2RefusesABadServerKeyExchangeIn12(t *testing.T) {
	leg := testTlsLegs()[2]
	fixture := testBdatGateCapture(t, leg)
	gate := fixture.gate(&testFixedVerifier{})
	var err error
	for _, entry := range fixture.trace {
		if entry.fromClient {
			if _, err = gate.ClientRecord(entry.record); err != nil {
				break
			}
			continue
		}
		record := bytes.Clone(entry.record)
		// the flight's messages may share records; find ServerKeyExchange by walking them
		if record[0] == tlsRecordHandshake {
			offset := tlsRecordHeaderBytes
			for offset+4 <= len(record) {
				size := int(record[offset+1])<<16 | int(record[offset+2])<<8 | int(record[offset+3])
				if record[offset] == tlsHandshakeServerKeyExchange {
					record[offset+4+size-1] ^= 1
				}
				offset += 4 + size
			}
		}
		if err = gate.ServerRecord(record); err != nil {
			break
		}
	}
	testExpectCheck(t, leg.name, err, checkE2)
}

func TestE2DoesNotKeepTheSecret(t *testing.T) {
	// D-SMTP-10: only the hash survives, as Z1's public input
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		gate := fixture.gate(&testFixedVerifier{})
		fixture.replayHandshake(t, gate)
		var shts []byte
		for _, entry := range fixture.trace {
			if entry.shts != nil {
				shts = entry.shts
			}
		}
		want := sha256.Sum256(shts)
		if !bytes.Equal(gate.session.shtsHash, want[:]) {
			t.Errorf("%s: H_shts is not SHA-256(SHTS)", leg.name)
		}
		if bytes.Equal(gate.session.shtsHash, shts) {
			t.Errorf("%s: the gate kept SHTS", leg.name)
		}
	}
}

func TestE2AcceptsDisclosureBeforeOrAfterTheClientsFinished(t *testing.T) {
	// the RPC and the stream are not ordered against each other
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		before, shts, finished := fixture.splitFlight13(t)
		for _, disclosureFirst := range []bool{true, false} {
			gate := fixture.gate(&testFixedVerifier{})
			fixture.feed(t, gate, before)
			var forwarded [][]byte
			var err error
			if disclosureFirst {
				if forwarded, err = gate.DiscloseShts(shts); err != nil || len(forwarded) != 0 {
					t.Fatalf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
				}
				forwarded, err = gate.ClientRecord(finished)
			} else {
				if forwarded, err = gate.ClientRecord(finished); err != nil || len(forwarded) != 0 {
					t.Fatalf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
				}
				forwarded, err = gate.DiscloseShts(shts)
			}
			if err != nil || len(forwarded) != 1 || !bytes.Equal(forwarded[0], finished) {
				t.Errorf("%s: disclosure first %v: %d forwarded, %v", leg.name, disclosureFirst, len(forwarded), err)
			}
			if gate.phase != edgePhaseApplication {
				t.Errorf("%s: disclosure first %v: phase %d", leg.name, disclosureFirst, gate.phase)
			}
		}
	}
}

func TestE2AcceptsAPartOvertakingTheClientsFinished(t *testing.T) {
	// pi1's RPC is not ordered against Finished either: it may verify, and clears nothing early
	for _, leg := range testTlsLegs()[:2] {
		fixture := testBdatGateCapture(t, leg)
		before, shts, finished := fixture.splitFlight13(t)
		gate := fixture.gate(&testFixedVerifier{})
		fixture.feed(t, gate, before)
		if _, err := gate.DiscloseShts(shts); err != nil {
			t.Fatal(err)
		}
		forwarded, err := gate.VerifyPart(context.Background(), fixture.parts[0])
		if err != nil || len(forwarded) != 0 {
			t.Fatalf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		if forwarded, err = gate.ClientRecord(finished); err != nil || len(forwarded) != 1 {
			t.Errorf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
		}
	}
}

// E3

// A gate past its handshake, with the records it will see next.
type testOpenGate struct {
	fixture *testGateFixture
	gate    *edgeSession
	client  [][]byte
	server  [][]byte
}

func testOpen(t *testing.T, fixture *testGateFixture, verifier partVerifier) *testOpenGate {
	t.Helper()
	gate := fixture.gate(verifier)
	next := fixture.replayHandshake(t, gate)
	return &testOpenGate{fixture: fixture, gate: gate, client: fixture.clientRecords(next), server: fixture.serverRecords(next)}
}

// Verifies parts and feeds server records up to the given part, leaving the gate ready for its
// records, and returns what that part clears. The trace's server records are fed in order.
func (self *testOpenGate) verifyThrough(t *testing.T, index uint32) {
	t.Helper()
	fed := 0
	for _, part := range self.fixture.parts {
		for uint64(fed) < part.ServerRecordCount {
			if err := self.gate.ServerRecord(self.server[fed]); err != nil {
				t.Fatal(err)
			}
			fed += 1
		}
		if _, err := self.gate.VerifyPart(context.Background(), part); err != nil {
			t.Fatal(err)
		}
		if part.Index == index {
			break
		}
	}
	self.server = self.server[fed:]
}

func TestE3HoldsAClientRecordUntilAPartCoversIt(t *testing.T) {
	for _, leg := range testTlsLegs() {
		open := testOpen(t, testBdatGateCapture(t, leg), &testFixedVerifier{})
		forwarded, err := open.gate.ClientRecord(open.client[0])
		if err != nil || len(forwarded) != 0 {
			t.Fatalf("%s: %d forwarded before its proof, %v", leg.name, len(forwarded), err)
		}
		forwarded, err = open.gate.VerifyPart(context.Background(), open.fixture.parts[0])
		if err != nil || len(forwarded) != 1 || !bytes.Equal(forwarded[0], open.client[0]) {
			t.Fatalf("%s: %d forwarded after its proof, %v", leg.name, len(forwarded), err)
		}
	}
}

func TestE3CutsARecordUnequalToWhatItsPartProved(t *testing.T) {
	for _, leg := range testTlsLegs() {
		open := testOpen(t, testBdatGateCapture(t, leg), &testFixedVerifier{})
		open.verifyThrough(t, 1)
		tampered := bytes.Clone(open.client[0])
		tampered[len(tampered)-1] ^= 1
		forwarded, err := open.gate.ClientRecord(tampered)
		if len(forwarded) != 0 {
			t.Errorf("%s: forwarded", leg.name)
		}
		testExpectCut(t, leg.name, err)
	}
}

func TestE3HoldsAMessageRecordBehindAnUncoveredServerRecord(t *testing.T) {
	// a late ticket relayed after pi3's count: its records wait, are not cut, and go once the part is
	// proven again over it
	for _, leg := range testTlsLegs() {
		open := testOpen(t, testBdatGateCapture(t, leg), &testFixedVerifier{})
		open.verifyThrough(t, 3)
		late := tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 64))
		if err := open.gate.ServerRecord(late); err != nil {
			t.Fatal(err)
		}
		// EHLO, MAIL and RCPT are not message records, and went on the trace's way
		for _, record := range open.client[:3] {
			if forwarded, err := open.gate.ClientRecord(record); err != nil || len(forwarded) != 1 {
				t.Fatalf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
			}
		}
		bdat := open.client[3]
		forwarded, err := open.gate.ClientRecord(bdat)
		if err != nil || len(forwarded) != 0 {
			t.Fatalf("%s: BDAT passed an uncovered server record: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		again := *open.fixture.parts[2]
		again.ServerRecordCount += 1
		again.Proof = []byte("proven again")
		forwarded, err = open.gate.VerifyPart(context.Background(), &again)
		if err != nil || len(forwarded) != 1 || !bytes.Equal(forwarded[0], bdat) {
			t.Fatalf("%s: %d forwarded after the part was proven again, %v", leg.name, len(forwarded), err)
		}
	}
}

func TestE3LetsQuitPastAnUncoveredServerRecord(t *testing.T) {
	// the MX's reply to the message is such a record, and QUIT must still reach it
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 3)
		for _, record := range open.client[:len(open.client)-1] {
			if _, err := open.gate.ClientRecord(record); err != nil {
				t.Fatal(err)
			}
		}
		if err := open.gate.ServerRecord(open.server[0]); err != nil {
			t.Fatal(err)
		}
		forwarded, err := open.gate.ClientRecord(open.client[len(open.client)-1])
		if err != nil || len(forwarded) != 1 {
			t.Fatalf("%s: QUIT: %d forwarded, %v", leg.name, len(forwarded), err)
		}
	}
}

func TestE3CutsABodyPastOctetN(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 3)
		// through the header block, which is everything before the body
		for _, record := range open.client[:5] {
			if _, err := open.gate.ClientRecord(record); err != nil {
				t.Fatal(err)
			}
		}
		// an unopened record longer than the body the preamble declared
		oversize := tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 1000))
		forwarded, err := open.gate.ClientRecord(oversize)
		if len(forwarded) != 0 {
			t.Errorf("%s: forwarded", leg.name)
		}
		testExpectCut(t, leg.name, err)
	}
}

func TestE3CutsAChunkShortOfOctetNAtQuit(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 3)
		for _, record := range open.client[:5] {
			if _, err := open.gate.ClientRecord(record); err != nil {
				t.Fatal(err)
			}
		}
		// a one-octet body record, then QUIT at its proven position, with most of the chunk missing
		overhead := tlsAeadTagBytes + tlsInnerTypeBytes
		if fixture.version() == tlsVersion12 {
			overhead = tlsAeadTagBytes + tlsExplicitNonceBytes
		}
		short := tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, overhead+1))
		if _, err := open.gate.ClientRecord(short); err != nil {
			t.Fatal(err)
		}
		forwarded, err := open.gate.ClientRecord(open.client[len(open.client)-1])
		if len(forwarded) != 0 {
			t.Errorf("%s: QUIT forwarded", leg.name)
		}
		testExpectCut(t, leg.name, err)
	}
}

func TestE3ForwardsNothingAfterTheFinalQuit(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 3)
		for _, record := range open.client {
			if _, err := open.gate.ClientRecord(record); err != nil {
				t.Fatal(err)
			}
		}
		// a second transaction, or a close_notify: either ends the connection, and neither is a cut
		forwarded, err := open.gate.ClientRecord(open.client[0])
		if err == nil || len(forwarded) != 0 {
			t.Errorf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		if errors.Is(err, sidecar.ErrSmtpRecordCut) {
			t.Errorf("%s: a record after QUIT counted as a cut", leg.name)
		}
	}
}

func TestE3CutsOnAFailedProof(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{err: errors.New("synthetic refusal")})
		forwarded, err := open.gate.VerifyPart(context.Background(), fixture.parts[0])
		if len(forwarded) != 0 {
			t.Errorf("%s: forwarded", leg.name)
		}
		testExpectCut(t, leg.name, err)
	}
}

func TestE3TreatsAPartAsMootOnceTheMxHasClosed(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{err: errors.New("synthetic refusal")})
		open.gate.ServerClosed()
		forwarded, err := open.gate.VerifyPart(context.Background(), fixture.parts[0])
		if err != nil || len(forwarded) != 0 {
			t.Errorf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
		}
	}
}

func TestE3RefusesPartsOutOfOrder(t *testing.T) {
	cases := []struct {
		name     string
		through  uint32
		index    int
		mutation func(part *sidecar.SmtpProofPart)
	}{
		{name: "a first part that is not pi1", index: 1},
		{name: "a skipped index", through: 1, index: 2},
		{name: "a gap before first_record", through: 1, index: 1, mutation: func(part *sidecar.SmtpProofPart) { part.FirstRecord += 1 }},
		{name: "pi1 with a mode", index: 0, mutation: func(part *sidecar.SmtpProofPart) { part.Mode = partModeBdat }},
		{name: "an unknown mode", through: 1, index: 1, mutation: func(part *sidecar.SmtpProofPart) { part.Mode = 3 }},
		{name: "mode changed from pi2", through: 2, index: 2, mutation: func(part *sidecar.SmtpProofPart) { part.Mode = partModeData }},
		{name: "server records never relayed", through: 1, index: 1, mutation: func(part *sidecar.SmtpProofPart) { part.ServerRecordCount += 100 }},
		{name: "pi1 over server records", index: 0, mutation: func(part *sidecar.SmtpProofPart) { part.ServerRecordCount = 1 }},
		{name: "no record", through: 1, index: 1, mutation: func(part *sidecar.SmtpProofPart) { part.Records = nil }},
		{name: "a command too long for its template", index: 0, mutation: func(part *sidecar.SmtpProofPart) {
			part.Records = [][]byte{tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 400))}
		}},
	}
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		for _, c := range cases {
			open := testOpen(t, fixture, &testFixedVerifier{})
			if 0 < c.through {
				open.verifyThrough(t, c.through)
			}
			part := *fixture.parts[c.index]
			// feed what a real pi2 or pi3 would cover, so only the mutation is out of place
			for uint64(len(open.gate.serverRecords)) < part.ServerRecordCount && 0 < len(open.server) {
				if err := open.gate.ServerRecord(open.server[0]); err != nil {
					t.Fatal(err)
				}
				open.server = open.server[1:]
			}
			if c.mutation != nil {
				c.mutation(&part)
			}
			_, err := open.gate.VerifyPart(context.Background(), &part)
			testExpectCheck(t, leg.name+": "+c.name, err, checkE3)
			if errors.Is(err, sidecar.ErrSmtpRecordCut) {
				t.Errorf("%s: %s: refused as a cut", leg.name, c.name)
			}
		}
	}
}

func TestE3RefusesARecordOfAnotherVersion(t *testing.T) {
	// SPEC.md section 6 fixes 0303, and an unopened body record is compared with nothing else
	for _, leg := range testTlsLegs() {
		open := testOpen(t, testBdatGateCapture(t, leg), &testFixedVerifier{})
		record := bytes.Clone(open.client[0])
		record[2] = 1
		_, err := open.gate.ClientRecord(record)
		testExpectCheck(t, leg.name, err, checkE1)
	}
}

func TestE3RefusesBdatRecordsThatShareASequenceNumber(t *testing.T) {
	// QUIT proven at the header block's own number would take its place in the gate, and BDAT 0 LAST
	// and that QUIT would then pass with no header block behind them
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		for _, offset := range []uint64{0, 1} {
			open := testOpen(t, fixture, &testFixedVerifier{})
			open.verifyThrough(t, 2)
			part := *fixture.parts[2]
			for uint64(len(open.gate.serverRecords)) < part.ServerRecordCount {
				if err := open.gate.ServerRecord(open.server[0]); err != nil {
					t.Fatal(err)
				}
				open.server = open.server[1:]
			}
			part.LastRecord = part.FirstRecord + offset
			_, err := open.gate.VerifyPart(context.Background(), &part)
			testExpectCheck(t, leg.name, err, checkE3)
		}
	}
}

// Holds the first verification until told, so that another part can pass it.
type testHeldVerifier struct {
	stateLock sync.Mutex
	hold      bool
	reached   chan struct{}
	release   chan struct{}
}

func (self *testHeldVerifier) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	hold := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		hold := self.hold
		self.hold = false
		return hold
	}()
	if hold {
		close(self.reached)
		<-self.release
	}
	return nil
}

// A gate at pi3, the first part it will see held in verification, and what that call returns.
func testHeldPart(t *testing.T, fixture *testGateFixture, held *sidecar.SmtpProofPart) (*testOpenGate, *testHeldVerifier, chan error) {
	t.Helper()
	verifier := &testHeldVerifier{reached: make(chan struct{}), release: make(chan struct{})}
	open := testOpen(t, fixture, verifier)
	open.verifyThrough(t, 2)
	for uint64(len(open.gate.serverRecords)) < fixture.parts[2].ServerRecordCount {
		if err := open.gate.ServerRecord(open.server[0]); err != nil {
			t.Fatal(err)
		}
		open.server = open.server[1:]
	}
	verifier.stateLock.Lock()
	verifier.hold = true
	verifier.stateLock.Unlock()
	done := make(chan error, 1)
	go func() {
		_, err := open.gate.VerifyPart(context.Background(), held)
		done <- err
	}()
	<-verifier.reached
	return open, verifier, done
}

func TestE3APartVerifiedBesideAnotherCannotReplaceIt(t *testing.T) {
	// both passed the order checks against pi2, and a replacement's checks never saw the other one, so
	// the one that lands second must not change what the gate holds
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		other := *fixture.parts[2]
		other.Proof = []byte("another proof")
		other.Records = testCloneByteSlices(fixture.parts[2].Records)
		other.Records[1][len(other.Records[1])-1] ^= 1
		open, verifier, done := testHeldPart(t, fixture, &other)
		if _, err := open.gate.VerifyPart(context.Background(), fixture.parts[2]); err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		close(verifier.release)
		err := <-done
		testExpectCheck(t, leg.name, err, checkE3)
		if errors.Is(err, sidecar.ErrSmtpRecordCut) {
			t.Errorf("%s: an overlap is no cut", leg.name)
		}
		if !bytes.Equal(open.gate.parts[2].part.Proof, fixture.parts[2].Proof) {
			t.Errorf("%s: the part that landed second replaced the first", leg.name)
		}
	}
}

func TestE3AResendBesideItsOriginalIsIdempotent(t *testing.T) {
	// a retried RPC can overlap the call it retries, and an honest send must survive that
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open, verifier, done := testHeldPart(t, fixture, fixture.parts[2])
		if _, err := open.gate.VerifyPart(context.Background(), fixture.parts[2]); err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		close(verifier.release)
		if err := <-done; err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
		if len(open.gate.parts) != 3 {
			t.Errorf("%s: %d parts", leg.name, len(open.gate.parts))
		}
	}
}

func testCloneByteSlices(values [][]byte) [][]byte {
	clones := make([][]byte, 0, len(values))
	for _, value := range values {
		clones = append(clones, bytes.Clone(value))
	}
	return clones
}

func TestE3ResendingAPartIsIdempotent(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		// the verifier would refuse a second look, so an exact resend must not reach it
		verifier := &testFixedVerifier{}
		open := testOpen(t, fixture, verifier)
		open.verifyThrough(t, 1)
		verifier.err = errors.New("verified twice")
		if _, err := open.gate.VerifyPart(context.Background(), fixture.parts[0]); err != nil {
			t.Errorf("%s: %v", leg.name, err)
		}
	}
}

func TestE3RefusesAReprovenPartThatChangesItsRecords(t *testing.T) {
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 3)
		late := tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 64))
		if err := open.gate.ServerRecord(late); err != nil {
			t.Fatal(err)
		}
		again := *fixture.parts[2]
		again.ServerRecordCount += 1
		again.Proof = []byte("proven again")
		again.Records = [][]byte{bytes.Clone(again.Records[0]), bytes.Clone(again.Records[1]), bytes.Clone(again.Records[2])}
		again.Records[1][len(again.Records[1])-1] ^= 1
		_, err := open.gate.VerifyPart(context.Background(), &again)
		testExpectCheck(t, leg.name, err, checkE3)
	}
}

func TestE3RefusesDataOctetsPastTheDeclaredCount(t *testing.T) {
	settings := DefaultProverSettings()
	settings.ForceData = true
	for _, leg := range testTlsLegs() {
		fixture := testGateCapture(t, leg, testMxDefaults(), settings, testJob("one line\r\n", "bob"))
		// a declared count one short of what the last part carries
		short := *fixture.preamble
		short.messageByteCount -= 1
		fixture.preamble = &short
		open := testOpen(t, fixture, &testFixedVerifier{})
		open.verifyThrough(t, 2)
		for uint64(len(open.gate.serverRecords)) < fixture.parts[2].ServerRecordCount {
			if err := open.gate.ServerRecord(open.server[0]); err != nil {
				t.Fatal(err)
			}
			open.server = open.server[1:]
		}
		_, err := open.gate.VerifyPart(context.Background(), fixture.parts[2])
		testExpectCheck(t, leg.name, err, checkE3)
	}
}

func TestE3BoundsWhatItHolds(t *testing.T) {
	for _, leg := range testTlsLegs() {
		settings := defaultEdgeSettings()
		settings.maxHeldBytes = 64
		fixture := testBdatGateCapture(t, leg)
		gate := newEdgeSession(settings, fixture.preamble, testMxHost, &testFixedVerifier{})
		fixture.replayHandshake(t, gate)
		oversize := tlsFrameRecord(tlsRecordApplicationData, tlsVersion12, make([]byte, 100))
		_, err := gate.ClientRecord(oversize)
		testExpectCheck(t, leg.name, err, checkE3)
	}
}
