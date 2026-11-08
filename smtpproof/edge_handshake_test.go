// E1 and E2 as the edge derives Z1's public inputs, against what the real server derived: crypto/tls's
// KeyLogWriter prints the secrets the MX used, so the edge's inputs are checked against the MX itself
// rather than against the prover that also computed them.

package smtpproof

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

// One line of an NSS key log: its label, the client random it names and the secret.
type testKeyLogLine struct {
	clientRandom []byte
	secret       []byte
}

func testKeyLog(t *testing.T, log string) map[string]*testKeyLogLine {
	t.Helper()
	lines := map[string]*testKeyLogLine{}
	for _, line := range strings.Split(log, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		clientRandom, err := hex.DecodeString(fields[1])
		if err != nil {
			t.Fatal(err)
		}
		secret, err := hex.DecodeString(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		lines[fields[0]] = &testKeyLogLine{clientRandom: clientRandom, secret: secret}
	}
	return lines
}

// Each leg with its server writing its key log to a buffer of the test's.
func testLoggingLegs() ([]*testTlsLeg, []*bytes.Buffer) {
	var legs []*testTlsLeg
	var logs []*bytes.Buffer
	for _, leg := range testTlsLegs() {
		log := &bytes.Buffer{}
		serverTls := leg.serverTls
		legs = append(legs, &testTlsLeg{
			name:   leg.name,
			suites: leg.suites,
			serverTls: func(t *testing.T) *tls.Config {
				config := serverTls(t)
				config.KeyLogWriter = log
				return config
			},
		})
		logs = append(logs, log)
	}
	return legs, logs
}

func TestEdgeInputsEqualServerKeyLog(t *testing.T) {
	legs, logs := testLoggingLegs()
	for i, leg := range legs {
		job := testJob("a body line\r\n", "bob")
		send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
		session := send.edge.session.session
		logged := testKeyLog(t, logs[i].String())

		if session.version == tlsVersion13 {
			// H_shts is the hash of the very secret the MX logged
			serverHandshake := logged["SERVER_HANDSHAKE_TRAFFIC_SECRET"]
			shtsHash := sha256.Sum256(serverHandshake.secret)
			if !bytes.Equal(session.shtsHash, shtsHash[:]) {
				t.Errorf("%s: H_shts is not the hash of the MX's SHTS", leg.name)
			}
			// H_sh and H_sf are the MX's transcript hashes: with the honest HS they give every secret the
			// MX logged, and a hash off by one bit would give none of them
			hs := send.backend.proved[0].handshakeSecret
			for label, want := range map[string][]byte{
				"s hs traffic": serverHandshake.secret,
				"c hs traffic": logged["CLIENT_HANDSHAKE_TRAFFIC_SECRET"].secret,
			} {
				if !bytes.Equal(tls13TrafficSecret(hs, label, session.helloHash), want) {
					t.Errorf("%s: H_sh does not give the MX's %s", leg.name, label)
				}
			}
			ms := tls13MasterSecret(hs)
			for label, want := range map[string][]byte{
				"s ap traffic": logged["SERVER_TRAFFIC_SECRET_0"].secret,
				"c ap traffic": logged["CLIENT_TRAFFIC_SECRET_0"].secret,
			} {
				if !bytes.Equal(tls13TrafficSecret(ms, label, session.finishedHash), want) {
					t.Errorf("%s: H_sf does not give the MX's %s", leg.name, label)
				}
			}
			continue
		}

		// 1.2: the MX logged its master secret under the client random it saw. With that secret alone,
		// none of the prover's, the edge's r_c, r_s, S_ckx and SF must satisfy Z1's Finished equation
		line := logged["CLIENT_RANDOM"]
		if !bytes.Equal(session.clientRandom, line.clientRandom) {
			t.Errorf("%s: r_c is not the client random the MX logged", leg.name)
		}
		block := tls12DeriveKeyBlock(line.secret, session.clientRandom, session.serverRandom)
		cipher, err := newTlsCipher(tlsVersion12, session.suite, block.serverKey, block.serverSalt)
		if err != nil {
			t.Fatal(err)
		}
		recordType, content, err := cipher.open(session.serverFinishedRecord)
		if err != nil || recordType != tlsRecordHandshake {
			t.Fatalf("%s: the MX's key block does not open SF: %v", leg.name, err)
		}
		finishedHash, err := session.preFinishedState.finish(nil)
		if err != nil {
			t.Fatal(err)
		}
		clientFinished := tls12FinishedMessage(line.secret, tlsLabelClientFinished, finishedHash)
		resumedHash, err := session.preFinishedState.finish(clientFinished)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, tls12FinishedMessage(line.secret, tlsLabelServerFinished, resumedHash)) {
			t.Errorf("%s: SF does not open to the verify_data the MX's secret gives S_ckx", leg.name)
		}
	}
}

func TestE1BoundsAServerHelloThatNeverEnds(t *testing.T) {
	// a ServerHello may declare 16 MiB, and an MX is whoever a sidecar mails: its records must not
	// pile up waiting for an end that need not come
	gate := newEdgeSession(defaultEdgeSettings(), testEmptyPreamble(), testMxHost, &testFixedVerifier{})
	if _, err := gate.ClientRecord(testClientHelloRecord(t, nil, testMxHost)); err != nil {
		t.Fatal(err)
	}
	header := []byte{tlsHandshakeServerHello, 0xff, 0xff, 0xff}
	if err := gate.ServerRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, append(header, make([]byte, 1000)...))); err != nil {
		t.Fatalf("the first record: %v", err)
	}
	var err error
	sent := 0
	for err == nil && sent < 2*defaultEdgeSettings().maxHandshakeBytes {
		err = gate.ServerRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, make([]byte, tlsMaxPlaintextBytes)))
		sent += tlsMaxPlaintextBytes
	}
	testExpectCheck(t, "an endless ServerHello", err, checkE1)
	if pending := len(gate.serverBuffer.pending); defaultEdgeSettings().maxHandshakeBytes+tlsMaxPlaintextBytes < pending {
		t.Errorf("held %d octets", pending)
	}
}

func TestTheGateEndsAtItsFirstRefusal(t *testing.T) {
	// every refusal ends the gate, so that what follows one, however honest, passes nothing: a record
	// out of turn, a cut, a failed proof and a refused part each, then the trace's honest rest
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		refusals := []struct {
			name   string
			refuse func(open *testOpenGate) error
		}{
			{name: "a handshake record after the handshake", refuse: func(open *testOpenGate) error {
				_, err := open.gate.ClientRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, make([]byte, 40)))
				return err
			}},
			{name: "a cut", refuse: func(open *testOpenGate) error {
				if _, err := open.gate.VerifyPart(t.Context(), fixture.parts[0]); err != nil {
					t.Fatal(err)
				}
				tampered := bytes.Clone(open.client[0])
				tampered[len(tampered)-1] ^= 1
				_, err := open.gate.ClientRecord(tampered)
				return err
			}},
			{name: "a part refused before verification", refuse: func(open *testOpenGate) error {
				_, err := open.gate.VerifyPart(t.Context(), fixture.parts[1])
				return err
			}},
		}
		for _, c := range refusals {
			open := testOpen(t, fixture, &testFixedVerifier{})
			if err := c.refuse(open); err == nil {
				t.Fatalf("%s: %s: no refusal", leg.name, c.name)
			}
			for _, part := range fixture.parts {
				if forwarded, err := open.gate.VerifyPart(t.Context(), part); err == nil || len(forwarded) != 0 {
					t.Errorf("%s: %s: part %d after the refusal: %d forwarded, %v", leg.name, c.name, part.Index, len(forwarded), err)
				}
			}
			for _, record := range open.client {
				if forwarded, err := open.gate.ClientRecord(record); err == nil || len(forwarded) != 0 {
					t.Errorf("%s: %s: a record after the refusal: %d forwarded, %v", leg.name, c.name, len(forwarded), err)
				}
			}
			if err := open.gate.ServerRecord(open.server[0]); err == nil {
				t.Errorf("%s: %s: a server record after the refusal was taken", leg.name, c.name)
			}
		}

		// a failed proof is a cut that ends the gate too, even with a part verifying beside it
		open := testOpen(t, fixture, &testFixedVerifier{err: sidecar.ErrSmtpRecordCut})
		if _, err := open.gate.VerifyPart(t.Context(), fixture.parts[0]); err == nil {
			t.Fatalf("%s: a failed proof passed", leg.name)
		}
		open.gate.verifier = &testFixedVerifier{}
		if forwarded, err := open.gate.VerifyPart(t.Context(), fixture.parts[0]); err == nil || len(forwarded) != 0 {
			t.Errorf("%s: the part passed once the proof failed: %v", leg.name, err)
		}
	}
}

func TestAPartVerifyingBesideARefusalReleasesNothing(t *testing.T) {
	// a part verifies with no lock held; a refusal landing meanwhile ends the gate, and the part's
	// commit must then release nothing it would have
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		verifier := &testHeldVerifier{hold: true, reached: make(chan struct{}), release: make(chan struct{})}
		open := testOpen(t, fixture, verifier)
		if forwarded, err := open.gate.ClientRecord(open.client[0]); err != nil || len(forwarded) != 0 {
			t.Fatalf("%s: %d forwarded, %v", leg.name, len(forwarded), err)
		}
		done := make(chan error, 1)
		var forwarded [][]byte
		go func() {
			var err error
			forwarded, err = open.gate.VerifyPart(t.Context(), fixture.parts[0])
			done <- err
		}()
		<-verifier.reached
		if err := open.gate.ServerRecord(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, make([]byte, 40))); err == nil {
			t.Fatalf("%s: a handshake record after the handshake passed", leg.name)
		}
		close(verifier.release)
		if err := <-done; err == nil || len(forwarded) != 0 {
			t.Errorf("%s: the part released %d records after the refusal: %v", leg.name, len(forwarded), err)
		}
	}
}
