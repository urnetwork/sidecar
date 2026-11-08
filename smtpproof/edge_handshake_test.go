// E1 and E2 as the edge derives Z1's public inputs, against what the real server derived: crypto/tls's
// KeyLogWriter prints the secrets the MX used, so the edge's inputs are checked against the MX itself
// rather than against the prover that also computed them. Beside that: the handshake messages split
// across records anywhere, and a SHA-1 signature refused where it verifies.

package smtpproof

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
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

// Holds the Z1 inputs the edge derived over a finished send to the secrets its MX logged.
func testExpectEdgeInputsInKeyLog(t *testing.T, leg *testTlsLeg, send *testSend, log string) {
	t.Helper()
	session := send.edge.session.session
	logged := testKeyLog(t, log)

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
		return
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

func TestEdgeInputsEqualServerKeyLog(t *testing.T) {
	legs, logs := testLoggingLegs()
	for i, leg := range legs {
		job := testJob("a body line\r\n", "bob")
		send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
		testExpectEdgeInputsInKeyLog(t, leg, send, logs[i].String())
	}
}

func TestEdgeInputsEqualServerKeyLogAfterARetry(t *testing.T) {
	// a HelloRetryRequest puts a message_hash of the first ClientHello in its place in H_sh and H_sf
	// (RFC 8446 §4.4.1), and the edge's hashes must still be the MX's. The MX prefers P-256, so it
	// retries the client's first share, which is X25519
	legs, logs := testLoggingLegs()
	for i, leg := range legs[:2] {
		retried := *leg
		retried.name += " after a retry"
		retried.serverTls = func(t *testing.T) *tls.Config {
			config := leg.serverTls(t)
			config.CurvePreferences = []tls.CurveID{tls.CurveP256}
			return config
		}
		job := testJob("a body line\r\n", "bob")
		send := testRunSend(t, &retried, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, &retried, send, job)
		if !send.edge.session.helloRetried {
			t.Fatalf("%s: the MX did not retry", retried.name)
		}
		testExpectEdgeInputsInKeyLog(t, &retried, send, logs[i].String())
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

// The SHA-1 schemes of RFC 8446 §4.2.3's legacy list, which no TLS 1.3 peer may use for
// CertificateVerify and E2 accepts in neither version.
const (
	testSchemeRsaPkcs1Sha1 uint16 = 0x0201
	testSchemeEcdsaSha1    uint16 = 0x0203
)

// A digest of signed under hash, for signing as a TLS peer would.
func testDigest(hash crypto.Hash, signed []byte) []byte {
	if hash == crypto.SHA1 {
		sum := sha1.Sum(signed)
		return sum[:]
	}
	sum := sha256.Sum256(signed)
	return sum[:]
}

func TestTlsSignaturesRefuseSha1WhereTheyVerify(t *testing.T) {
	// valid SHA-1 signatures under both key types, refused in both versions, beside SHA-256 twins that
	// pass: the refusal is the scheme's, not a failed verification's
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signed := tlsCertificateVerifySigned(make([]byte, sha256.Size))
	signEcdsa := func(hash crypto.Hash) []byte {
		signature, err := ecdsa.SignASN1(rand.Reader, ecdsaKey, testDigest(hash, signed))
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}
	signPkcs1 := func(hash crypto.Hash) []byte {
		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, testDigest(hash, signed))
		if err != nil {
			t.Fatal(err)
		}
		return signature
	}
	cases := []struct {
		name      string
		version   uint16
		publicKey crypto.PublicKey
		scheme    uint16
		signature []byte
		accept    bool
	}{
		{name: "ecdsa sha-1 in 1.3", version: tlsVersion13, publicKey: &ecdsaKey.PublicKey, scheme: testSchemeEcdsaSha1, signature: signEcdsa(crypto.SHA1)},
		{name: "ecdsa sha-1 in 1.2", version: tlsVersion12, publicKey: &ecdsaKey.PublicKey, scheme: testSchemeEcdsaSha1, signature: signEcdsa(crypto.SHA1)},
		{name: "rsa pkcs1 sha-1 in 1.3", version: tlsVersion13, publicKey: &rsaKey.PublicKey, scheme: testSchemeRsaPkcs1Sha1, signature: signPkcs1(crypto.SHA1)},
		{name: "rsa pkcs1 sha-1 in 1.2", version: tlsVersion12, publicKey: &rsaKey.PublicKey, scheme: testSchemeRsaPkcs1Sha1, signature: signPkcs1(crypto.SHA1)},
		{name: "ecdsa sha-256 in 1.3", version: tlsVersion13, publicKey: &ecdsaKey.PublicKey, scheme: tlsSchemeEcdsaSecp256r1, signature: signEcdsa(crypto.SHA256), accept: true},
		{name: "ecdsa sha-256 in 1.2", version: tlsVersion12, publicKey: &ecdsaKey.PublicKey, scheme: tlsSchemeEcdsaSecp256r1, signature: signEcdsa(crypto.SHA256), accept: true},
		{name: "rsa pkcs1 sha-256 in 1.2", version: tlsVersion12, publicKey: &rsaKey.PublicKey, scheme: tlsSchemeRsaPkcs1Sha256, signature: signPkcs1(crypto.SHA256), accept: true},
	}
	for _, c := range cases {
		err := tlsVerifySignature(c.version, c.publicKey, c.scheme, signed, c.signature)
		if (err == nil) != c.accept {
			t.Errorf("%s: accepted %v, want %v: %v", c.name, err == nil, c.accept, err)
		}
	}
}

// A leg whose MX signs with a certificate the test holds the key of.
func testLegSigningWith(leg *testTlsLeg, certificate tls.Certificate) *testTlsLeg {
	return &testTlsLeg{
		name:   leg.name,
		suites: leg.suites,
		serverTls: func(t *testing.T) *tls.Config {
			config := leg.serverTls(t)
			config.Certificates = []tls.Certificate{certificate}
			return config
		},
	}
}

// Replays a 1.3 handshake whose flight carries CertificateVerify as resign writes it over the
// transcript hash it signs, with the server's Finished recomputed under SHTS, so that the flight is
// what an MX holding the key could have sent. Returns what DiscloseShts returns.
func testE2ResignedFlight13(t *testing.T, fixture *testGateFixture, resign func(transcriptHash []byte) []byte) error {
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
	var transcript []byte
	finishedSeen := false
	for _, entry := range fixture.trace {
		switch {
		case entry.shts != nil:
			_, err := gate.DiscloseShts(entry.shts)
			return err
		case entry.fromClient:
			if entry.record[0] == tlsRecordHandshake {
				transcript = append(transcript, entry.record[tlsRecordHeaderBytes:]...)
			}
			if _, err := gate.ClientRecord(entry.record); err != nil {
				return err
			}
		default:
			record := entry.record
			switch {
			case record[0] == tlsRecordHandshake:
				transcript = append(transcript, record[tlsRecordHeaderBytes:]...)
			case record[0] == tlsRecordApplicationData && !finishedSeen:
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
					hash := sha256.Sum256(transcript)
					switch message[0] {
					case tlsHandshakeCertificateVerify:
						message = tlsHandshakeMessage(tlsHandshakeCertificateVerify, resign(hash[:]))
					case tlsHandshakeFinished:
						message = tlsHandshakeMessage(tlsHandshakeFinished, tls13FinishedData(shts, hash[:]))
						finishedSeen = true
					}
					transcript = append(transcript, message...)
					rebuilt = append(rebuilt, message...)
				}
				if record, err = sealer.seal(tlsRecordHandshake, rebuilt); err != nil {
					t.Fatal(err)
				}
			}
			if err := gate.ServerRecord(record); err != nil {
				return err
			}
		}
	}
	t.Fatal("the trace disclosed no SHTS")
	return nil
}

// Replays a 1.2 handshake whose ServerKeyExchange is signed as resign signs r_c || r_s || params.
// Returns the gate's first error, or nil once the whole handshake has passed.
func testE2ResignedKeyExchange12(t *testing.T, fixture *testGateFixture, resign func(signed []byte) []byte) error {
	t.Helper()
	gate := fixture.gate(&testFixedVerifier{})
	var clientRandom, serverRandom []byte
	serverChangeSeen := false
	for _, entry := range fixture.trace {
		if entry.fromClient {
			if clientRandom == nil {
				hello, err := tlsParseClientHello(entry.record[tlsRecordHeaderBytes+4:])
				if err != nil {
					t.Fatal(err)
				}
				clientRandom = hello.random
			}
			if _, err := gate.ClientRecord(entry.record); err != nil {
				return err
			}
		} else {
			record := entry.record
			// the server's flight in clear, each message whole in its record, as crypto/tls writes it
			if record[0] == tlsRecordHandshake && !serverChangeSeen {
				payload := record[tlsRecordHeaderBytes:]
				var rebuilt []byte
				for offset := 0; offset+4 <= len(payload); {
					size := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
					message := payload[offset : offset+4+size]
					offset += 4 + size
					switch message[0] {
					case tlsHandshakeServerHello:
						hello, err := tlsParseServerHello(message[4:])
						if err != nil {
							t.Fatal(err)
						}
						serverRandom = hello.random
					case tlsHandshakeServerKeyExchange:
						_, _, params, _, _, err := tlsParseServerKeyExchange(message[4:])
						if err != nil {
							t.Fatal(err)
						}
						signed := bytes.Join([][]byte{clientRandom, serverRandom, params}, nil)
						message = tlsHandshakeMessage(tlsHandshakeServerKeyExchange, append(bytes.Clone(params), resign(signed)...))
					}
					rebuilt = append(rebuilt, message...)
				}
				record = tlsFrameRecord(tlsRecordHandshake, tlsVersion12, rebuilt)
			}
			serverChangeSeen = serverChangeSeen || record[0] == tlsRecordChangeCipherSpec
			if err := gate.ServerRecord(record); err != nil {
				return err
			}
		}
		gate.stateLock.Lock()
		done := gate.phase == edgePhaseApplication
		gate.stateLock.Unlock()
		if done {
			return nil
		}
	}
	t.Fatal("the trace never finished its handshake")
	return nil
}

// A signature over what E2 checks, under the given scheme, as a scheme and length-prefixed signature.
func testSignedBy(t *testing.T, key *ecdsa.PrivateKey, scheme uint16, hash crypto.Hash, signed []byte) []byte {
	t.Helper()
	signature, err := ecdsa.SignASN1(rand.Reader, key, testDigest(hash, signed))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte{byte(scheme >> 8), byte(scheme), byte(len(signature) >> 8), byte(len(signature))}
	return append(body, signature...)
}

func TestE2RefusesASha1SignatureThatVerifies(t *testing.T) {
	// an MX holding its key signs the handshake under ecdsa_sha1, validly: E2 refuses it in both
	// versions, and the same handshake signed under ecdsa_secp256r1_sha256 passes
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := testCertificate(t, key)
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, testLegSigningWith(leg, certificate))
		for _, c := range []struct {
			scheme uint16
			hash   crypto.Hash
			accept bool
		}{
			{scheme: testSchemeEcdsaSha1, hash: crypto.SHA1},
			{scheme: tlsSchemeEcdsaSecp256r1, hash: crypto.SHA256, accept: true},
		} {
			var err error
			if fixture.version() == tlsVersion13 {
				err = testE2ResignedFlight13(t, fixture, func(transcriptHash []byte) []byte {
					return testSignedBy(t, key, c.scheme, c.hash, tlsCertificateVerifySigned(transcriptHash))
				})
			} else {
				err = testE2ResignedKeyExchange12(t, fixture, func(signed []byte) []byte {
					return testSignedBy(t, key, c.scheme, c.hash, signed)
				})
			}
			if c.accept {
				if err != nil {
					t.Errorf("%s: scheme %#x: %v", leg.name, c.scheme, err)
				}
				continue
			}
			testExpectCheck(t, leg.name, err, checkE2)
		}
	}
}

// Where a run of handshake records sits in a trace: the entries from start to end, all of one side,
// and the handshake octets they carry. sealer gives each framing of the run its records' writer: one
// in clear, or 1.3's flight sealed again from its first sequence number.
type testHandshakeRun struct {
	name   string
	start  int
	end    int
	octets []byte
	sealer func() func(content []byte) []byte
}

// The runs whose messages may be split across records anywhere: the ClientHello, the server's clear
// flight, 1.2's client flight before its change_cipher_spec, and 1.3's sealed server flight.
func testHandshakeRuns(t *testing.T, fixture *testGateFixture) []*testHandshakeRun {
	t.Helper()
	trace := fixture.trace
	var runs []*testHandshakeRun
	// a run of one side's records of recordType from start, while no record of another type comes
	clear := func(name string, start int, fromClient bool) {
		end := start
		var octets []byte
		for end < len(trace) && trace[end].shts == nil && trace[end].fromClient == fromClient && trace[end].record[0] == tlsRecordHandshake {
			octets = append(octets, trace[end].record[tlsRecordHeaderBytes:]...)
			end += 1
		}
		if end == start {
			t.Fatalf("%s: no %s", fixture.leg.name, name)
		}
		runs = append(runs, &testHandshakeRun{name: name, start: start, end: end, octets: octets, sealer: func() func(content []byte) []byte {
			return func(content []byte) []byte {
				return tlsFrameRecord(tlsRecordHandshake, tlsVersion12, content)
			}
		}})
	}
	first := func(fromClient bool, after int, recordType uint8) int {
		for i := after; i < len(trace); i += 1 {
			if trace[i].shts == nil && trace[i].fromClient == fromClient && trace[i].record[0] == recordType {
				return i
			}
		}
		t.Fatalf("%s: no record of type %d", fixture.leg.name, recordType)
		return 0
	}
	clear("ClientHello", 0, true)
	serverStart := first(false, 0, tlsRecordHandshake)
	clear("server's clear flight", serverStart, false)
	if fixture.version() == tlsVersion12 {
		clear("client's flight", first(true, 1, tlsRecordHandshake), true)
		return runs
	}

	// 1.3's flight, opened under SHTS's key until its Finished
	var shts []byte
	for _, entry := range trace {
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
	start := first(false, serverStart, tlsRecordApplicationData)
	end := start
	var octets []byte
	buffer := &tlsHandshakeBuffer{}
	finished := false
	for !finished {
		if trace[end].fromClient || trace[end].shts != nil {
			t.Fatalf("%s: another event inside the server's flight", fixture.leg.name)
		}
		_, content, err := opener.open(trace[end].record)
		if err != nil {
			t.Fatal(err)
		}
		octets = append(octets, content...)
		buffer.add(content)
		for message := buffer.next(); message != nil; message = buffer.next() {
			finished = finished || message[0] == tlsHandshakeFinished
		}
		end += 1
	}
	runs = append(runs, &testHandshakeRun{name: "server's sealed flight", start: start, end: end, octets: octets, sealer: func() func(content []byte) []byte {
		cipher, err := newTlsCipher(tlsVersion13, suite, key, iv)
		if err != nil {
			t.Fatal(err)
		}
		return func(content []byte) []byte {
			record, err := cipher.seal(tlsRecordHandshake, content)
			if err != nil {
				t.Fatal(err)
			}
			return record
		}
	}})
	return runs
}

// The trace with a run's octets carried in two records split at offset.
func (self *testHandshakeRun) split(trace []*testTraceEntry, offset int) []*testTraceEntry {
	fromClient := trace[self.start].fromClient
	seal := self.sealer()
	split := make([]*testTraceEntry, 0, len(trace)+1)
	split = append(split, trace[:self.start]...)
	split = append(split,
		&testTraceEntry{fromClient: fromClient, record: seal(self.octets[:offset])},
		&testTraceEntry{fromClient: fromClient, record: seal(self.octets[offset:])})
	return append(split, trace[self.end:]...)
}

// Replays every event of a fixture into a fresh gate under a verifier that accepts every proof. It
// returns the gate, the client records it handed out and its first error.
func testReplayWhole(fixture *testGateFixture) (*edgeSession, int, error) {
	gate := fixture.gate(&testFixedVerifier{})
	handed := 0
	for _, event := range testReplayEvents(fixture) {
		var forwarded [][]byte
		var err error
		switch {
		case event.part != 0:
			forwarded, err = gate.VerifyPart(context.Background(), fixture.parts[event.part-1])
		case event.shts != nil:
			forwarded, err = gate.DiscloseShts(event.shts)
		case event.fromClient:
			forwarded, err = gate.ClientRecord(event.record)
		default:
			err = gate.ServerRecord(event.record)
		}
		if err != nil {
			return gate, handed, err
		}
		handed += len(forwarded)
	}
	return gate, handed, nil
}

// Whether two handshakes gave Z1 the same public inputs.
func testSameSession(a *sessionStatement, b *sessionStatement) bool {
	sameState := a.preFinishedState == nil && b.preFinishedState == nil
	if a.preFinishedState != nil && b.preFinishedState != nil {
		sameState = a.preFinishedState.chaining == b.preFinishedState.chaining &&
			bytes.Equal(a.preFinishedState.tail, b.preFinishedState.tail) &&
			a.preFinishedState.length == b.preFinishedState.length
	}
	return sameState && a.version == b.version && a.suite == b.suite &&
		bytes.Equal(a.shtsHash, b.shtsHash) && bytes.Equal(a.helloHash, b.helloHash) && bytes.Equal(a.finishedHash, b.finishedHash) &&
		bytes.Equal(a.clientRandom, b.clientRandom) && bytes.Equal(a.serverRandom, b.serverRandom) &&
		bytes.Equal(a.serverFinishedRecord, b.serverFinishedRecord)
}

func TestTheGateReadsHandshakeMessagesSplitAcrossRecordsAnywhere(t *testing.T) {
	// a handshake message may span records, and records may pack several: each run of the handshake is
	// carried in two records split at every offset, and the gate must pass the connection and give Z1
	// the inputs the unsplit one gave. 1.3's flight is sealed again under SHTS's key, as an MX may
	// frame it
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		gate, _, err := testReplayWhole(fixture)
		if err != nil {
			t.Fatalf("%s: the unsplit replay: %v", leg.name, err)
		}
		want := gate.session
		for _, run := range testHandshakeRuns(t, fixture) {
			for offset := 1; offset < len(run.octets); offset += 1 {
				split := &testGateFixture{leg: fixture.leg, preamble: fixture.preamble, trace: run.split(fixture.trace, offset), parts: fixture.parts}
				clientRecords := 0
				for _, entry := range split.trace {
					if entry.fromClient {
						clientRecords += 1
					}
				}
				gate, handed, err := testReplayWhole(split)
				if err != nil {
					t.Fatalf("%s: %s split at %d of %d: %v", leg.name, run.name, offset, len(run.octets), err)
				}
				if handed != clientRecords {
					t.Fatalf("%s: %s split at %d: %d of %d client records handed", leg.name, run.name, offset, handed, clientRecords)
				}
				if !testSameSession(gate.session, want) {
					t.Fatalf("%s: %s split at %d: other inputs for Z1", leg.name, run.name, offset)
				}
			}
		}
	}
}
