// The provers' own TLS client against sidecartest's MXs (SMTP-M9-02): ScriptedMx behind crypto/tls's
// server and RecordMx behind a server written apart from this module, so tlsClient finishes a real
// dialog with two implementations it shares no code with, through the gate and the relation. RecordMx
// also sends what crypto/tls cannot: a late NewSessionTicket, a KeyUpdate, padded records.

package smtpproof

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The edge's pre-TLS dialog by hand: banner, EHLO, STARTTLS and its 220, with nothing after it.
func testMxPreTls(t *testing.T, conn net.Conn) {
	t.Helper()
	reader := bufio.NewReader(conn)
	expect := func(code string) {
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(line, code) {
				t.Fatalf("%q where %s belongs", line, code)
			}
			if len(line) < 4 || line[3] == ' ' {
				return
			}
		}
	}
	expect("220")
	conn.Write([]byte("EHLO " + testHeloName + "\r\n"))
	expect("250")
	conn.Write([]byte("STARTTLS\r\n"))
	expect("220")
	if 0 < reader.Buffered() {
		t.Fatal("octets after STARTTLS's 220")
	}
}

// What one send through a sidecartest MX left behind.
type testMxSend struct {
	edge    *testEdge
	backend *testWitnessBackend
	result  *sidecar.SmtpProofResult
	err     error
}

// The prover, the gate and the relation, as testRunSendWith runs them, against mx.
func testRunSendToMx(t *testing.T, suites []uint16, mx sidecartest.MxServer, settings *ProverSettings, job *sidecar.SmtpProofJob) *testMxSend {
	t.Helper()
	sidecarConn, edgeSidecarConn := testPipe()
	edgeMxConn, mxConn := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	mxDone := make(chan struct{})
	go func() {
		defer close(mxDone)
		mx.ServeMx(mxConn)
	}()
	testMxPreTls(t, edgeMxConn)
	backend := newTestWitnessBackend()
	edge := &testEdge{
		session:     newEdgeSession(defaultEdgeSettings(), newSessionPreamble(job.Preamble), job.Preamble.MxHost, backend),
		sidecarConn: edgeSidecarConn,
		mxConn:      edgeMxConn,
	}
	edge.run()
	prover := &Prover{settings: settings, backend: backend, tlsSuites: suites}
	result, err := prover.SendSmtp(context.Background(), sidecarConn, job, edge)
	sidecarConn.Close()
	<-mxDone
	edge.fail(nil)
	edge.relays.Wait()
	return &testMxSend{edge: edge, backend: backend, result: result, err: err}
}

type testMxLeg struct {
	name    string
	suites  []uint16
	version uint16
	suite   uint16
}

func testMxLegs() []*testMxLeg {
	return []*testMxLeg{
		{name: "tls13 aes", suites: []uint16{tlsSuiteAes128GcmSha256}, version: tls.VersionTLS13, suite: tls.TLS_AES_128_GCM_SHA256},
		{name: "tls13 chacha", suites: []uint16{tlsSuiteChacha20Poly1305Sha256}, version: tls.VersionTLS13, suite: tls.TLS_CHACHA20_POLY1305_SHA256},
		{name: "tls12 ecdsa", suites: []uint16{tlsSuiteEcdheEcdsaAes128GcmSha256}, version: tls.VersionTLS12, suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{name: "tls12 rsa", suites: []uint16{tlsSuiteEcdheRsaAes128GcmSha256}, version: tls.VersionTLS12, suite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
}

// The job's settings for a mode: DATA forced, in small parts, as ExportCapture sends it.
func testMxModeSettings(data bool) *ProverSettings {
	settings := DefaultProverSettings()
	if data {
		settings.ForceData = true
		settings.DataPartBytes = 12
	}
	return settings
}

func testExpectMxTransaction(t *testing.T, name string, send *testMxSend, transactions []*sidecartest.MxTransaction, job *sidecar.SmtpProofJob) {
	t.Helper()
	if send.err != nil {
		t.Fatalf("%s: %v (edge: %v)", name, send.err, send.edge.failure())
	}
	if !send.result.Accepted {
		t.Fatalf("%s: not accepted: %+v", name, send.result)
	}
	if len(transactions) != 1 || string(transactions[0].Message) != string(job.Message) || len(transactions[0].Recipients) != len(job.RecipientLocals) {
		t.Fatalf("%s: the MX took %d transactions", name, len(transactions))
	}
}

func TestTlsClientCompletesADialogWithAScriptedMx(t *testing.T) {
	for _, leg := range testMxLegs() {
		for _, data := range []bool{false, true} {
			mx, err := sidecartest.NewScriptedMx(testMxHost, nil, &sidecartest.ScriptedMxSettings{
				MinVersion:   leg.version,
				MaxVersion:   leg.version,
				CipherSuites: []uint16{leg.suite},
				RsaKey:       leg.suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			})
			if err != nil {
				t.Fatal(err)
			}
			job := testJob("one line\r\nanother line\r\n", "bob", "carol")
			if data {
				job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
			}
			send := testRunSendToMx(t, leg.suites, mx, testMxModeSettings(data), job)
			testExpectMxTransaction(t, leg.name, send, mx.Transactions(), job)
		}
	}
}

func TestTlsClientCompletesADialogWithARecordMx(t *testing.T) {
	for _, leg := range testMxLegs() {
		for _, data := range []bool{false, true} {
			mx, err := sidecartest.NewRecordMx(testMxHost, nil, &sidecartest.RecordMxSettings{Version: leg.version, Suite: leg.suite})
			if err != nil {
				t.Fatal(err)
			}
			job := testJob("one line\r\nanother line\r\n", "bob", "carol")
			if data {
				job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
			}
			send := testRunSendToMx(t, leg.suites, mx, testMxModeSettings(data), job)
			if errs := mx.HandshakeErrors(); len(errs) != 0 {
				t.Fatalf("%s: %v", leg.name, errs)
			}
			testExpectMxTransaction(t, leg.name, send, mx.Transactions(), job)
		}
	}
}

// Z7: a KeyUpdate from the MX fails the send, since this client never updates keys, and fails it
// before any message octet reaches the MX.
func TestTlsClientRefusesAKeyUpdateBeforeAnyEffect(t *testing.T) {
	for _, leg := range testMxLegs()[:2] {
		mx, err := sidecartest.NewRecordMx(testMxHost, nil, &sidecartest.RecordMxSettings{Version: leg.version, Suite: leg.suite, KeyUpdateBeforeReply: 2})
		if err != nil {
			t.Fatal(err)
		}
		send := testRunSendToMx(t, leg.suites, mx, DefaultProverSettings(), testJob("one line\r\n", "bob"))
		if send.err == nil && send.result.Accepted {
			t.Fatalf("%s: sent past a KeyUpdate", leg.name)
		}
		if transactions := mx.Transactions(); len(transactions) != 0 {
			t.Errorf("%s: the MX took %d transactions", leg.name, len(transactions))
		}
	}
}

// A late NewSessionTicket, which no compliant MX sends this client: the parts it falls under are
// covered again over it (E3's hold), and the send goes through with one transaction.
func TestTlsClientSendsPastALateTicket(t *testing.T) {
	for _, leg := range testMxLegs()[:2] {
		for _, before := range []int{1, 2, 3} {
			mx, err := sidecartest.NewRecordMx(testMxHost, nil, &sidecartest.RecordMxSettings{Version: leg.version, Suite: leg.suite, TicketBeforeReply: before})
			if err != nil {
				t.Fatal(err)
			}
			job := testJob("one line\r\n", "bob")
			send := testRunSendToMx(t, leg.suites, mx, DefaultProverSettings(), job)
			testExpectMxTransaction(t, leg.name, send, mx.Transactions(), job)
		}
	}
}

// Replies split across records: the EHLO reply's CHUNKING line spans two records, which Z9 cannot
// read as one keyword, so the send takes DATA (SPEC.md reading 17), and goes through.
func TestTlsClientSendsThroughRepliesSplitAcrossRecords(t *testing.T) {
	for _, leg := range testMxLegs()[:2] {
		mx, err := sidecartest.NewRecordMx(testMxHost, nil, &sidecartest.RecordMxSettings{Version: leg.version, Suite: leg.suite, SplitRepliesAt: 5})
		if err != nil {
			t.Fatal(err)
		}
		job := testJob("one line\r\n", "bob")
		send := testRunSendToMx(t, leg.suites, mx, DefaultProverSettings(), job)
		testExpectMxTransaction(t, leg.name, send, mx.Transactions(), job)
		if send.result.Mode != partModeData {
			t.Errorf("%s: mode %d", leg.name, send.result.Mode)
		}
	}
}

// An MX that pads its records, which RFC 8446 allows: no part proves a padded record, so the send ends
// before MAIL with no effect. An interop limit the census sizes, never a way past the gate.
func TestTlsClientEndsBeforeAnyEffectAtPaddedMxRecords(t *testing.T) {
	for _, leg := range testMxLegs()[:2] {
		mx, err := sidecartest.NewRecordMx(testMxHost, nil, &sidecartest.RecordMxSettings{Version: leg.version, Suite: leg.suite, PadReplyRecords: 17})
		if err != nil {
			t.Fatal(err)
		}
		send := testRunSendToMx(t, leg.suites, mx, DefaultProverSettings(), testJob("one line\r\n", "bob"))
		if send.err == nil {
			t.Fatalf("%s: sent past padded records: %+v", leg.name, send.result)
		}
		for _, command := range mx.Accepted() {
			if strings.HasPrefix(command, "MAIL") {
				t.Errorf("%s: the MX accepted %q", leg.name, command)
			}
		}
	}
}
