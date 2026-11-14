// The whole path in one process: the prover and its TLS client, a real record gate between them and
// the MX, and a scripted MX over Go's crypto/tls server. The MX is the point: it models what a
// receiver does with what reaches it, so "before any effect" is something a test can observe.

package smtpproof

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// What the scripted MX offers and refuses.
type testMxSettings struct {
	// Post-TLS EHLO keywords.
	keywords []string
	// The reply to MAIL. Empty is 250.
	mailReply string
	// The reply to the RCPT of this local part. Absent is 250.
	rcptReplies map[string]string
	// The reply to DATA. Empty is 354.
	dataReply string
	// Treats a bare-LF "." line as the end of DATA, like receivers vulnerable to SMTP smuggling.
	laxDataEnd bool
	// Splits the EHLO reply into two records at this many octets. 0 sends it whole.
	splitEhloAt int
	// Writes the EHLO reply a line per record, after any split.
	ehloLinePerRecord bool
	// Has the edge forge server records from this application record on, 1 being the first. A
	// malicious edge can relay anything, and has no key to make it verify.
	edgeForgesFrom int
}

func testMxDefaults() *testMxSettings {
	return &testMxSettings{keywords: []string{"PIPELINING", "CHUNKING"}, rcptReplies: map[string]string{}}
}

// One transaction the MX accepted: the effect tests look for.
type testMxTransaction struct {
	sender     string
	recipients []string
	message    []byte
}

type testMx struct {
	settings *testMxSettings

	stateLock sync.Mutex
	accepted  []*testMxTransaction
	commands  []string
}

func (self *testMx) transactions() []*testMxTransaction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.accepted
}

func (self *testMx) seen() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.commands
}

// Serves one connection after STARTTLS. Any input a real parser would treat as a command is treated
// as one here, including what a sender meant as message octets.
func (self *testMx) serve(conn *tls.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(reply string) {
		conn.Write([]byte(reply + "\r\n"))
	}
	var transaction *testMxTransaction
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.TrimRight(line, "\r\n")
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.commands = append(self.commands, command)
		}()
		verb := strings.ToUpper(strings.SplitN(command, " ", 2)[0])
		switch {
		case verb == "EHLO":
			reply := "250-" + testMxHost
			for _, keyword := range self.settings.keywords {
				reply += "\r\n250-" + keyword
			}
			reply += "\r\n250 SMTPUTF8"
			if self.settings.splitEhloAt != 0 {
				conn.Write([]byte(reply[:self.settings.splitEhloAt]))
				reply = reply[self.settings.splitEhloAt:]
			}
			if self.settings.ehloLinePerRecord {
				lines := strings.SplitAfter(reply, "\r\n")
				for _, line := range lines[:len(lines)-1] {
					conn.Write([]byte(line))
				}
				reply = lines[len(lines)-1]
			}
			write(reply)
		case strings.HasPrefix(strings.ToUpper(command), "MAIL FROM:"):
			if self.settings.mailReply != "" {
				write(self.settings.mailReply)
				continue
			}
			transaction = &testMxTransaction{sender: command[len("MAIL FROM:"):]}
			write("250 2.1.0 Ok")
		case strings.HasPrefix(strings.ToUpper(command), "RCPT TO:"):
			if transaction == nil {
				write("503 5.5.1 Need MAIL")
				continue
			}
			path := command[len("RCPT TO:"):]
			local := strings.SplitN(strings.Trim(path, "<>"), "@", 2)[0]
			if reply, ok := self.settings.rcptReplies[local]; ok {
				write(reply)
				continue
			}
			transaction.recipients = append(transaction.recipients, path)
			write("250 2.1.5 Ok")
		case verb == "BDAT":
			if !strings.Contains(strings.Join(self.settings.keywords, " "), "CHUNKING") {
				// an MX without CHUNKING refuses the line and reads what follows as commands
				write("500 5.5.1 Unknown command")
				continue
			}
			fields := strings.Fields(command)
			size, _ := strconv.Atoi(fields[1])
			chunk := make([]byte, size)
			if _, err := io.ReadFull(reader, chunk); err != nil {
				return
			}
			if transaction == nil || len(transaction.recipients) == 0 {
				write("554 5.5.1 No valid recipients")
				continue
			}
			transaction.message = chunk
			self.accept(transaction)
			transaction = nil
			write("250 2.0.0 Ok: queued")
		case verb == "DATA":
			if self.settings.dataReply != "" {
				write(self.settings.dataReply)
				continue
			}
			if transaction == nil || len(transaction.recipients) == 0 {
				write("554 5.5.1 No valid recipients")
				continue
			}
			write("354 End data with <CR><LF>.<CR><LF>")
			var message bytes.Buffer
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == ".\r\n" || (self.settings.laxDataEnd && line == ".\n") {
					break
				}
				// a real receiver undoes dot-stuffing, so an unstuffed dot would be lost here
				message.WriteString(strings.TrimPrefix(line, "."))
			}
			transaction.message = message.Bytes()
			self.accept(transaction)
			transaction = nil
			write("250 2.0.0 Ok: queued")
		case verb == "QUIT":
			write("221 2.0.0 Bye")
			return
		default:
			write("500 5.5.1 Unknown command")
		}
	}
}

func (self *testMx) accept(transaction *testMxTransaction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.accepted = append(self.accepted, transaction)
}

// Stands in for a proof system. A proof here is only a handle on the witness, so what is under test
// is everything around the proof: that the edge, deriving its statement on its own, arrives at one
// the prover's witness satisfies. Never reachable outside tests.
type testWitnessBackend struct {
	stateLock  sync.Mutex
	witnesses  map[string]*partWitness
	statements []*partStatement
	proved     []*partWitness
	// When set, sees and may change each part's witness before it is held.
	mutate func(statement *partStatement, witness *partWitness)
}

func newTestWitnessBackend() *testWitnessBackend {
	return &testWitnessBackend{witnesses: map[string]*partWitness{}}
}

func (self *testWitnessBackend) provePart(ctx context.Context, statement *partStatement, witness *partWitness) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	proof := binary.BigEndian.AppendUint64(nil, uint64(len(self.witnesses)))
	self.witnesses[string(proof)] = witness
	self.statements = append(self.statements, statement)
	self.proved = append(self.proved, witness)
	return proof, nil
}

func (self *testWitnessBackend) verifyPart(ctx context.Context, statement *partStatement, proof []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	witness, ok := self.witnesses[string(proof)]
	if !ok {
		return errors.New("unknown proof")
	}
	if failures := relationCheckPart(statement, witness); 0 < len(failures) {
		return failures[0]
	}
	return nil
}

// The relay: both directions of the edge, around one gate. Records for the MX go out under
// forwardLock, taken around each gate call, because the gate's order is the MX's order.
type testEdge struct {
	session     *edgeSession
	sidecarConn net.Conn
	mxConn      net.Conn

	forwardLock sync.Mutex
	// As testMxSettings.edgeForgesFrom.
	forgesFrom int
	// When set, what a malicious sidecar sends in place of each record the prover wrote: none, that
	// record, another, or more than one.
	rewriteClient func(record []byte) [][]byte
	// When set, called after each call into the gate has written what it released.
	afterForward func()
	// Both relay goroutines, so a test reads the trace only once it is whole.
	relays sync.WaitGroup

	stateLock sync.Mutex
	err       error
	trace     []*testTraceEntry
	parts     []*sidecar.SmtpProofPart
}

// One event at the gate, in the order it happened, so a fresh gate can replay a real connection.
type testTraceEntry struct {
	fromClient bool
	record     []byte
	shts       []byte
}

func (self *testEdge) addTrace(entry *testTraceEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.trace = append(self.trace, entry)
}

func (self *testEdge) fail(err error) {
	if err != nil {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.err == nil {
				self.err = err
			}
		}()
	}
	self.sidecarConn.Close()
	self.mxConn.Close()
}

// The first thing that ended the relay.
func (self *testEdge) failure() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.err
}

func testReadRecord(conn net.Conn) ([]byte, error) {
	header := make([]byte, tlsRecordHeaderBytes)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	record := make([]byte, tlsRecordHeaderBytes+(int(header[3])<<8|int(header[4])))
	copy(record, header)
	if _, err := io.ReadFull(conn, record[tlsRecordHeaderBytes:]); err != nil {
		return nil, err
	}
	return record, nil
}

func (self *testEdge) forward(call func() ([][]byte, error)) error {
	self.forwardLock.Lock()
	defer self.forwardLock.Unlock()
	records, err := call()
	if err != nil {
		return err
	}
	for _, record := range records {
		if _, err := self.mxConn.Write(record); err != nil {
			return err
		}
	}
	if self.afterForward != nil {
		self.afterForward()
	}
	return nil
}

func (self *testEdge) run() {
	self.relays.Add(2)
	go func() {
		defer self.relays.Done()
		for {
			record, err := testReadRecord(self.sidecarConn)
			if err != nil {
				self.fail(nil)
				return
			}
			records := [][]byte{record}
			if self.rewriteClient != nil {
				records = self.rewriteClient(record)
			}
			for _, record := range records {
				self.addTrace(&testTraceEntry{fromClient: true, record: record})
				if err := self.forward(func() ([][]byte, error) { return self.session.ClientRecord(record) }); err != nil {
					self.fail(err)
					return
				}
			}
		}
	}()
	go func() {
		defer self.relays.Done()
		applicationRecords := 0
		for {
			record, err := testReadRecord(self.mxConn)
			if err != nil {
				self.session.ServerClosed()
				self.fail(nil)
				return
			}
			self.addTrace(&testTraceEntry{record: record})
			if err := self.session.ServerRecord(record); err != nil {
				self.fail(err)
				return
			}
			self.session.stateLock.Lock()
			application := self.session.phase == edgePhaseApplication
			self.session.stateLock.Unlock()
			if application {
				applicationRecords += 1
				if 0 < self.forgesFrom && self.forgesFrom <= applicationRecords {
					record = bytes.Clone(record)
					record[tlsRecordHeaderBytes] ^= 1
				}
			}
			if _, err := self.sidecarConn.Write(record); err != nil {
				return
			}
		}
	}()
}

// The prover's side of the RPC, straight into the gate.
func (self *testEdge) DiscloseShts(ctx context.Context, shts []byte) error {
	self.addTrace(&testTraceEntry{shts: shts})
	return self.forward(func() ([][]byte, error) { return self.session.DiscloseShts(shts) })
}

func (self *testEdge) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.parts = append(self.parts, part)
	}()
	return self.forward(func() ([][]byte, error) { return self.session.VerifyPart(ctx, part) })
}

const (
	testRecipientDomain = "recipient.example"
	testNetworkDomain   = "net.root.example"
	testEnvelopeDomain  = "b.net.root.example"
	testHeloName        = "o1.out.relay.example"
	testMessageId       = "abcdefghijklmnopqrstuvwxyz@net.root.example"
	testSelector        = "s1"
	testXUrRef          = "1.aeibceqtcqkrmfyydenbxifbukr2jjngu4"
	testFeedbackId      = "n:c:gaytemzugu3doobzhi5typj6h4:urnetwork"
)

// A message whose header block meets Z5.
func testHeaderBlock() string {
	return "From: Alice Example <alice@" + testNetworkDomain + ">\r\n" +
		"To: <bob@" + testRecipientDomain + ">\r\n" +
		"Subject: A synthetic message\r\n" +
		"Date: Fri, 06 Nov 2026 12:00:00 +0000\r\n" +
		"Message-ID: <" + testMessageId + ">\r\n" +
		"X-UR-Ref: " + testXUrRef + "\r\n" +
		"Feedback-ID: " + testFeedbackId + "\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; h=from:date:message-id:x-ur-ref:feedback-id; d=" +
		testNetworkDomain + "; s=" + testSelector + "; t=1; x=2; bh=AAAA; b=BBBB\r\n" +
		"\r\n"
}

func testJob(body string, recipients ...string) *sidecar.SmtpProofJob {
	message := []byte(testHeaderBlock() + body)
	return &sidecar.SmtpProofJob{
		SendId: []byte("synthetic-send-id"),
		Preamble: &sidecar.SmtpProofPreamble{
			RecipientDomain:  testRecipientDomain,
			RecipientCount:   uint32(len(recipients)),
			MessageId:        testMessageId,
			HeaderFromDomain: testNetworkDomain,
			DkimSelector:     testSelector,
			MessageByteCount: uint64(len(message)),
			HeloName:         testHeloName,
			XUrRef:           testXUrRef,
			FeedbackId:       testFeedbackId,
			EnvelopeDomain:   testEnvelopeDomain,
			MxHost:           testMxHost,
		},
		SenderLocal:     "bounce-1",
		RecipientLocals: recipients,
		Message:         message,
		VerifyPeer:      testVerifyAny,
	}
}

// One whole send and everything it left behind.
type testSend struct {
	mx      *testMx
	edge    *testEdge
	backend *testWitnessBackend
	result  *sidecar.SmtpProofResult
	err     error
}

// The TLS configurations every honest control runs under, one per covered version and suite.
type testTlsLeg struct {
	name      string
	serverTls func(*testing.T) *tls.Config
	suites    []uint16
}

func testTlsLegs() []*testTlsLeg {
	return []*testTlsLeg{
		{
			name:   "tls13 aes",
			suites: []uint16{tlsSuiteAes128GcmSha256},
			serverTls: func(t *testing.T) *tls.Config {
				return &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}, MinVersion: tls.VersionTLS13}
			},
		},
		{
			name:   "tls13 chacha",
			suites: []uint16{tlsSuiteChacha20Poly1305Sha256},
			serverTls: func(t *testing.T) *tls.Config {
				return &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}, MinVersion: tls.VersionTLS13}
			},
		},
		{
			name:   "tls12 aes",
			suites: []uint16{tlsSuiteEcdheEcdsaAes128GcmSha256},
			serverTls: func(t *testing.T) *tls.Config {
				return &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}, MaxVersion: tls.VersionTLS12}
			},
		},
	}
}

// Runs a job through the prover, the gate and the MX, to the end.
func testRunSend(t *testing.T, leg *testTlsLeg, mxSettings *testMxSettings, proverSettings *ProverSettings, job *sidecar.SmtpProofJob) *testSend {
	t.Helper()
	backend := newTestWitnessBackend()
	send := testRunSendWith(t, leg, mxSettings, proverSettings, job, backend, backend)
	send.backend = backend
	return send
}

// As testRunSend, under a given proof system.
func testRunSendWith(t *testing.T, leg *testTlsLeg, mxSettings *testMxSettings, proverSettings *ProverSettings, job *sidecar.SmtpProofJob, partProver partProver, partVerifier partVerifier) *testSend {
	t.Helper()
	return testRunSendThrough(t, leg, mxSettings, proverSettings, job, partProver, partVerifier, nil)
}

// As testRunSendWith, with the relay set up by configure, when given, before anything flows.
func testRunSendThrough(t *testing.T, leg *testTlsLeg, mxSettings *testMxSettings, proverSettings *ProverSettings, job *sidecar.SmtpProofJob, partProver partProver, partVerifier partVerifier, configure func(edge *testEdge)) *testSend {
	t.Helper()
	sidecarConn, edgeSidecarConn := testPipe()
	edgeMxConn, mxConn := testPipe()

	mx := &testMx{settings: mxSettings}
	server := tls.Server(mxConn, leg.serverTls(t))
	mxDone := make(chan struct{})
	go func() {
		defer close(mxDone)
		if err := server.Handshake(); err != nil {
			return
		}
		mx.serve(server)
	}()

	edge := &testEdge{
		session:     newEdgeSession(defaultEdgeSettings(), newSessionPreamble(job.Preamble, DefaultProofSettings()), job.Preamble.MxHost, partVerifier),
		sidecarConn: edgeSidecarConn,
		mxConn:      edgeMxConn,
		forgesFrom:  mxSettings.edgeForgesFrom,
	}
	if configure != nil {
		configure(edge)
	}
	edge.run()

	prover := &Prover{settings: proverSettings, backend: partProver, tlsSuites: leg.suites}
	result, err := prover.SendSmtp(context.Background(), sidecarConn, job, edge)
	sidecarConn.Close()
	<-mxDone
	edge.fail(nil)
	edge.relays.Wait()
	return &testSend{mx: mx, edge: edge, result: result, err: err}
}

func testExpectOneTransaction(t *testing.T, leg *testTlsLeg, send *testSend, job *sidecar.SmtpProofJob) {
	t.Helper()
	if send.err != nil {
		t.Fatalf("%s: send: %v (edge: %v)", leg.name, send.err, send.edge.failure())
	}
	if !send.result.Accepted {
		t.Fatalf("%s: not accepted: %+v", leg.name, send.result)
	}
	transactions := send.mx.transactions()
	if len(transactions) != 1 {
		t.Fatalf("%s: %d transactions", leg.name, len(transactions))
	}
	if !bytes.Equal(transactions[0].message, job.Message) {
		t.Errorf("%s: message differs", leg.name)
	}
	if len(transactions[0].recipients) != len(job.RecipientLocals) {
		t.Errorf("%s: %d recipients", leg.name, len(transactions[0].recipients))
	}
}

func TestSendBdatThroughTheGate(t *testing.T) {
	for _, leg := range testTlsLegs() {
		job := testJob(strings.Repeat("a body line\r\n", 8), "bob", "carol")
		send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
		if send.result.Mode != partModeBdat {
			t.Errorf("%s: mode %d", leg.name, send.result.Mode)
		}
		if got := len(send.backend.statements); got != 3 {
			t.Errorf("%s: %d parts, want pi1 to pi3", leg.name, got)
		}
	}
}

func TestSendThroughTheGateAfterAHelloRetryRequest(t *testing.T) {
	// an MX preferring another group retries, and Go's server follows the retry with a dummy
	// change_cipher_spec, which reaches the gate ahead of the second ClientHello
	for _, leg := range testTlsLegs()[:2] {
		retried := *leg
		retried.serverTls = func(t *testing.T) *tls.Config {
			config := leg.serverTls(t)
			config.CurvePreferences = []tls.CurveID{tls.CurveP256}
			return config
		}
		job := testJob("one line\r\n", "bob")
		send := testRunSend(t, &retried, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, &retried, send, job)
	}
}

func TestSendBdatBodyLongerThanOneRecord(t *testing.T) {
	settings := DefaultProverSettings()
	settings.MaxRecordContentBytes = 1024
	for _, leg := range testTlsLegs() {
		job := testJob(strings.Repeat("0123456789abcde\r\n", 400), "bob")
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectOneTransaction(t, leg, send, job)
	}
}

func TestSendDataWhereTheMxLacksChunking(t *testing.T) {
	mxSettings := testMxDefaults()
	mxSettings.keywords = []string{"PIPELINING"}
	settings := DefaultProverSettings()
	settings.DataPartBytes = 256
	for _, leg := range testTlsLegs() {
		job := testJob(strings.Repeat("a body line\r\n", 100), "bob")
		send := testRunSend(t, leg, mxSettings, settings, job)
		testExpectOneTransaction(t, leg, send, job)
		if send.result.Mode != partModeData {
			t.Errorf("%s: mode %d", leg.name, send.result.Mode)
		}
		// the message splits across parts, each proven before its records go
		if got := len(send.backend.statements); got < 5 {
			t.Errorf("%s: %d parts, want later DATA parts too", leg.name, got)
		}
	}
}

func TestSendFallsToDataWhereTheKeywordSpansTwoRecords(t *testing.T) {
	// Z9 reads the keyword inside one record, so BDAT here could never be proven, and an MX that wrote
	// its reply this way must still get its mail
	lineStart := len("250-" + testMxHost + "\r\n250-PIPELINING\r\n")
	for _, c := range []struct {
		name    string
		splitAt int
		mode    uint32
	}{
		{name: "inside the keyword", splitAt: lineStart + len("250-CHUN"), mode: partModeData},
		{name: "at the line's start, so that its CR LF is in the other record", splitAt: lineStart, mode: partModeData},
		{name: "before the line before it", splitAt: lineStart - len("LINING\r\n"), mode: partModeBdat},
	} {
		for _, leg := range testTlsLegs() {
			settings := testMxDefaults()
			settings.splitEhloAt = c.splitAt
			job := testJob("one line\r\n", "bob")
			send := testRunSend(t, leg, settings, DefaultProverSettings(), job)
			testExpectOneTransaction(t, leg, send, job)
			if send.result.Mode != c.mode {
				t.Errorf("%s: %s: mode %d, want %d", leg.name, c.name, send.result.Mode, c.mode)
			}
		}
	}
}

func TestSendDataForcedWhereChunkingIsOffered(t *testing.T) {
	settings := DefaultProverSettings()
	settings.ForceData = true
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob")
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectOneTransaction(t, leg, send, job)
		if send.result.Mode != partModeData {
			t.Errorf("%s: mode %d", leg.name, send.result.Mode)
		}
	}
}

func TestSendDataStuffsEveryLeadingDot(t *testing.T) {
	// a line a receiver would otherwise change, which would break the message and its DKIM signature
	settings := DefaultProverSettings()
	settings.ForceData = true
	body := ".leading dot\r\n.\r\n..two dots\r\nplain\r\n"
	for _, leg := range testTlsLegs() {
		job := testJob(body, "bob")
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectOneTransaction(t, leg, send, job)
	}
}

func TestSendAsksForANewConnectionWhenTheCountFitsOnlyData(t *testing.T) {
	// the count does not choose the mode (plan-SMTP-preamble-byte-count): an MX offering CHUNKING gets
	// BDAT, and a count only DATA can meet means a new connection declaring BDAT's
	for _, leg := range testTlsLegs() {
		job := testJob(".leading dot\r\n", "bob")
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
		send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if send.result.ReconnectByteCount != uint64(len(job.Message)) || send.result.Mode != partModeBdat {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		for _, command := range send.mx.seen() {
			if !strings.HasPrefix(command, "EHLO") {
				t.Errorf("%s: %q reached the MX", leg.name, command)
			}
		}

		job.Preamble.MessageByteCount = send.result.ReconnectByteCount
		send = testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
		if send.result.Mode != partModeBdat {
			t.Errorf("%s: mode %d", leg.name, send.result.Mode)
		}
	}
}

func TestSendIsNeverTooLargeWhereChunkingIsOffered(t *testing.T) {
	// a stuffed count once chose DATA here, and DATA's measured cap then called the message too_large,
	// although BDAT carries it at any size
	settings := DefaultProverSettings()
	settings.DataProofBytes = 100
	for _, leg := range testTlsLegs() {
		job := testJob(".a leading dot\r\n"+strings.Repeat("a body line\r\n", 100), "bob")
		job.Preamble.MessageByteCount = uint64(len(dotStuffed(job.Message)))
		send := testRunSend(t, leg, testMxDefaults(), settings, job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if send.result.TooLarge || send.result.ReconnectByteCount != uint64(len(job.Message)) {
			t.Errorf("%s: %+v", leg.name, send.result)
		}

		job.Preamble.MessageByteCount = send.result.ReconnectByteCount
		send = testRunSend(t, leg, testMxDefaults(), settings, job)
		testExpectOneTransaction(t, leg, send, job)
	}
}

func TestSendAsksForANewConnectionWhenTheCountFitsOnlyBdat(t *testing.T) {
	// the count went out before the MX's capabilities were known, and DATA's differs
	mxSettings := testMxDefaults()
	mxSettings.keywords = []string{"PIPELINING"}
	for _, leg := range testTlsLegs() {
		job := testJob(".leading dot\r\n", "bob")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if send.result.ReconnectByteCount != uint64(len(dotStuffed(job.Message))) {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		for _, command := range send.mx.seen() {
			if !strings.HasPrefix(command, "EHLO") {
				t.Errorf("%s: %q reached the MX", leg.name, command)
			}
		}

		// and that new connection, declaring the stuffed count, delivers it
		job.Preamble.MessageByteCount = send.result.ReconnectByteCount
		send = testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
	}
}

// Records what a prover would submit, without any edge.
type testChannelLog struct {
	parts []*sidecar.SmtpProofPart
}

func (self *testChannelLog) DiscloseShts(ctx context.Context, shts []byte) error {
	return nil
}

func (self *testChannelLog) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	self.parts = append(self.parts, part)
	return nil
}

func TestALateTicketIsCoveredByAPartThatOpensNoRecord(t *testing.T) {
	// a ticket arriving after the message's parts began holds their message records at the edge (E3
	// step 5), and no message part covers a server record, so an env part that opens no client record
	// covers it (DESIGN-DETAILS 3.2.6): no part is proven again. Go's server sends no ticket to this
	// client, so the record comes straight to the prover's reader, here as the MX would have sealed it
	// under the real server key
	for _, leg := range testTlsLegs()[:2] {
		capture := testBdatCapture(t, leg)
		statement, witness := capture.part(t, 3)
		session := statement.session

		// the run as it stands just after the msg part, the last, whose records are known and covered
		backend := newTestWitnessBackend()
		channel := &testChannelLog{}
		records := make([]*proverServerRecord, 0, statement.serverRecordCount)
		for range statement.previousServerRecordCount {
			records = append(records, &proverServerRecord{public: &partRecord{}})
		}
		for i, record := range statement.serverRecords {
			records = append(records, &proverServerRecord{public: record, plaintext: witness.serverPlaintexts[i]})
		}
		run := &proverRun{
			settings: DefaultProverSettings(),
			backend:  backend,
			channel:  channel,
			job:      &sidecar.SmtpProofJob{SendId: []byte("synthetic-send-id")},
			session:  session,
			preamble: session.preamble,
			// the connection's C and rho, as the run drew them after the handshake
			keyCommitment:     statement.keyCommitment,
			keyBlind:          witness.keyBlind,
			serverIn:          make(chan *proverServerEvent, 2),
			records:           records,
			nextPart:          4,
			nextRecord:        statement.lastRecord + 1,
			covered:           uint64(len(records)),
			repliesProven:     statement.repliesProven + statement.replyCount,
			mode:              statement.mode,
			headerRecordCount: statement.headerRecordCount,
			messageStarted:    true,
			result: &tlsHandshakeResult{
				version:         session.version,
				handshakeSecret: witness.handshakeSecret,
				clientKey:       witness.clientKey,
				clientIv:        witness.clientIv,
				serverKey:       witness.serverKey,
				serverIv:        witness.serverIv,
			},
		}

		seq := statement.serverRecords[len(statement.serverRecords)-1].seq + 1
		ticket := []byte{tlsHandshakeNewSessionTicket, 0, 0, 0, tlsRecordHandshake}
		sealed := &partRecord{seq: seq, raw: bytes.Clone(statement.serverRecords[0].raw)}
		testSeal(t, statement, sealed, witness.serverKey, witness.serverIv, ticket)
		run.serverIn <- &proverServerEvent{record: &tlsServerRecord{seq: seq, raw: sealed.raw, recordType: tlsRecordHandshake, content: ticket[:len(ticket)-1]}}

		// then the reply to the message, which ends the wait
		reply := []byte("250 2.0.0 Ok: queued\r\n")
		replyRecord := &partRecord{seq: seq + 1, raw: bytes.Clone(statement.serverRecords[0].raw)}
		testSeal(t, statement, replyRecord, witness.serverKey, witness.serverIv, append(bytes.Clone(reply), tlsRecordApplicationData))
		run.serverIn <- &proverServerEvent{record: &tlsServerRecord{seq: seq + 1, raw: replyRecord.raw, recordType: tlsRecordApplicationData, content: reply}}

		replies, err := run.awaitReplies(context.Background(), 1)
		if err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		if len(replies) != 1 || replies[0].code != "250" {
			t.Errorf("%s: %+v", leg.name, replies)
		}
		if len(channel.parts) != 1 {
			t.Fatalf("%s: %d parts submitted, want one over the ticket", leg.name, len(channel.parts))
		}
		cover := channel.parts[0]
		if cover.Index != 4 || len(cover.Records) != 0 || cover.FirstRecord != statement.lastRecord+1 || cover.LastRecord != statement.lastRecord ||
			cover.ServerRecordCount != statement.serverRecordCount+1 || cover.ReplyCount != 0 || cover.Last || len(cover.Carry) != 0 {
			t.Errorf("%s: %+v", leg.name, cover)
		}
		// what was proven satisfies the relation over the ticket alone
		proved := backend.statements[0]
		if len(proved.clientRecords) != 0 || len(proved.serverRecords) != 1 {
			t.Errorf("%s: the statement opens %d records over %d", leg.name, len(proved.clientRecords), len(proved.serverRecords))
		}
	}
}

func TestSendRefusesACountThatFitsNeitherMode(t *testing.T) {
	job := testJob("one line\r\n", "bob")
	job.Preamble.MessageByteCount += 1
	prover := &Prover{settings: DefaultProverSettings(), backend: newTestWitnessBackend()}
	sidecarConn, _ := testPipe()
	if _, err := prover.SendSmtp(context.Background(), sidecarConn, job, nil); err == nil {
		t.Error("sent a message that fits neither count")
	}
}

func TestSendWithoutPipeliningPacesEachCommand(t *testing.T) {
	mxSettings := testMxDefaults()
	mxSettings.keywords = []string{"CHUNKING"}
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob", "carol", "dave")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
	}
}

func TestSendWithoutABody(t *testing.T) {
	for _, leg := range testTlsLegs() {
		job := testJob("", "bob")
		send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
		testExpectOneTransaction(t, leg, send, job)
	}
}

func TestAForgedReplyFromTheEdgeSendsNothing(t *testing.T) {
	// FS-31: an honest MX answers 451 and a malicious edge would turn that into a 250. It holds no key
	// that opens or seals a reply, so what it relays fails its tag at the client, the send ends, and
	// the sender keeps the message to retry
	mxSettings := testMxDefaults()
	mxSettings.mailReply = "451 4.3.0 Try later"
	mxSettings.edgeForgesFrom = 2
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		if send.err == nil {
			t.Fatalf("%s: a forged reply went unnoticed: %+v", leg.name, send.result)
		}
		if !strings.Contains(send.err.Error(), "authentication") {
			t.Errorf("%s: %v", leg.name, send.err)
		}
		if len(send.mx.transactions()) != 0 {
			t.Errorf("%s: a transaction was accepted", leg.name)
		}
	}
}

func TestRefusedMailEndsBeforeAnyMessageOctet(t *testing.T) {
	mxSettings := testMxDefaults()
	mxSettings.mailReply = "550 5.7.1 Refused"
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if send.result.Accepted || send.result.RefusedCode != "550" {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		if len(send.mx.transactions()) != 0 {
			t.Errorf("%s: a transaction was accepted", leg.name)
		}
		// nothing past the envelope ever reached the MX
		for _, command := range send.mx.seen() {
			if strings.HasPrefix(command, "BDAT") {
				t.Errorf("%s: %q reached the MX", leg.name, command)
			}
		}
	}
}

func TestMixedRecipientsEndBeforeAnyMessageOctet(t *testing.T) {
	mxSettings := testMxDefaults()
	mxSettings.rcptReplies["carol"] = "550 5.1.1 No such user"
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob", "carol")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if send.result.Accepted || send.result.RefusedCode != "550" {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		if len(send.mx.transactions()) != 0 {
			t.Errorf("%s: a transaction was accepted", leg.name)
		}
	}
}

func TestRefusedDataEndsBeforeAnyMessageOctet(t *testing.T) {
	mxSettings := testMxDefaults()
	mxSettings.keywords = []string{"PIPELINING"}
	mxSettings.dataReply = "451 4.3.0 Try later"
	for _, leg := range testTlsLegs() {
		job := testJob("one line\r\n", "bob")
		send := testRunSend(t, leg, mxSettings, DefaultProverSettings(), job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if send.result.Accepted || send.result.RefusedCode != "451" {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		if len(send.mx.transactions()) != 0 {
			t.Errorf("%s: a transaction was accepted", leg.name)
		}
	}
}

func TestOversizeMessageToAnMxWithoutChunkingStopsBeforeMail(t *testing.T) {
	mxSettings := testMxDefaults()
	mxSettings.keywords = nil
	settings := DefaultProverSettings()
	settings.DataProofBytes = 100
	for _, leg := range testTlsLegs() {
		job := testJob(strings.Repeat("a body line\r\n", 100), "bob")
		send := testRunSend(t, leg, mxSettings, settings, job)
		if send.err != nil {
			t.Fatalf("%s: %v", leg.name, send.err)
		}
		if !send.result.TooLarge {
			t.Errorf("%s: %+v", leg.name, send.result)
		}
		for _, command := range send.mx.seen() {
			if !strings.HasPrefix(command, "EHLO") {
				t.Errorf("%s: %q reached the MX", leg.name, command)
			}
		}
	}
}

func TestSendStopsOnABadPreambleBeforeAnyEffect(t *testing.T) {
	leg := testTlsLegs()[0]
	job := testJob("one line\r\n", "bob")
	job.Preamble.RecipientDomain = "a.example>\r\nRCPT TO:<victim@other.example"
	send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
	if send.err == nil {
		t.Fatal("sent")
	}
	if 0 < len(send.mx.transactions()) || 0 < len(send.edge.parts) {
		t.Errorf("%d transactions, %d parts", len(send.mx.transactions()), len(send.edge.parts))
	}
}

func TestProverBoundsWhatAnMxCanMakeItHold(t *testing.T) {
	// a reply that never ends would otherwise grow without limit, and a part could never cover it
	settings := DefaultProverSettings()
	settings.MaxServerBytes = 1024
	run := &proverRun{
		settings: settings,
		result:   &tlsHandshakeResult{version: tlsVersion12},
		serverIn: make(chan *proverServerEvent),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			record := &tlsServerRecord{recordType: tlsRecordApplicationData, raw: make([]byte, 100), content: []byte("250-more")}
			select {
			case run.serverIn <- &proverServerEvent{record: record}:
			case <-ctx.Done():
				return
			}
		}
	}()
	if _, err := run.awaitReplies(ctx, 1); err == nil {
		t.Error("the prover kept reading")
	}
	if settings.MaxServerBytes+100 < run.serverBytes {
		t.Errorf("held %d octets", run.serverBytes)
	}
}

func TestProverRefusesAMessageTheRelationRefuses(t *testing.T) {
	// the prover checks itself first, so a bad message never reaches the MX as a transaction
	cases := []struct {
		name     string
		mutation func(job *sidecar.SmtpProofJob)
	}{
		{name: "from outside the declared domain", mutation: func(job *sidecar.SmtpProofJob) {
			job.Message = bytes.Replace(job.Message, []byte("@"+testNetworkDomain+">"), []byte("@victim.example>"), 1)
		}},
		{name: "wrong message id", mutation: func(job *sidecar.SmtpProofJob) {
			job.Preamble.MessageId = "other@" + testNetworkDomain
		}},
		{name: "a field behind a leading dot", mutation: func(job *sidecar.SmtpProofJob) {
			job.Message = append([]byte(".From: <x@victim.example>\r\n"), job.Message...)
		}},
	}
	for _, leg := range testTlsLegs() {
		for _, c := range cases {
			job := testJob("one line\r\n", "bob")
			c.mutation(job)
			job.Preamble.MessageByteCount = uint64(len(job.Message))
			send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), job)
			if send.err == nil {
				t.Fatalf("%s: %s: sent", leg.name, c.name)
			}
			if !strings.Contains(send.err.Error(), "Z5") {
				t.Errorf("%s: %s: %v", leg.name, c.name, send.err)
			}
			if len(send.mx.transactions()) != 0 {
				t.Errorf("%s: %s: a transaction was accepted", leg.name, c.name)
			}
		}
	}
}

func testFormat(statement *partStatement) string {
	return fmt.Sprintf("part %d mode %d", statement.index, statement.mode)
}

// SMTP-M9-35: until key sets of version 2 exist (SMTP-M9-40) the prover names no key set, has nothing to
// prepare, and refuses a job under any named set before an octet goes out, while a job naming none proves
// as before. The verifier holds only the unnamed set: a preamble naming any is refused.
func TestProverAndVerifierRefuseEveryNamedKeySet(t *testing.T) {
	prover := NewProver(DefaultProverSettings(), nil, t.TempDir())
	if keySet := prover.KeySet(); len(keySet) != 0 {
		t.Errorf("KeySet %x", keySet)
	}
	readiness, err := prover.PrepareKeys(context.Background())
	if err != nil || !readiness.Done || len(readiness.KeySets) != 0 {
		t.Errorf("PrepareKeys %+v, %v", readiness, err)
	}
	job := testJob("body\r\n", "bob")
	job.KeySet = bytes.Repeat([]byte{5}, sha256.Size)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	written := make(chan int, 1)
	go func() {
		buffer := make([]byte, 1)
		n, _ := server.Read(buffer)
		written <- n
	}()
	if _, err := prover.SendSmtp(context.Background(), client, job, nil); !errors.Is(err, sidecar.ErrSmtpProofKeySet) {
		t.Errorf("a named set: %v", err)
	}
	client.Close()
	if n := <-written; n != 0 {
		t.Error("a refused job wrote to the MX")
	}

	verifier, err := NewVerifier(DefaultVerifierSettings(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.HoldsKeySet(nil) || verifier.HoldsKeySet(job.KeySet) {
		t.Error("HoldsKeySet holds a named set")
	}
	preamble := *testJob("body\r\n", "bob").Preamble
	preamble.ProofKeySet = job.KeySet
	if _, err := verifier.NewSmtpProofSession(&preamble); !errors.Is(err, sidecar.ErrSmtpProofKeySet) {
		t.Errorf("a session under a named set: %v", err)
	}
	preamble.ProofKeySet = nil
	if _, err := verifier.NewSmtpProofSession(&preamble); err != nil {
		t.Errorf("a session under none: %v", err)
	}
}
