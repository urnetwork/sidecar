// The whole path in one process: the prover and its TLS client, a real record gate between them and
// the MX, and a scripted MX over Go's crypto/tls server. The MX is the point: it models what a
// receiver does with what reaches it, so "before any effect" is something a test can observe.

package smtpproof

import (
	"bufio"
	"bytes"
	"context"
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
			write(reply + "\r\n250 SMTPUTF8")
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
				message.WriteString(line)
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
			self.addTrace(&testTraceEntry{fromClient: true, record: record})
			if err := self.forward(func() ([][]byte, error) { return self.session.ClientRecord(record) }); err != nil {
				self.fail(err)
				return
			}
		}
	}()
	go func() {
		defer self.relays.Done()
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
	testXUrRef          = "1.AAAABBBBCCCCDDDD"
	testFeedbackId      = "transactional:community:token:urnetwork"
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
		session:     newEdgeSession(defaultEdgeSettings(), newSessionPreamble(job.Preamble), job.Preamble.MxHost, partVerifier),
		sidecarConn: edgeSidecarConn,
		mxConn:      edgeMxConn,
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
