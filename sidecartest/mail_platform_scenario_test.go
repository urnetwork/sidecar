// S7's SNI-less abuse@<root> and FS-39's ARF canary at T2 (§22.4, §22.7, MAIL-M5-04): rpt.bringyour.com's
// listener as server/mxedgehost composes it, in one process. tlsedgeservice's PROXY listener stands in front of
// mxedgeservice's platform role, whose MxEdgeDeps carry tlsedgeservice's hello functions, and SMTP-M5-05's report
// intake stands behind it on its fakes, the joint run FS-39 asks for. A sender writes the lb's PROXY v1 line,
// then the pre-TLS dialog, STARTTLS and a TLS handshake naming no server, then its transactions. T3's run of the
// same path, on the stores through sidecarhost.Run, is server/mxedgehost's.
//
// Everything waits on a pipe, on the fake clock's timers or on the intake: nothing sleeps.

package sidecartest_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// The scenario's names and documentation addresses, synthetic (connect/CODESTYLE.md's test data rule).
const (
	scenarioBannerHostName = "mx.report.example"
	scenarioReportHostName = "rpt.report.example"
	scenarioRootDomainName = "root.example"
	scenarioAbuseRecipient = "abuse@" + scenarioRootDomainName
	scenarioRootRecipient  = "root@" + scenarioReportHostName
	scenarioSender         = "203.0.113.9"
	scenarioEhloName       = "relay.sender.example"
	// The lb's own address, PROXY's destination, which the listener does not keep.
	scenarioLbAddress = "192.0.2.25"
	// A network whose mail a report encloses, under the root.
	scenarioNetDomain = "quietnet.root.example"
	// How long one step may wait before the test fails: a bound on a hang, never a pause.
	scenarioStepTimeout = 30 * time.Second
)

// A Logger keeping every line, for a scan.
type scenarioLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *scenarioLogger) keep(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

// Every line so far.
func (self *scenarioLogger) Lines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.lines)
}

func (self *scenarioLogger) Info(args ...any) { self.keep(fmt.Sprint(args...)) }

func (self *scenarioLogger) Infof(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

func (self *scenarioLogger) Warningf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

func (self *scenarioLogger) Errorf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// Every level, so a verbose line is caught too.
func (self *scenarioLogger) V(level int32) sidecar.Verbose { return &scenarioVerbose{log: self} }

type scenarioVerbose struct {
	log *scenarioLogger
}

func (self *scenarioVerbose) Enabled() bool { return true }

func (self *scenarioVerbose) Info(args ...any) { self.log.Info(args...) }

func (self *scenarioVerbose) Infof(format string, args ...any) { self.log.Infof(format, args...) }

// The lb's side of the block's TCP 25 port: each connection a test dials is the server's end of a pipe. Its
// address is a TCP one, as NewProxyHeaderListener needs to know its port.
type scenarioListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func newScenarioListener() *scenarioListener {
	return &scenarioListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (self *scenarioListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *scenarioListener) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
	})
	return nil
}

func (self *scenarioListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(scenarioLbAddress), Port: 25}
}

// SMTP-M5-05's intake as the platform listener reaches it, for the joint run alone: what SMTP-M5-06's adapter
// in the platform host does, written here so the run needs no server package. An outcome that kept nothing is
// unread, and the listener refuses that only for a role recipient, as plan-ABUSE-auto-reply has it.
type scenarioReportIntake struct {
	intake *smtpedgeservice.SmtpReportIntake
}

func (self *scenarioReportIntake) Accept(ctx context.Context, message *mxedgeservice.PlatformMessage) (mxedgeservice.PlatformOutcome, error) {
	outcome, err := self.intake.Accept(ctx, &smtpedgeservice.SmtpReportMessage{
		Recipient:   message.Recipient,
		ArrivalTime: message.ArrivalTime,
		Raw:         message.Raw,
	})
	if err != nil {
		return 0, err
	}
	switch outcome {
	case smtpedgeservice.SmtpReportOutcomeCase, smtpedgeservice.SmtpReportOutcomeComplaint,
		smtpedgeservice.SmtpReportOutcomeCounted, smtpedgeservice.SmtpReportOutcomeDuplicate,
		smtpedgeservice.SmtpReportOutcomeEmpty:
		return mxedgeservice.PlatformOutcomeTaken, nil
	}
	return mxedgeservice.PlatformOutcomeUnread, nil
}

// The platform listener behind the PROXY listener, and what a test reads of it.
type platformScenario struct {
	t           *testing.T
	ctx         context.Context
	clock       *sidecartest.FakeClock
	host        *sidecartest.FakeHost
	settings    *mxedgeservice.MxEdgeSettings
	log         *scenarioLogger
	certificate *x509.Certificate
	service     *mxedgeservice.MxEdgeService
	listener    *scenarioListener
	served      chan error
}

// The listener on a fake host with the mxedge gate open, its intake given, serving the PROXY listener.
func newPlatformScenario(t *testing.T, ctx context.Context, clock *sidecartest.FakeClock, host *sidecartest.FakeHost, intake mxedgeservice.PlatformIntake) *platformScenario {
	t.Helper()
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.BannerHostName = scenarioBannerHostName
	settings.DeviationUrl = "https://deviation.example/rfc3207"
	settings.PlatformReportHostName = scenarioReportHostName
	settings.PlatformRootDomainName = scenarioRootDomainName
	settings.PlatformAbuseUrl = "https://abuse.example/form"
	host.Gates.OpenService(sidecar.ServiceGateMxedge)
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: scenarioReportHostName},
		DNSNames:     []string{scenarioReportHostName},
		NotBefore:    clock.Now().Add(-time.Hour),
		NotAfter:     clock.Now().Add(24 * time.Hour),
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	self := &platformScenario{
		t:           t,
		ctx:         ctx,
		clock:       clock,
		host:        host,
		settings:    settings,
		log:         &scenarioLogger{},
		certificate: parsed,
		listener:    newScenarioListener(),
		served:      make(chan error, 1),
	}
	serviceHost := host.ServiceHost()
	gates := serviceHost.GatesOrClosed()
	// as server/mxedgehost's NewEngineDeps wires them
	deps := &mxedgeservice.MxEdgeDeps{
		ReadClientHello: func(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
			hello, err := tlsedgeservice.ReadClientHello(conn, maxByteCount)
			if err != nil {
				return nil, err
			}
			return &mxedgeservice.MxClientHello{ServerName: hello.ServerName, RawBytes: hello.RawBytes}, nil
		},
		NormalizeSni: tlsedgeservice.NormalizeSni,
		WriteTlsAlert: func(conn net.Conn, alert mxedgeservice.MxTlsAlert) error {
			return tlsedgeservice.WriteTlsAlert(conn, tlsedgeservice.TlsAlertCode(alert))
		},
		GateOpen: func() bool {
			return gates.Service(sidecar.ServiceGateMxedge).Enabled()
		},
		Clock: clock,
		Log:   self.log,
	}
	service, err := mxedgeservice.NewMxEdgePlatformService(ctx, serviceHost, deps, &mxedgeservice.MxEdgePlatformDeps{
		Certificate: &tls.Certificate{Certificate: [][]byte{certificateBytes}, PrivateKey: privateKey},
		Intake:      intake,
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	self.service = service
	t.Cleanup(service.Close)
	proxySettings := tlsedgeservice.DefaultProxyHeaderSettings()
	proxySettings.Clock = clock
	proxyListener, err := tlsedgeservice.NewProxyHeaderListener(ctx, self.listener, proxySettings)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		self.served <- service.Serve(proxyListener)
	}()
	return self
}

// A sender's end of one connection through the lb.
type scenarioClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
}

// Connects as the lb does, and returns before anything is written.
func (self *platformScenario) dial() *scenarioClient {
	self.t.Helper()
	serverConn, clientConn := net.Pipe()
	self.t.Cleanup(func() { clientConn.Close() })
	select {
	case self.listener.conns <- serverConn:
	case <-time.After(scenarioStepTimeout):
		self.t.Fatal("the PROXY listener never accepted")
	}
	return &scenarioClient{t: self.t, conn: clientConn, reader: bufio.NewReader(clientConn)}
}

// Writes text, which returns once the other end has read it all.
func (self *scenarioClient) write(text string) {
	self.t.Helper()
	if _, err := self.conn.Write([]byte(text)); err != nil {
		self.t.Fatalf("write: %v", err)
	}
}

// Reads one line and compares it, CRLF aside.
func (self *scenarioClient) expect(want string) {
	self.t.Helper()
	line, err := self.reader.ReadString('\n')
	if err != nil {
		self.t.Fatalf("expected %q: %v", want, err)
	}
	if line != want+"\r\n" {
		self.t.Fatalf("read %q, want %q", line, want)
	}
}

// Waits until a timer is set for at, so a step moves the fake clock only once the wait it means is armed.
func (self *platformScenario) awaitTimerAt(at time.Time) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, scenarioStepTimeout)
	defer cancel()
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			self.t.Fatalf("no timer was set for %v", at)
		}
	}
}

// Opens a session from the sender through the lb's PROXY v1 line, the dialog and STARTTLS, then a TLS
// handshake naming no server, as a reporter without SNI makes it. The certificate is the block's.
func (self *platformScenario) openTls() *textproto.Conn {
	self.t.Helper()
	client := self.dial()
	client.write(fmt.Sprintf("PROXY TCP4 %s %s 49152 25\r\n", scenarioSender, scenarioLbAddress))
	client.expect("220 " + scenarioBannerHostName + " ESMTP")
	client.write("EHLO " + scenarioEhloName + "\r\n")
	client.expect("250-" + scenarioBannerHostName)
	client.expect("250-ENHANCEDSTATUSCODES")
	client.expect("250 STARTTLS")
	// the 220 waits out the quiet time in which a byte behind STARTTLS resets the connection
	quietEnd := self.clock.Now().Add(self.settings.StartTlsQuietTimeout)
	client.write("STARTTLS\r\n")
	self.awaitTimerAt(quietEnd)
	self.clock.Advance(self.settings.StartTlsQuietTimeout)
	client.expect("220 2.0.0 Ready to start TLS")
	if 0 < client.reader.Buffered() {
		self.t.Fatal("bytes before the handshake")
	}
	tlsConn := tls.Client(client.conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		// no ServerName, so no SNI; the certificate is checked against the block's own
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !state.PeerCertificates[0].Equal(self.certificate) {
				return errors.New("not the platform's certificate")
			}
			return nil
		},
	})
	if err := tlsConn.HandshakeContext(self.ctx); err != nil {
		self.t.Fatalf("handshake: %v", err)
	}
	text := textproto.NewConn(tlsConn)
	self.t.Cleanup(func() { text.Close() })
	return text
}

// Sends line and answers the reply's code and text.
func scenarioCommand(t *testing.T, text *textproto.Conn, line string) (int, string) {
	t.Helper()
	if err := text.PrintfLine("%s", line); err != nil {
		t.Fatalf("%s: %v", line, err)
	}
	code, message, err := text.ReadResponse(0)
	if err != nil && code == 0 {
		t.Fatalf("%s: %v", line, err)
	}
	return code, message
}

// One transaction to recipient carrying message, answering DATA's final reply's code and text.
func scenarioSend(t *testing.T, text *textproto.Conn, recipient string, message []byte) (int, string) {
	t.Helper()
	if code, reply := scenarioCommand(t, text, "MAIL FROM:<reporter@sender.example>"); code != 250 {
		t.Fatalf("MAIL: %d %s", code, reply)
	}
	if code, reply := scenarioCommand(t, text, "RCPT TO:<"+recipient+">"); code != 250 {
		t.Fatalf("RCPT: %d %s", code, reply)
	}
	if code, reply := scenarioCommand(t, text, "DATA"); code != 354 {
		t.Fatalf("DATA: %d %s", code, reply)
	}
	writer := text.DotWriter()
	if _, err := writer.Write(message); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	code, reply, err := text.ReadResponse(0)
	if err != nil && code == 0 {
		t.Fatalf("after DATA: %v", err)
	}
	return code, reply
}

// Ends the session with QUIT.
func scenarioQuit(t *testing.T, text *textproto.Conn) {
	t.Helper()
	if code, reply := scenarioCommand(t, text, "QUIT"); code != 221 {
		t.Fatalf("QUIT: %d %s", code, reply)
	}
}

// A person's mail to a role address enclosing a message of fromDomain, CRLF throughout.
func scenarioRoleMail(fromDomain string, subject string, bodyText string) []byte {
	enclosed := (&sidecartest.SmtpFixtureMessage{FromDomain: fromDomain, MessageId: "<m2@" + fromDomain + ">", Subject: subject, Body: bodyText}).Bytes()
	return []byte("From: A Person <person@person.example>\r\nTo: " + scenarioAbuseRecipient + "\r\nSubject: spam from your network\r\n" +
		"Content-Type: multipart/mixed; boundary=\"" + sidecartest.SmtpFixtureBoundary + "\"\r\n\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "\r\nContent-Type: text/plain\r\n\r\nPlease look at the attached.\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "\r\nContent-Type: message/rfc822\r\n\r\n" + string(enclosed) + "\r\n--" + sidecartest.SmtpFixtureBoundary + "--\r\n")
}

// An ARF report from a feedback loop's key about an enclosed message of fromDomain, DKIM-signed.
func scenarioArfReport(key *sidecartest.SmtpDkimFixtureKey, fromDomain string, subject string, bodyText string) []byte {
	enclosed := (&sidecartest.SmtpFixtureMessage{
		FromDomain: fromDomain,
		MessageId:  "<m1@" + fromDomain + ">",
		XUrRef:     "1.abcdefghijklmnopqrstuvwxyz234567ab",
		Subject:    subject,
		Body:       bodyText,
	}).Bytes()
	report := sidecartest.BuildSmtpArfReport(key.Domain, "abuse", enclosed, false)
	return sidecartest.SignSmtpDkimFixture(report, key, &sidecartest.SmtpDkimFixtureOptions{
		HeaderRelaxed: true,
		BodyRelaxed:   true,
		Headers:       []string{"from", "to", "subject", "date", "message-id"},
	})
}

// The scan's needles that are not canaries: the sender, its EHLO name and the recipients, which no log line
// or metric may hold (I-13).
func scenarioForbidAddresses(capture *sidecartest.PrivacyCapture) {
	capture.Forbid("sender address", []byte(scenarioSender))
	capture.Forbid("ehlo name", []byte(scenarioEhloName))
	capture.Forbid("abuse recipient", []byte(scenarioAbuseRecipient))
	capture.Forbid("root recipient", []byte(scenarioRootRecipient))
}

// S7 at M5: a reporter that sends no SNI reaches the platform listener through the lb's PROXY line, and its
// mail to abuse@<root> reaches the intake whole, for that recipient, after a 250. No line of the listener's log
// and no metric holds the sender, its EHLO name or the recipient.
func TestPlatformScenarioSniLessAbuseMailReachesTheIntake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*scenarioStepTimeout)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	intake := sidecartest.NewFakePlatformIntake()
	scenario := newPlatformScenario(t, ctx, clock, host, intake)

	text := scenario.openTls()
	if code, reply := scenarioCommand(t, text, "EHLO "+scenarioEhloName); code != 250 {
		t.Fatalf("EHLO after TLS: %d %s", code, reply)
	}
	message := scenarioRoleMail(scenarioNetDomain, "about your network", "enclosed spam")
	if code, reply := scenarioSend(t, text, scenarioAbuseRecipient, message); code != 250 {
		t.Fatalf("abuse@ without SNI: %d %s", code, reply)
	}
	scenarioQuit(t, text)

	messages := intake.Messages()
	if len(messages) != 1 {
		t.Fatalf("%d messages reached the intake", len(messages))
	}
	if messages[0].Recipient != scenarioAbuseRecipient || !bytes.Equal(messages[0].Raw, message) {
		t.Fatalf("the intake got %q with %d bytes", messages[0].Recipient, len(messages[0].Raw))
	}
	capture := sidecartest.NewPrivacyCapture()
	scenarioForbidAddresses(capture)
	for _, line := range scenario.log.Lines() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	for _, line := range host.Metrics.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Fatalf("%v", findings)
	}
}

// A connection that does not open with the lb's PROXY header is no sender: the listener drops it before the
// engine sees it, so it gets no banner and nothing is said to it, and the next one through the lb is served.
func TestPlatformScenarioDropsAConnectionWithNoProxyHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*scenarioStepTimeout)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	intake := sidecartest.NewFakePlatformIntake()
	scenario := newPlatformScenario(t, ctx, clock, host, intake)

	client := scenario.dial()
	client.write("EHLO " + scenarioEhloName + "\r\n")
	rest, err := io.ReadAll(client.reader)
	if err != nil || 0 < len(rest) {
		t.Fatalf("a connection with no PROXY header read %q, %v", rest, err)
	}
	// the listener goes on: a sender through the lb gets the banner
	client = scenario.dial()
	client.write(fmt.Sprintf("PROXY TCP4 %s %s 49152 25\r\n", scenarioSender, scenarioLbAddress))
	client.expect("220 " + scenarioBannerHostName + " ESMTP")
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	if 0 < len(intake.Messages()) {
		t.Fatal("the intake was given a message")
	}
}

// FS-39's ARF canary, run with SMTP-M5-05's intake behind the listener: a feedback loop's ARF report to
// root@<report host> and a person's mail to abuse@<root> are taken, 250, the one stored as a complaint and the
// other handed to §21 as a case, each about the network it encloses mail of, while role mail that names no
// network is refused unread with plan-ABUSE-auto-reply's 550 5.7.1. No canary from an enclosed subject or body
// reaches a log line, a metric, a stored row or a case, and no log line or metric holds the sender, its EHLO
// name or a recipient.
func TestPlatformScenarioArfCanaryJointWithReportIntake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*scenarioStepTimeout)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)

	// SMTP-M5-05's intake on its fakes, the network's mail key known, the enclosed domain attributed
	store := sidecartest.NewFakeSmtpEdgeStore(clock, nil)
	txt := sidecartest.NewFakeSmtpDnsTxt()
	loopKey := sidecartest.NewSmtpDkimFixtureEd25519Key("loop", "fbl1", "loop.example")
	txt.Set(loopKey.RecordName(), loopKey.TxtRecord())
	keys := sidecartest.NewFakeSmtpReportKeys()
	join := sidecartest.NewFakeSmtpReportJoin()
	sink := sidecartest.NewFakeSmtpAbuseSink()
	networkId := sidecar.NewId()
	keys.Add(networkId)
	join.Attribute(scenarioNetDomain, networkId, "high")
	intakeLog := &scenarioLogger{}
	smtpSettings := smtpedgeservice.DefaultSmtpEdgeSettings()
	smtpSettings.Root = scenarioRootDomainName
	smtpSettings.ReportHostName = scenarioReportHostName
	smtpSettings.LoopAllowlist = []string{"loop.example"}
	reportIntake, err := smtpedgeservice.NewSmtpReportIntake(host.ServiceHost(), store, &smtpedgeservice.SmtpReportIntakeDeps{
		Tokens: sidecartest.NewFakeSmtpNetTokens(),
		Labels: sidecartest.NewFakeSmtpLabels(),
		Keys:   keys,
		Txt:    txt,
		Join:   join,
		Sink:   sink,
		Log:    intakeLog,
	}, smtpSettings)
	if err != nil {
		t.Fatal(err)
	}
	scenario := newPlatformScenario(t, ctx, clock, host, &scenarioReportIntake{intake: reportIntake})

	capture := sidecartest.NewPrivacyCapture()
	subjectCanary := capture.CanaryText("enclosed subject")
	bodyCanary := capture.CanaryText("enclosed body")
	text := scenario.openTls()
	if code, reply := scenarioCommand(t, text, "EHLO "+scenarioEhloName); code != 250 {
		t.Fatalf("EHLO after TLS: %d %s", code, reply)
	}
	if code, reply := scenarioSend(t, text, scenarioRootRecipient, scenarioArfReport(loopKey, scenarioNetDomain, subjectCanary, bodyCanary)); code != 250 {
		t.Fatalf("an ARF report: %d %s", code, reply)
	}
	if code, reply := scenarioSend(t, text, scenarioAbuseRecipient, scenarioRoleMail(scenarioNetDomain, subjectCanary, bodyCanary)); code != 250 {
		t.Fatalf("role mail about a network: %d %s", code, reply)
	}
	// role mail enclosing nothing names no network: refused unread, pointing at the form
	code, reply := scenarioSend(t, text, scenarioAbuseRecipient, []byte("From: A Person <person@person.example>\r\nContent-Type: text/plain\r\n\r\nyour network spams me\r\n"))
	if code != 550 || !strings.HasPrefix(reply, "5.7.1 ") || !strings.Contains(reply, scenario.settings.PlatformAbuseUrl) {
		t.Fatalf("unattributed role mail: %d %s", code, reply)
	}
	scenarioQuit(t, text)

	// the report's complaint and the role mail's, which also went to §21
	complaints := store.Complaints()
	if len(complaints) != 2 || complaints[0].NetworkId != networkId || complaints[1].NetworkId != networkId {
		t.Fatalf("%d complaints", len(complaints))
	}
	cases := sink.Reports()
	if len(cases) != 1 || cases[0].NetworkId != networkId {
		t.Fatalf("cases %+v", cases)
	}
	// the canaries: nowhere a server keeps or says anything
	capture.AddSource(store.PrivacyItems)
	for _, line := range append(scenario.log.Lines(), intakeLog.Lines()...) {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	for _, line := range host.Metrics.Dump() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	for _, report := range cases {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "case", Body: []byte(fmt.Sprintf("%+v", report))})
	}
	if findings := capture.Scan(); len(findings) != 0 {
		t.Fatalf("%v", findings)
	}
	// the addresses: in no log line or metric
	addressCapture := sidecartest.NewPrivacyCapture()
	scenarioForbidAddresses(addressCapture)
	for _, line := range append(scenario.log.Lines(), intakeLog.Lines()...) {
		addressCapture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	for _, line := range host.Metrics.Dump() {
		addressCapture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
	}
	if findings := addressCapture.Scan(); len(findings) != 0 {
		t.Fatalf("%v", findings)
	}
}
