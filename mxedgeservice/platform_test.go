// The platform role, T2 over net.Pipe: the router's front, then TLS ended in the engine under the
// platform certificate, then a go-smtp session through sidecar.MailSmtpServe, with a scripted sender
// on the other end, since MAIL-M7-03's kit is for the receiver. Nothing here sleeps: a step waits on
// the pipe, on a monitor or on the fake intake's gate.

package mxedgeservice_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The platform's names, synthetic (connect/CODESTYLE.md's test data rule).
const (
	testReportHostName = "rpt.example"
	testRootDomainName = "root.example"
	testAbuseUrl       = "https://abuse.example/form"
	// 26 lowercase base32 characters, a token's shape (plan-SMTP-net-token)
	testReportToken = "abcdefghijklmnopqrstuvwxyz"
	// A message cap small enough to pass in a test.
	testPlatformMessageByteCount = 4 * 1024
)

// testSettings with the platform's names, a small message cap and room for every buffer a test makes
// unless it says otherwise.
func testPlatformSettings() *mxedgeservice.MxEdgeSettings {
	settings := testSettings()
	settings.PlatformReportHostName = testReportHostName
	settings.PlatformRootDomainName = testRootDomainName
	settings.PlatformAbuseUrl = testAbuseUrl
	settings.PlatformMessageByteCount = testPlatformMessageByteCount
	settings.PlatformBufferByteCount = 1024 * 1024
	return settings
}

// The platform's bringyour.com certificate, as secret_files would hold it, for a name of its own and
// valid around the fake clock's start.
func testPlatformCertificate(t *testing.T) (*tls.Certificate, *x509.Certificate) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	start := sidecartest.DefaultClockStart()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(25),
		Subject:      pkix.Name{CommonName: testReportHostName},
		DNSNames:     []string{testReportHostName},
		NotBefore:    start.Add(-time.Hour),
		NotAfter:     start.Add(24 * time.Hour),
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificateBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{certificateBytes}, PrivateKey: privateKey}, parsed
}

// A platform engine and what a test reads of it.
type testPlatform struct {
	*testEngine
	intake      *sidecartest.FakePlatformIntake
	certificate *x509.Certificate
}

// What a platform test may change before the engine starts.
type testPlatformOptions struct {
	settings *mxedgeservice.MxEdgeSettings
	// Leaves the intake out, as a host that wired none.
	noIntake bool
	// Leaves the certificate out, as a host whose secret_files hold none.
	noCertificate bool
	unready       bool
}

// A platform engine serving a test listener, past its first probe, with the mxedge gate open.
func newTestPlatform(t *testing.T, options *testPlatformOptions) *testPlatform {
	t.Helper()
	if options == nil {
		options = &testPlatformOptions{}
	}
	certificate, parsed := testPlatformCertificate(t)
	platformDeps := &mxedgeservice.MxEdgePlatformDeps{Certificate: certificate}
	if options.noCertificate {
		platformDeps.Certificate = nil
	}
	intake := sidecartest.NewFakePlatformIntake()
	if !options.noIntake {
		platformDeps.Intake = intake
	}
	settings := options.settings
	if settings == nil {
		settings = testPlatformSettings()
	}
	engine := newTestEngine(t, &testEngineOptions{settings: settings, platform: platformDeps, unready: options.unready})
	return &testPlatform{testEngine: engine, intake: intake, certificate: parsed}
}

// A sender's session with the platform role from the end of its TLS handshake.
type testPlatformClient struct {
	t    *testing.T
	conn *tls.Conn
	text *textproto.Conn
}

// The TLS config of a sender naming serverName, or none when it is empty. A reporter with no SNI
// names nothing to verify, so it compares the certificate it gets with the one the block holds.
func (self *testPlatform) clientTlsConfig(serverName string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if serverName == "" {
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || !state.PeerCertificates[0].Equal(self.certificate) {
				return errors.New("not the platform's certificate")
			}
			return nil
		}
		return config
	}
	roots := x509.NewCertPool()
	roots.AddCert(self.certificate)
	config.RootCAs = roots
	config.ServerName = serverName
	config.Time = self.clock.Now
	return config
}

// Opens a session from sender through the pre-TLS dialog and STARTTLS, then a TLS handshake naming
// serverName, or none when it is empty.
func (self *testPlatform) openTls(sender string, serverName string) *testPlatformClient {
	self.t.Helper()
	client := self.open(sender)
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	self.startTls(client)
	tlsConn := tls.Client(client.conn, self.clientTlsConfig(serverName))
	if err := tlsConn.Handshake(); err != nil {
		self.t.Fatalf("handshake: %v", err)
	}
	return &testPlatformClient{t: self.t, conn: tlsConn, text: textproto.NewConn(tlsConn)}
}

// Sends line and answers the reply's code and text, whatever the code.
func (self *testPlatformClient) command(line string) (int, string, error) {
	if err := self.text.PrintfLine("%s", line); err != nil {
		return 0, "", err
	}
	code, message, err := self.text.ReadResponse(0)
	return code, message, err
}

// Sends line and fails unless the reply is wantCode, answering the reply's text.
func (self *testPlatformClient) expectReply(line string, wantCode int) string {
	self.t.Helper()
	code, message, err := self.command(line)
	if err != nil {
		self.t.Fatalf("%s: %v", line, err)
	}
	if code != wantCode {
		self.t.Fatalf("%s: %d %s, want %d", line, code, message, wantCode)
	}
	return message
}

// EHLO's extensions after TLS, keyword to parameters.
func (self *testPlatformClient) ehlo() map[string]string {
	self.t.Helper()
	lines := strings.Split(self.expectReply("EHLO relay.example", 250), "\n")
	extensionParameters := map[string]string{}
	for _, line := range lines[1:] {
		keyword, parameters, _ := strings.Cut(line, " ")
		extensionParameters[keyword] = parameters
	}
	return extensionParameters
}

// Sends body after DATA's 354, dot-stuffed, and answers the reply to its end.
func (self *testPlatformClient) data(body string) (int, string, error) {
	code, message, err := self.command("DATA")
	if err != nil || code != 354 {
		return code, message, fmt.Errorf("DATA: %d %s %v", code, message, err)
	}
	writer := self.text.DotWriter()
	if _, err := io.WriteString(writer, body); err != nil {
		return 0, "", err
	}
	if err := writer.Close(); err != nil {
		return 0, "", err
	}
	return self.text.ReadResponse(0)
}

// Sends QUIT and reads to the end, which must come with nothing more said.
func (self *testPlatformClient) quit() {
	self.t.Helper()
	self.expectReply("QUIT", 221)
	rest, err := io.ReadAll(self.conn)
	if err != nil || 0 < len(rest) {
		self.t.Fatalf("after QUIT: %q %v", rest, err)
	}
}

// A report as an ARF sender writes it, with a canary in its body that no log or metric may hold.
func testArfReport(canary string) string {
	return "From: <feedback@isp.example>\r\n" +
		"To: <abuse@" + testRootDomainName + ">\r\n" +
		"Subject: complaint\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=b\r\n" +
		"\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"A complaint about " + canary + ".\r\n" +
		".a line a dot starts\r\n" +
		"--b--\r\n"
}

// S7's SNI-less abuse@<root>: a reporter that names no server still ends TLS under the platform's
// certificate, and its message reaches the intake once, as it was sent.
func TestPlatformTakesAbuseMailWithNoSni(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, "")
	client.ehlo()
	client.expectReply("MAIL FROM:<feedback@isp.example>", 250)
	client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 250)
	body := testArfReport("the canary")
	code, message, err := client.data(body)
	if err != nil || code != 250 {
		t.Fatalf("DATA: %d %s %v", code, message, err)
	}
	client.quit()

	messages := platform.intake.Messages()
	if len(messages) != 1 {
		t.Fatalf("the intake took %d messages", len(messages))
	}
	if messages[0].Recipient != "abuse@"+testRootDomainName {
		t.Errorf("recipient %q", messages[0].Recipient)
	}
	if string(messages[0].Raw) != body {
		t.Errorf("raw %q, want %q", messages[0].Raw, body)
	}
	if !messages[0].ArrivalTime.Equal(platform.clock.Now()) {
		t.Errorf("arrival %v", messages[0].ArrivalTime)
	}
	platform.service.AwaitSessionCount(0)
	if value := platform.host.Metrics.Value("urnetwork_mxedge_sessions_total", "platform_served"); value != 1 {
		t.Errorf("platform_served counted %v", value)
	}
}

// A sender that names the report host gets the same certificate, and a check of it holds.
func TestPlatformTakesAReportWithSni(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, testReportHostName)
	client.ehlo()
	client.expectReply("MAIL FROM:<dmarc@isp.example>", 250)
	client.expectReply("RCPT TO:<"+testReportToken+"@"+testReportHostName+">", 250)
	if code, message, err := client.data("Subject: Report domain\r\n\r\nzip\r\n"); err != nil || code != 250 {
		t.Fatalf("DATA: %d %s %v", code, message, err)
	}
	client.quit()
	if messages := platform.intake.Messages(); len(messages) != 1 || messages[0].Recipient != testReportToken+"@"+testReportHostName {
		t.Fatalf("the intake took %+v", messages)
	}
}

// After TLS the session advertises SIZE at the platform's cap, and neither STARTTLS nor AUTH.
func TestPlatformAdvertisesItsCapAndNoStartTlsOrAuth(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, "")
	extensionParameters := client.ehlo()
	if extensionParameters["SIZE"] != fmt.Sprint(testPlatformMessageByteCount) {
		t.Errorf("SIZE %q", extensionParameters["SIZE"])
	}
	for _, keyword := range []string{"STARTTLS", "AUTH", "LIMITS"} {
		if _, ok := extensionParameters[keyword]; ok {
			t.Errorf("%s is advertised: %v", keyword, extensionParameters)
		}
	}
	client.quit()
}

// The listener answers for its own recipients alone, in any case: a third gets 550 5.1.1, and so does
// any other name on either domain.
func TestPlatformTakesOnlyItsOwnRecipients(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, "")
	client.ehlo()
	client.expectReply("MAIL FROM:<sender@isp.example>", 250)
	for _, recipient := range []string{
		"abuse@" + testRootDomainName,
		"Postmaster@" + strings.ToUpper(testRootDomainName),
		"root@" + testReportHostName,
		testReportToken + "@" + testReportHostName + ".",
	} {
		client.expectReply("RCPT TO:<"+recipient+">", 250)
	}
	for _, recipient := range []string{
		"someone@" + testRootDomainName,
		"abuse@" + testReportHostName,
		"postmaster@mx." + testRootDomainName,
		"abcdefghijklmnopqrstuvwxy@" + testReportHostName,
		"abcdefghijklmnopqrstuvwxy1@" + testReportHostName,
		"root@" + testRootDomainName,
		"abuse@other.example",
	} {
		if message := client.expectReply("RCPT TO:<"+recipient+">", 550); !strings.HasPrefix(message, "5.1.1 ") {
			t.Errorf("%s: %q", recipient, message)
		}
	}
	if code, message, err := client.data("Subject: x\r\n\r\ny\r\n"); err != nil || code != 250 {
		t.Fatalf("DATA: %d %s %v", code, message, err)
	}
	client.quit()
	got := []string{}
	for _, message := range platform.intake.Messages() {
		got = append(got, message.Recipient)
	}
	want := []string{
		"abuse@" + testRootDomainName,
		"postmaster@" + testRootDomainName,
		"root@" + testReportHostName,
		testReportToken + "@" + testReportHostName,
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the intake took %v, want %v", got, want)
	}
}

// The router's front holds here too: a plaintext transaction gets 530 with no closed handshake behind
// it, and nothing reaches the intake.
func TestPlatformRefusesPlaintextWith530(t *testing.T) {
	platform := newTestPlatform(t, nil)
	if code := platform.plaintextReplyTo(testSender); code != "530" {
		t.Errorf("plaintext MAIL got %s", code)
	}
	if messages := platform.intake.Messages(); len(messages) != 0 {
		t.Errorf("the intake took %d messages", len(messages))
	}
}

func TestPlatformRefusesABodyOverItsCapWith552(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, "")
	client.ehlo()
	client.expectReply("MAIL FROM:<sender@isp.example>", 250)
	client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 250)
	body := "Subject: large\r\n\r\n" + strings.Repeat(strings.Repeat("x", 78)+"\r\n", 2*testPlatformMessageByteCount/80)
	code, message, err := client.data(body)
	if err != nil || code != 552 || !strings.HasPrefix(message, "5.3.4 ") {
		t.Fatalf("DATA: %d %s %v", code, message, err)
	}
	// a SIZE past the cap is refused before a byte is sent
	if message := client.expectReply(fmt.Sprintf("MAIL FROM:<sender@isp.example> SIZE=%d", testPlatformMessageByteCount+1), 552); !strings.HasPrefix(message, "5.3.4 ") {
		t.Errorf("MAIL with SIZE: %q", message)
	}
	client.quit()
	if messages := platform.intake.Messages(); len(messages) != 0 {
		t.Errorf("the intake took %d messages", len(messages))
	}
	if value := platform.host.Metrics.Value("urnetwork_mxedge_platform_messages_total", "too_large"); value != 1 {
		t.Errorf("too_large counted %v", value)
	}
}

// With no intake wired, every recipient the listener answers for gets 451 4.3.0, so the sender keeps
// its mail and nothing is read.
func TestPlatformWithNoIntakeAnswers451(t *testing.T) {
	platform := newTestPlatform(t, &testPlatformOptions{noIntake: true})
	client := platform.openTls(testSender, "")
	client.ehlo()
	client.expectReply("MAIL FROM:<sender@isp.example>", 250)
	if message := client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 451); !strings.HasPrefix(message, "4.3.0 ") {
		t.Errorf("RCPT: %q", message)
	}
	client.expectReply("RCPT TO:<someone@"+testRootDomainName+">", 550)
	client.quit()
}

// A closed gate keeps the listener dark past TLS as before it: a recipient gets 451 4.3.0.
func TestPlatformWithTheGateClosedAnswers451(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, "")
	platform.gateOpen.Store(false)
	client.ehlo()
	client.expectReply("MAIL FROM:<sender@isp.example>", 250)
	client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 451)
	client.quit()
	if messages := platform.intake.Messages(); len(messages) != 0 {
		t.Errorf("the intake took %d messages", len(messages))
	}
}

// plan-ABUSE-auto-reply: role mail the intake could not attribute is refused with the form's pointer.
func TestPlatformRefusesUnreadRoleMailWith550(t *testing.T) {
	platform := newTestPlatform(t, nil)
	platform.intake.SetOutcome("abuse@"+testRootDomainName, mxedgeservice.PlatformOutcomeUnread)
	client := platform.openTls(testSender, "")
	client.ehlo()
	client.expectReply("MAIL FROM:<person@isp.example>", 250)
	client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 250)
	code, message, err := client.data("Subject: help\r\n\r\nplease\r\n")
	if err != nil || code != 550 || message != "5.7.1 Not read. Report abuse at "+testAbuseUrl {
		t.Fatalf("DATA: %d %q %v", code, message, err)
	}
	// beside a recipient whose message was taken, the transaction ends 250
	client.expectReply("MAIL FROM:<person@isp.example>", 250)
	client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 250)
	client.expectReply("RCPT TO:<root@"+testReportHostName+">", 250)
	if code, message, err := client.data("Subject: help\r\n\r\nplease\r\n"); err != nil || code != 250 {
		t.Fatalf("DATA: %d %q %v", code, message, err)
	}
	client.quit()
}

// An intake that cannot finish answers 451 4.3.0 for the whole message, whose text says nothing of why.
func TestPlatformIntakeErrorAnswers451(t *testing.T) {
	platform := newTestPlatform(t, nil)
	platform.intake.SetError("root@"+testReportHostName, errors.New("store refused db.example's statement"))
	client := platform.openTls(testSender, "")
	client.ehlo()
	client.expectReply("MAIL FROM:<dmarc@isp.example>", 250)
	client.expectReply("RCPT TO:<root@"+testReportHostName+">", 250)
	code, message, err := client.data("Subject: Report\r\n\r\nzip\r\n")
	if err != nil || code != 451 || message != "4.3.0 Try again later" {
		t.Fatalf("DATA: %d %q %v", code, message, err)
	}
	client.quit()
}

// FS-39's canary: an ARF body's marker, the envelope, the sender's address and its EHLO name reach no log
// line and no metric, on the paths that log.
func TestPlatformCanaryReachesNoLogOrMetric(t *testing.T) {
	canary := "canary-6b1f0c2e"
	platform := newTestPlatform(t, nil)
	platform.intake.SetError("root@"+testReportHostName, errors.New("refused "+canary))
	client := platform.openTls(testSender, testReportHostName)
	client.ehlo()
	client.expectReply("MAIL FROM:<reporter@isp.example>", 250)
	client.expectReply("RCPT TO:<abuse@"+testRootDomainName+">", 250)
	if code, _, err := client.data(testArfReport(canary)); err != nil || code != 250 {
		t.Fatalf("DATA: %d %v", code, err)
	}
	client.expectReply("MAIL FROM:<reporter@isp.example>", 250)
	client.expectReply("RCPT TO:<root@"+testReportHostName+">", 250)
	client.expectReply("RCPT TO:<stranger@"+testRootDomainName+">", 550)
	if code, _, err := client.data(testArfReport(canary)); err != nil || code != 451 {
		t.Fatalf("DATA: %d %v", code, err)
	}
	client.quit()
	platform.service.AwaitSessionCount(0)

	scanned := append(platform.log.Lines(), platform.host.Metrics.Dump()...)
	if len(platform.log.Lines()) == 0 {
		t.Fatal("no line was logged, so the scan proves nothing")
	}
	for _, secret := range []string{canary, "reporter@", "isp.example", "abuse@", "stranger@", testReportHostName, testSender, "relay.example"} {
		for _, line := range scanned {
			if strings.Contains(line, secret) {
				t.Errorf("%q holds %q", line, secret)
			}
		}
	}
}

// 50 sessions at once, each holding its message at the intake: what they hold together stays within
// PlatformBufferByteCount, every session gets 250 or 452 4.3.1, and a held message is at least its size.
func TestPlatformHoldsMemoryWithinItsBoundAcross50Sessions(t *testing.T) {
	const sessionCount = 50
	body := "Subject: Report\r\n\r\n" + strings.Repeat(strings.Repeat("r", 98)+"\r\n", 30)
	settings := testPlatformSettings()
	settings.SenderSessionCount = sessionCount
	settings.SenderAggregateSessionCount = sessionCount
	settings.PlatformBufferByteCount = 10 * len(body)
	platform := newTestPlatform(t, &testPlatformOptions{settings: settings})
	platform.intake.Hold()

	clients := []*testPlatformClient{}
	for range sessionCount {
		client := platform.openTls(testSender, "")
		client.ehlo()
		client.expectReply("MAIL FROM:<dmarc@isp.example>", 250)
		client.expectReply("RCPT TO:<root@"+testReportHostName+">", 250)
		clients = append(clients, client)
	}
	type reply struct {
		code int
		err  error
	}
	replies := make(chan reply, sessionCount)
	for _, client := range clients {
		go func() {
			code, _, err := client.data(body)
			replies <- reply{code: code, err: err}
		}()
	}
	// every session has either been answered or holds its message at the intake
	heldCount := 0
	refusedCount := 0
	for heldCount+refusedCount < sessionCount {
		select {
		case <-platform.intake.Held():
			heldCount += 1
		case got := <-replies:
			if got.err != nil || got.code != 452 {
				t.Fatalf("a session got %d %v while the intake held", got.code, got.err)
			}
			refusedCount += 1
		}
	}
	peak := platform.service.PlatformBufferPeak()
	if int64(settings.PlatformBufferByteCount) < peak {
		t.Errorf("held %d bytes at once, past %d", peak, settings.PlatformBufferByteCount)
	}
	if heldCount == 0 || refusedCount == 0 {
		t.Errorf("%d held and %d refused", heldCount, refusedCount)
	}
	if int64(settings.PlatformBufferByteCount) < int64(heldCount*len(body)) {
		t.Errorf("%d messages of %d bytes held within %d", heldCount, len(body), settings.PlatformBufferByteCount)
	}
	platform.intake.Release()
	for range heldCount {
		if got := <-replies; got.err != nil || got.code != 250 {
			t.Errorf("a held session got %d %v", got.code, got.err)
		}
	}
	for _, client := range clients {
		client.quit()
	}
	platform.service.AwaitSessionCount(0)
	if held := platform.service.PlatformBufferHeld(); held != 0 {
		t.Errorf("%d bytes still held", held)
	}
}

// Ready needs today's k and the certificate, and no store, since the platform writes no session record.
func TestPlatformIsReadyWithNoStore(t *testing.T) {
	platform := newTestPlatform(t, nil)
	if !platform.service.Ready() {
		t.Error("not ready")
	}
	if counts := platform.store.OpCounts(); 0 < len(counts) {
		t.Errorf("the store was called: %v", counts)
	}
}

// With no certificate the role is not ready, and a session that reaches STARTTLS's 220 closes in the
// handshake, written to the closed-handshake memory, as the router's do.
func TestPlatformWithNoCertificateIsNotReadyAndClosesInTheHandshake(t *testing.T) {
	platform := newTestPlatform(t, &testPlatformOptions{noCertificate: true})
	if platform.service.Ready() {
		t.Error("ready with no certificate")
	}
	client := platform.open(testSender)
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	platform.startTls(client)
	client.write("hello")
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertUnrecognizedName))
	client.expectEnd()
	platform.service.AwaitSessionCount(0)
	if code := platform.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("a plaintext retry got %s", code)
	}
}

// A sender whose handshake fails is remembered as a closed handshake, so its plaintext retry gets 451.
func TestPlatformFailedHandshakeIsRemembered(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.open(testSender)
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()
	platform.startTls(client)
	// a record header no TLS sender writes, which the handshake reads whole and refuses
	client.write("GET /")
	io.ReadAll(client.reader)
	platform.service.AwaitSessionCount(0)
	if value := platform.host.Metrics.Value("urnetwork_mxedge_sessions_total", "platform_handshake_failed"); value != 1 {
		t.Errorf("platform_handshake_failed counted %v", value)
	}
	if code := platform.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("a plaintext retry got %s", code)
	}
}

// A session past TLS that goes quiet is closed at PlatformIdleTimeout on the engine's clock, counted
// from the sender's last byte: a command half way moves the deadline past the first one.
func TestPlatformClosesAnIdleSession(t *testing.T) {
	platform := newTestPlatform(t, nil)
	client := platform.openTls(testSender, "")
	client.ehlo()
	idleTimeout := platform.settings.PlatformIdleTimeout
	platform.clock.Advance(idleTimeout / 2)
	client.expectReply("NOOP", 250)
	platform.clock.Advance(idleTimeout/2 + time.Second)
	client.expectReply("NOOP", 250)
	platform.clock.Advance(idleTimeout)
	if rest, _ := io.ReadAll(client.conn); 0 < len(rest) {
		t.Errorf("read %q", rest)
	}
	platform.service.AwaitSessionCount(0)
}

// The platform's names must be there, and pass the router's own rules for names and urls.
func TestPlatformRefusesSettingsWithoutItsNames(t *testing.T) {
	for name, clear := range map[string]func(settings *mxedgeservice.MxEdgeSettings){
		"platform_report_host": func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformReportHostName = "" },
		"platform_root":        func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformRootDomainName = "root..example" },
		"platform_abuse_url":   func(settings *mxedgeservice.MxEdgeSettings) { settings.PlatformAbuseUrl = "http://abuse.example/form" },
	} {
		settings := testPlatformSettings()
		clear(settings)
		err := settings.ValidatePlatform()
		if !errors.Is(err, mxedgeservice.ErrMxEdgeSettingsRefused) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
		if err := settings.Validate(); err != nil {
			t.Errorf("%s: the router's validate refused %v", name, err)
		}
	}
}
