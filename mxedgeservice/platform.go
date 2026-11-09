// The platform role (D-MAIL-10, §15.4's platform mail, MAIL-M5-03): rpt.bringyour.com's listener for
// §14.8's reports and <root>'s role mail. It keeps the router's front, the caps, the banner, the pre-TLS
// dialog and its plaintext refusal, then, unlike the router, ends TLS itself under the one bringyour.com
// certificate, SNI or none (S7), and runs a go-smtp session on it through sidecar.MailSmtpServe.
//
// This is §2.8's one exception, mx-4: the only place a URnetwork server reads mail meant for it. So the
// envelope and the message stay in this process's memory, each message goes to PlatformIntake once per
// recipient and nowhere else, and nothing here persists, logs or counts an envelope, a recipient, an
// address or a byte of a message (I-2, I-13). go-smtp's Debug stays nil and its ErrorLog writes nothing,
// since either would carry a session's text.
//
// The listener answers for its own recipients alone, <token>@ and root@ on the report host and
// postmaster@ and abuse@ on <root>, since the rule that inbound TLS ends on a customer's device has only
// this exception (D-MAIL-1). Anything else is 550 5.1.1.

package mxedgeservice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/urnetwork/sidecar"
)

// A message the platform listener took, for one of its recipients: what SMTP-M5-05's SmtpReportMessage
// carries, which this engine may not import (§4.4). Memory only (§2.8 mx-4).
type PlatformMessage struct {
	// The RCPT the listener took, lowercased: <token>@ or root@ on the report host, or postmaster@ or
	// abuse@ on <root>.
	Recipient   string
	ArrivalTime time.Time
	// The message as received. Each recipient's call is given the same bytes, so a call must not
	// change them.
	Raw []byte
}

// How the intake ended with one recipient's message.
type PlatformOutcome int

const (
	// Taken as the intake's rules have it, counted, stored or dropped, which tells a sender nothing:
	// the listener answers 250.
	PlatformOutcomeTaken PlatformOutcome = iota + 1
	// Role mail that §14.8's header-only parse could not attribute, dropped unread. SMTP-M5-05 gives it
	// as any outcome but a case for postmaster@ or abuse@. When every recipient's message ends so, the
	// listener answers plan-ABUSE-auto-reply's 550 5.7.1, pointing the sender at §21.8's form.
	PlatformOutcomeUnread
)

// SMTP-M5-05's SmtpReportIntake as this engine reaches it: SMTP-M5-06 adapts it in the platform host,
// and sidecartest.FakePlatformIntake records calls until then. Called once for each recipient of a
// message, on the session's goroutine, before the DATA or BDAT reply. Safe for concurrent use.
type PlatformIntake interface {
	// An error is an intake that could not finish, a store or DNS that did not answer: the listener
	// answers 451 4.3.0 and the sender retries the whole message. It carries no report text.
	Accept(ctx context.Context, message *PlatformMessage) (PlatformOutcome, error)
}

// What the platform role needs beyond MxEdgeDeps, which server/mxedgehost's platform block supplies
// (MAIL-M5-04). The router's three hello functions are not needed: crypto/tls reads the hello here.
type MxEdgePlatformDeps struct {
	// The bringyour.com certificate and key from secret_files, under which every session's TLS ends,
	// whatever its SNI, or with none. nil leaves the role not ready, and a session that reaches
	// STARTTLS's 220 then closes in the handshake.
	Certificate *tls.Certificate
	// nil answers 451 4.3.0 to every recipient, so a sender retries and nothing is read.
	Intake PlatformIntake
}

// The platform role's state, built once with the engine.
type mxPlatform struct {
	service     *MxEdgeService
	certificate *tls.Certificate
	intake      PlatformIntake
	tlsConfig   *tls.Config
	server      *smtp.Server
	recipients  *mxPlatformRecipients
	buffers     *mxPlatformBuffers
	replies     *mxPlatformReplies
}

// Starts the engine in the platform role. It needs no store: a platform session names no network, so it
// leaves no session record (reading 3), and the role is ready once a probe has read today's k and
// platformDeps holds a certificate. host needs Redis and Metrics, and settings must pass
// ValidatePlatform. A nil platformDeps leaves the role not ready.
func NewMxEdgePlatformService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	deps *MxEdgeDeps,
	platformDeps *MxEdgePlatformDeps,
	settings *MxEdgeSettings,
) (*MxEdgeService, error) {
	if err := settings.ValidatePlatform(); err != nil {
		return nil, err
	}
	if platformDeps == nil {
		platformDeps = &MxEdgePlatformDeps{}
	}
	return newMxEdgeService(ctx, host, nil, deps, settings, func(self *MxEdgeService) {
		self.platform = newMxPlatform(self, platformDeps)
		self.handoff = self.servePlatform
		self.depsComplete = platformDeps.Certificate != nil
	})
}

// The role on service's settings, its TLS config and go-smtp server built once for every session.
func newMxPlatform(service *MxEdgeService, platformDeps *MxEdgePlatformDeps) *mxPlatform {
	settings := service.settings
	self := &mxPlatform{
		service:     service,
		certificate: platformDeps.Certificate,
		intake:      platformDeps.Intake,
		recipients:  newMxPlatformRecipients(settings),
		buffers:     newMxPlatformBuffers(int64(settings.PlatformBufferByteCount)),
		replies:     newMxPlatformReplies(settings),
	}
	if self.certificate != nil {
		self.tlsConfig = &tls.Config{
			// one certificate whatever the SNI, so a reporter that sends none still delivers (S7)
			Certificates: []tls.Certificate{*self.certificate},
			MinVersion:   tls.VersionTLS12,
			// a reporter reconnects seldom, and each process would hold its own ticket keys, so a ticket
			// would buy nothing past this block
			SessionTicketsDisabled: true,
		}
	}
	server := smtp.NewServer(&mxPlatformBackend{platform: self})
	server.Domain = settings.BannerHostName
	server.MaxMessageBytes = int64(settings.PlatformMessageByteCount)
	// recipients are counted by the session, which answers 452 4.5.3 past PlatformRecipientCount, so
	// EHLO advertises no LIMITS (reading 10)
	server.MaxRecipients = 0
	server.EnableREQUIRETLS = true
	server.EnableSMTPUTF8 = true
	// a line of either could name an address or carry a message's bytes
	server.Debug = nil
	server.ErrorLog = log.New(io.Discard, "", 0)
	// waits are on the engine's clock (servePlatform), never a socket's own deadline
	server.ReadTimeout = 0
	server.WriteTimeout = 0
	self.server = server
	return self
}

// Ends every platform session still open, once the engine has closed their connections.
func (self *mxPlatform) close() {
	self.server.Close()
}

// The handoff in the platform role: TLS ends here, then one go-smtp session. A session with no
// certificate to offer closes in the handshake as the router's do, and so does one whose handshake
// fails, each written to the closed-handshake memory first, so a plaintext retry is told to wait.
func (self *MxEdgeService) servePlatform(session *mxSession) string {
	if self.platform.tlsConfig == nil {
		return self.closeHandshake(session)
	}
	conn := session.conn
	stopSession := self.clock.AfterFunc(self.settings.PlatformSessionTimeout, func() {
		conn.Close()
	})
	defer stopSession()
	idleConn := newMxIdleConn(conn, self.clock, self.settings.PlatformIdleTimeout)
	defer idleConn.stop()

	tlsConn := tls.Server(idleConn, self.platform.tlsConfig)
	handshakeErr := func() error {
		stopHandshake := self.clock.AfterFunc(self.settings.PlatformHandshakeTimeout, func() {
			conn.Close()
		})
		defer stopHandshake()
		return tlsConn.Handshake()
	}()
	if handshakeErr != nil {
		self.recordClosedHandshake(session)
		return mxSessionResultPlatformHandshakeFailed
	}
	// closes tlsConn on every path, a refusal's included
	if err := sidecar.MailSmtpServe(self.platform.server, tlsConn); errors.Is(err, smtp.ErrServerClosed) {
		return mxSessionResultEnded
	}
	return mxSessionResultPlatformServed
}

// A connection whose Read arms a timer on the engine's clock, which closes it when no byte comes in its
// time. Reads come from one session's goroutine, but stop comes from another.
type mxIdleConn struct {
	net.Conn
	clock       sidecar.Clock
	idleTimeout time.Duration

	stateLock sync.Mutex
	stopTimer func() bool
	stopped   bool
}

// Armed from now.
func newMxIdleConn(conn net.Conn, clock sidecar.Clock, idleTimeout time.Duration) *mxIdleConn {
	self := &mxIdleConn{Conn: conn, clock: clock, idleTimeout: idleTimeout}
	self.arm()
	return self
}

// Moves the timer to now plus the idle time, unless stopped.
func (self *mxIdleConn) arm() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.stopped {
		return
	}
	if self.stopTimer != nil {
		self.stopTimer()
	}
	self.stopTimer = self.clock.AfterFunc(self.idleTimeout, func() {
		self.Conn.Close()
	})
}

// A byte read is a sender still there.
func (self *mxIdleConn) Read(data []byte) (int, error) {
	byteCount, err := self.Conn.Read(data)
	if 0 < byteCount {
		self.arm()
	}
	return byteCount, err
}

// Stops the timer for good.
func (self *mxIdleConn) stop() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.stopped = true
	if self.stopTimer != nil {
		self.stopTimer()
	}
}

// A message token: 26 lowercase base32 characters of 16 random octets (plan-SMTP-net-token), which
// SMTP-M5-05 reads the same way.
const mxPlatformTokenByteCount = 26

// <root>'s rua's fixed local part, which no token can equal (plan-SMTP-net-token).
const mxPlatformRootLocalPart = "root"

// The recipients the listener answers for, from settings.
type mxPlatformRecipients struct {
	reportHostName string
	rootDomainName string
}

// Settings' names, lowercased once.
func newMxPlatformRecipients(settings *MxEdgeSettings) *mxPlatformRecipients {
	return &mxPlatformRecipients{
		reportHostName: mxLowerAscii(settings.PlatformReportHostName),
		rootDomainName: mxLowerAscii(settings.PlatformRootDomainName),
	}
}

// The recipient lowercased, when it is one the listener takes: a token or root on the report host,
// postmaster or abuse on <root>.
func (self *mxPlatformRecipients) take(recipient string) (string, bool) {
	at := -1
	for i := len(recipient) - 1; 0 <= i; i-- {
		if recipient[i] == '@' {
			at = i
			break
		}
	}
	if at < 0 {
		return "", false
	}
	localPart := mxLowerAscii(recipient[:at])
	domain := mxLowerAscii(recipient[at+1:])
	if 0 < len(domain) && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	switch domain {
	case self.reportHostName:
		if localPart != mxPlatformRootLocalPart && !mxPlatformToken(localPart) {
			return "", false
		}
	case self.rootDomainName:
		if localPart != "postmaster" && localPart != "abuse" {
			return "", false
		}
	default:
		return "", false
	}
	return localPart + "@" + domain, true
}

// Whether the recipient goes to §21.8's role flow, whose unattributed mail is refused unread.
func (self *mxPlatformRecipients) role(recipient string) bool {
	return recipient == "postmaster@"+self.rootDomainName || recipient == "abuse@"+self.rootDomainName
}

// Whether localPart has a token's shape. Which network holds it is the intake's to find, off this path.
func mxPlatformToken(localPart string) bool {
	if len(localPart) != mxPlatformTokenByteCount {
		return false
	}
	for i := range len(localPart) {
		c := localPart[i]
		if !('a' <= c && c <= 'z' || '2' <= c && c <= '7') {
			return false
		}
	}
	return true
}

// ASCII letters lowered, and every other byte kept, so a non-ASCII name stays unequal to any of ours.
func mxLowerAscii(text string) string {
	lowered := []byte(text)
	for i, c := range lowered {
		if 'A' <= c && c <= 'Z' {
			lowered[i] = c + ('a' - 'A')
		}
	}
	return string(lowered)
}

// The bytes all platform sessions in this process hold at once, which PlatformBufferByteCount bounds.
// What a buffer holds is counted by its capacity, so the bound is on the live buffers, not on garbage
// awaiting collection. Safe for concurrent use.
type mxPlatformBuffers struct {
	maxByteCount int64

	stateLock     sync.Mutex
	heldByteCount int64
	// The most held at once, for a test.
	peakByteCount int64
}

// Nothing held, and at most maxByteCount.
func newMxPlatformBuffers(maxByteCount int64) *mxPlatformBuffers {
	return &mxPlatformBuffers{maxByteCount: maxByteCount}
}

// Holds byteCount more, or nothing when that would pass the bound.
func (self *mxPlatformBuffers) reserve(byteCount int64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.maxByteCount < self.heldByteCount+byteCount {
		return false
	}
	self.heldByteCount += byteCount
	self.peakByteCount = max(self.peakByteCount, self.heldByteCount)
	return true
}

// Lets byteCount go.
func (self *mxPlatformBuffers) release(byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heldByteCount -= byteCount
}

// The platform listener's replies past go-smtp's own. Each is an *smtp.SMTPError, since go-smtp writes
// any other error's text to the sender.
type mxPlatformReplies struct {
	unknownRecipient *smtp.SMTPError
	noIntake         *smtp.SMTPError
	tooManyRecipient *smtp.SMTPError
	bufferFull       *smtp.SMTPError
	retry            *smtp.SMTPError
	unread           *smtp.SMTPError
}

// Settings have passed ValidatePlatform, so the url carries no CR or LF into a reply.
func newMxPlatformReplies(settings *MxEdgeSettings) *mxPlatformReplies {
	return &mxPlatformReplies{
		unknownRecipient: &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such recipient here"},
		noIntake:         &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Try again later"},
		tooManyRecipient: &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"},
		bufferFull:       &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 3, 1}, Message: "Insufficient system storage, try again later"},
		retry:            &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Try again later"},
		unread:           &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: fmt.Sprintf("Not read. Report abuse at %s", settings.PlatformAbuseUrl)},
	}
}
