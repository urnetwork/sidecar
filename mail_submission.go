//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The daemon's local mail server, its submission side (§15.10, R-MAIL-1, D-MAIL-11, I-8, I-9, I-17, X7, R-CTX-24,
// R-TRUST-6, owner decisions 47, 84, 130; MAIL-M9-01): the local server is the MTA (PLAN.md:104). A mail client
// submits to it on §5.8's submission port, and it takes each message through §15.10's steps (MailClient.SubmitMessage):
// a same-network recipient's deposit, and internet mail queued at o/ for a prover host, which sends it through §14's
// smtpedge. It never relays to port 25 itself: nothing here dials anything.
//
//	listen    DaemonLocalListen's submission listener: every interface unless --listen narrows it, implicit TLS
//	          (RFC 8314 §3) off loopback, chosen per connection by its local address, and plaintext only on 127.0.0.1
//	          and ::1; a connection that is neither is closed unanswered (mailImapListener's rule). Off loopback the
//	          certificate is the device's for the address the client reached (D-TRUST-8)
//	greet     go-smtp's ordinary Serve: a local client gets a greeting, unlike a receiver's session after STARTTLS
//	auth      AUTH PLAIN on every connection, loopback included (I-17), over the one local credential IMAP takes
//	          (MailLocalLogin, shared with IMAP, so alternating the two buys a guesser nothing): the matching secret
//	          names the network the session submits for, and a refusal costs the client its delay. MAIL before AUTH
//	          is refused. STARTTLS is never offered, since off loopback the connection is TLS already
//	rcpt      a same-network recipient no record a receiver honors holds is refused at RCPT, 550 5.1.1; any other is
//	          taken, at most RecipientMaxCount, then 452 4.5.3
//	data      the message's From header, held to mail:<alias>#send, and the envelope's recipients make the send; the
//	          envelope's MAIL FROM is not the message's sender and is not used, since internet mail's envelope sender
//	          is the mailbox's bounce address (mail_bounce.go). 250 once every recipient is deposited or queued; a send
//	          that waits on a person's approval answers 451 4.7.1 naming the approval, nothing kept, deposited or
//	          queued, so the client sends the same bytes again after `ur approve <id>` and the gate finds its decision;
//	          the gate's refusal 554 5.7.1; a From this device may not send as 553 5.7.1; a deposit or queue that did
//	          not commit 451 4.3.0, so the client retries and the repos that took it may get it twice, as §22.7 allows
//	same uid  a process of the daemon's own OS user may submit as ur does (owner decision 47), and the gate still holds
//	          what is outward: the credential grants only what the daemon grants its OS user
//	bounds    at most ConnectionMaxCount sessions at once, a further one answered 421 and closed; each command line
//	          within LineMaxByteCount, a message within MessageMaxByteCount, and each read and write within its timeout
//	logs      go-smtp's error log writes nothing and its debug writer is unset, since either would carry a client's
//	          address or a session's text, a credential among it (I-7, I-13)
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
)

// No hosted network serves submission: none has mail on with a credential made, so the listener stays closed.
var ErrMailSubmissionNoAccount = errors.New("mail submission: no network has mail on with a credential")

// The name the server greets with: local, since a client reaches it on its own device or LAN by address.
const mailSubmissionDomain = "localhost"

// The server's tunables.
type MailSubmissionSettings struct {
	// Sessions open at once: 64, as IMAP's. A LAN host holding connections open costs a goroutine each.
	ConnectionMaxCount int
	// How long one read or one write of a session may take: RFC 5321 §4.5.3.2's 5 min for a command.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// How long one message's submission may take, the gate and the delivery: 5 min.
	SubmitTimeout time.Duration
	// The most bytes of one message: MailSendSettings.MessageMaxByteCount's 50 MiB, past which go-smtp answers 552.
	MessageMaxByteCount int64
	// The most recipients of one message: §15.7's 100.
	RecipientMaxCount int
	// The most bytes of one command line: RFC 5321 §4.5.3.1.6's doubled 1,000, go-smtp's 2,000.
	LineMaxByteCount int
}

// The defaults, a fresh value each call.
func DefaultMailSubmissionSettings() *MailSubmissionSettings {
	return &MailSubmissionSettings{
		ConnectionMaxCount:  64,
		ReadTimeout:         5 * time.Minute,
		WriteTimeout:        5 * time.Minute,
		SubmitTimeout:       5 * time.Minute,
		MessageMaxByteCount: int64(DefaultMailSendSettings().MessageMaxByteCount),
		RecipientMaxCount:   DefaultMailSendSettings().RecipientMaxCount,
		LineMaxByteCount:    2000,
	}
}

// Whether every value is in range.
func (self *MailSubmissionSettings) valid() bool {
	return self != nil && 0 < self.ConnectionMaxCount && 0 < self.ReadTimeout && 0 < self.WriteTimeout && 0 < self.SubmitTimeout &&
		0 < self.MessageMaxByteCount && 0 < self.RecipientMaxCount && 0 < self.LineMaxByteCount
}

// What a session submits through: MailClient, or a test's.
type MailSubmitter interface {
	// Whether recipient may be named at RCPT: nil, or ErrMailSubmitUnknownRecipient for a same-network address no
	// honored record holds.
	CheckSubmitRecipient(ctx context.Context, recipient string) error
	// Sends a submitted message to its envelope recipients (MailClient.SubmitMessage).
	SubmitMessage(ctx context.Context, args *MailSubmitArgs) (*MailSendResult, error)
}

// One network's mail as the server reaches it.
type MailSubmissionAccount struct {
	NetworkId Id
	// The network's credential, which AUTH matches.
	Credential *MailLocalCredential
	Submitter  MailSubmitter
}

// What NewMailSubmissionServer builds on.
type MailSubmissionServerArgs struct {
	// The accounts the server serves, read at each AUTH.
	Accounts func() []*MailSubmissionAccount
	// The check and its cost, IMAP's. Nil: one of the server's own.
	Login *MailLocalLogin
	// Nil: real time.
	Clock Clock
	// Nil: DefaultMailSubmissionSettings.
	Settings *MailSubmissionSettings
}

// See the file header.
type MailSubmissionServer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	accounts func() []*MailSubmissionAccount
	login    *MailLocalLogin
	clock    Clock
	settings *MailSubmissionSettings
	server   *smtp.Server
	// the sessions open, which admission raises and each session's end lowers
	sessions *MonitorValue[int]
	// each Serve running, which Close waits out before go-smtp's Close
	serving   sync.WaitGroup
	closeOnce sync.Once

	stateLock sync.Mutex
	listeners map[net.Listener]bool
	closed    bool
}

// A server over args' accounts, serving nothing until Serve.
func NewMailSubmissionServer(ctx context.Context, args *MailSubmissionServerArgs) (*MailSubmissionServer, error) {
	if args == nil || args.Accounts == nil {
		return nil, errors.New("mail submission: a server needs its accounts")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailSubmissionSettings()
	}
	if !settings.valid() {
		return nil, errors.New("mail submission: the server's bounds are positive")
	}
	clock := clockOrReal(args.Clock)
	login := args.Login
	if login == nil {
		var err error
		if login, err = NewMailLocalLogin(clock, nil); err != nil {
			return nil, err
		}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &MailSubmissionServer{
		ctx:       cancelCtx,
		cancel:    cancel,
		accounts:  args.Accounts,
		login:     login,
		clock:     clock,
		settings:  settings,
		sessions:  NewMonitorValue(0),
		listeners: map[net.Listener]bool{},
	}
	server := smtp.NewServer(smtp.BackendFunc(self.newSession))
	server.Domain = mailSubmissionDomain
	server.MaxMessageBytes = settings.MessageMaxByteCount
	server.MaxLineLength = settings.LineMaxByteCount
	// enforced in the session's Rcpt with 452 4.5.3, so no LIMITS keyword is advertised (plan-MAIL-small-readings#10)
	server.MaxRecipients = 0
	// mailImapListener hands go-smtp a plaintext connection only on loopback, so an AUTH go-smtp sees off TLS is a
	// loopback one, which D-MAIL-11 allows; every other connection is a *tls.Conn, which go-smtp reads as TLS
	server.AllowInsecureAuth = true
	server.ReadTimeout = settings.ReadTimeout
	server.WriteTimeout = settings.WriteTimeout
	// a line of go-smtp's names a client's address, and its debug a session's text (I-7, I-13)
	server.ErrorLog = log.New(io.Discard, "", 0)
	server.Debug = nil
	self.server = server
	context.AfterFunc(cancelCtx, self.shutdown)
	return self, nil
}

// A session for conn, or a refusal past ConnectionMaxCount or once closed, which go-smtp answers 421.
func (self *MailSubmissionServer) newSession(conn *smtp.Conn) (smtp.Session, error) {
	if self.ctx.Err() != nil {
		return nil, &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 3, 2}, Message: "Shutting down"}
	}
	admitted := self.sessions.Update(func(count int) int {
		if self.settings.ConnectionMaxCount <= count {
			return count
		}
		return count + 1
	})
	if !admitted {
		return nil, &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many connections"}
	}
	return newMailSubmissionSession(self, conn), nil
}

// A session's end, giving its place back.
func (self *MailSubmissionServer) sessionClosed() {
	self.sessions.Update(func(count int) int { return count - 1 })
}

// Serves listener, a DaemonLocalListener's submission connections, until it closes or the server does.
// net.ErrClosed once the server has closed.
func (self *MailSubmissionServer) Serve(listener net.Listener) error {
	wrapped := &mailImapListener{Listener: listener}
	admitted := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.listeners[wrapped] = true
		self.serving.Add(1)
		return true
	}()
	if !admitted {
		return net.ErrClosed
	}
	defer func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.listeners, wrapped)
		}()
		self.serving.Done()
	}()
	err := self.server.Serve(wrapped)
	if self.ctx.Err() != nil {
		return net.ErrClosed
	}
	return err
}

// Ends every listener and session, each Serve having returned when it does. Safe more than once.
func (self *MailSubmissionServer) Close() {
	self.cancel()
	self.shutdown()
}

// Closes go-smtp's server, its listeners and connections, then waits out each Serve. Once.
func (self *MailSubmissionServer) shutdown() {
	self.closeOnce.Do(func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.closed = true
		}()
		// go-smtp's Close closes the listeners it serves and every connection, so each Serve returns
		self.server.Close()
		self.serving.Wait()
	})
}

// A context for one message's submission, ended at SubmitTimeout or with the server.
func (self *MailSubmissionServer) submitContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(self.settings.SubmitTimeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// This network's mail as the daemon's submission server serves it: false while mail is off or no credential is made.
func (self *MailClient) SubmissionAccount() (*MailSubmissionAccount, bool) {
	if !self.Enabled() {
		return nil, false
	}
	credential, err := self.LocalCredential()
	if err != nil {
		return nil, false
	}
	if configured, err := credential.Configured(); err != nil || !configured {
		return nil, false
	}
	return &MailSubmissionAccount{NetworkId: self.networkId, Credential: credential, Submitter: self}, true
}

// The daemon's submission server and its listener (D-MAIL-11): see the file header. Safe for concurrent use.
type DaemonMailSubmission struct {
	daemon *Daemon
	ctx    context.Context
	// the hosted networks' accounts; a test stands its own in
	accounts func() []*MailSubmissionAccount
	// held across a whole Start, which reads keychains and binds a port, so two never open two listeners
	startLock sync.Mutex

	stateLock sync.Mutex
	listener  *DaemonLocalListener
}

// The daemon's submission server, made on first use, listening once Start runs.
func (self *Daemon) MailSubmission() *DaemonMailSubmission {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held, ok := self.mailSubmission.(*DaemonMailSubmission); ok {
		return held
	}
	held := &DaemonMailSubmission{daemon: self, ctx: self.ctx}
	held.accounts = held.hostedAccounts
	self.mailSubmission = held
	return held
}

// Each hosted network's account, in network order.
func (self *DaemonMailSubmission) hostedAccounts() []*MailSubmissionAccount {
	accounts := []*MailSubmissionAccount{}
	for _, network := range self.daemon.Sidecars() {
		client, err := network.Sidecar.Mail()
		if err != nil {
			continue
		}
		if account, ok := client.SubmissionAccount(); ok {
			accounts = append(accounts, account)
		}
	}
	return accounts
}

// The certificate off loopback: the device's, of the first hosted network whose mail serves submission, for the
// local address the client reached, never a name the client chose.
func (self *DaemonMailSubmission) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.Conn == nil {
		return nil, ErrTlsCertificateNames
	}
	addrPort, err := netip.ParseAddrPort(hello.Conn.LocalAddr().String())
	if err != nil {
		return nil, ErrTlsCertificateNames
	}
	for _, network := range self.daemon.Sidecars() {
		client, err := network.Sidecar.Mail()
		if err != nil {
			continue
		}
		if _, ok := client.SubmissionAccount(); ok {
			return network.Sidecar.TlsDeviceCertificate([]string{addrPort.Addr().Unmap().String()})
		}
	}
	return nil, ErrMailSubmissionNoAccount
}

// Opens submission's listener with the daemon's first port and --listen and serves it, once there is an account to
// serve; a second call answers the listener already open. ErrMailSubmissionNoAccount while there is none, which leaves
// the port closed. AUTH shares IMAP's login and its cost (Daemon.MailImap).
func (self *DaemonMailSubmission) Start() (*DaemonLocalListenerStatus, error) {
	self.startLock.Lock()
	defer self.startLock.Unlock()
	if listener := self.openListener(); listener != nil {
		status := listener.status()
		return &status, nil
	}
	if len(self.accounts()) == 0 {
		return nil, ErrMailSubmissionNoAccount
	}
	server, err := NewMailSubmissionServer(self.ctx, &MailSubmissionServerArgs{
		Accounts: self.accounts,
		Login:    self.daemon.MailImap().Login(),
		Clock:    self.daemon.clock,
	})
	if err != nil {
		return nil, err
	}
	listener, err := self.daemon.LocalListen(&DaemonLocalListenArgs{
		Service: DaemonLocalSubmission,
		Tls: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: self.certificate,
		},
	})
	if err != nil {
		server.Close()
		return nil, err
	}
	context.AfterFunc(self.ctx, func() {
		listener.Close()
	})
	go server.Serve(listener)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.listener = listener
	}()
	status := listener.status()
	return &status, nil
}

// The listener Start opened, nil before.
func (self *DaemonMailSubmission) openListener() *DaemonLocalListener {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listener
}
