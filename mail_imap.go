//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The daemon's IMAP server (R-MAIL-1, D-MAIL-11, I-7, I-17, owner decisions 47, 84, 130; MAIL-M8-07): emersion/go-imap
// v2's imapserver, a pre-release (QD-470), behind a thin seam, each session on one network's MailImapStore
// (mail_imap_session.go). A daemon runs one, on DaemonLocalImap's port (Daemon.MailImap).
//
//	listen    DaemonLocalListen's IMAP listener: every interface unless --listen narrows it, implicit TLS (RFC 8314 §3)
//	          off loopback, chosen per connection by its local address, and plaintext only on 127.0.0.1 and ::1. A
//	          connection that is neither, which that helper never hands out, is closed unanswered. Off loopback the
//	          certificate is the device's for the address the client reached, never a name the client chose, so a
//	          LAN host cannot make the daemon mint a leaf per hello
//	auth      LOGIN, and AUTHENTICATE PLAIN, which go-imap routes to the same call, on every connection, loopback
//	          included (I-17): MailLocalLogin over every account's credential, whose matching secret names the network
//	          the session serves, and whose refusal costs the client its delay (mail_local_credential.go). STARTTLS is
//	          never offered, since off loopback the connection is TLS already
//	accounts  each hosted network whose mail is on and whose credential is made, read again at each LOGIN, so turning
//	          mail on or making a credential needs no restart
//	bounds    at most ConnectionMaxCount sessions at once, a further one answered BYE and closed; each command's store
//	          calls end at CommandTimeout; go-imap holds a command line to 50 KiB and a literal outside APPEND, which
//	          is refused, to 4 KiB
//	search    until MAIL-M10-03 SEARCH scans i/: each message's entry, its subject, sender, snippet, date, size and
//	          flags, never its body (mail_imap_session.go)
//	logs      go-imap's logger writes nothing and its debug writer is unset, since either would carry a session's
//	          text, a credential among it (I-7)
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

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// No hosted network serves IMAP: none has mail on with a credential made, so the listener stays closed.
var ErrMailImapNoAccount = errors.New("mail imap: no network has mail on with a credential")

// The server's tunables.
type MailImapServerSettings struct {
	// How often a session in IDLE reads its folder again with no hint: 60 s, so a change no hint names still shows
	// within it.
	IdlePollInterval time.Duration
	// How long one command's store calls may take: 60 s, past a refused LOGIN's longest wait.
	CommandTimeout time.Duration
	// Sessions open at once: 64. A LAN host holding connections open costs a goroutine each, so they are bounded.
	ConnectionMaxCount int
	// How deep SEARCH's NOT and OR nest before a nested criterion matches nothing: 32, deeper than any client writes,
	// so a crafted command's recursion stays bounded.
	SearchMaxDepth int
}

// The defaults, a fresh value each call.
func DefaultMailImapServerSettings() *MailImapServerSettings {
	return &MailImapServerSettings{
		IdlePollInterval:   60 * time.Second,
		CommandTimeout:     60 * time.Second,
		ConnectionMaxCount: 64,
		SearchMaxDepth:     32,
	}
}

// One network's mailbox as the server reaches it.
type MailImapAccount struct {
	NetworkId Id
	// The network's credential, which LOGIN matches.
	Credential *MailLocalCredential
	// The member's mailbox as IMAP sees it, built at its first use; an error while the mail component has nothing to
	// read yet, which a session answers as unavailable.
	Store func() (*MailImapStore, error)
	// The mailbox's hint: a revision and a channel that closes at its next change, which IDLE waits on beside the
	// store's own. Nil waits on the store and IdlePollInterval alone.
	Hints func() (uint64, chan struct{})
}

// What NewMailImapServer builds on.
type MailImapServerArgs struct {
	// The accounts the server serves, read at each LOGIN.
	Accounts func() []*MailImapAccount
	// The check and its cost, shared with submission. Nil: one of the server's own.
	Login *MailLocalLogin
	// Nil: real time.
	Clock Clock
	// Nil: DefaultMailImapServerSettings.
	Settings *MailImapServerSettings
}

// See the file header.
type MailImapServer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	accounts func() []*MailImapAccount
	login    *MailLocalLogin
	clock    Clock
	settings *MailImapServerSettings
	server   *imapserver.Server
	// the sessions open, which admission raises and each session's end lowers
	sessions *MonitorValue[int]
	// each Serve running, which Close waits out before go-imap's Close: go-imap's Serve joins its own wait group after
	// it registers a listener, so a Close that met a Serve just begun would wait on that group as it is joined
	serving   sync.WaitGroup
	closeOnce sync.Once

	stateLock sync.Mutex
	listeners map[net.Listener]bool
	closed    bool
}

// A server over args' accounts, serving nothing until Serve.
func NewMailImapServer(ctx context.Context, args *MailImapServerArgs) (*MailImapServer, error) {
	// a line of go-imap's could carry a credential or a message (I-7)
	return newMailImapServer(ctx, args, log.New(io.Discard, "", 0))
}

// NewMailImapServer with go-imap's logger, which a test sets to see a panic go-imap recovered.
func newMailImapServer(ctx context.Context, args *MailImapServerArgs, imapLog imapserver.Logger) (*MailImapServer, error) {
	if args == nil || args.Accounts == nil {
		return nil, errors.New("mail imap: a server needs its accounts")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailImapServerSettings()
	}
	if settings.IdlePollInterval <= 0 || settings.CommandTimeout <= 0 || settings.ConnectionMaxCount <= 0 || settings.SearchMaxDepth < 0 {
		return nil, errors.New("mail imap: the server's bounds are positive")
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
	self := &MailImapServer{
		ctx:       cancelCtx,
		cancel:    cancel,
		accounts:  args.Accounts,
		login:     login,
		clock:     clock,
		settings:  settings,
		sessions:  NewMonitorValue(0),
		listeners: map[net.Listener]bool{},
	}
	self.server = imapserver.New(&imapserver.Options{
		NewSession: self.newSession,
		Caps:       imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapUIDPlus: {}},
		Logger:     imapLog,
		// raw session bytes, a credential among them (I-7)
		DebugWriter: nil,
		// mailImapListener hands go-imap a plaintext connection only on loopback, so a LOGIN go-imap sees off TLS is a
		// loopback one, which D-MAIL-11 allows; every other connection is a *tls.Conn, which go-imap reads as TLS
		InsecureAuth: true,
	})
	context.AfterFunc(cancelCtx, self.shutdown)
	return self, nil
}

// A session for conn, or BYE past ConnectionMaxCount or once closed.
func (self *MailImapServer) newSession(conn *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
	if self.ctx.Err() != nil {
		return nil, nil, &imap.Error{Type: imap.StatusResponseTypeBye, Text: "Shutting down"}
	}
	admitted := self.sessions.Update(func(count int) int {
		if self.settings.ConnectionMaxCount <= count {
			return count
		}
		return count + 1
	})
	if !admitted {
		return nil, nil, &imap.Error{Type: imap.StatusResponseTypeBye, Text: "Too many connections"}
	}
	return newMailImapSession(self, conn), nil, nil
}

// A session's end, giving its place back.
func (self *MailImapServer) sessionClosed() {
	self.sessions.Update(func(count int) int { return count - 1 })
}

// Serves listener, a DaemonLocalListener's IMAP connections, until it closes or the server does. net.ErrClosed once
// the server has closed.
func (self *MailImapServer) Serve(listener net.Listener) error {
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
	return self.server.Serve(wrapped)
}

// Ends every listener and session, each Serve having returned when it does. Safe more than once.
func (self *MailImapServer) Close() {
	self.cancel()
	self.shutdown()
}

// Closes the listeners, waits out each Serve, then ends go-imap's server and its connections. Once.
func (self *MailImapServer) shutdown() {
	self.closeOnce.Do(func() {
		listeners := func() []net.Listener {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.closed = true
			listeners := make([]net.Listener, 0, len(self.listeners))
			for listener := range self.listeners {
				listeners = append(listeners, listener)
			}
			return listeners
		}()
		for _, listener := range listeners {
			listener.Close()
		}
		self.serving.Wait()
		self.server.Close()
	})
}

// A context for one command's store calls, ended at CommandTimeout or with the server.
func (self *MailImapServer) commandContext() (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(self.settings.CommandTimeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// Hands go-imap each connection as D-MAIL-11 allows it: a TLS one as its *tls.Conn, a loopback one plain, and closes
// any other unanswered.
type mailImapListener struct {
	net.Listener
}

// The next connection D-MAIL-11 allows, as go-imap is to see it.
func (self *mailImapListener) Accept() (net.Conn, error) {
	for {
		conn, err := self.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if local, ok := conn.(*DaemonLocalConn); ok {
			// Loopback is the helper's reading of the address the connection arrived at
			if _, isTls := local.Conn.(*tls.Conn); local.Tls && isTls {
				return local.Conn, nil
			}
			if local.Loopback && !local.Tls {
				return local.Conn, nil
			}
			local.Close()
			continue
		}
		// a listener that is not the helper's: plaintext only from and to loopback
		if mailImapLoopback(conn.LocalAddr()) && mailImapLoopback(conn.RemoteAddr()) {
			return conn, nil
		}
		conn.Close()
	}
}

// Whether addr is a loopback address.
func mailImapLoopback(addr net.Addr) bool {
	addrPort, err := netip.ParseAddrPort(addr.String())
	return err == nil && addrPort.Addr().Unmap().IsLoopback()
}

// The client's address, for the credential's cost, or the zero address.
func mailImapClient(conn net.Conn) netip.Addr {
	if conn == nil {
		return netip.Addr{}
	}
	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return netip.Addr{}
	}
	return addrPort.Addr().Unmap()
}

// This network's mailbox as the daemon's IMAP server serves it: false while mail is off or no credential is made.
func (self *MailClient) ImapAccount() (*MailImapAccount, bool) {
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
	return &MailImapAccount{
		NetworkId:  self.networkId,
		Credential: credential,
		Store:      self.ImapStore,
		Hints:      self.ImapHints,
	}, true
}

// The daemon's IMAP server and its listener (D-MAIL-11): see the file header. Safe for concurrent use.
type DaemonMailImap struct {
	daemon *Daemon
	ctx    context.Context
	login  *MailLocalLogin
	// the hosted networks' accounts; a test stands its own in
	accounts func() []*MailImapAccount
	// held across a whole Start, which reads keychains and binds a port, so two never open two listeners; a lock of
	// its own, never stateLock, since it is held across that I/O
	startLock sync.Mutex

	stateLock sync.Mutex
	listener  *DaemonLocalListener
}

// The daemon's IMAP server, made on first use, listening once Start runs.
func (self *Daemon) MailImap() *DaemonMailImap {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if held, ok := self.mailImap.(*DaemonMailImap); ok {
		return held
	}
	login, _ := NewMailLocalLogin(self.clock, nil)
	held := &DaemonMailImap{daemon: self, ctx: self.ctx, login: login}
	held.accounts = held.hostedAccounts
	self.mailImap = held
	return held
}

// Each hosted network's account, in network order.
func (self *DaemonMailImap) hostedAccounts() []*MailImapAccount {
	accounts := []*MailImapAccount{}
	for _, network := range self.daemon.Sidecars() {
		client, err := network.Sidecar.Mail()
		if err != nil {
			continue
		}
		if account, ok := client.ImapAccount(); ok {
			accounts = append(accounts, account)
		}
	}
	return accounts
}

// The login IMAP checks with, which submission shares (MAIL-M9-01).
func (self *DaemonMailImap) Login() *MailLocalLogin {
	return self.login
}

// The certificate off loopback: the device's, of the first hosted network whose mail serves IMAP, for the local
// address the client reached.
func (self *DaemonMailImap) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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
		if _, ok := client.ImapAccount(); ok {
			return network.Sidecar.TlsDeviceCertificate([]string{addrPort.Addr().Unmap().String()})
		}
	}
	return nil, ErrMailImapNoAccount
}

// Opens IMAP's listener with the daemon's first port and --listen and serves it, once there is an account to serve;
// a second call answers the listener already open. ErrMailImapNoAccount while there is none, which leaves the port
// closed, so a daemon with no IMAP account exposes nothing.
func (self *DaemonMailImap) Start() (*DaemonLocalListenerStatus, error) {
	self.startLock.Lock()
	defer self.startLock.Unlock()
	if listener := self.openListener(); listener != nil {
		status := listener.status()
		return &status, nil
	}
	if len(self.accounts()) == 0 {
		return nil, ErrMailImapNoAccount
	}
	server, err := NewMailImapServer(self.ctx, &MailImapServerArgs{
		Accounts: self.accounts,
		Login:    self.login,
		Clock:    self.daemon.clock,
	})
	if err != nil {
		return nil, err
	}
	listener, err := self.daemon.LocalListen(&DaemonLocalListenArgs{
		Service: DaemonLocalImap,
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
func (self *DaemonMailImap) openListener() *DaemonLocalListener {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listener
}
