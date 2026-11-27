//go:build !sidecar_http && !ios_extension

// §15.5's receiver (R-MAIL-1, R-MAIL-9, D-MAIL-4, I-8, I-14, I-15, I-17, X6, R-CTX-24; MAIL-M7-13): a sidecar with an
// approved listen on sock:smtp/25/mx, which holds its mail host key and ends inbound TLS on this device, never at a
// URnetwork edge.
//
//	listen    one §9 registration, smtp/25/<host> (mx, or mx.<scope> for a Team scope's receiver), protocol
//	          smtp-starttls and max_streams 16, which burners share. Sidecar.Listen goes through §5.4's Authorize
//	          first (I-8), and may answer *ApprovalPendingError: Start answers it to its caller, which surfaces it, and
//	          the receiver asks again every ApprovalRetryInterval until a person's decision lets it through. Under a
//	          requests rule the grant asked lasts ListenExpires, 7 days, held to the rule's maxExpiry, so a person
//	          approves the receiver once a week (owner decision 687). A listen that fails otherwise, or ends, is asked
//	          again after ListenRetryInterval
//	serving   the registration starts not serving, so it takes no ticket, and serves only once a key is live
//	          (mail_receiver_keys.go): a new key never serves before its TLSA is live, so a DANE sender never fails on
//	          a key it cannot match. With no key live it stops serving again, and a stream ticketed before meets a
//	          handshake that fails
//	streams   each admitted stream is held to its ticket first: only a stream whose dialer_network_id is
//	          urnetwork-edge, the router's, comes on (§15.4), and any other is reset as the TLS front resets one
//	          (RST_IDENTITY). Then crypto/tls's handshake within HandshakeTimeout, early data first since the router
//	          sent the ClientHello in StreamOpen, on the served key's certificate, and the session (MAIL-M7-14) runs on
//	          the finished connection
//	cert      {*.<net>.<root>, <net>.<root>} with the alias's pair, covering mx.<net>.<root> and every burner, on the
//	          served key: §13's issued chain once the device holds one on that key, a self-signed leaf until then,
//	          asked again at each handshake so the issued chain follows the self-signed leaf with no gap; while a
//	          rotation keeps an older key serving, the certificate last presented on it, or a self-signed leaf on it
//	retire    once a key serves, a key the receiver neither holds nor serves, a rotation's old key at the swap above
//	          all, has its TLSA retired by a repeat of the served key's post naming it (mail_receiver_keys.go's retire
//	          row; owner decision 443)
//	stop      the listen's end, a revocation's above all (the registrar resets every stream RST_REVOKED and closes the
//	          listener), stops the receiver at once: nothing serves until a listen goes through §5.4's gate again,
//	          which a revoked grant refuses. Server side, the removal drops the receiver's TLSA (DNS-M7-02)
//
// A restore_required answer re-registers the host key (§19.10): Reregister posts each held key's TLSA again, which
// the route takes as a repeat, keeping the times this device recorded, then the served key's again naming every
// retirement the store keeps, since the restored rows may hold a key it retired published again.
//
// A session's RCPT is one of §15.8's forms under the root, or the bounce of a send strict mode moved to a custom
// domain's envelope, bounces+<token>@b.<domain> (QD-1129), which a DSN reaches through the custom MX
// (MailReceiverRecipient); either resolves through the network's mailcfg, and anything else is unknown, 550 5.1.1.
//
// No URnetwork component or evs repo holds the mail host key: the keychain holds it, and only certificates reach a
// handshake and only the TLSA times the component's store. Nothing here logs a host, a name, an address or a key
// (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The socket name a receiver listens on, before its host: §15.5's smtp/25/mx, or a Team scope's smtp/25/mx.<scope>.
const mailReceiverListenPrefix = "smtp/25/"

// The recipient an RCPT's address names under root (see the file header): one of §15.8's forms, or a custom domain's
// bounce, which only a network's own mailcfg holds. False for anything else, which a session answers as an unknown
// address, so the grammar tells a sender nothing a lookup would not.
func MailReceiverRecipient(root string, address string) (MailRecipient, bool) {
	if recipient, err := ParseMailRecipient(root, address); err == nil {
		return recipient, true
	}
	if recipient, err := ParseMailCustomBounceRecipient(root, address); err == nil {
		return recipient, true
	}
	return MailRecipient{}, false
}

var (
	// Start was called on a receiver already started.
	ErrMailReceiverStarted = errors.New("mail receiver: started already")
	// No key is live, so no certificate is presented and no stream is served.
	ErrMailReceiverNotServing = errors.New("mail receiver: no key is live")
	// The receiver was made without what it needs.
	ErrMailReceiverInvalid = errors.New("mail receiver: invalid")
)

// What a receiver is tuned by (§15.5). Every duration and count must be positive, but ListenExpires, which may be 0.
type MailReceiverSettings struct {
	// The registration's max_streams: sessions at once on this receiver (§15.5's 16), which bounds what one
	// receiver's checks and spool hold.
	MaxStreams int
	// How long the grant the listen asks lasts, its SocketListenSettings.Expires (§15.5, §9.9; owner decision 687):
	// 7 days, the longest the implicit document's requests rule gives a tls/ or smtp/ listen, so a receiver under that
	// rule is approved once a week rather than every hour, its expiresDefault. MatchAclRequest holds it to the rule's
	// maxExpiry, refusing a listen past it, so under a document whose rule gives less it must be at most that. 0 asks
	// the rule's expiresDefault. A standing grant passes the listen whatever this asks.
	ListenExpires time.Duration
	// The TTL §12 publishes a receiver key's TLSA with (§15.5's 300 s), which dns.yml's tlsa sets server side.
	TlsaTtl time.Duration
	// The TTLs after its publication at which a key goes live: RFC 7671 §8.1's 2.
	TlsaLiveTtlCount int
	// While the listen waits on a person's decision, how often it is asked again. The gate finds the request it
	// filed, so asking files nothing new.
	ApprovalRetryInterval time.Duration
	// After a listen that failed for another reason, or that ended, the wait before the next.
	ListenRetryInterval time.Duration
	// After a POST /dns/key-record, a key read or a names read that failed, the wait before the next pass: a key's
	// publication and a rotated-out key's retirement alike.
	PublishRetryInterval time.Duration
	// How long a rotated-out key's retirement is kept once the route confirmed it, for a restore's re-registration to
	// name it again (§19.10): a restore brings back any of the 14 daily generations D-OPS-18 keeps, which skipped
	// runs spread over more days, so 30 days.
	RetiredKeyRetention time.Duration
	// With nothing else due, how often the key pass reads the keychain again for a rotation's successor.
	KeyCheckInterval time.Duration
	// A stream's TLS handshake, from its admission: past it the stream closes, so a stalled sender holds none of
	// max_streams' slots.
	HandshakeTimeout time.Duration
}

// The one default: §15.5's numbers.
func DefaultMailReceiverSettings() *MailReceiverSettings {
	return &MailReceiverSettings{
		MaxStreams:            16,
		ListenExpires:         7 * 24 * time.Hour,
		TlsaTtl:               300 * time.Second,
		TlsaLiveTtlCount:      2,
		ApprovalRetryInterval: time.Minute,
		ListenRetryInterval:   30 * time.Second,
		PublishRetryInterval:  30 * time.Second,
		RetiredKeyRetention:   30 * 24 * time.Hour,
		KeyCheckInterval:      10 * time.Minute,
		HandshakeTimeout:      60 * time.Second,
	}
}

// Whether every field is in range.
func (self *MailReceiverSettings) valid() bool {
	return self != nil && 0 < self.MaxStreams && 0 <= self.ListenExpires && 0 < self.TlsaTtl && 0 < self.TlsaLiveTtlCount &&
		0 < self.ApprovalRetryInterval && 0 < self.ListenRetryInterval && 0 < self.PublishRetryInterval &&
		0 < self.RetiredKeyRetention && 0 < self.KeyCheckInterval && 0 < self.HandshakeTimeout
}

// How long after its publication a key goes live.
func (self *MailReceiverSettings) liveDelay() time.Duration {
	return time.Duration(self.TlsaLiveTtlCount) * self.TlsaTtl
}

// What a receiver listens through: Sidecar.Listen's *SocketListener on smtp/25/<host>, or a test's queue.
type MailReceiverListener interface {
	AcceptSocket(ctx context.Context) (*SocketConn, error)
	// §9.9's SetServing: false keeps the lease and takes no tickets.
	SetServing(serving bool)
	Close() error
	// The urnetwork-edge network as the registrar's newest answer names it, which admission's step 3 held the ticket
	// to; false before an answer names it.
	tlsEdgeNetworkId() (Id, bool)
}

// One stream past its handshake, as the session takes it.
type MailReceiverStream struct {
	// The admitted stream, whose ticket and open metadata (MailIngress) the session reads.
	Conn *SocketConn
	// The finished TLS connection over Conn, which the session owns and closes.
	Tls *tls.Conn
	// The SHA-256 of the SPKI the handshake presented: the key whose TLSA sni_tlsa_live asks after (§15.5).
	SpkiSha256 [sha256.Size]byte
}

// What NewMailReceiver builds on.
type MailReceiverArgs struct {
	// mx, or mx.<scope> for a Team scope's receiver, as POST /dns/key-record and smtp/25/<host> name it.
	Host string
	// Sidecar.Listen, through §5.4's gate, which may answer *ApprovalPendingError.
	Listen func(ctx context.Context, address string, settings *SocketListenSettings) (MailReceiverListener, error)
	// The device key and its certificate.
	Keys MailReceiverKeys
	// POST /dns/key-record.
	Publisher MailReceiverKeyPublisher
	// §13.8's identifier set for the network: the names the certificate covers and the TLSA's attestation binds.
	Names func(ctx context.Context) ([]string, error)
	// The mail component's sealed directory, which keeps the TLSA publication times. Nil keeps them in memory only,
	// so a restart publishes again and waits again.
	Store SidecarStore
	// Called once a key serves, so the zone watch holds its TLSA (DnsWatch.WatchMailHost); nil for none.
	Watch func(host string, spkiSha256 []byte)
	// Each stream past its handshake, on its own goroutine, until ctx ends: §15.5's session (MAIL-M7-14), which owns
	// the stream. Nil closes every stream after its handshake.
	Serve func(ctx context.Context, stream *MailReceiverStream)
	// Whether a stream the router ticketed is taken, from its open metadata (the router's MailIngress) and the served
	// key's SPKI SHA-256, before its handshake: strict mode's admission (MailStrictPolicy.AdmitMetadata, MAIL-M7-24).
	// A stream it refuses gets a TLS alert and its end before any SMTP byte, so the sender retries. Nil takes every
	// stream.
	Admit func(ctx context.Context, metadata []byte, spkiSha256 []byte) bool
	// The self-signed leaf's lifetime and backdate (§13.8); nil takes the defaults.
	TlsSettings *SidecarTlsSettings
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailReceiverSettings.
	Settings *MailReceiverSettings
}

// The key a receiver serves and what it presents on it.
type mailReceiverServedKey struct {
	key        *TlsDeviceKey
	spkiSha256 [sha256.Size]byte
	names      []string
	// The certificate last presented on key, which serves on while key is no longer the keychain's current one.
	certificate *tls.Certificate
}

// What a receiver says of itself.
type MailReceiverStatus struct {
	// A registration is held.
	Listening bool
	// A key is live, so the registration takes tickets.
	Serving bool
	// The listen waits on this approval (§5.4), nil when it does not.
	ApprovalId *Id
	// The SHA-256 of the served key's SPKI, nil while none serves.
	SpkiSha256 []byte
	// Why the last listen or key pass failed, empty when it did not. Names no host or key (I-13).
	Problem string
}

// §15.5's receiver. See the file header.
type MailReceiver struct {
	// The direct-MX listener shares the lifetime of the approved registration.
	runDirect func(context.Context)
	// Closed after the registration, key worker and every registered or direct session have exited.
	done        chan struct{}
	args        *MailReceiverArgs
	settings    *MailReceiverSettings
	tlsSettings *SidecarTlsSettings
	clock       Clock
	log         Logger
	tlsConfig   *tls.Config
	// asks the key pass to run now: a rotation, a restore's re-registration
	keyWake chan struct{}

	// held across a key pass, which reads and writes tlsa
	passLock sync.Mutex
	tlsa     *mailReceiverTlsaRecords

	stateLock  sync.Mutex
	started    bool
	listener   MailReceiverListener
	served     *mailReceiverServedKey
	approvalId *Id
	problem    string
}

// A receiver of args.Host, which does nothing until Start.
func NewMailReceiver(args *MailReceiverArgs) (*MailReceiver, error) {
	switch {
	case args == nil:
		return nil, fmt.Errorf("%w: no args", ErrMailReceiverInvalid)
	case args.Listen == nil || args.Keys == nil || args.Publisher == nil || args.Names == nil:
		return nil, fmt.Errorf("%w: a receiver needs its listen, keys, publisher and names", ErrMailReceiverInvalid)
	case !isDnsWatchMailHost(args.Host):
		return nil, fmt.Errorf("%w: a receiver's host is mx or mx.<scope>", ErrMailReceiverInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailReceiverSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: settings out of range", ErrMailReceiverInvalid)
	}
	tlsSettings := args.TlsSettings
	if tlsSettings == nil {
		tlsSettings = DefaultSidecarTlsSettings()
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	self := &MailReceiver{
		done:        make(chan struct{}),
		args:        args,
		settings:    settings,
		tlsSettings: tlsSettings,
		clock:       clockOrReal(args.Clock),
		log:         log,
		keyWake:     make(chan struct{}, 1),
		tlsa:        newMailReceiverTlsaRecords(args.Store, args.Host),
	}
	self.tlsConfig = self.newTlsConfig(nil)
	return self, nil
}

// The configuration a receiver's handshakes run on: the served key's certificate, chosen at each handshake (see the
// file header). TLS 1.2 or 1.3, since senders still offer 1.2 (RFC 8314 has submission, not relay, require more).
// A copy each call, sharing nothing the caller may change.
func (self *MailReceiver) TlsConfig() *tls.Config {
	return self.tlsConfig.Clone()
}

// A configuration whose GetCertificate presents the served key's certificate, noting the key in presented when it is
// not nil.
func (self *MailReceiver) newTlsConfig(presented *mailReceiverServedKey) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// each receiver holds its own ticket keys and senders reconnect seldom, so a ticket would buy nothing
		SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certificate, served, err := self.certificate()
			if err != nil {
				return nil, err
			}
			if presented != nil {
				*presented = *served
			}
			return certificate, nil
		},
	}
}

// What the receiver presents now, and the key it is on: see the file header's cert row.
func (self *MailReceiver) certificate() (*tls.Certificate, *mailReceiverServedKey, error) {
	served := func() *mailReceiverServedKey {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.served == nil {
			return nil
		}
		copied := *self.served
		return &copied
	}()
	if served == nil {
		return nil, nil, ErrMailReceiverNotServing
	}
	now := self.clock.Now()
	// the device's own on its current key: §13's issued chain, or the self-signed leaf, when that key is the served one
	if certificate, err := self.args.Keys.TlsDeviceCertificate(served.names); err == nil {
		if spkiSha256, ok := mailCertificateSpkiSha256(certificate); ok && spkiSha256 == served.spkiSha256 {
			self.keepCertificate(served.spkiSha256, certificate)
			served.certificate = certificate
			return certificate, served, nil
		}
	}
	// the keychain moved on to a successor whose TLSA is not live yet: the served key's last certificate, while valid
	if served.certificate != nil && mailCertificateValidAt(served.certificate, now) {
		return served.certificate, served, nil
	}
	leaf, err := newTlsSelfSignedCertificate(served.key, served.names, now, self.tlsSettings)
	if err != nil {
		return nil, nil, err
	}
	self.keepCertificate(served.spkiSha256, leaf)
	served.certificate = leaf
	return leaf, served, nil
}

// Keeps certificate as the last presented on the served key, if that key still serves.
func (self *MailReceiver) keepCertificate(spkiSha256 [sha256.Size]byte, certificate *tls.Certificate) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.served != nil && self.served.spkiSha256 == spkiSha256 {
		self.served.certificate = certificate
	}
}

// What the receiver says of itself now.
func (self *MailReceiver) Status() MailReceiverStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := MailReceiverStatus{
		Listening: self.listener != nil,
		Serving:   self.served != nil,
		Problem:   self.problem,
	}
	if self.approvalId != nil {
		approvalId := *self.approvalId
		status.ApprovalId = &approvalId
	}
	if self.served != nil {
		status.SpkiSha256 = bytes.Clone(self.served.spkiSha256[:])
	}
	return status
}

// Starts the receiver on ctx, which ends it: one listen through §5.4's gate now, then the receiver's loop, which
// serves while a key is live and asks again for a listen that waits, fails or ends. Answers the first listen's
// error: nil once it holds the registration, *ApprovalPendingError while a person's decision is awaited, which the
// caller surfaces while the loop asks again. A second Start refuses.
func (self *MailReceiver) Start(ctx context.Context) error {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.started {
			return false
		}
		self.started = true
		return true
	}()
	if !first {
		return ErrMailReceiverStarted
	}
	listener, err := self.listen(ctx)
	go self.run(ctx, listener, err)
	return err
}

// One listen on smtp/25/<host>, its outcome kept for Status.
func (self *MailReceiver) listen(ctx context.Context) (MailReceiverListener, error) {
	listener, err := self.args.Listen(ctx, mailReceiverListenPrefix+self.args.Host, &SocketListenSettings{
		Protocol:   socketListenSmtpProtocol,
		MaxStreams: self.settings.MaxStreams,
		Expires:    self.settings.ListenExpires,
	})
	if err == nil && listener == nil {
		err = fmt.Errorf("%w: the listen answered no listener", ErrMailReceiverInvalid)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.approvalId = nil
		self.problem = ""
		var pending *ApprovalPendingError
		switch {
		case errors.As(err, &pending):
			approvalId := pending.ApprovalId
			self.approvalId = &approvalId
		case err != nil:
			self.problem = "listen: " + err.Error()
		}
	}()
	if err != nil {
		return nil, err
	}
	return listener, nil
}

// The receiver's loop: serves each listen until it ends, and asks again for one that waits, fails or ends.
func (self *MailReceiver) run(ctx context.Context, listener MailReceiverListener, listenErr error) {
	defer close(self.done)
	for {
		if listener != nil {
			self.serveListener(ctx, listener)
			listener = nil
			listenErr = nil
		}
		wait := self.settings.ListenRetryInterval
		var pending *ApprovalPendingError
		if errors.As(listenErr, &pending) {
			wait = self.settings.ApprovalRetryInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(wait):
		}
		listener, listenErr = self.listen(ctx)
	}
}

// Serves listener until it ends or ctx does: the key pass beside the accept loop, each stream on its own goroutine,
// all of them joined before it returns.
func (self *MailReceiver) serveListener(ctx context.Context, listener MailReceiverListener) {
	listenCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.listener = listener
	}()
	var group sync.WaitGroup
	group.Go(func() {
		self.runKeys(listenCtx, listener)
	})
	if self.runDirect != nil {
		group.Go(func() { self.runDirect(listenCtx) })
	}
	for {
		conn, err := listener.AcceptSocket(listenCtx)
		if err != nil {
			break
		}
		group.Go(func() {
			self.serve(listenCtx, listener, conn)
		})
	}
	// the listen ended, a revocation's included: nothing serves from here (the file header's stop row)
	cancel()
	listener.Close()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.listener = nil
		self.served = nil
	}()
	group.Wait()
	if ctx.Err() == nil {
		self.log.Infof("[mail]the receiver's listen ended; it serves nothing until a listen goes through again")
	}
}

// One admitted stream: its ticket held to the edge, its handshake within HandshakeTimeout, then the session.
func (self *MailReceiver) serve(ctx context.Context, listener MailReceiverListener, conn *SocketConn) {
	edgeNetworkId, known := listener.tlsEdgeNetworkId()
	ticket := conn.Ticket()
	if !known || ticket == nil || !bytes.Equal(ticket.GetDialerNetworkId(), edgeNetworkId.Bytes()) {
		// only the router dials a receiver, and its open metadata is trusted only from it (§15.4)
		conn.reset(protocol.StreamResetCode_RST_IDENTITY)
		return
	}
	if self.args.Admit != nil {
		served := func() []byte {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.served == nil {
				return nil
			}
			return bytes.Clone(self.served.spkiSha256[:])
		}()
		if !self.args.Admit(ctx, conn.OpenMetadata(), served) {
			// before any SMTP byte: a fatal alert and the stream's end, a temporary failure the sender retries
			conn.Write(mailStrictRefusalAlert)
			conn.Close()
			return
		}
	}
	presented := &mailReceiverServedKey{}
	tlsConn := tls.Server(conn, self.newTlsConfig(presented))
	handshakeErr := func() error {
		handshakeCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := self.clock.AfterFunc(self.settings.HandshakeTimeout, cancel)
		defer stop()
		return tlsConn.HandshakeContext(handshakeCtx)
	}()
	if handshakeErr != nil {
		tlsConn.Close()
		return
	}
	if self.args.Serve == nil {
		tlsConn.Close()
		return
	}
	// a stream outlives no listen: its end closes the session's connection
	stop := context.AfterFunc(ctx, func() {
		tlsConn.Close()
	})
	defer stop()
	self.args.Serve(ctx, &MailReceiverStream{Conn: conn, Tls: tlsConn, SpkiSha256: presented.spkiSha256})
}

// Asks the key pass to run now.
func (self *MailReceiver) wakeKeys() {
	select {
	case self.keyWake <- struct{}{}:
	default:
	}
}

// The key pass, until ctx ends: at once, then when its pass says, or when woken. The pass's wait runs from its end,
// cut at the time a key's TLSA goes live, which is waited for itself (QD-1425).
func (self *MailReceiver) runKeys(ctx context.Context, listener MailReceiverListener) {
	for {
		wait, liveAt := self.keyPass(ctx, listener, false)
		passAt := self.clock.Now().Add(wait)
		if !liveAt.IsZero() && liveAt.Before(passAt) {
			passAt = liveAt
		}
		select {
		case <-ctx.Done():
			return
		case <-ClockAfterAt(self.clock, passAt):
		case <-self.keyWake:
		}
	}
}

// One key pass (mail_receiver_keys.go's file header): publishes what lacks a TLSA, decides the key to serve and sets
// serving to match, rotates out what is neither held nor served and, once a key serves, retires the TLSA of what was
// rotated out, and answers when the next pass is due: a wait from the pass's end, and the time a key's TLSA goes live
// where one is still to, zero for none. With republish, each held key is posted again whatever its record says, as a
// restore asks, keeping the times recorded, and the retirement names every one kept.
func (self *MailReceiver) keyPass(ctx context.Context, listener MailReceiverListener, republish bool) (time.Duration, time.Time) {
	self.passLock.Lock()
	defer self.passLock.Unlock()
	nextWait := self.settings.KeyCheckInterval
	var liveAt time.Time
	problem := ""
	fail := func(what string, err error) {
		if problem == "" {
			problem = what + ": " + err.Error()
		}
		nextWait = min(nextWait, self.settings.PublishRetryInterval)
	}
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.problem = problem
	}()

	if err := self.tlsa.load(); err != nil {
		// unread records publish nothing and serve nothing new, never a key taken as live that is not
		fail("tlsa records", err)
		return nextWait, liveAt
	}
	names, err := self.args.Names(ctx)
	if err != nil {
		fail("names", err)
		return nextWait, liveAt
	}
	current, pending, err := self.args.Keys.TlsKeys()
	if err != nil || current == nil {
		if err == nil {
			err = ErrMailReceiverKeys
		}
		// a locked keychain changes nothing served: the served key is held in memory, and nothing new is published
		fail("keys", err)
		return nextWait, liveAt
	}
	for _, key := range []*TlsDeviceKey{current, pending} {
		if key == nil {
			continue
		}
		_, published := self.tlsa.publishTime(key)
		if published && !republish {
			continue
		}
		testHookBarrier("mail.receiver.publish.before", "")
		err := self.args.Publisher.PublishKeyRecord(ctx, self.args.Host, key, names, nil)
		testHookBarrier("mail.receiver.publish.after", "")
		if err != nil {
			fail("key record", err)
			continue
		}
		if published {
			continue
		}
		if err := self.tlsa.put(key, self.clock.Now()); err != nil {
			fail("tlsa records", err)
		}
	}

	now := self.clock.Now()
	keyLiveAt := func(key *TlsDeviceKey) (time.Time, bool) {
		publishTime, ok := self.tlsa.publishTime(key)
		if !ok {
			return time.Time{}, false
		}
		return publishTime.Add(self.settings.liveDelay()), true
	}
	soonestLive := func(at time.Time) {
		if liveAt.IsZero() || at.Before(liveAt) {
			liveAt = at
		}
	}
	var serve *TlsDeviceKey
	if at, ok := keyLiveAt(current); ok {
		if now.Before(at) {
			soonestLive(at)
		} else {
			serve = current
		}
	}
	served := func() *TlsDeviceKey {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.served == nil {
			return nil
		}
		return self.served.key
	}()
	if serve == nil && served != nil {
		// the key served before serves on while its successor's TLSA is not live yet
		if at, ok := keyLiveAt(served); ok && !now.Before(at) {
			serve = served
		}
	}
	if pending != nil {
		if at, ok := keyLiveAt(pending); ok && now.Before(at) {
			soonestLive(at)
		}
	}
	self.setServed(listener, serve, names)
	if err := self.tlsa.rotateOut(current, pending, serve); err != nil {
		fail("tlsa records", err)
	}
	if err := self.tlsa.forgetRetired(now, self.settings.RetiredKeyRetention); err != nil {
		fail("tlsa records", err)
	}
	// once a key serves, a repeat of its post retires what was rotated out: at a rotation the old key, from the swap
	// on and never while it serves; a restore names every retirement kept (mail_receiver_keys.go's retire row)
	if serve != nil {
		if retire := self.tlsa.retireList(republish); 0 < len(retire) {
			testHookBarrier("mail.receiver.retire.before", "")
			err := self.args.Publisher.PublishKeyRecord(ctx, self.args.Host, serve, names, retire)
			testHookBarrier("mail.receiver.retire.after", "")
			if err != nil {
				// tried again with the next pass's writes, after PublishRetryInterval
				fail("key record", err)
			} else if err := self.tlsa.confirmRetired(retire, self.clock.Now()); err != nil {
				fail("tlsa records", err)
			}
		}
	}
	return max(nextWait, 0), liveAt
}

// Serves key on names, nil serving none, and sets the registration's serving to match.
func (self *MailReceiver) setServed(listener MailReceiverListener, key *TlsDeviceKey, names []string) {
	changed := false
	var spkiSha256 [sha256.Size]byte
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if key == nil {
			changed = self.served != nil
			self.served = nil
			return
		}
		spkiSha256 = key.SpkiSha256()
		if self.served != nil && self.served.spkiSha256 == spkiSha256 {
			if !slices.Equal(self.served.names, names) {
				// new names take a new certificate
				self.served.names = append([]string(nil), names...)
				self.served.certificate = nil
			}
			return
		}
		changed = true
		self.served = &mailReceiverServedKey{key: key, spkiSha256: spkiSha256, names: append([]string(nil), names...)}
	}()
	listener.SetServing(key != nil)
	if changed && key != nil && self.args.Watch != nil {
		self.args.Watch(self.args.Host, spkiSha256[:])
	}
}

// restore_required's step for the receiver (§19.10): posts each held key's TLSA again, which the route takes as a
// repeat of what it holds, then serves as the key pass decides and, once a key serves, posts it again naming every
// retirement kept, so a key the restored rows hold published again leaves TLSA. Nil when no listen is held, since the
// next listen's pass publishes what lacks a record.
func (self *MailReceiver) Reregister(ctx context.Context) error {
	listener := func() MailReceiverListener {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.listener
	}()
	if listener == nil {
		return nil
	}
	self.keyPass(ctx, listener, true)
	problem := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.problem
	}()
	if problem != "" {
		return fmt.Errorf("mail receiver: %s", problem)
	}
	return nil
}
