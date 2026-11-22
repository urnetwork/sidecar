//go:build !sidecar_http && !js && !ios_extension

// §15.5's session (R-MAIL-1, R-MAIL-2, R-MAIL-12, R-MAIL-13, D-MAIL-3, D-MAIL-5, D-MAIL-14, D-KEYS-17, FS-23, FS-121,
// I-2, I-5, X6, R-CTX-24; MAIL-M7-14): one sender's SMTP over one stream the receiver admitted from the router and
// handshook (mail_receiver.go).
//
//	ingress   MailIngress from StreamOpen.metadata, trusted only because the receiver held the ticket's
//	          dialer_network_id to urnetwork-edge; one past IngressMaxByteCount, that does not parse or of a version
//	          this build does not know closes the stream, since the router always sends one
//	smtp      go-smtp's fork through mailSmtpServe, with no second 220 (RFC 3207 §4.2): EHLO advertises SIZE at
//	          mail_inbound_message_bytes, 8BITMIME, SMTPUTF8, PIPELINING, CHUNKING, ENHANCEDSTATUSCODES and REQUIRETLS,
//	          and no AUTH, the backend being no AuthSession; MaxRecipients stays 0, so no LIMITS, and RCPT counts on its
//	          own (QD-543). MaxLineLength rises past any command to LineMaxByteCount, since go-smtp holds DATA's lines
//	          to it too and long-line mail would fail
//	limits    GET /sidecar/limits' mail_inbound_message_bytes, mail_inbound_recipients and
//	          mail_inbound_repos_per_message, read at most each LimitsInterval at EHLO; a limit not there to read, or
//	          not above 0, answers the EHLO 451 4.3.0, never an unbounded SIZE. They hold whatever the answer's
//	          enforced says, as the closure floor and pacing do, unlike the other local pre-checks (owner decision
//	          520; QD-1023): they size a session rather than refuse a creation, read as none while dark they would
//	          refuse every EHLO, and mxedge cuts each splice at the same message cap whatever the switch
//	mail      MAIL follows the handshake within MailTimeout (60 s), or the stream closes
//	bare      RFC 5321's bare RCPT TO:<Postmaster>, which go-smtp's fork hands Rcpt as postmaster alone
//	          (MailSmtpBarePostmaster), is postmaster at the domain the session serves before mailcfg's rules (owner
//	          decision 446): the domain of the MX host the sender reached, its SNI less the host's first label, or with
//	          no SNI the receiver's own zone (PostmasterDomain). Every answer below is then the full address's
//	rcpt      §15.8's grammar and the signed mailcfg (MailConfig.Resolve): unknown, burned or paused 550 5.1.1; GET
//	          /mail/status's storage_full, read at most each StatusInterval, 452 4.2.2; past mail_inbound_recipients
//	          452 4.5.3; a repo past mail_inbound_repos_per_message 452 4.5.3 (QD-208), a group counting once;
//	          mailcfg not synced, or a lookup that failed, 451 4.3.0, never 550
//	data      DATA and BDAT stream into the spool (mail_spool.go) ChunkByteCount at a time, hashed as they arrive. At
//	          the last byte one of the receiver's check slots takes the message (MailAuthSlots), whose 30 s start then,
//	          and the evidence is sealed (MailEvidenceBuilder); then one deposit a repo (mail_deposit.go)
//	reply     250 only once evs confirmed every deposit; 451 4.3.0 for any failure, within the depositor's
//	          DepositTimeout, and at DATA's start, before the body is spooled or checked, where this receiver's own
//	          verified state gives it no deposit into a recipient's repo (MailDepositor.Refuses). Accepted mail never
//	          bounces, and no authentication result refuses it: a check that fails or is cut deposits as no result. A
//	          reset (RFC 5321 §3.8), RSET mid-BDAT's ErrDataReset or the connection's end, discards everything, and
//	          nothing commits
//
// Every reply's text is fixed: no lookup's error, address or name reaches the sender, and nothing here logs one
// (I-13). go-smtp's Debug stays nil and its ErrorLog writes nothing, since either would carry a session's text. One
// go-smtp server a session, so its limits are that session's. The server is safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-smtp"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// GET /sidecar/limits' keys a receiver applies (§20.4).
const (
	mailLimitInboundMessageBytes    = "mail_inbound_message_bytes"
	mailLimitInboundRecipients      = "mail_inbound_recipients"
	mailLimitInboundReposPerMessage = "mail_inbound_repos_per_message"
)

// A MailIngress that is not the router's: past its bound, not a MailIngress, or of a version this build does not
// know.
var ErrMailIngressInvalid = errors.New("mail ingress invalid")

// MailIngress from a stream's open metadata, held to bound, its version and its fields' shapes: sender_ip 4 or 16
// bytes, sender_port a port.
func ParseMailIngress(metadata []byte, maxByteCount int) (*protocol.MailIngress, error) {
	if len(metadata) == 0 || maxByteCount < len(metadata) {
		return nil, fmt.Errorf("%w: none, or past its bound", ErrMailIngressInvalid)
	}
	ingress := &protocol.MailIngress{}
	if err := proto.Unmarshal(metadata, ingress); err != nil {
		return nil, fmt.Errorf("%w: it does not decode", ErrMailIngressInvalid)
	}
	if ingress.GetVersion() != mailFormatVersion {
		return nil, fmt.Errorf("%w: version %d", ErrMailIngressInvalid, ingress.GetVersion())
	}
	if senderIpByteCount := len(ingress.GetSenderIp()); senderIpByteCount != 4 && senderIpByteCount != 16 {
		return nil, fmt.Errorf("%w: sender_ip's size", ErrMailIngressInvalid)
	}
	if 65535 < ingress.GetSenderPort() {
		return nil, fmt.Errorf("%w: sender_port", ErrMailIngressInvalid)
	}
	return ingress, nil
}

// What an RCPT's address resolves to.
type MailSessionRecipient struct {
	// Whether mail for it is taken; unknown, burned and paused all read false.
	Known bool
	// The address as mailcfg spells it, which the deposit's trailer names.
	Address string
	// The repo its mail goes to: a mailbox or a group's repo.
	RepoId Id
}

// What NewMailSessionServer builds on.
type MailSessionArgs struct {
	// The production receiver's signed mailbox configuration. Other hosts can supply Resolve.
	mailConfig *MailConfig
	// This receiver, which every deposit names.
	ReceiverSidecarId Id
	// An RCPT's address: §15.8's grammar, then mailcfg (MailConfig.Resolve). An error is temporary: mailcfg not
	// synced, or a read that failed.
	Resolve func(ctx context.Context, address string) (*MailSessionRecipient, error)
	// The domain whose postmaster a bare RCPT TO:<Postmaster> names in a session whose SNI names no MX host, as a
	// direct-MX sender may send none: this receiver's own zone, <net>.<root>, or a scope receiver's
	// <scope>.<net>.<root> (owner decision 446). An error is temporary, as Resolve's is. Nil, or an empty answer,
	// leaves such a bare postmaster unknown (550 5.1.1).
	PostmasterDomain func(ctx context.Context) (string, error)
	// GET /mail/status (SidecarApi.MailStatus).
	Status func(ctx context.Context) (*MailNetworkStatus, error)
	// GET /sidecar/limits (SidecarApi.Limits).
	Limits func(ctx context.Context) (*QuotaLimits, error)
	// The reception-time checks and their slots; a nil checker deposits every message with no evidence, as
	// "evidence unavailable".
	Checker *MailAuthChecker
	Slots   *MailAuthSlots
	// The deposits.
	Depositor *MailDepositor
	// The mail component's sealed directory, under whose spool/ each message waits.
	SpoolStore SidecarStore
	// §15.5's strict_chain for a spliced session's message (MailStrictPolicy.StrictChain, MAIL-M7-24): the SNI, the
	// recipients' domains and the presented key. Nil seals none, and no direct-MX session asks it.
	StrictChain func(ctx context.Context, sniHost string, recipientDomains []string, spkiSha256 []byte) bool
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailSessionSettings.
	Settings *MailSessionSettings
}

// The limits a session runs under, from GET /sidecar/limits.
type mailSessionLimits struct {
	messageByteCount int64
	recipientCount   int
	repoCount        int
}

// A receiver's sessions. See the file header.
type MailSessionServer struct {
	args     *MailSessionArgs
	settings *MailSessionSettings
	evidence *MailEvidenceBuilder
	clock    Clock
	log      Logger

	stateLock  sync.Mutex
	limits     *mailSessionLimits
	limitsTime time.Time

	statusLock sync.Mutex
	status     *MailNetworkStatus
	statusTime time.Time
	statusErr  error
}

// A server of sessions over args. Any spool a crash left is swept first.
func NewMailSessionServer(args *MailSessionArgs) (*MailSessionServer, error) {
	if args == nil || (args.Resolve == nil && args.mailConfig == nil) || args.Limits == nil || args.Depositor == nil || args.SpoolStore == nil {
		return nil, fmt.Errorf("%w: a session needs its resolver, limits, depositor and spool", ErrMailReceiverInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailSessionSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: session settings out of range", ErrMailReceiverInvalid)
	}
	if args.Checker != nil && args.Slots == nil {
		return nil, fmt.Errorf("%w: checks with no slots", ErrMailReceiverInvalid)
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	if err := sweepMailSpools(args.SpoolStore); err != nil {
		log.Warningf("[mail]a spool a crash left was not swept: %v", err)
	}
	return &MailSessionServer{
		args:     args,
		settings: settings,
		evidence: NewMailEvidenceBuilder(args.ReceiverSidecarId),
		clock:    clockOrReal(args.Clock),
		log:      log,
	}, nil
}

// GET /sidecar/limits' receiver keys, read again once LimitsInterval has passed; an error when not there to read or
// not above 0.
func (self *MailSessionServer) sessionLimits(ctx context.Context) (*mailSessionLimits, error) {
	now := self.clock.Now()
	held := func() *mailSessionLimits {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.limits != nil && now.Sub(self.limitsTime) < self.settings.LimitsInterval {
			return self.limits
		}
		return nil
	}()
	if held != nil {
		return held, nil
	}
	quotaLimits, err := self.args.Limits(ctx)
	if err != nil {
		return nil, err
	}
	limits := &mailSessionLimits{
		messageByteCount: quotaLimits.Limits[mailLimitInboundMessageBytes],
		recipientCount:   int(quotaLimits.Limits[mailLimitInboundRecipients]),
		repoCount:        int(quotaLimits.Limits[mailLimitInboundReposPerMessage]),
	}
	// a key the answer lacks reads 0, not included, and -1 none, neither of which bounds a message: refused
	if limits.messageByteCount <= 0 || limits.recipientCount <= 0 || limits.repoCount <= 0 {
		return nil, errors.New("mail limits not there to read")
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.limits = limits
		self.limitsTime = now
	}()
	return limits, nil
}

// The last status within StatusInterval. On a refresh error the previous value is returned with the error so
// storage pressure can still defer, while domain ownership requires a fresh successful read.
func (self *MailSessionServer) networkStatus(ctx context.Context) (*MailNetworkStatus, error) {
	if self.args.Status == nil {
		return nil, ErrMailUnbound
	}
	// One shared read per interval, even when multiple listeners begin new transactions together.
	self.statusLock.Lock()
	defer self.statusLock.Unlock()
	if err := ctx.Err(); err != nil {
		return self.status, err
	}
	now := self.clock.Now()
	if !self.statusTime.IsZero() && now.Sub(self.statusTime) < self.settings.StatusInterval {
		return self.status, self.statusErr
	}
	status, err := self.args.Status(ctx)
	if err == nil && status == nil {
		err = ErrMailUnbound
	}
	if err == nil {
		self.status = status
	}
	if ctx.Err() == nil {
		self.statusTime, self.statusErr = now, err
	}
	return self.status, err
}

// A failed refresh preserves the last storage pressure reading. EVS still enforces its deposit limit.
func (self *MailSessionServer) storageFull(ctx context.Context) bool {
	status, _ := self.networkStatus(ctx)
	return status != nil && status.StorageFull
}

// Resolves customer aliases through the same signed record and policy as the network's own alias. The envelope
// keeps the customer's address so the strict-chain check and sealed evidence use the domain the sender selected.
func (self *MailSessionServer) resolve(ctx context.Context, address string) (*MailSessionRecipient, error) {
	config := self.args.mailConfig
	if config == nil {
		return self.args.Resolve(ctx, address)
	}
	zone, _, err := config.zone()
	if err != nil {
		return nil, err
	}
	recipient, knownForm := MailReceiverRecipient(zone.Root, address)
	envelope := recipient.Address()
	if !knownForm {
		custom, domain, ok := mailCustomAddress(zone, address)
		if !ok {
			return &MailSessionRecipient{}, nil
		}
		status, err := self.networkStatus(ctx)
		if err != nil {
			return nil, err
		}
		verified := status.VerifiedDomains
		if verified == nil {
			// An older API only reports the verified domains that have a strict MX host.
			verified = status.StrictDomains
		}
		if !slices.Contains(verified, domain) {
			return &MailSessionRecipient{}, nil
		}
		recipient = custom
		envelope = custom.LocalPart + "@" + domain
	}
	lookup, err := config.Resolve(ctx, recipient)
	if err != nil {
		return nil, err
	}
	return &MailSessionRecipient{Known: lookup.Known, Address: envelope, RepoId: lookup.MailboxRepoId}, nil
}

// The replies a session gives. Fixed texts: nothing a lookup said reaches a sender.
var (
	mailSessionReplyUnknown       = &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "No such recipient here"}
	mailSessionReplyFull          = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 2, 2}, Message: "Mailbox full, try again later"}
	mailSessionReplyTooMany       = &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients, send the rest later"}
	mailSessionReplyTryLater      = &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary failure, try again later"}
	mailSessionReplyNoTransaction = &smtp.SMTPError{Code: 503, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "Bad sequence of commands"}
)

// One stream's session, past its handshake: MailReceiverArgs.Serve. Returns when the session ends, with the stream
// closed.
func (self *MailSessionServer) Serve(ctx context.Context, stream *MailReceiverStream) {
	defer stream.Tls.Close()
	ingress, err := ParseMailIngress(stream.Conn.OpenMetadata(), self.settings.IngressMaxByteCount)
	if err != nil {
		// the router always sends one, so a stream without is no sender's
		return
	}
	self.serveSession(ctx, stream, ingress, false)
}

// One direct-MX session past its handshake (MailDirectListener, mail_direct.go): tlsConn on the key whose SPKI
// SHA-256 is spkiSha256, with the MailIngress the listener built of its own connection. The same session and deposit
// as a spliced stream's. Returns when the session ends, with the connection closed.
func (self *MailSessionServer) ServeDirect(ctx context.Context, tlsConn *tls.Conn, spkiSha256 [sha256.Size]byte, ingress *protocol.MailIngress) {
	defer tlsConn.Close()
	if ingress == nil || ingress.GetVersion() != mailFormatVersion {
		return
	}
	self.serveSession(ctx, &MailReceiverStream{Tls: tlsConn, SpkiSha256: spkiSha256}, ingress, true)
}

// One session over stream, its ingress read already; direct for a direct-MX session, which never seals strict_chain.
func (self *MailSessionServer) serveSession(ctx context.Context, stream *MailReceiverStream, ingress *protocol.MailIngress, direct bool) {
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	closeStream := func() {
		cancel()
		stream.Tls.Close()
	}
	stopSession := self.clock.AfterFunc(self.settings.SessionTimeout, closeStream)
	defer stopSession()
	session := &MailSession{
		server:  self,
		ctx:     sessionCtx,
		stream:  stream,
		ingress: ingress,
		direct:  direct,
	}
	session.stopMailTimer = self.clock.AfterFunc(self.settings.MailTimeout, closeStream)
	defer session.stopMailTimer()

	server := smtp.NewServer(&mailSessionBackend{session: session})
	server.MaxRecipients = 0
	server.MaxLineLength = self.settings.LineMaxByteCount
	server.EnableSMTPUTF8 = true
	server.EnableREQUIRETLS = true
	server.Debug = nil
	server.ErrorLog = log.New(io.Discard, "", 0)
	// waits are on the receiver's clock, never a socket's own deadline
	server.ReadTimeout = 0
	server.WriteTimeout = 0
	session.smtpServer = server
	if err := mailSmtpServe(server, stream.Tls); err != nil && !errors.Is(err, smtp.ErrServerClosed) && self.log.V(2).Enabled() {
		self.log.Infof("[mail]a session ended: %T", err)
	}
}

// go-smtp's backend for one session.
type mailSessionBackend struct {
	session *MailSession
}

// At EHLO or HELO: the session, once its limits are there to read, which set SIZE before EHLO's answer lists it.
func (self *mailSessionBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	session := self.session
	limits, err := session.server.sessionLimits(session.ctx)
	if err != nil {
		return nil, mailSessionReplyTryLater
	}
	session.conn = conn
	session.limits = limits
	session.smtpServer.MaxMessageBytes = limits.messageByteCount
	return session, nil
}

// One sender's SMTP on one stream (smtp.Session). go-smtp calls it from the connection's goroutine, and a BDAT's Data
// from a goroutine of its own, which the fork's reset waits out (third_party/go-smtp/URNETWORK.md); the transaction
// sits under its own lock all the same, since Close may call Logout from another goroutine, and Data works on a copy.
type MailSession struct {
	server  *MailSessionServer
	ctx     context.Context
	stream  *MailReceiverStream
	ingress *protocol.MailIngress
	// a direct-MX session (MailDirectListener), which never seals strict_chain
	direct        bool
	smtpServer    *smtp.Server
	conn          *smtp.Conn
	limits        *mailSessionLimits
	stopMailTimer func() bool

	stateLock   sync.Mutex
	transaction mailSessionTransaction
}

// One transaction: MAIL taken, its reverse path and options, and the recipients by repo in the order first named.
type mailSessionTransaction struct {
	mailTaken      bool
	mailFrom       string
	requireTls     bool
	smtpUtf8       bool
	targets        []*MailDepositTarget
	recipientCount int
}

// A copy that shares nothing with the session's.
func (self mailSessionTransaction) clone() mailSessionTransaction {
	copied := self
	copied.targets = make([]*MailDepositTarget, 0, len(self.targets))
	for _, target := range self.targets {
		copied.targets = append(copied.targets, &MailDepositTarget{RepoId: target.RepoId, Recipients: append([]string(nil), target.Recipients...)})
	}
	return copied
}

// See smtp.Session: the transaction's state goes.
func (self *MailSession) Reset() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.transaction = mailSessionTransaction{}
}

// See smtp.Session.
func (self *MailSession) Logout() error {
	self.Reset()
	return nil
}

// A transaction begins: the reverse path and REQUIRETLS kept for the trailer, SMTPUTF8 for the checks.
func (self *MailSession) Mail(from string, options *smtp.MailOptions) error {
	self.stopMailTimer()
	transaction := mailSessionTransaction{mailTaken: true, mailFrom: from}
	if options != nil {
		transaction.requireTls = options.RequireTLS
		transaction.smtpUtf8 = options.UTF8
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.transaction = transaction
	return nil
}

// See the file header's bare and rcpt rows. The two checks before the bare form's mapping read no address, so the
// bare form meets them as the full address does.
func (self *MailSession) Rcpt(to string, options *smtp.RcptOptions) error {
	mailTaken, recipientCount := func() (bool, int) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.transaction.mailTaken, self.transaction.recipientCount
	}()
	if !mailTaken {
		return mailSessionReplyNoTransaction
	}
	if self.limits.recipientCount <= recipientCount {
		return mailSessionReplyTooMany
	}
	address := to
	if to == MailSmtpBarePostmaster {
		domain, err := self.postmasterDomain()
		if err != nil {
			return mailSessionReplyTryLater
		}
		if domain == "" {
			return mailSessionReplyUnknown
		}
		address = MailSmtpBarePostmaster + "@" + domain
	}
	recipient, err := self.server.resolve(self.ctx, address)
	if err != nil {
		return mailSessionReplyTryLater
	}
	if recipient == nil || !recipient.Known {
		return mailSessionReplyUnknown
	}
	if self.server.storageFull(self.ctx) {
		return mailSessionReplyFull
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transaction := &self.transaction
	var target *MailDepositTarget
	for _, held := range transaction.targets {
		if held.RepoId == recipient.RepoId {
			target = held
			break
		}
	}
	if target == nil {
		if self.limits.repoCount <= len(transaction.targets) {
			// a repo past the bound waits for a later transaction, which bounds a retry's duplicates (QD-208)
			return mailSessionReplyTooMany
		}
		target = &MailDepositTarget{RepoId: recipient.RepoId}
		transaction.targets = append(transaction.targets, target)
	}
	target.Recipients = append(target.Recipients, recipient.Address)
	transaction.recipientCount += 1
	return nil
}

// The domain the session serves, whose postmaster a bare RCPT TO:<Postmaster> names (RFC 5321 §4.5.1; owner decision
// 446). A sender's SNI names the MX host it looked up, which is <mx>.<domain>: mx.<net>.<root> serves <net>.<root>
// and every burner under its wildcard, an alias's or a scope's mx host its zone, and a custom MX host its domain
// (§12.8 step 4, as MailStrictPolicy reads it). So a receiver serving several domains picks the one this sender
// reached. With no SNI, or one of a single label, it is the receiver's own zone from PostmasterDomain, and empty
// when that names none. Either way the address then meets every rule the full address meets, Resolve's grammar
// first, so a strange SNI only picks an address the sender could have written whole.
func (self *MailSession) postmasterDomain() (string, error) {
	host := mailStrictHost(self.stream.Tls.ConnectionState().ServerName)
	if _, domain, ok := strings.Cut(host, "."); ok && domain != "" {
		return domain, nil
	}
	if self.server.args.PostmasterDomain == nil {
		return "", nil
	}
	domain, err := self.server.args.PostmasterDomain(self.ctx)
	if err != nil {
		return "", err
	}
	return mailStrictHost(domain), nil
}

// See the file header's data and reply rows. go-smtp reads on to the message's end after a refusal, so a sender
// always gets the one reply.
func (self *MailSession) Data(reader io.Reader) error {
	transaction := func() mailSessionTransaction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.transaction.clone()
	}()
	if !transaction.mailTaken || len(transaction.targets) == 0 {
		return mailSessionReplyNoTransaction
	}
	server := self.server
	if server.args.Depositor.Refuses(transaction.targets) {
		// a repo this receiver's own state gives no deposit (§8.5): no deposit can commit, so the message is answered
		// at once, its body read on and dropped by go-smtp, as the deposit's refusal would answer it far later
		return mailSessionReplyTryLater
	}
	spool, err := newMailSpool(server.args.SpoolStore, server.settings.ChunkByteCount)
	if err != nil {
		return mailSessionReplyTryLater
	}
	defer spool.close()
	buffer := make([]byte, server.settings.ChunkByteCount)
	defer clear(buffer)
	for {
		byteCount, readErr := reader.Read(buffer)
		if 0 < byteCount {
			if _, err := spool.Write(buffer[:byteCount]); err != nil {
				return mailSessionReplyTryLater
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if errors.Is(readErr, smtp.ErrDataTooLarge) {
			return smtp.ErrDataTooLarge
		}
		if readErr != nil {
			// a reset, the connection's end or a broken line: everything goes, nothing commits
			return mailSessionReplyTryLater
		}
	}
	if err := spool.finish(); err != nil {
		return mailSessionReplyTryLater
	}
	receiveTime := server.clock.Now()
	state := self.stream.Tls.ConnectionState()
	input := &MailDepositInput{
		Spool:      spool,
		Ingress:    self.ingress,
		Evidence:   self.evidence(spool, &transaction, receiveTime, state.ServerName),
		MailFrom:   transaction.mailFrom,
		RequireTls: transaction.requireTls,
		TlsVersion: uint32(state.Version),
		TlsSuite:   uint32(state.CipherSuite),
		Targets:    transaction.targets,
	}
	if err := server.args.Depositor.Deposit(self.ctx, input); err != nil {
		if server.log.V(1).Enabled() {
			server.log.Infof("[mail]a message's deposits did not all commit; the sender retries")
		}
		return mailSessionReplyTryLater
	}
	return nil
}

// strict_chain for one message (MAIL-M7-24): the strict policy's answer for a spliced session, never a direct-MX one's.
func (self *MailSessionServer) strictChain(ctx context.Context, sniHost string, recipients []string, spkiSha256 []byte, direct bool) bool {
	if direct || self.args.StrictChain == nil {
		return false
	}
	return self.args.StrictChain(ctx, sniHost, mailRecipientDomains(recipients), spkiSha256)
}

// The message's sealed evidence, nil when there is none to seal: no checker on this leg, or the checks' own read of
// the spool failed. Either deposits as "evidence unavailable", which only ever weakens a label (D-MAIL-14).
func (self *MailSession) evidence(spool *mailSpool, transaction *mailSessionTransaction, receiveTime time.Time, sniHost string) *protocol.MailAuthEvidence {
	server := self.server
	if server.args.Checker == nil {
		return nil
	}
	input := &MailAuthInput{
		Message:            spool,
		Size:               spool.Size(),
		MailFrom:           []byte(transaction.mailFrom),
		SmtpUtf8:           transaction.smtpUtf8,
		SniHost:            sniHost,
		ReceiverSpkiSha256: append([]byte(nil), self.stream.SpkiSha256[:]...),
	}
	if self.conn != nil {
		// SPF's HELO identity is the EHLO the receiver saw, after TLS (QD-370)
		input.EhloName = self.conn.Hostname()
	}
	if senderIp, ok := netip.AddrFromSlice(self.ingress.GetSenderIp()); ok {
		input.SenderIp = senderIp.Unmap()
	}
	outcome, err := server.args.Slots.Check(self.ctx, server.args.Checker, input)
	if err != nil {
		return nil
	}
	messageSha256 := spool.Sha256()
	recipients := []string{}
	for _, target := range transaction.targets {
		recipients = append(recipients, target.Recipients...)
	}
	evidence, err := server.evidence.Build(&MailEvidenceInput{
		MessageSha256:     messageSha256[:],
		ReceiveTimeMillis: uint64(receiveTime.UnixMilli()),
		StrictChain:       server.strictChain(self.ctx, sniHost, recipients, self.stream.SpkiSha256[:], self.direct),
		Outcome:           outcome,
	})
	if err != nil {
		return nil
	}
	return evidence
}
