//go:build !sidecar_http && !js && !ios_extension

// A Team's direct MX on its mail indexer (§15.4's Team paragraph; R-MAIL-2, D-MAIL-12, I-8, I-15, X6; MAIL-M7-23):
// MailDirectListener is the indexer's own public TCP 25, which mxedge's prober verified and §12.8's records point
// mx.<net>.<root> at, so a sender reaches the device with no URnetwork edge on the path.
//
//	dialog   the greeting and STARTTLS, as the router's are (D-MAIL-2): before TLS only EHLO, HELO, STARTTLS and QUIT,
//	         within the dialog's bytes and line bound; MAIL, RCPT, DATA and BDAT get 530 5.7.0, since this device holds
//	         no fleet memory of closed handshakes; anything else 502 5.5.1; a byte behind STARTTLS resets the
//	         connection (the CVE-2011-0411 class)
//	caps     its own: sessions per sender /64 or /32, per /48 or /24, and in all (max_streams' 16), past which 421 4.7.0
//	         before the greeting
//	tls      the receiver's served key and certificate (MailReceiver), the same TLSA a DANE sender checks, within
//	         HandshakeTimeout
//	session  then the same session and deposit as a spliced stream's (MailSessionServer.ServeDirect), MailIngress built
//	         here: the sender's address and port, the SNI the handshake named and the pre-TLS EHLO, no PTR or listing,
//	         which only mxedge has
//
// A direct MX stays in URnetwork's zone, so its mail is ordinary mail with EX2's residual and never carries
// strict_custom_mx (MAIL-M7-24). Nothing here logs an address or a name (I-13). Safe for concurrent use.

package sidecar

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// Public SMTP port from §15.4, shared by every direct MX and the edge's probes.
const mailDirectSmtpPort = 25

// The replies the dialog gives. Fixed texts: nothing a sender sent is echoed.
const (
	mailDirectReplyStartTls    = "220 2.0.0 Ready to start TLS\r\n"
	mailDirectReplyQuit        = "221 2.0.0 Bye\r\n"
	mailDirectReplyTlsRequired = "530 5.7.0 Must issue a STARTTLS command first\r\n"
	mailDirectReplyUnknown     = "502 5.5.1 Command not implemented\r\n"
	mailDirectReplySyntax      = "501 5.5.4 Syntax error\r\n"
	mailDirectReplyBusy        = "421 4.7.0 Too many connections, try again later\r\n"
)

// What NewMailDirectListener builds on.
type MailDirectListenerArgs struct {
	// The indexer's receiver, whose served key and certificate the handshake presents.
	Receiver *MailReceiver
	// The sessions, the receiver's own.
	Sessions *MailSessionServer
	// The name the greeting and EHLO give: the mail host, mx.<net>.<root>.
	HostName string
	// Nil is real time.
	Clock Clock
	// Nil logs nothing.
	Log Logger
	// Nil takes DefaultMailDirectSettings.
	Settings *MailDirectSettings
}

// A direct MX's listener (see the file header).
type MailDirectListener struct {
	args     *MailDirectListenerArgs
	settings *MailDirectSettings
	clock    Clock
	log      Logger

	stateLock    sync.Mutex
	sessionCount int
	senderCounts map[netip.Prefix]int
}

// A listener over args, which takes nothing until Serve.
func NewMailDirectListener(args *MailDirectListenerArgs) (*MailDirectListener, error) {
	if args == nil || args.Receiver == nil || args.Sessions == nil || args.HostName == "" || strings.ContainsAny(args.HostName, " \r\n") {
		return nil, fmt.Errorf("%w: a direct listener needs its receiver, sessions and host name", ErrMailReceiverInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultMailDirectSettings()
	}
	if !settings.valid() {
		return nil, fmt.Errorf("%w: direct settings out of range", ErrMailReceiverInvalid)
	}
	log := args.Log
	if log == nil {
		log = NewNoopLogger()
	}
	return &MailDirectListener{
		args: args, settings: settings, clock: clockOrReal(args.Clock), log: log,
		senderCounts: map[netip.Prefix]int{},
	}, nil
}

// Reconciles the assignments for this receiver, including pending probes. Each public address owns its listener
// and its accepted connections. Removing an assignment, losing the grant, or ending the component closes both.
func (self *MailDirectListener) runAssigned(ctx context.Context, interval time.Duration, assignments func(context.Context) []netip.Addr, listen func(context.Context, string, string) (net.Listener, error)) {
	type binding struct {
		cancel context.CancelFunc
		done   chan struct{}
	}
	bindings := map[netip.Addr]binding{}
	defer func() {
		for _, current := range bindings {
			current.cancel()
		}
		for _, current := range bindings {
			<-current.done
		}
	}()
	for ctx.Err() == nil {
		addresses := assignments(ctx)
		for address, current := range bindings {
			if !slices.Contains(addresses, address) {
				current.cancel()
				<-current.done
				delete(bindings, address)
			}
		}
		for _, address := range addresses {
			if current, ok := bindings[address]; ok {
				select {
				case <-current.done:
					current.cancel()
					delete(bindings, address)
				default:
					continue
				}
			}
			endpoint := netip.AddrPortFrom(address, mailDirectSmtpPort)
			listener, err := listen(ctx, "tcp", endpoint.String())
			if err != nil {
				self.log.Warningf("[mail]an assigned direct MX listener could not bind: %T", err)
				continue
			}
			listenCtx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			bindings[address] = binding{cancel: cancel, done: done}
			go func() {
				defer close(done)
				if err := self.Serve(listenCtx, listener); err != nil {
					self.log.Warningf("[mail]an assigned direct MX listener ended: %T", err)
				}
			}()
		}
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(interval):
		}
	}
}

// Takes the listener's connections until ctx ends or the listener fails. All connections on this address close
// and join before it returns, independently of the receiver's other public addresses.
func (self *MailDirectListener) Serve(ctx context.Context, listener net.Listener) error {
	serveCtx, cancel := context.WithCancel(ctx)
	var group sync.WaitGroup
	defer group.Wait()
	defer cancel()
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		group.Go(func() { self.serveConn(serveCtx, conn) })
	}
}

// The sender's /64 or /32 and its /48 or /24.
func mailDirectSenderPrefixes(address netip.Addr) (netip.Prefix, netip.Prefix) {
	address = address.Unmap()
	if address.Is4() {
		narrow, _ := address.Prefix(32)
		wide, _ := address.Prefix(24)
		return narrow, wide
	}
	narrow, _ := address.Prefix(64)
	wide, _ := address.Prefix(48)
	return narrow, wide
}

// Takes a session's place under the caps, answering the release; false past a cap.
func (self *MailDirectListener) admit(sender netip.Addr) (func(), bool) {
	narrow, wide := mailDirectSenderPrefixes(sender)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.SessionCount <= self.sessionCount || self.settings.SenderSessionCount <= self.senderCounts[narrow] ||
		self.settings.SenderAggregateSessionCount <= self.senderCounts[wide] {
		return nil, false
	}
	self.sessionCount += 1
	self.senderCounts[narrow] += 1
	self.senderCounts[wide] += 1
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sessionCount -= 1
		for _, prefix := range []netip.Prefix{narrow, wide} {
			if self.senderCounts[prefix] -= 1; self.senderCounts[prefix] <= 0 {
				delete(self.senderCounts, prefix)
			}
		}
	}, true
}

// One connection: the caps, the dialog, the handshake, then the session (see the file header).
func (self *MailDirectListener) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	var sender netip.AddrPort
	if ok {
		sender = remote.AddrPort()
	}
	if !sender.IsValid() {
		return
	}
	release, admitted := self.admit(sender.Addr())
	if !admitted {
		io.WriteString(conn, mailDirectReplyBusy)
		return
	}
	defer release()
	dialogCtx, cancel := context.WithCancel(ctx)
	stopDialog := self.clock.AfterFunc(self.settings.DialogTimeout, func() {
		cancel()
		conn.Close()
	})
	ehloName, started := self.dialog(dialogCtx, conn)
	stopDialog()
	cancel()
	if !started {
		return
	}
	presented := &mailReceiverServedKey{}
	tlsConn := self.tlsServer(conn, presented)
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
	senderIp := sender.Addr().Unmap()
	ingress := &protocol.MailIngress{
		Version:           mailFormatVersion,
		SenderIp:          senderIp.AsSlice(),
		SenderPort:        uint32(sender.Port()),
		Sni:               dnsAsciiLower(tlsConn.ConnectionState().ServerName),
		EhloName:          ehloName,
		ReceiveTimeMillis: uint64(max(self.clock.Now().UnixMilli(), 0)),
	}
	self.args.Sessions.ServeDirect(ctx, tlsConn, presented.spkiSha256, ingress)
}

// The handshake's server side on the receiver's served key, noting the key it presented.
func (self *MailDirectListener) tlsServer(conn net.Conn, presented *mailReceiverServedKey) *tls.Conn {
	return tls.Server(conn, self.args.Receiver.newTlsConfig(presented))
}

// The pre-TLS dialog: the greeting, then commands until STARTTLS's 220 with nothing behind it (started true, the
// EHLO or HELO name given), QUIT, a reset, the bound, or the connection's end.
func (self *MailDirectListener) dialog(ctx context.Context, conn net.Conn) (ehloName string, started bool) {
	host := self.args.HostName
	if _, err := io.WriteString(conn, "220 "+host+" ESMTP\r\n"); err != nil {
		return "", false
	}
	reader := bufio.NewReaderSize(conn, self.settings.LineMaxByteCount+2)
	readByteCount := 0
	greeted := false
	for {
		if ctx.Err() != nil {
			return "", false
		}
		line, err := reader.ReadSlice('\n')
		readByteCount += len(line)
		if err != nil || self.settings.DialogMaxByteCount < readByteCount || self.settings.LineMaxByteCount+2 < len(line) {
			return "", false
		}
		text := strings.TrimRight(string(line), "\r\n")
		verb, argument, _ := strings.Cut(text, " ")
		reply := mailDirectReplyUnknown
		switch strings.ToUpper(verb) {
		case "EHLO", "HELO":
			argument = strings.TrimSpace(argument)
			if argument == "" || self.settings.EhloNameMaxByteCount < len(argument) || strings.ContainsAny(argument, " \t") {
				reply = mailDirectReplySyntax
				break
			}
			ehloName, greeted = argument, true
			reply = "250 " + host + "\r\n"
			if strings.EqualFold(verb, "EHLO") {
				reply = "250-" + host + "\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n"
			}
		case "STARTTLS":
			switch {
			case argument != "" || !greeted:
				reply = mailDirectReplySyntax
			case 0 < reader.Buffered():
				// a byte behind STARTTLS: the CVE-2011-0411 class resets the connection
				return "", false
			default:
				if _, err := io.WriteString(conn, mailDirectReplyStartTls); err != nil {
					return "", false
				}
				return ehloName, true
			}
		case "QUIT":
			io.WriteString(conn, mailDirectReplyQuit)
			return "", false
		case "MAIL", "RCPT", "DATA", "BDAT":
			reply = mailDirectReplyTlsRequired
		}
		if _, err := io.WriteString(conn, reply); err != nil {
			return "", false
		}
	}
}
