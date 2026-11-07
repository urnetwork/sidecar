// PROXY-unwrapped listening, §13.4's PROXY paragraph on the engine leg (reading 14). The lb opens every
// connection it forwards with a PROXY v1 line, and this wraps a net.Listener so that what Accept hands
// out has that header off and its address kept. A connection that does not open with one within the
// bounds is dropped with no alert: only the lb reaches this port, as for every stream block on warp's
// service network, so whatever else arrives is no visitor, and tlsedge owes it no TLS. v2 is taken too,
// as §13.4 asks.
//
// pires/go-proxyproto parses. It is not used as a listener, which would read lazily on the first Read
// and pass a connection with no header under some policies, and which refuses a v1 line that arrives
// in two reads. Here the header is read before Accept sees the connection, on a goroutine of its own
// so that a stalled peer delays nobody, and the bytes are framed first: the header must end inside
// max_bytes before pires is given it, and pires then reads from memory, which is what policy REQUIRE
// asks and an explicit bound on top. Bytes that came in behind the header are the hello's, and are
// served first by Read, so none is lost.
//
// Neither address reaches a log (I-13): nothing here logs, and a read error is dropped with its
// connection, since a net.OpError prints the addresses it failed on.
//
// A listener and a ProxyHeaderConn are safe for concurrent use, as a net.Listener and net.Conn are.

package tlsedgeservice

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// Wire values, from haproxy's proxy-protocol.txt: "PROXY " and its §2.1 limit on a whole v1 line, CRLF
// included, and v2's fixed part, §2.2: signature, version and command, family, and a 16-bit length.
const (
	proxyHeaderV1Prefix         = "PROXY "
	proxyHeaderV1MaxByteCount   = 107
	proxyHeaderV2FixedByteCount = 16
	proxyHeaderV2LengthOffset   = 14
)

// Why a header was not taken. No text holds an address.
var (
	errProxyHeaderMissing   = errors.New("connection does not open with a PROXY header")
	errProxyHeaderTooLong   = errors.New("PROXY header past max bytes")
	errProxyHeaderNoVisitor = errors.New("PROXY header names no visitor")
)

// tlsedge.yml's proxy_header (§13.5), and what bounds a listener's own work around it.
type ProxyHeaderSettings struct {
	// timeout_s: from accept to the header's last byte, one deadline for the whole header, so a peer
	// sending it a byte at a time cannot stretch it.
	Timeout time.Duration
	// max_bytes: the most a header may take. A v2 header's length past this drops the connection
	// without its bytes being waited for. It also sizes each pending connection's buffer. At least
	// 107, a whole v1 line. pires refuses a v2 header past its own 4,096 B of length, above this.
	MaxByteCount int
	// Connections one listener holds between accept and its Accept, whether reading a header or
	// waiting for the caller. Past this a new connection drops at once, so a host that stops accepting,
	// or peers that stall, cost a bounded number of goroutines and buffers. A peer that sends its
	// header at once holds a slot only for a moment.
	MaxPendingCount int
	// The wait after a temporary accept failure such as running out of descriptors, which keeps the
	// loop from spinning.
	AcceptRetryTimeout time.Duration
}

// The only source of these defaults. timeout_s and max_bytes are §13.5's.
func DefaultProxyHeaderSettings() *ProxyHeaderSettings {
	return &ProxyHeaderSettings{
		Timeout:            2 * time.Second,
		MaxByteCount:       2048,
		MaxPendingCount:    4096,
		AcceptRetryTimeout: 100 * time.Millisecond,
	}
}

// Every field must be usable, because a zero reads as no bound nowhere here: it fails.
func (self *ProxyHeaderSettings) validate() error {
	switch {
	case self == nil:
		return errors.New("no proxy header settings")
	case self.Timeout <= 0:
		return errors.New("proxy header Timeout must be positive")
	case self.MaxByteCount < proxyHeaderV1MaxByteCount:
		return fmt.Errorf("proxy header MaxByteCount must hold a v1 line of %d B", proxyHeaderV1MaxByteCount)
	case self.MaxPendingCount <= 0:
		return errors.New("proxy header MaxPendingCount must be positive")
	case self.AcceptRetryTimeout <= 0:
		return errors.New("proxy header AcceptRetryTimeout must be positive")
	}
	return nil
}

// A connection with its PROXY header off, as a listener from NewProxyHeaderListener accepts it.
//
// RemoteAddr is the visitor, so anything printing it prints a visitor's address, which must not reach
// a log (I-13). LocalAddr stays the accepting socket's: PROXY's destination is not kept, since DNAT
// rewrites it.
type ProxyHeaderConn struct {
	net.Conn
	visitorAddr netip.AddrPort
	acceptPort  int

	stateLock sync.Mutex
	// what came in behind the header, ahead of everything still in the socket
	surplusBytes []byte
}

// The visitor's address and port from PROXY, with a 4-in-6 address unmapped, so that a caller choosing
// a /32 or a /64 sees the visitor's family. Edge memory only (§2.8 tls-2).
func (self *ProxyHeaderConn) VisitorAddr() netip.AddrPort {
	return self.visitorAddr
}

// The port of the listener this came through, never PROXY's destination, which DNAT rewrites (§13.4).
func (self *ProxyHeaderConn) AcceptPort() int {
	return self.acceptPort
}

// The visitor, as VisitorAddr says. A caller that takes a plain net.Conn, as mxedge's does, gets the
// sender from here.
func (self *ProxyHeaderConn) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(self.visitorAddr)
}

// Half-closes the connection toward the visitor, as FIN maps from a stream's close (§13.5's step 6).
func (self *ProxyHeaderConn) CloseWrite() error {
	if writeCloser, ok := self.Conn.(interface{ CloseWrite() error }); ok {
		return writeCloser.CloseWrite()
	}
	return errors.ErrUnsupported
}

// Bytes that came in behind the header, then the socket's, in order. A read deadline binds only the
// socket's: bytes already here are returned whatever it says.
func (self *ProxyHeaderConn) Read(b []byte) (int, error) {
	byteCount := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		byteCount := copy(b, self.surplusBytes)
		self.surplusBytes = self.surplusBytes[byteCount:]
		if len(self.surplusBytes) == 0 {
			// and let the header's buffer go
			self.surplusBytes = nil
		}
		return byteCount
	}()
	if 0 < byteCount {
		return byteCount, nil
	}
	return self.Conn.Read(b)
}

// Reads until a whole header is in reader's buffer, which is at least maxByteCount long, and returns
// without having read past what the peer has sent. Anything that cannot open a header refuses at the
// first byte that shows it.
func peekProxyHeader(reader *bufio.Reader, maxByteCount int) error {
	for wantByteCount := 1; ; wantByteCount = reader.Buffered() + 1 {
		// one read of the socket at most, and more may arrive than was asked for
		if _, err := reader.Peek(wantByteCount); err != nil {
			return err
		}
		peeked, err := reader.Peek(reader.Buffered())
		if err != nil {
			return err
		}
		v1Prefix := []byte(proxyHeaderV1Prefix)
		switch {
		case bytes.HasPrefix(v1Prefix, peeked[:min(len(peeked), len(v1Prefix))]):
			if 0 <= bytes.IndexByte(peeked[:min(len(peeked), proxyHeaderV1MaxByteCount)], '\n') {
				return nil
			}
			if proxyHeaderV1MaxByteCount <= len(peeked) {
				return errProxyHeaderTooLong
			}
		case bytes.HasPrefix(proxyproto.SIGV2, peeked[:min(len(peeked), len(proxyproto.SIGV2))]):
			if len(peeked) < proxyHeaderV2FixedByteCount {
				continue
			}
			headerByteCount := proxyHeaderV2FixedByteCount + int(binary.BigEndian.Uint16(peeked[proxyHeaderV2LengthOffset:]))
			if maxByteCount < headerByteCount {
				return errProxyHeaderTooLong
			}
			if headerByteCount <= len(peeked) {
				return nil
			}
		default:
			return errProxyHeaderMissing
		}
	}
}

// Reads one header off reader, which is at least maxByteCount long, and gives the visitor it names.
// Only a TCP visitor is one: LOCAL, v1's UNKNOWN and every other family refuse, since each would leave
// tlsedge with no address to cap or hand on.
func readProxyHeader(reader *bufio.Reader, maxByteCount int) (netip.AddrPort, error) {
	if err := peekProxyHeader(reader, maxByteCount); err != nil {
		return netip.AddrPort{}, err
	}
	header, err := proxyproto.Read(reader)
	if err != nil {
		return netip.AddrPort{}, err
	}
	sourceAddr, _, ok := header.TCPAddrs()
	if !ok || header.Command != proxyproto.PROXY {
		return netip.AddrPort{}, errProxyHeaderNoVisitor
	}
	visitorAddr := sourceAddr.AddrPort()
	return netip.AddrPortFrom(visitorAddr.Addr().Unmap(), visitorAddr.Port()), nil
}

// The wrapper over a net.Listener. run accepts, each connection gets a goroutine for its header, and
// the unbuffered readyConns hands finished ones to Accept, so a connection is always held by exactly
// one of those.
type proxyHeaderListener struct {
	ctx      context.Context
	cancel   context.CancelCauseFunc
	listener net.Listener
	settings ProxyHeaderSettings

	acceptPort int
	readyConns chan *ProxyHeaderConn
	// one token per connection between accept and Accept
	pendingSlots chan struct{}
	// run and every connection's goroutine
	workGroup sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

// Wraps listener, a TCP listener bound for one port, and starts accepting. Accept then gives only
// connections that opened with a PROXY header, each a *ProxyHeaderConn. Ending ctx closes it as Close
// does, and Close closes listener. The settings are copied.
func NewProxyHeaderListener(ctx context.Context, listener net.Listener, settings *ProxyHeaderSettings) (net.Listener, error) {
	if err := settings.validate(); err != nil {
		return nil, err
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("a PROXY header listener needs a TCP listener, to know its port")
	}
	listenerCtx, cancel := context.WithCancelCause(ctx)
	self := &proxyHeaderListener{
		ctx:          listenerCtx,
		cancel:       cancel,
		listener:     listener,
		settings:     *settings,
		acceptPort:   tcpAddr.Port,
		readyConns:   make(chan *ProxyHeaderConn),
		pendingSlots: make(chan struct{}, settings.MaxPendingCount),
	}
	// ending the context is what stops run, which is blocked in the inner Accept
	context.AfterFunc(listenerCtx, self.closeListener)
	self.workGroup.Go(self.run)
	return self, nil
}

// Closes the inner listener, once.
func (self *proxyHeaderListener) closeListener() {
	self.closeOnce.Do(func() {
		self.closeErr = self.listener.Close()
	})
}

// Accepts until the listener closes, and never waits on a peer.
func (self *proxyHeaderListener) run() {
	for {
		conn, err := self.listener.Accept()
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Temporary() {
				select {
				case <-self.ctx.Done():
					return
				case <-time.After(self.settings.AcceptRetryTimeout):
				}
				continue
			}
			// the first cause wins, so a Close that came first still reads as a Close
			self.cancel(err)
			return
		}
		deadline := time.Now().Add(self.settings.Timeout)
		select {
		case self.pendingSlots <- struct{}{}:
			self.workGroup.Go(func() {
				defer func() {
					<-self.pendingSlots
				}()
				self.admit(conn, deadline)
			})
		default:
			conn.Close()
		}
	}
}

// Takes one connection's header and hands it to Accept, or drops it, with no alert either way.
func (self *proxyHeaderListener) admit(conn net.Conn, deadline time.Time) {
	// a closing listener ends a read at once, rather than at its deadline
	stopClose := context.AfterFunc(self.ctx, func() {
		conn.Close()
	})
	headerConn, err := self.readHeader(conn, deadline)
	if err != nil {
		stopClose()
		conn.Close()
		return
	}
	select {
	case self.readyConns <- headerConn:
		stopClose()
	case <-self.ctx.Done():
		conn.Close()
	}
}

// One connection's header and whatever came with it, within the settings' bounds.
func (self *proxyHeaderListener) readHeader(conn net.Conn, deadline time.Time) (*ProxyHeaderConn, error) {
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(conn, self.settings.MaxByteCount)
	visitorAddr, err := readProxyHeader(reader, self.settings.MaxByteCount)
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	// peeking only what is buffered reads nothing
	surplusBytes, err := reader.Peek(reader.Buffered())
	if err != nil {
		return nil, err
	}
	return &ProxyHeaderConn{
		Conn:         conn,
		visitorAddr:  visitorAddr,
		acceptPort:   self.acceptPort,
		surplusBytes: surplusBytes,
	}, nil
}

// The next connection whose header is read, as a *ProxyHeaderConn. Fails with net.ErrClosed once the
// listener is closed or its context ended, and with the inner listener's error if that failed for
// good.
func (self *proxyHeaderListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.readyConns:
		return conn, nil
	case <-self.ctx.Done():
		if err := context.Cause(self.ctx); !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, net.ErrClosed
	}
}

// Closes the inner listener and every connection that has not reached Accept, and returns once they
// are gone. Connections already accepted are the caller's.
func (self *proxyHeaderListener) Close() error {
	self.cancel(net.ErrClosed)
	self.closeListener()
	self.workGroup.Wait()
	return self.closeErr
}

// The inner listener's address.
func (self *proxyHeaderListener) Addr() net.Addr {
	return self.listener.Addr()
}
