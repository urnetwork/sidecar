package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

var ErrServerClosed = errors.New("smtp: server already closed")

// Logger interface is used by Server to report unexpected internal errors.
type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}

// A SMTP server.
type Server struct {
	// The type of network, "tcp" or "unix".
	Network string
	// TCP or Unix address to listen on.
	Addr string
	// The server TLS configuration.
	TLSConfig *tls.Config
	// Enable LMTP mode, as defined in RFC 2033.
	LMTP bool

	Domain            string
	MaxRecipients     int
	MaxMessageBytes   int64
	MaxLineLength     int
	AllowInsecureAuth bool
	Debug             io.Writer
	ErrorLog          Logger
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration

	// Advertise SMTPUTF8 (RFC 6531) capability.
	// Should be used only if backend supports it.
	EnableSMTPUTF8 bool

	// Advertise REQUIRETLS (RFC 8689) capability.
	// Should be used only if backend supports it.
	EnableREQUIRETLS bool

	// Advertise BINARYMIME (RFC 3030) capability.
	// Should be used only if backend supports it.
	EnableBINARYMIME bool

	// Advertise DSN (RFC 3461) capability.
	// Should be used only if backend supports it.
	EnableDSN bool

	// Advertise RRVS (RFC 7293) capability.
	// Should be used only if backend supports it.
	EnableRRVS bool

	// Advertise DELIVERBY (RFC 2852) capability.
	// Should be used only if backend supports it.
	EnableDELIVERBY bool
	// The minimum time, with seconds precision, that a client
	// may specify in the BY argument with return mode.
	// A zero value indicates no set minimum.
	// Only use if DELIVERBY is enabled.
	MinimumDeliverByTime time.Duration

	// Advertise MT-PRIORITY (RFC 6710) capability.
	// Should only be used if backend supports it.
	EnableMTPRIORITY bool
	// The priority profile mapping as defined
	// in RFC 6710 section 10.2.
	//
	// Default value of NONE to advertise no specific profile.
	MtPriorityProfile PriorityProfile

	// The server backend.
	Backend Backend

	wg   sync.WaitGroup
	done chan struct{}

	locker    sync.Mutex
	listeners []net.Listener
	conns     map[*Conn]struct{}
}

// New creates a new SMTP server.
func NewServer(be Backend) *Server {
	return &Server{
		// Doubled maximum line length per RFC 5321 (Section 4.5.3.1.6)
		MaxLineLength: 2000,

		Backend:  be,
		done:     make(chan struct{}, 1),
		ErrorLog: log.New(os.Stderr, "smtp/server ", log.LstdFlags),
		conns:    make(map[*Conn]struct{}),
	}
}

// Serve accepts incoming connections on the Listener l.
func (s *Server) Serve(l net.Listener) error {
	s.locker.Lock()
	s.listeners = append(s.listeners, l)
	s.locker.Unlock()

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		c, err := l.Accept()
		if err != nil {
			select {
			case <-s.done:
				// we called Close()
				return nil
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				s.ErrorLog.Printf("accept error: %s; retrying in %s", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()

			err := s.handleConn(newConn(c, s))
			if err != nil {
				s.ErrorLog.Printf("error handling %v: %s", c.RemoteAddr(), err)
			}
		}()
	}
}

// ServeConnOptions holds the options of ServeConn.
type ServeConnOptions struct {
	// AfterStartTls marks a connection whose STARTTLS exchange happened
	// before it reached the server, such as in a proxy that answered the
	// plaintext EHLO and STARTTLS itself. The connection must be a
	// *tls.Conn. The server sends no greeting, since after the TLS
	// handshake the client speaks first (RFC 3207 section 4.2), and it
	// waits for the client's EHLO.
	AfterStartTls bool
}

// ErrServeConnNotTls is returned by ServeConn when AfterStartTls is set and
// the connection is not a *tls.Conn.
var ErrServeConnNotTls = errors.New("smtp: AfterStartTls needs a *tls.Conn")

// ServeConn serves one connection accepted elsewhere, and returns when its
// session ends. From the call on, the server owns c as it owns the
// connections Serve accepts: Close closes it, Shutdown waits for it, and it
// is closed when ServeConn returns. Once the server is closed, ServeConn
// closes c without writing to it and returns ErrServerClosed.
//
// The server must come from NewServer.
func (s *Server) ServeConn(c net.Conn, opts ServeConnOptions) error {
	if _, isTLS := c.(*tls.Conn); opts.AfterStartTls && !isTLS {
		c.Close()
		return ErrServeConnNotTls
	}

	conn := newConn(c, s)

	// Close and Shutdown close done before they take the lock, so either
	// this sees done closed, or they see conn and count it in wg.
	s.locker.Lock()
	select {
	case <-s.done:
		s.locker.Unlock()
		c.Close()
		return ErrServerClosed
	default:
	}
	s.wg.Add(1)
	s.conns[conn] = struct{}{}
	s.locker.Unlock()

	defer s.wg.Done()

	return s.serveConn(conn, !opts.AfterStartTls)
}

// ServeTlsConn serves one connection whose STARTTLS exchange happened before
// it reached the server, as ServeConn does with AfterStartTls set. If the
// TLS handshake has not run yet, it runs before the session starts.
func (s *Server) ServeTlsConn(c *tls.Conn) error {
	return s.ServeConn(c, ServeConnOptions{AfterStartTls: true})
}

func (s *Server) handleConn(c *Conn) error {
	s.locker.Lock()
	s.conns[c] = struct{}{}
	s.locker.Unlock()

	return s.serveConn(c, true)
}

// serveConn runs the session on c, which the caller has added to s.conns,
// and removes it from there when the session ends. A session after
// STARTTLS elsewhere starts without the greeting.
func (s *Server) serveConn(c *Conn, greet bool) error {
	defer func() {
		c.Close()

		s.locker.Lock()
		delete(s.conns, c)
		s.locker.Unlock()
	}()

	if tlsConn, ok := c.conn.(*tls.Conn); ok {
		if d := s.ReadTimeout; d != 0 {
			c.conn.SetReadDeadline(time.Now().Add(d))
		}
		if d := s.WriteTimeout; d != 0 {
			c.conn.SetWriteDeadline(time.Now().Add(d))
		}
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
	}

	if greet {
		c.greet()
	}

	for {
		line, err := c.readLine()
		if err == nil {
			cmd, arg, err := parseCmd(line)
			if err != nil {
				c.protocolError(501, EnhancedCode{5, 5, 2}, "Bad command")
				continue
			}

			c.handle(cmd, arg)
		} else {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if err == ErrTooLongLine {
				c.writeResponse(500, EnhancedCode{5, 4, 0}, "Too long line, closing connection")
				return nil
			}

			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				c.writeResponse(421, EnhancedCode{4, 4, 2}, "Idle timeout, bye bye")
				return nil
			}

			c.writeResponse(421, EnhancedCode{4, 4, 0}, "Connection error, sorry")
			return err
		}
	}
}

func (s *Server) network() string {
	if s.Network != "" {
		return s.Network
	}
	if s.LMTP {
		return "unix"
	}
	return "tcp"
}

// ListenAndServe listens on the network address s.Addr and then calls Serve
// to handle requests on incoming connections.
//
// If s.Addr is blank and LMTP is disabled, ":smtp" is used.
func (s *Server) ListenAndServe() error {
	network := s.network()

	addr := s.Addr
	if !s.LMTP && addr == "" {
		addr = ":smtp"
	}

	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// ListenAndServeTLS listens on the TCP network address s.Addr and then calls
// Serve to handle requests on incoming TLS connections.
//
// If s.Addr is blank and LMTP is disabled, ":smtps" is used.
func (s *Server) ListenAndServeTLS() error {
	network := s.network()

	addr := s.Addr
	if !s.LMTP && addr == "" {
		addr = ":smtps"
	}

	l, err := tls.Listen(network, addr, s.TLSConfig)
	if err != nil {
		return err
	}

	return s.Serve(l)
}

// Close immediately closes all active listeners and connections.
//
// Close returns any error returned from closing the server's underlying
// listener(s).
func (s *Server) Close() error {
	select {
	case <-s.done:
		return ErrServerClosed
	default:
		close(s.done)
	}

	var err error
	s.locker.Lock()
	for _, l := range s.listeners {
		if lerr := l.Close(); lerr != nil && err == nil {
			err = lerr
		}
	}

	for conn := range s.conns {
		conn.Close()
	}
	s.locker.Unlock()

	return err
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners and then waiting indefinitely for connections to return to
// idle and then shut down.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the Server's underlying Listener(s).
func (s *Server) Shutdown(ctx context.Context) error {
	select {
	case <-s.done:
		return ErrServerClosed
	default:
		close(s.done)
	}

	var err error
	s.locker.Lock()
	for _, l := range s.listeners {
		if lerr := l.Close(); lerr != nil && err == nil {
			err = lerr
		}
	}
	s.locker.Unlock()

	connDone := make(chan struct{})
	go func() {
		defer close(connDone)
		s.wg.Wait()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-connDone:
		return err
	}
}
