package smtp_test

import (
	"errors"
	"io"
	"net/textproto"
	"sync"
	"testing"

	"github.com/emersion/go-smtp"
)

// A backend whose Data counts the transfers running at once, and whose Reset
// counts the times it ran beside one. The first transfer cut short answers a
// 451 of its own, which a later transaction must never take as its reply.
type bdatResetBackend struct {
	mu          sync.Mutex
	active      int
	maxActive   int
	resetsInUse int
	cut         chan struct{}
}

func (be *bdatResetBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &bdatResetSession{backend: be}, nil
}

type bdatResetSession struct {
	backend *bdatResetBackend
}

func (s *bdatResetSession) Reset() {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	if s.backend.active != 0 {
		s.backend.resetsInUse++
	}
}

func (s *bdatResetSession) Logout() error {
	return nil
}

func (s *bdatResetSession) Mail(from string, opts *smtp.MailOptions) error {
	return nil
}

func (s *bdatResetSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	return nil
}

func (s *bdatResetSession) Data(r io.Reader) error {
	be := s.backend
	be.mu.Lock()
	be.active++
	if be.maxActive < be.active {
		be.maxActive = be.active
	}
	be.mu.Unlock()
	defer func() {
		be.mu.Lock()
		be.active--
		be.mu.Unlock()
	}()
	_, err := io.Copy(io.Discard, r)
	if errors.Is(err, smtp.ErrDataReset) {
		close(be.cut)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "the cut transfer's own answer"}
	}
	return err
}

// URNETWORK.md's second change: RSET between BDAT chunks ends the cut
// transfer's Data before anything is reset, so Reset never runs beside a
// Data and two transactions' Data never overlap, and the next transaction's
// LAST answers that transaction's own result, never the cut one's.
func TestUrnetworkBdatResetEndsTheCutTransferFirst(t *testing.T) {
	be := &bdatResetBackend{cut: make(chan struct{})}
	serverConn, clientConn := serveConnTestPlainPipe(t)
	server := serveConnTestServer(be)
	served := serveConnTestGo(func() error {
		return server.ServeConn(serverConn, smtp.ServeConnOptions{})
	})
	text := textproto.NewConn(clientConn)
	expect := func(code int, line string) {
		t.Helper()
		if line != "" {
			if err := text.PrintfLine("%s", line); err != nil {
				t.Fatal(err)
			}
		}
		if got, message, err := text.ReadResponse(code); err != nil {
			t.Fatalf("%q answered %d %s: %v", line, got, message, err)
		}
	}
	chunk := func(code int, line string, data string) {
		t.Helper()
		if err := text.PrintfLine("%s", line); err != nil {
			t.Fatal(err)
		}
		if _, err := clientConn.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		expect(code, "")
	}

	expect(220, "")
	expect(250, "EHLO client.example")
	expect(250, "MAIL FROM:<a@client.example>")
	expect(250, "RCPT TO:<b@mx.example>")
	chunk(250, "BDAT 4", "abcd")
	expect(250, "RSET")
	<-be.cut
	expect(250, "MAIL FROM:<a@client.example>")
	expect(250, "RCPT TO:<b@mx.example>")
	chunk(250, "BDAT 2 LAST", "ef")
	expect(221, "QUIT")
	if err := <-served; err != nil {
		t.Fatal(err)
	}

	be.mu.Lock()
	defer be.mu.Unlock()
	if be.resetsInUse != 0 {
		t.Errorf("Reset ran beside a transfer's Data %d times", be.resetsInUse)
	}
	if be.maxActive != 1 {
		t.Errorf("%d transfers' Data ran at once", be.maxActive)
	}
}
