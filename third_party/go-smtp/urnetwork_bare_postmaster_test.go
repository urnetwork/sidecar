package smtp_test

import (
	"io"
	"net/textproto"
	"sync"
	"testing"

	"github.com/emersion/go-smtp"
)

// A backend that keeps every reverse path Mail and every recipient Rcpt was
// given, with the NOTIFY each RCPT carried.
type barePostmasterBackend struct {
	mu         sync.Mutex
	froms      []string
	recipients []string
	notifies   [][]smtp.DSNNotify
}

func (be *barePostmasterBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &barePostmasterSession{backend: be}, nil
}

func (be *barePostmasterBackend) taken() (froms []string, recipients []string, notifies [][]smtp.DSNNotify) {
	be.mu.Lock()
	defer be.mu.Unlock()
	froms = append(froms, be.froms...)
	recipients = append(recipients, be.recipients...)
	notifies = append(notifies, be.notifies...)
	return froms, recipients, notifies
}

// Whether a and b hold the same strings in the same order. The module's go
// version predates the slices package.
func barePostmasterEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type barePostmasterSession struct {
	backend *barePostmasterBackend
}

func (s *barePostmasterSession) Reset() {}

func (s *barePostmasterSession) Logout() error {
	return nil
}

func (s *barePostmasterSession) Mail(from string, opts *smtp.MailOptions) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	s.backend.froms = append(s.backend.froms, from)
	return nil
}

func (s *barePostmasterSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	s.backend.recipients = append(s.backend.recipients, to)
	s.backend.notifies = append(s.backend.notifies, opts.Notify)
	return nil
}

func (s *barePostmasterSession) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// A session on server over a pipe, greeted and past EHLO, and a function that
// sends a line and fails the test unless the reply has code. A test ends the
// session with QUIT; the cleanup closes the client's end first, so a test that
// failed before its QUIT ends the session too, then waits for it.
func barePostmasterTestSession(t *testing.T, server *smtp.Server) func(code int, line string) {
	t.Helper()
	serverConn, clientConn := serveConnTestPlainPipe(t)
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
	t.Cleanup(func() {
		clientConn.Close()
		if err := <-served; err != nil && !t.Failed() {
			t.Error(err)
		}
	})
	expect(220, "")
	expect(250, "EHLO client.example")
	return expect
}

// URNETWORK.md's third change: RCPT's bare <Postmaster>, in any ASCII case,
// reaches Rcpt as "postmaster", while a full address keeps its case as
// upstream keeps it.
func TestUrnetworkRcptTakesABarePostmaster(t *testing.T) {
	be := &barePostmasterBackend{}
	expect := barePostmasterTestSession(t, serveConnTestServer(be))
	expect(250, "MAIL FROM:<a@client.example>")
	expect(250, "RCPT TO:<Postmaster>")
	expect(250, "RCPT TO:<postmaster>")
	expect(250, "RCPT TO:<POSTMASTER>")
	expect(250, "rcpt to:<pOSTMASTEr>")
	expect(250, "RCPT TO:<Postmaster@mx.example>")
	expect(221, "QUIT")

	_, recipients, _ := be.taken()
	want := []string{"postmaster", "postmaster", "postmaster", "postmaster", "Postmaster@mx.example"}
	if !barePostmasterEqual(recipients, want) {
		t.Errorf("Rcpt took %q, want %q", recipients, want)
	}
}

// What follows a bare <Postmaster>'s bracket is RCPT's parameters, parsed as
// they are after any path: DSN's NOTIFY reaches Rcpt, and an unknown one is
// refused.
func TestUrnetworkRcptBarePostmasterKeepsItsParameters(t *testing.T) {
	be := &barePostmasterBackend{}
	server := serveConnTestServer(be)
	server.EnableDSN = true
	expect := barePostmasterTestSession(t, server)
	expect(250, "MAIL FROM:<a@client.example>")
	expect(250, "RCPT TO:<Postmaster> NOTIFY=SUCCESS,FAILURE")
	expect(500, "RCPT TO:<Postmaster> X-UNKNOWN=1")
	expect(221, "QUIT")

	_, recipients, notifies := be.taken()
	if !barePostmasterEqual(recipients, []string{"postmaster"}) {
		t.Fatalf("Rcpt took %q", recipients)
	}
	if len(notifies[0]) != 2 || notifies[0][0] != smtp.DSNNotifySuccess || notifies[0][1] != smtp.DSNNotifyFailure {
		t.Errorf("NOTIFY reached Rcpt as %q", notifies[0])
	}
}

// Every other path with no domain still answers 501 and never reaches Rcpt:
// an empty domain, a longer or other local part, the bare name without its
// brackets, quoted or behind a source route, and a fold only Unicode makes.
func TestUrnetworkRcptRefusesEveryOtherPathWithoutADomain(t *testing.T) {
	be := &barePostmasterBackend{}
	expect := barePostmasterTestSession(t, serveConnTestServer(be))
	expect(250, "MAIL FROM:<a@client.example>")
	for _, line := range []string{
		"RCPT TO:<Postmaster@>",
		"RCPT TO:<Postmasters>",
		"RCPT TO:<other>",
		"RCPT TO:<Postmaster",
		"RCPT TO:Postmaster",
		"RCPT TO:<\"Postmaster\">",
		"RCPT TO:<@relay.example:Postmaster>",
		// U+017F, which Unicode folds to s
		"RCPT TO:<poſtmaster>",
	} {
		expect(501, line)
	}
	expect(250, "RCPT TO:<b@mx.example>")
	expect(221, "QUIT")

	_, recipients, _ := be.taken()
	if !barePostmasterEqual(recipients, []string{"b@mx.example"}) {
		t.Errorf("Rcpt took %q", recipients)
	}
}

// MAIL's reverse-path keeps upstream's rule: a bare <Postmaster> answers 501,
// and a full address is taken.
func TestUrnetworkMailRefusesABarePostmaster(t *testing.T) {
	be := &barePostmasterBackend{}
	expect := barePostmasterTestSession(t, serveConnTestServer(be))
	expect(501, "MAIL FROM:<Postmaster>")
	expect(501, "MAIL FROM:<postmaster>")
	expect(250, "MAIL FROM:<postmaster@client.example>")
	expect(221, "QUIT")

	froms, _, _ := be.taken()
	if !barePostmasterEqual(froms, []string{"postmaster@client.example"}) {
		t.Errorf("Mail took %q", froms)
	}
}
