// The edge's pre-TLS dialog and its reply parser (SMTP-M9-12): banner, EHLO with the PTR name,
// STARTTLS and its 220, nothing forwarded before it and an octet behind it failing the MX (§22.6, the
// CVE-2011-0411 class); replies bounded as connect's are, 2,048 octets and 510 a line. FuzzSmtpMxReplies
// holds the parser to its bounds on any input.

package smtpedgeservice

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// An MX that answers in turn: its first reply is there at once, and each write the dialog makes brings
// the next, so nothing arrives ahead of the command it answers unless a test puts it there.
type turnConn struct {
	replies  []string
	readable []byte
	written  bytes.Buffer
}

func newTurnConn(replies ...string) *turnConn {
	conn := &turnConn{replies: replies}
	conn.next()
	return conn
}

func (self *turnConn) next() {
	if len(self.replies) != 0 {
		self.readable = append(self.readable, self.replies[0]...)
		self.replies = self.replies[1:]
	}
}

func (self *turnConn) Read(buffer []byte) (int, error) {
	if len(self.readable) == 0 {
		return 0, io.EOF
	}
	n := copy(buffer, self.readable)
	self.readable = self.readable[n:]
	return n, nil
}

func (self *turnConn) Write(data []byte) (int, error) {
	self.written.Write(data)
	self.next()
	return len(data), nil
}

func preTlsSettings() *SmtpEdgeSettings {
	return DefaultSmtpEdgeSettings()
}

const (
	testBanner   = "220 mx.dest.example ESMTP\r\n"
	testEhlo     = "250-mx.dest.example\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250 STARTTLS\r\n"
	testStartTls = "220 2.0.0 Ready to start TLS\r\n"
)

func TestSmtpPreTlsRunsBannerEhloAndStartTls(t *testing.T) {
	conn := newTurnConn(testBanner, testEhlo, testStartTls)
	keywords, err := smtpPreTls(conn, "o1.out.root.example", preTlsSettings())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keywords, "|") != "PIPELINING|SIZE 52428800|STARTTLS" {
		t.Fatalf("keywords %q", keywords)
	}
	if conn.written.String() != "EHLO o1.out.root.example\r\nSTARTTLS\r\n" {
		t.Fatalf("wrote %q", conn.written.String())
	}
}

func TestSmtpPreTlsFailsAByteAfterThe220(t *testing.T) {
	conn := newTurnConn(testBanner, testEhlo, testStartTls+"250 injected\r\n")
	if _, err := smtpPreTls(conn, "o1.out.root.example", preTlsSettings()); !errors.Is(err, errSmtpPreTlsInjected) {
		t.Fatalf("%v", err)
	}
	// and an octet ahead of the STARTTLS the edge never sent, which would answer it
	conn = newTurnConn(testBanner, testEhlo+testStartTls)
	if _, err := smtpPreTls(conn, "o1.out.root.example", preTlsSettings()); !errors.Is(err, errSmtpPreTlsInjected) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(conn.written.String(), "STARTTLS") {
		t.Fatal("STARTTLS sent after an octet came ahead of it")
	}
}

func TestSmtpPreTlsNoStartTlsSendsNoStartTls(t *testing.T) {
	conn := newTurnConn(testBanner, "250-mx.dest.example\r\n250 PIPELINING\r\n")
	if _, err := smtpPreTls(conn, "o1.out.root.example", preTlsSettings()); !errors.Is(err, errSmtpPreTlsNoStartTls) {
		t.Fatalf("%v", err)
	}
	if conn.written.String() != "EHLO o1.out.root.example\r\n" {
		t.Fatalf("wrote %q", conn.written.String())
	}
	// STARTTLS with a parameter is not the keyword
	conn = newTurnConn(testBanner, "250-mx.dest.example\r\n250 STARTTLS NOW\r\n")
	if _, err := smtpPreTls(conn, "o1.out.root.example", preTlsSettings()); !errors.Is(err, errSmtpPreTlsNoStartTls) {
		t.Fatalf("%v", err)
	}
}

func TestSmtpPreTlsBannersAndRefusals(t *testing.T) {
	cases := []struct {
		replies []string
		want    error
	}{
		{replies: []string{"421 mx.dest.example busy\r\n"}, want: errSmtpPreTlsBackoff},
		{replies: []string{"554 no service\r\n"}, want: errSmtpPreTlsBanner},
		{replies: []string{testBanner, "550 who are you\r\n"}, want: errSmtpPreTlsEhlo},
		{replies: []string{testBanner, testEhlo, "454 TLS not available\r\n"}, want: errSmtpPreTlsStartTlsRefused},
		{replies: []string{"220 partial"}, want: io.ErrUnexpectedEOF},
		{replies: nil, want: io.EOF},
	}
	for _, c := range cases {
		if _, err := smtpPreTls(newTurnConn(c.replies...), "o1.out.root.example", preTlsSettings()); !errors.Is(err, c.want) {
			t.Errorf("%q: %v, want %v", c.replies, err, c.want)
		}
	}
}

func TestSmtpReplyParserReadsMultilineReplies(t *testing.T) {
	parser := newSmtpReplyParser(strings.NewReader("250-first\r\n250-second\n250 last\r\n354\r\n"), preTlsSettings())
	reply, err := parser.next()
	if err != nil {
		t.Fatal(err)
	}
	if reply.code != 250 || strings.Join(reply.lines, "|") != "first|second|last" {
		t.Fatalf("reply %+v", reply)
	}
	reply, err = parser.next()
	if err != nil || reply.code != 354 || len(reply.lines) != 1 || reply.lines[0] != "" {
		t.Fatalf("reply %+v, %v", reply, err)
	}
	if _, err := parser.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("%v", err)
	}
}

func TestSmtpReplyParserBounds(t *testing.T) {
	settings := preTlsSettings()
	cases := []struct {
		name string
		data string
	}{
		{name: "a line past 510 octets", data: "250 " + strings.Repeat("a", 507) + "\r\n"},
		{name: "an unended line past 510 octets", data: "250 " + strings.Repeat("a", 600)},
		{name: "a reply past 2,048 octets", data: strings.Repeat("250-"+strings.Repeat("a", 96)+"\r\n", 21) + "250 end\r\n"},
		{name: "lines that change code", data: "250-a\r\n251 b\r\n"},
		{name: "a separator not - or space", data: "250+a\r\n"},
		{name: "a first digit past 5", data: "650 a\r\n"},
		{name: "a short code", data: "25\r\n"},
		{name: "a control octet", data: "250 a\x00b\r\n"},
		{name: "a bare CR inside", data: "250 a\rb\r\n"},
	}
	for _, c := range cases {
		parser := newSmtpReplyParser(strings.NewReader(c.data), settings)
		if _, err := parser.next(); !errors.Is(err, errSmtpReplyMalformed) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// at the bounds exactly, a reply parses
	line := "250 " + strings.Repeat("a", 506) + "\r\n"
	if reply, err := newSmtpReplyParser(strings.NewReader(line), settings).next(); err != nil || len(reply.lines[0]) != 506 {
		t.Fatalf("a 510-octet line: %v", err)
	}
}

func FuzzSmtpMxReplies(f *testing.F) {
	for _, seed := range []string{
		testBanner, testEhlo, testStartTls, testBanner + testEhlo + testStartTls,
		"421 busy\r\n", "250-a\n250 b\n", "250-" + strings.Repeat("x", 600), "220 ready\r\n\x16\x03\x01",
	} {
		f.Add([]byte(seed))
	}
	settings := preTlsSettings()
	f.Fuzz(func(t *testing.T, data []byte) {
		parser := newSmtpReplyParser(bytes.NewReader(data), settings)
		taken := 0
		for {
			reply, err := parser.next()
			if len(parser.buffer) != settings.MxReplyMaxByteCount {
				t.Fatalf("the buffer grew to %d", len(parser.buffer))
			}
			if err != nil {
				return
			}
			if reply.code < 200 || 599 < reply.code || len(reply.lines) == 0 {
				t.Fatalf("reply %+v", reply)
			}
			size := 0
			for _, line := range reply.lines {
				if settings.MxReplyLineMaxByteCount < len(line)+4 {
					t.Fatalf("a %d-octet line", len(line))
				}
				size += len(line) + 4
			}
			if settings.MxReplyMaxByteCount < size {
				t.Fatalf("a %d-octet reply", size)
			}
			taken += size
			if len(data) < taken {
				t.Fatalf("took %d of %d octets", taken, len(data))
			}
		}
	})
}
