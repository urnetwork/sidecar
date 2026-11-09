// A sending MTA a test scripts step by step (MAIL-M7-03): the PROXY v1 line an lb writes ahead of it,
// EHLO, bytes pipelined in one write, STARTTLS with or without SNI on TLS 1.2 or 1.3, DATA or BDAT, a
// plaintext transaction where a sender retries without TLS, and a close in mid-message. Each step writes
// what an MTA would and reads the reply, so mxedge's router, the platform listener and a receiver each
// meet a sender as one arrives. Not safe for concurrent use: one goroutine drives one connection.

package sidecartest

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// A reply that is not one: a short line, a code that is not three digits, or a continuation that
// changes its code.
var ErrMailReply = errors.New("not an SMTP reply")

// One reply: its code and each line's text after the code and its separator.
type MailReply struct {
	Code  int
	Lines []string
}

// Whether the reply's code is code.
func (self *MailReply) Is(code int) bool {
	return self != nil && self.Code == code
}

// The reply as it came, one line, for a failure message.
func (self *MailReply) String() string {
	if self == nil {
		return "no reply"
	}
	return fmt.Sprintf("%d %s", self.Code, strings.Join(self.Lines, " / "))
}

// A sender on one connection.
type ScriptedMta struct {
	conn   net.Conn
	reader *bufio.Reader
}

func NewScriptedMta(conn net.Conn) *ScriptedMta {
	return &ScriptedMta{conn: conn, reader: bufio.NewReader(conn)}
}

// The connection, the TLS one after StartTls.
func (self *ScriptedMta) Conn() net.Conn {
	return self.conn
}

// The PROXY v1 line an lb's stream port sends ahead of the sender's bytes (§15.4).
func (self *ScriptedMta) WriteProxyV1(source netip.AddrPort, destination netip.AddrPort) error {
	family := "TCP4"
	if source.Addr().Unmap().Is6() {
		family = "TCP6"
	}
	_, err := fmt.Fprintf(self.conn, "PROXY %s %s %s %d %d\r\n", family, source.Addr().Unmap(), destination.Addr().Unmap(), source.Port(), destination.Port())
	return err
}

// Writes text as it is, in one write: a pipelined burst, a byte behind STARTTLS, a bare line.
func (self *ScriptedMta) Write(text string) error {
	_, err := io.WriteString(self.conn, text)
	return err
}

// Reads one reply, every line of a multi-line one.
func (self *ScriptedMta) ReadReply() (*MailReply, error) {
	reply := &MailReply{}
	for {
		line, err := self.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return nil, fmt.Errorf("%w: %q", ErrMailReply, line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil || code < 200 || 599 < code {
			return nil, fmt.Errorf("%w: %q", ErrMailReply, line)
		}
		if reply.Code != 0 && reply.Code != code {
			return nil, fmt.Errorf("%w: code %d after %d", ErrMailReply, code, reply.Code)
		}
		reply.Code = code
		separator := byte(' ')
		if 3 < len(line) {
			separator = line[3]
		}
		text := ""
		if 4 < len(line) {
			text = line[4:]
		}
		reply.Lines = append(reply.Lines, text)
		if separator != '-' {
			return reply, nil
		}
	}
}

// Writes line and CRLF, then reads the reply.
func (self *ScriptedMta) Command(line string) (*MailReply, error) {
	if err := self.Write(line + "\r\n"); err != nil {
		return nil, err
	}
	return self.ReadReply()
}

// Reads the banner.
func (self *ScriptedMta) Banner() (*MailReply, error) {
	return self.ReadReply()
}

func (self *ScriptedMta) Ehlo(name string) (*MailReply, error) {
	return self.Command("EHLO " + name)
}

// TLS as MTAs offer it: no certificate check, since opportunistic senders accept any (§2.8 EX3), and the
// one version asked for. An empty serverName sends no SNI.
func MailMtaTlsConfig(serverName string, version uint16) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	}
}

// STARTTLS, its 220, then the handshake under config. Every step after this one runs inside TLS.
func (self *ScriptedMta) StartTls(config *tls.Config) (*tls.ConnectionState, error) {
	reply, err := self.Command("STARTTLS")
	if err != nil {
		return nil, err
	}
	if !reply.Is(220) {
		return nil, fmt.Errorf("STARTTLS answered %s", reply)
	}
	if 0 < self.reader.Buffered() {
		return nil, errors.New("bytes arrived behind the 220, before the handshake")
	}
	// tls.Client with an empty ServerName sends no SNI, which a sender without one does
	tlsConn := tls.Client(self.conn, config)
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	self.conn = tlsConn
	self.reader = bufio.NewReader(tlsConn)
	state := tlsConn.ConnectionState()
	return &state, nil
}

func (self *ScriptedMta) MailFrom(address string) (*MailReply, error) {
	return self.Command("MAIL FROM:<" + address + ">")
}

func (self *ScriptedMta) RcptTo(address string) (*MailReply, error) {
	return self.Command("RCPT TO:<" + address + ">")
}

// A message's lines dot-stuffed (RFC 5321 §4.5.2), ending CRLF.
func mailDotStuff(message []byte) []byte {
	text := string(message)
	if !strings.HasSuffix(text, "\r\n") {
		text += "\r\n"
	}
	lines := strings.SplitAfter(text, "\r\n")
	var builder strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, ".") {
			builder.WriteByte('.')
		}
		builder.WriteString(line)
	}
	return []byte(builder.String())
}

// DATA, its 354, the message dot-stuffed and its end, then the reply.
func (self *ScriptedMta) Data(message []byte) (*MailReply, error) {
	reply, err := self.Command("DATA")
	if err != nil {
		return nil, err
	}
	if !reply.Is(354) {
		return reply, nil
	}
	if _, err := self.conn.Write(append(mailDotStuff(message), []byte(".\r\n")...)); err != nil {
		return nil, err
	}
	return self.ReadReply()
}

// The message as BDAT chunks of at most chunkByteCount (RFC 3030), the last marked LAST, each reply read
// before the next chunk; the last chunk's reply, or the first that is not 250.
func (self *ScriptedMta) Bdat(message []byte, chunkByteCount int) (*MailReply, error) {
	if chunkByteCount <= 0 {
		return nil, errors.New("a chunk needs a positive size")
	}
	for offset := 0; ; offset += chunkByteCount {
		end := min(offset+chunkByteCount, len(message))
		last := end == len(message)
		command := fmt.Sprintf("BDAT %d", end-offset)
		if last {
			command += " LAST"
		}
		if err := self.Write(command + "\r\n"); err != nil {
			return nil, err
		}
		if _, err := self.conn.Write(message[offset:end]); err != nil {
			return nil, err
		}
		reply, err := self.ReadReply()
		if err != nil {
			return nil, err
		}
		if last || !reply.Is(250) {
			return reply, nil
		}
	}
}

// DATA, its 354, then only the message's first byteCount bytes, then a close: a sender gone in
// mid-message, which must leave nothing accepted.
func (self *ScriptedMta) DataCutAt(message []byte, byteCount int) error {
	reply, err := self.Command("DATA")
	if err != nil {
		return err
	}
	if !reply.Is(354) {
		return fmt.Errorf("DATA answered %s", reply)
	}
	if _, err := self.conn.Write(message[:min(byteCount, len(message))]); err != nil {
		return err
	}
	return self.Close()
}

// MAIL FROM with no STARTTLS before it, as a sender retrying in plaintext does: the reply to MAIL, which
// mxedge answers 451 or 530 (§15.4).
func (self *ScriptedMta) PlaintextTransaction(from string) (*MailReply, error) {
	return self.MailFrom(from)
}

func (self *ScriptedMta) Quit() (*MailReply, error) {
	return self.Command("QUIT")
}

func (self *ScriptedMta) Close() error {
	return self.conn.Close()
}
