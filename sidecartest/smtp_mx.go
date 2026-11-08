//go:build !sidecar_http

// T2's outside world for outbound mail (§14.4, FS-31), shared by ScriptedMx and RecordMx: an
// in-process connection with no port and no timer, and one SMTP state machine that both run behind
// their TLS. The machine records exactly what it accepted, command by command, and every transaction
// it took, so "fails before any effect" is an assertion on that record, and an MX's reading of a body
// it never agreed to take is the real one: an MX without CHUNKING answers BDAT 500 and parses what
// follows as commands, and a lax one ends DATA at a bare-LF dot (RFC 3030 §2, CVE-2023-51764).
//
// Addresses are RFC 5737's and names .example (connect/CODESTYLE.md's test data rule).

package sidecartest

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// The most one command line may hold, CRLF included (RFC 5321 §4.5.3.1.4).
const mxCommandLineByteCount = 512

// The longest data line taken, past RFC 5321's 1,000 so a test can send a long one and see it read.
const mxDataLineByteCount = 64 * 1024

var errMxLineTooLong = errors.New("mx: line too long")

// An MX that serves one connection to its end, such as ScriptedMx and RecordMx.
type MxServer interface {
	ServeMx(conn net.Conn)
}

// One direction of an in-process connection, unbounded, so a writer never waits on a reader and
// two pipelining sides never deadlock.
type mxStream struct {
	stateLock sync.Mutex
	monitor   *sync.Cond
	pending   []byte
	closed    bool
	deadline  time.Time
}

func newMxStream() *mxStream {
	stream := &mxStream{}
	stream.monitor = sync.NewCond(&stream.stateLock)
	return stream
}

func (self *mxStream) write(data []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return 0, io.ErrClosedPipe
	}
	self.pending = append(self.pending, data...)
	self.monitor.Broadcast()
	return len(data), nil
}

func (self *mxStream) read(buffer []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for len(self.pending) == 0 {
		if self.closed {
			return 0, io.EOF
		}
		if !self.deadline.IsZero() && !time.Now().Before(self.deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		self.monitor.Wait()
	}
	n := copy(buffer, self.pending)
	self.pending = self.pending[n:]
	return n, nil
}

func (self *mxStream) close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.monitor.Broadcast()
}

// Only a deadline already past is honored, which is how a TLS stack cancels a read: nothing here runs
// on a timer.
func (self *mxStream) setDeadline(deadline time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deadline = deadline
	self.monitor.Broadcast()
}

// One end of an in-process connection.
type mxConn struct {
	readStream  *mxStream
	writeStream *mxStream
	localAddr   net.Addr
	remoteAddr  net.Addr
}

func (self *mxConn) Read(buffer []byte) (int, error) { return self.readStream.read(buffer) }
func (self *mxConn) Write(data []byte) (int, error)  { return self.writeStream.write(data) }
func (self *mxConn) LocalAddr() net.Addr             { return self.localAddr }
func (self *mxConn) RemoteAddr() net.Addr            { return self.remoteAddr }
func (self *mxConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (self *mxConn) SetReadDeadline(deadline time.Time) error {
	self.readStream.setDeadline(deadline)
	return nil
}

func (self *mxConn) SetDeadline(deadline time.Time) error {
	self.readStream.setDeadline(deadline)
	return nil
}

// Closing either end ends both directions, as a TCP reset would.
func (self *mxConn) Close() error {
	self.readStream.close()
	self.writeStream.close()
	return nil
}

// A connected pair, the client's end first. Each end's addresses read as the other's reversed.
func NewMxPipe(clientAddr net.Addr, serverAddr net.Addr) (net.Conn, net.Conn) {
	clientToServer := newMxStream()
	serverToClient := newMxStream()
	return &mxConn{readStream: serverToClient, writeStream: clientToServer, localAddr: clientAddr, remoteAddr: serverAddr},
		&mxConn{readStream: clientToServer, writeStream: serverToClient, localAddr: serverAddr, remoteAddr: clientAddr}
}

// What an MX offers and how it answers (§14.5's scripted cases, FS-31). Start from DefaultMxScript.
type MxScript struct {
	// The greeting. A 421 backs the destination off, and the MX closes after it.
	Banner string
	// Pre-TLS EHLO keywords, STARTTLS added unless NoStartTls. Hints only: Z8 proves the post-TLS
	// reply (RFC 3207 §4.2).
	PreTlsKeywords []string
	NoStartTls     bool
	// Octets the MX writes after STARTTLS's 220, ahead of the handshake: the CVE-2011-0411 class,
	// which the edge must refuse.
	AfterStartTls []byte
	// Post-TLS EHLO keywords: whether the MX offers CHUNKING and PIPELINING is here.
	Keywords []string
	// Replies after TLS by verb, MAIL, RCPT, DATA, BDAT, EHLO or QUIT, in place of the machine's own.
	// A BDAT reply comes after its chunk is read.
	Replies map[string]string
	// Replies to RCPT by the recipient's local part, for mixed outcomes.
	RcptReplies map[string]string
	// The reply once a whole message is in: 250 by default, a 4xx or 5xx refusing it.
	MessageReply string
	// Ends DATA at a bare-LF dot line too, as receivers open to SMTP smuggling do.
	LaxDataEnd bool
	// Without PIPELINING, a command sent ahead of a reply gets 554 and the MX closes, as Postfix
	// does. Off, the machine records it and answers in turn. Either way only a command that arrived
	// with the one before it is seen: a client's own barriers prove the rest.
	RefusePipelining bool
}

func DefaultMxScript() *MxScript {
	return &MxScript{
		Banner:         "",
		PreTlsKeywords: []string{"PIPELINING", "SIZE 52428800", "8BITMIME"},
		Keywords:       []string{"PIPELINING", "CHUNKING", "SIZE 52428800", "8BITMIME", "SMTPUTF8"},
		Replies:        map[string]string{},
		RcptReplies:    map[string]string{},
	}
}

// One command as the machine took it.
type MxEvent struct {
	// After TLS.
	Secure bool
	// The command line, CRLF trimmed. A BDAT chunk is its own event, as "<chunk n octets>".
	Command string
	// The whole reply, every line, CRLF trimmed.
	Reply string
	// The machine accepted it: a 2xx or a 354.
	Accepted bool
	// A command sent ahead of a reply the MX never offered PIPELINING for.
	PipeliningViolation bool
}

// One transaction the MX took: the effect a test looks for.
type MxTransaction struct {
	Secure bool
	// MAIL's path and RCPT's accepted paths, angle brackets kept.
	Sender     string
	Recipients []string
	// What the MX took as the message: BDAT's chunks joined, or DATA's lines unstuffed.
	Message []byte
	Mode    sidecar.SmtpMode
}

// What one MX saw across its connections, safe for concurrent use.
type mxRecord struct {
	stateLock    sync.Mutex
	events       []*MxEvent
	transactions []*MxTransaction
	connections  int
}

func (self *mxRecord) addEvent(event *MxEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func (self *mxRecord) addTransaction(transaction *MxTransaction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.transactions = append(self.transactions, transaction)
}

func (self *mxRecord) addConnection() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.connections += 1
}

// Every event, in order.
func (self *mxRecord) Events() []*MxEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	events := make([]*MxEvent, 0, len(self.events))
	for _, event := range self.events {
		kept := *event
		events = append(events, &kept)
	}
	return events
}

// Every command the machine accepted, in order: exactly what it would act on.
func (self *mxRecord) Accepted() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var accepted []string
	for _, event := range self.events {
		if event.Accepted {
			accepted = append(accepted, event.Command)
		}
	}
	return accepted
}

// Every transaction the MX took, in order.
func (self *mxRecord) Transactions() []*MxTransaction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	transactions := make([]*MxTransaction, 0, len(self.transactions))
	for _, transaction := range self.transactions {
		kept := *transaction
		kept.Recipients = append([]string(nil), transaction.Recipients...)
		kept.Message = bytes.Clone(transaction.Message)
		transactions = append(transactions, &kept)
	}
	return transactions
}

// Connections the MX served.
func (self *mxRecord) Connections() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.connections
}

// Whether any command arrived ahead of a reply the MX never offered PIPELINING for.
func (self *mxRecord) PipeliningViolated() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, event := range self.events {
		if event.PipeliningViolation {
			return true
		}
	}
	return false
}

// The SMTP state machine of one connection, pre-TLS or after it.
type mxSmtpSession struct {
	host   string
	script *MxScript
	record *mxRecord
	reader *bufio.Reader
	writer io.Writer
	secure bool

	ehloSeen    bool
	transaction *MxTransaction
	// MAIL has been accepted in the current transaction
	mailAccepted bool
	chunks       bytes.Buffer
}

// Reads one line of at most limit octets, CRLF or bare LF ending it, the ending kept.
func readMxLine(reader *bufio.Reader, limit int) (string, error) {
	var line []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		line = append(line, fragment...)
		if limit < len(line) {
			return "", errMxLineTooLong
		}
		if err == nil {
			return string(line), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
}

// The keywords this phase offers.
func (self *mxSmtpSession) keywords() []string {
	if self.secure {
		return self.script.Keywords
	}
	keywords := append([]string(nil), self.script.PreTlsKeywords...)
	if !self.script.NoStartTls {
		keywords = append(keywords, "STARTTLS")
	}
	return keywords
}

func (self *mxSmtpSession) offers(keyword string) bool {
	for _, offered := range self.keywords() {
		if strings.EqualFold(strings.Fields(offered + " ")[0], keyword) {
			return true
		}
	}
	return false
}

func (self *mxSmtpSession) write(reply string) error {
	_, err := self.writer.Write([]byte(strings.ReplaceAll(reply, "\n", "\r\n") + "\r\n"))
	return err
}

// The script's reply for verb after TLS, else fallback.
func (self *mxSmtpSession) replyFor(verb string, fallback string) string {
	if self.secure {
		if reply, ok := self.script.Replies[verb]; ok {
			return reply
		}
	}
	return fallback
}

func mxAccepts(reply string) bool {
	return strings.HasPrefix(reply, "2") || strings.HasPrefix(reply, "354")
}

func (self *mxSmtpSession) reset() {
	self.transaction = nil
	self.mailAccepted = false
	self.chunks.Reset()
}

// Runs the dialog until QUIT, the end of the connection, or STARTTLS's 220, which returns true with
// nothing read past the STARTTLS line.
func (self *mxSmtpSession) serve() (bool, error) {
	for {
		line, err := readMxLine(self.reader, mxCommandLineByteCount)
		if errors.Is(err, errMxLineTooLong) {
			self.record.addEvent(&MxEvent{Secure: self.secure, Command: "<line too long>", Reply: "500 5.5.2 Line too long"})
			return false, self.write("500 5.5.2 Line too long")
		}
		if err != nil {
			return false, err
		}
		command := strings.TrimRight(line, "\r\n")
		event := &MxEvent{Secure: self.secure, Command: command}
		verb := strings.ToUpper(strings.Fields(command + " ")[0])
		// a BDAT chunk may follow its command in one write; anything else read with the command came
		// ahead of its reply
		if verb != "BDAT" && 0 < self.reader.Buffered() {
			switch {
			case verb == "STARTTLS":
				// what follows STARTTLS ahead of its 220 must never reach the session inside TLS
				// (CVE-2011-0411), so a careful MX drops it with the connection
				event.PipeliningViolation = true
				event.Reply = "554 5.5.0 Error: improper command pipelining after STARTTLS"
				self.record.addEvent(event)
				return false, self.write(event.Reply)
			case !self.offers("PIPELINING"):
				event.PipeliningViolation = true
				if self.script.RefusePipelining {
					event.Reply = "554 5.5.0 Error: improper command pipelining"
					self.record.addEvent(event)
					return false, self.write(event.Reply)
				}
			}
		}
		quit, startTls, err := self.handle(verb, command, event)
		event.Accepted = mxAccepts(event.Reply)
		self.record.addEvent(event)
		if err != nil {
			return false, err
		}
		if startTls {
			// the injected octets go in the 220's own write, as one segment would carry them
			reply := append([]byte(event.Reply+"\r\n"), self.script.AfterStartTls...)
			if _, err := self.writer.Write(reply); err != nil {
				return false, err
			}
			return true, nil
		}
		if writeErr := self.write(event.Reply); writeErr != nil {
			return false, writeErr
		}
		if quit {
			return false, nil
		}
	}
}

// Decides one command's reply into event.Reply. BDAT reads its chunk here, so its reply follows it.
func (self *mxSmtpSession) handle(verb string, command string, event *MxEvent) (quit bool, startTls bool, err error) {
	upper := strings.ToUpper(command)
	switch {
	case verb == "EHLO" || verb == "HELO":
		self.reset()
		self.ehloSeen = true
		reply := "250-" + self.host
		keywords := self.keywords()
		if verb == "HELO" {
			keywords = nil
		}
		for i, keyword := range keywords {
			if i == len(keywords)-1 {
				reply += "\n250 " + keyword
			} else {
				reply += "\n250-" + keyword
			}
		}
		if len(keywords) == 0 {
			reply = "250 " + self.host
		}
		event.Reply = self.replyFor("EHLO", reply)
	case verb == "STARTTLS":
		switch {
		case self.secure:
			event.Reply = "503 5.5.1 Error: TLS already active"
		case !self.offers("STARTTLS"):
			event.Reply = "502 5.5.1 Error: command not implemented"
		default:
			event.Reply = "220 2.0.0 Ready to start TLS"
			return false, true, nil
		}
	case strings.HasPrefix(upper, "MAIL FROM:"):
		switch {
		case !self.ehloSeen:
			event.Reply = "503 5.5.1 Error: send HELO/EHLO first"
		case self.mailAccepted:
			event.Reply = "503 5.5.1 Error: nested MAIL command"
		default:
			event.Reply = self.replyFor("MAIL", "250 2.1.0 Ok")
			if mxAccepts(event.Reply) {
				path := strings.Fields(strings.TrimSpace(command[len("MAIL FROM:"):]) + " ")[0]
				self.transaction = &MxTransaction{Secure: self.secure, Sender: path}
				self.mailAccepted = true
			}
		}
	case strings.HasPrefix(upper, "RCPT TO:"):
		if !self.mailAccepted {
			event.Reply = "503 5.5.1 Error: need MAIL command"
			break
		}
		path := strings.Fields(strings.TrimSpace(command[len("RCPT TO:"):]) + " ")[0]
		local := strings.SplitN(strings.Trim(path, "<>"), "@", 2)[0]
		reply, ok := self.script.RcptReplies[local]
		if !ok || !self.secure {
			reply = self.replyFor("RCPT", "250 2.1.5 Ok")
		}
		event.Reply = reply
		if mxAccepts(reply) {
			self.transaction.Recipients = append(self.transaction.Recipients, path)
		}
	case verb == "DATA":
		switch {
		case !self.mailAccepted:
			event.Reply = "503 5.5.1 Error: need MAIL command"
		case len(self.transaction.Recipients) == 0:
			event.Reply = "554 5.5.1 Error: no valid recipients"
		default:
			event.Reply = self.replyFor("DATA", "354 End data with <CR><LF>.<CR><LF>")
		}
		if !strings.HasPrefix(event.Reply, "354") {
			break
		}
		// the 354 goes out before the message arrives
		self.record.addEvent(&MxEvent{Secure: self.secure, Command: command, Reply: event.Reply, Accepted: true})
		if err := self.write(event.Reply); err != nil {
			return false, false, err
		}
		message, err := self.readData()
		if err != nil {
			return false, false, err
		}
		event.Command = fmt.Sprintf("<data %d octets>", len(message))
		event.Reply = self.finishMessage(message, sidecar.SmtpModeData)
	case verb == "BDAT":
		if !self.secure || !self.offers("CHUNKING") {
			// an MX without CHUNKING reads what follows as commands (RFC 3030 §2)
			event.Reply = "500 5.5.1 Error: command not recognized"
			break
		}
		fields := strings.Fields(command)
		size, sizeErr := 0, error(nil)
		if 2 <= len(fields) {
			size, sizeErr = strconv.Atoi(fields[1])
		}
		last := len(fields) == 3 && strings.EqualFold(fields[2], "LAST")
		if len(fields) < 2 || 3 < len(fields) || sizeErr != nil || size < 0 || (len(fields) == 3 && !last) {
			event.Reply = "501 5.5.4 Syntax: BDAT size [LAST]"
			break
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(self.reader, chunk); err != nil {
			return false, false, err
		}
		switch {
		case !self.mailAccepted:
			event.Reply = "503 5.5.1 Error: need MAIL command"
		case len(self.transaction.Recipients) == 0:
			event.Reply = "554 5.5.1 Error: no valid recipients"
		default:
			self.chunks.Write(chunk)
			if last {
				event.Reply = self.finishMessage(bytes.Clone(self.chunks.Bytes()), sidecar.SmtpModeBdat)
			} else {
				event.Reply = fmt.Sprintf("250 2.0.0 %d octets received", size)
			}
		}
		if reply, ok := self.script.Replies["BDAT"]; ok && self.secure {
			event.Reply = reply
		}
	case verb == "RSET":
		self.reset()
		event.Reply = "250 2.0.0 Ok"
	case verb == "NOOP":
		event.Reply = "250 2.0.0 Ok"
	case verb == "QUIT":
		event.Reply = self.replyFor("QUIT", "221 2.0.0 Bye")
		return true, false, nil
	default:
		event.Reply = "500 5.5.2 Error: command not recognized"
	}
	return false, false, nil
}

// Reads DATA's lines to the end mark, undoing dot-stuffing.
func (self *mxSmtpSession) readData() ([]byte, error) {
	var message bytes.Buffer
	for {
		line, err := readMxLine(self.reader, mxDataLineByteCount)
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" || (self.script.LaxDataEnd && line == ".\n") {
			return message.Bytes(), nil
		}
		message.WriteString(strings.TrimPrefix(line, "."))
	}
}

// Takes a whole message unless the script refuses it, and resets the transaction either way.
func (self *mxSmtpSession) finishMessage(message []byte, mode sidecar.SmtpMode) string {
	reply := "250 2.0.0 Ok: queued"
	if self.secure && self.script.MessageReply != "" {
		reply = self.script.MessageReply
	}
	if strings.HasPrefix(reply, "2") {
		transaction := self.transaction
		transaction.Message = message
		transaction.Mode = mode
		self.record.addTransaction(transaction)
	}
	self.reset()
	self.ehloSeen = true
	return reply
}

// A self-signed certificate for an MX host, ECDSA P-256 or RSA-2048, valid from 2026 to 2100.
func NewMxCertificate(host string, rsaKey bool) (tls.Certificate, error) {
	var signer crypto.Signer
	if rsaKey {
		rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return tls.Certificate{}, err
		}
		signer = rsaPrivate
	} else {
		ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}
		signer = ecdsaPrivate
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer, Leaf: leaf}, nil
}

// TLSA 3 1 1 for a certificate: DANE-EE over the SHA-256 of its public key (RFC 7672 §3.1).
func MxTlsaFor(certificate *x509.Certificate) *sidecar.SmtpTlsaRecord {
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: digest[:]}
}
