//go:build !sidecar_http

// T2's sidecar.SmtpProver: a plain crypto/tls client and §14.5's dialog in miniature, for the sender
// and the engine before smtpproof's Prover, which this module cannot import. It proves nothing: each
// part carries a marker for a proof and no record ciphertexts, since crypto/tls seals as it sends, so
// only a script admits its parts (FakeSmtpProofVerifier), never the real verifier. Its parts number
// the client's application records from 1 in its own count, one record per 16 KiB of a write, which
// is how FakeSmtpProofVerifier's credit reads them.
//
// The dialog keeps the real one's order and refusals: SHTS disclosed after a 1.3 handshake; pi1 before
// EHLO; the mode from the post-TLS keywords; too_large and a mismatched count decided before MAIL;
// pi2 before MAIL, RCPT and DATA, pipelined only under PIPELINING; pi3, the last, before the message,
// and QUIT once the MX took it. A DATA send is one part here, where the real prover splits it.
// It records every send. Safe for concurrent use.

package sidecartest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

var _ sidecar.SmtpProver = (*FakeSmtpProver)(nil)

var (
	errFakeSmtpProverJob       = errors.New("fake smtp prover: the job does not hold together")
	errFakeSmtpProverNoMeasure = errors.New("fake smtp prover: no measure loaded")
)

// A record's most plaintext octets, as crypto/tls writes them with dynamic sizing off.
const fakeSmtpProverRecordByteCount = 16 * 1024

// What the fake offers and allows.
type FakeSmtpProverSettings struct {
	// The highest TLS version offered: tls.VersionTLS13, or tls.VersionTLS12 to hold a send there.
	MaxVersion uint16
	// The DATA cap in dot-stuffed octets, past which a DATA send is too_large: 1 MiB, the M1
	// reference's smtp_data_proof_bytes (D-SMTP-20). 0 sends no DATA at all, as a host whose part
	// cannot prove in 2 minutes.
	DataProofByteCount uint64
	// DATA whatever the MX offers, as the interop runs force it.
	ForceData bool
	// What Measure returns. Nil fails Measure, as on a host with no keys.
	Measure *sidecar.SmtpProverMeasure
}

func DefaultFakeSmtpProverSettings() *FakeSmtpProverSettings {
	return &FakeSmtpProverSettings{
		MaxVersion:         tls.VersionTLS13,
		DataProofByteCount: 1024 * 1024,
	}
}

// One SendSmtp, as the fake saw it.
type FakeSmtpProverSend struct {
	Preamble *sidecar.SmtpProofPreamble
	// 1.2 or 1.3, once the handshake finished.
	TlsVersion uint16
	// The SHTS disclosed, 1.3 only.
	Shts []byte
	// Every part submitted, in order.
	Parts []*sidecar.SmtpProofPart
	// Every command line written, CRLF included, the message excepted.
	Commands []string
	// Every reply read, its last line's code first.
	Replies []string
	Result  *sidecar.SmtpProofResult
	Err     error
}

type FakeSmtpProver struct {
	settings *FakeSmtpProverSettings

	stateLock sync.Mutex
	sends     []*FakeSmtpProverSend
}

// A nil settings takes DefaultFakeSmtpProverSettings.
func NewFakeSmtpProver(settings *FakeSmtpProverSettings) *FakeSmtpProver {
	if settings == nil {
		settings = DefaultFakeSmtpProverSettings()
	}
	return &FakeSmtpProver{settings: settings}
}

// Every send, finished or not, in the order each started.
func (self *FakeSmtpProver) Sends() []*FakeSmtpProverSend {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*FakeSmtpProverSend(nil), self.sends...)
}

func (self *FakeSmtpProver) Measure(ctx context.Context) (*sidecar.SmtpProverMeasure, error) {
	if self.settings.Measure == nil {
		return nil, errFakeSmtpProverNoMeasure
	}
	measure := *self.settings.Measure
	return &measure, nil
}

// Takes 1.3's SHTS from the key log, the one secret a real prover discloses (E2).
type fakeSmtpKeyLog struct {
	stateLock sync.Mutex
	shts      []byte
}

func (self *fakeSmtpKeyLog) Write(line []byte) (int, error) {
	fields := strings.Fields(string(line))
	if len(fields) == 3 && fields[0] == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
		if secret, err := hex.DecodeString(fields[2]); err == nil {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.shts = secret
		}
	}
	return len(line), nil
}

func (self *fakeSmtpKeyLog) secret() []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.shts)
}

// A message as DATA carries it: each line's leading dot doubled (RFC 5321 §4.5.2).
func fakeSmtpDotStuffed(message []byte) []byte {
	var stuffed bytes.Buffer
	lineStart := true
	for _, octet := range message {
		if lineStart && octet == '.' {
			stuffed.WriteByte('.')
		}
		stuffed.WriteByte(octet)
		lineStart = octet == '\n'
	}
	return stuffed.Bytes()
}

// One reply as read: its code and lines.
type fakeSmtpReply struct {
	code  string
	lines []string
}

// Reads one whole reply, which may run over several lines and records.
func readFakeSmtpReply(reader *bufio.Reader) (*fakeSmtpReply, error) {
	reply := &fakeSmtpReply{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return nil, fmt.Errorf("fake smtp prover: a short reply line %q", line)
		}
		reply.code = line[:3]
		text := ""
		if 4 <= len(line) {
			text = line[4:]
		}
		reply.lines = append(reply.lines, text)
		if len(line) == 3 || line[3] == ' ' {
			return reply, nil
		}
		if line[3] != '-' {
			return nil, fmt.Errorf("fake smtp prover: a malformed reply line %q", line)
		}
	}
}

// The state of one send.
type fakeSmtpProverRun struct {
	prover  *FakeSmtpProver
	job     *sidecar.SmtpProofJob
	channel sidecar.SmtpProofChannel
	send    *FakeSmtpProverSend
	conn    *tls.Conn
	reader  *bufio.Reader
	// application records written so far
	recordCount uint64
	nextIndex   uint32
}

func (self *FakeSmtpProver) SendSmtp(ctx context.Context, conn net.Conn, job *sidecar.SmtpProofJob, channel sidecar.SmtpProofChannel) (*sidecar.SmtpProofResult, error) {
	send := &FakeSmtpProverSend{}
	if job != nil && job.Preamble != nil {
		preamble := *job.Preamble
		send.Preamble = &preamble
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.sends = append(self.sends, send)
	}()
	run := &fakeSmtpProverRun{prover: self, job: job, channel: channel, send: send, nextIndex: 1}
	result, err := run.run(ctx, conn)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		send.Result = result
		send.Err = err
	}()
	return result, err
}

func (self *fakeSmtpProverRun) run(ctx context.Context, conn net.Conn) (*sidecar.SmtpProofResult, error) {
	job := self.job
	if job == nil || job.Preamble == nil || job.VerifyPeer == nil || len(job.RecipientLocals) == 0 ||
		uint32(len(job.RecipientLocals)) != job.Preamble.RecipientCount {
		return nil, errFakeSmtpProverJob
	}
	declared := job.Preamble.MessageByteCount
	stuffed := fakeSmtpDotStuffed(job.Message)
	if declared != uint64(len(job.Message)) && declared != uint64(len(stuffed)) {
		return nil, errFakeSmtpProverJob
	}
	headerEnd := bytes.Index(job.Message, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, errFakeSmtpProverJob
	}

	keyLog := &fakeSmtpKeyLog{}
	self.conn = tls.Client(conn, &tls.Config{
		ServerName: job.Preamble.MxHost,
		// the job's policy decides TL1-TL3, in place of crypto/tls's own roots
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			chain := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				certificate, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				chain = append(chain, certificate)
			}
			return job.VerifyPeer(chain)
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: self.prover.settings.MaxVersion,
		// E1's 1.2 suites; 1.3's are crypto/tls's to choose
		CipherSuites:                []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		SessionTicketsDisabled:      true,
		DynamicRecordSizingDisabled: true,
		KeyLogWriter:                keyLog,
	})
	stop := context.AfterFunc(ctx, func() { self.conn.Close() })
	defer stop()
	if err := self.conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	self.reader = bufio.NewReader(self.conn)
	version := self.conn.ConnectionState().Version
	func() {
		self.prover.stateLock.Lock()
		defer self.prover.stateLock.Unlock()
		self.send.TlsVersion = version
	}()
	if version == tls.VersionTLS13 {
		shts := keyLog.secret()
		func() {
			self.prover.stateLock.Lock()
			defer self.prover.stateLock.Unlock()
			self.send.Shts = shts
		}()
		if err := self.channel.DiscloseShts(ctx, shts); err != nil {
			return nil, err
		}
	}

	// pi1: EHLO
	ehlo := "EHLO " + job.Preamble.HeloName + "\r\n"
	if err := self.submit(ctx, sidecar.SmtpModeUnknown, false, fakeSmtpRecordCount(ehlo)); err != nil {
		return nil, err
	}
	if err := self.command(ehlo); err != nil {
		return nil, err
	}
	reply, err := self.reply()
	if err != nil {
		return nil, err
	}
	if reply.code != "250" {
		return &sidecar.SmtpProofResult{RefusedCode: reply.code}, nil
	}
	chunking, pipelining := false, false
	for _, line := range reply.lines[1:] {
		switch strings.ToUpper(strings.Fields(line + " ")[0]) {
		case "CHUNKING":
			chunking = true
		case "PIPELINING":
			pipelining = true
		}
	}
	mode := sidecar.SmtpModeData
	if chunking && !self.prover.settings.ForceData {
		mode = sidecar.SmtpModeBdat
	}
	count := uint64(len(job.Message))
	if mode == sidecar.SmtpModeData {
		count = uint64(len(stuffed))
		if self.prover.settings.DataProofByteCount < count {
			return &sidecar.SmtpProofResult{Mode: uint32(mode), TooLarge: true}, nil
		}
	}
	if declared != count {
		return &sidecar.SmtpProofResult{Mode: uint32(mode), ReconnectByteCount: count}, nil
	}

	// pi2: the envelope
	mailCommand := "MAIL FROM:<" + job.SenderLocal + "@" + job.Preamble.EnvelopeDomain + ">"
	if job.Preamble.Flags&sidecar.SmtpFlagRequireTls != 0 {
		mailCommand += " REQUIRETLS"
	}
	commands := []string{mailCommand + "\r\n"}
	for _, local := range job.RecipientLocals {
		commands = append(commands, "RCPT TO:<"+local+"@"+job.Preamble.RecipientDomain+">\r\n")
	}
	if mode == sidecar.SmtpModeData {
		commands = append(commands, "DATA\r\n")
	}
	envelopeRecords := uint64(0)
	for _, command := range commands {
		envelopeRecords += fakeSmtpRecordCount(command)
	}
	if err := self.submit(ctx, mode, false, envelopeRecords); err != nil {
		return nil, err
	}
	refuses := func(i int, reply *fakeSmtpReply) bool {
		if mode == sidecar.SmtpModeData && i == len(commands)-1 {
			return reply.code != "354"
		}
		return reply.code[0] != '2'
	}
	if pipelining {
		// one command a record, as SPEC.md's client writes them, all before the first reply
		for _, command := range commands {
			if err := self.command(command); err != nil {
				return nil, err
			}
		}
		var refusal *fakeSmtpReply
		for i := range commands {
			reply, err := self.reply()
			if err != nil {
				return nil, err
			}
			if refusal == nil && refuses(i, reply) {
				refusal = reply
			}
		}
		if refusal != nil {
			return &sidecar.SmtpProofResult{Mode: uint32(mode), RefusedCode: refusal.code}, nil
		}
	} else {
		for i, command := range commands {
			if err := self.command(command); err != nil {
				return nil, err
			}
			reply, err := self.reply()
			if err != nil {
				return nil, err
			}
			if refuses(i, reply) {
				return &sidecar.SmtpProofResult{Mode: uint32(mode), RefusedCode: reply.code}, nil
			}
		}
	}

	// pi3, the last: the message, then QUIT once the MX took it
	var message []string
	switch mode {
	case sidecar.SmtpModeBdat:
		message = []string{"BDAT " + strconv.Itoa(len(job.Message)) + " LAST\r\n", string(job.Message)}
	default:
		message = []string{string(stuffed), ".\r\n"}
	}
	messageRecords := fakeSmtpRecordCount("QUIT\r\n")
	for _, content := range message {
		messageRecords += fakeSmtpRecordCount(content)
	}
	if err := self.submit(ctx, mode, true, messageRecords); err != nil {
		return nil, err
	}
	for i, content := range message {
		if i == 0 && mode == sidecar.SmtpModeBdat {
			if err := self.command(content); err != nil {
				return nil, err
			}
			continue
		}
		if err := self.write(content); err != nil {
			return nil, err
		}
	}
	reply, err = self.reply()
	if err != nil {
		return nil, err
	}
	if reply.code[0] != '2' {
		return &sidecar.SmtpProofResult{Mode: uint32(mode), RefusedCode: reply.code}, nil
	}
	if err := self.command("QUIT\r\n"); err != nil {
		return nil, err
	}
	return &sidecar.SmtpProofResult{Mode: uint32(mode), Accepted: true}, nil
}

// The records crypto/tls writes for content, with dynamic sizing off.
func fakeSmtpRecordCount(content string) uint64 {
	return uint64((len(content) + fakeSmtpProverRecordByteCount - 1) / fakeSmtpProverRecordByteCount)
}

// Submits the next part, covering the next recordCount application records.
func (self *fakeSmtpProverRun) submit(ctx context.Context, mode sidecar.SmtpMode, last bool, recordCount uint64) error {
	part := &sidecar.SmtpProofPart{
		SendId:      bytes.Clone(self.job.SendId),
		Index:       self.nextIndex,
		Mode:        uint32(mode),
		FirstRecord: self.recordCount + 1,
		LastRecord:  self.recordCount + recordCount,
		Proof:       []byte("fake smtp proof"),
		Last:        last,
	}
	self.nextIndex += 1
	func() {
		self.prover.stateLock.Lock()
		defer self.prover.stateLock.Unlock()
		self.send.Parts = append(self.send.Parts, part)
	}()
	return self.channel.SubmitPart(ctx, part)
}

// Writes one command line in one write, and records it.
func (self *fakeSmtpProverRun) command(line string) error {
	func() {
		self.prover.stateLock.Lock()
		defer self.prover.stateLock.Unlock()
		self.send.Commands = append(self.send.Commands, line)
	}()
	return self.write(line)
}

func (self *fakeSmtpProverRun) write(content string) error {
	self.recordCount += fakeSmtpRecordCount(content)
	_, err := self.conn.Write([]byte(content))
	return err
}

func (self *fakeSmtpProverRun) reply() (*fakeSmtpReply, error) {
	reply, err := readFakeSmtpReply(self.reader)
	if err != nil {
		return nil, err
	}
	func() {
		self.prover.stateLock.Lock()
		defer self.prover.stateLock.Unlock()
		self.send.Replies = append(self.send.Replies, reply.code+" "+strings.Join(reply.lines, " / "))
	}()
	return reply, nil
}
