//go:build !sidecar_http

// StubSmtpEdge: a minimal smtpedge on a pipe, so the sender builds and runs before the engine does
// (SMTP-M9-07). It speaks the frames (smtp_frame.go), resolves and dials through the seams
// (SmtpMxResolver and SmtpMxDialer, MxWorld in tests), runs the pre-TLS dialog itself, and splices
// whole TLS records through a SmtpProofSession, so nothing reaches the MX that the session did not
// clear. SubmitProof and Handshake are SMTP_PROOF's and SMTP_HANDSHAKE's handlers, and ProofChannel
// lands a sender's calls on them as smtpProofChannel's RPCs would, every SmtpProof field included.
//
// A preamble naming a key set the verifier does not hold is answered KEYS before any MX is dialed
// (DESIGN-DETAILS 3.2.5).
//
// It has no gate, quota, halt or send log, and its X-UR-Ref and Feedback-ID have the issued values'
// exact widths (plan-SMTP-small-readings#3, #4) and no MAC behind them: those are SMTP-M9-10's to
// issue. Safe for concurrent use.

package sidecartest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	errSmtpPreTlsBanner     = errors.New("smtp pre-tls: the banner refuses")
	errSmtpPreTlsNoStartTls = errors.New("smtp pre-tls: no STARTTLS offered")
	errSmtpPreTlsInjected   = errors.New("smtp pre-tls: octets after STARTTLS's 220")
	errStubSmtpEdgeNoSend   = errors.New("stub smtp edge: no such send")
)

// The lowercase unpadded base32 the issued values use.
var smtpStubBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// Gives the joined dnssec_chain for a recipient domain and the MX chosen, as MxWorld does.
type MxChainSource interface {
	Chain(domain string, mxHost string) ([]byte, error)
}

// What the stub answers and as whom it sends.
type StubSmtpEdgeSettings struct {
	// Answered to every preamble without resolving or dialing, unless OK.
	Code protocol.SmtpPreambleCode
	// retry_after_ms for HALTED, QUOTA and TRY_LATER.
	RetryAfter time.Duration
	// The sending address and its PTR name, which HELO repeats (§14.6).
	SendingAddress netip.Addr
	HeloName       string
	// b.<net>.<root>, which a real edge reads from the ticket's network, never from the sidecar.
	EnvelopeDomain string
	// The frames' bound, which both ends share. Nil is sidecar.DefaultSmtpFrameSettings'.
	Frame *sidecar.SmtpFrameSettings
	// The most octets one TLS record may hold on the wire, header included: 2^14 + 2,048 of ciphertext
	// (RFC 5246 §6.2.3) and the 5-octet header, past any 1.3 record's 2^14 + 256.
	RecordMaxByteCount int
}

func DefaultStubSmtpEdgeSettings() *StubSmtpEdgeSettings {
	return &StubSmtpEdgeSettings{
		Code:               protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK,
		SendingAddress:     netip.MustParseAddr("192.0.2.25"),
		HeloName:           "o1.out.root.example",
		EnvelopeDomain:     "b.n1.root.example",
		RecordMaxByteCount: 5 + 16*1024 + 2048,
	}
}

// One connection the stub spliced.
type stubSmtpConnection struct {
	session sidecar.SmtpProofSession
	mxConn  net.Conn
	// ClientRecord, VerifyPart and DiscloseShts each write what they clear under this, so the MX
	// gets the session's order
	writeLock sync.Mutex
	closeOnce sync.Once
	sidecar   net.Conn
}

func (self *stubSmtpConnection) close() {
	self.closeOnce.Do(func() {
		self.mxConn.Close()
		self.sidecar.Close()
	})
}

// Writes records the session cleared, in order, under writeLock.
func (self *stubSmtpConnection) writeClearedWithLock(records [][]byte) error {
	for _, record := range records {
		if _, err := self.mxConn.Write(record); err != nil {
			return err
		}
	}
	return nil
}

type StubSmtpEdge struct {
	resolver sidecar.SmtpMxResolver
	dialer   sidecar.SmtpMxDialer
	verifier sidecar.SmtpProofVerifier
	settings *StubSmtpEdgeSettings

	stateLock   sync.Mutex
	preambles   []*protocol.SmtpPreamble
	results     []*protocol.SmtpPreambleResult
	connections map[string]*stubSmtpConnection
}

// A nil settings takes DefaultStubSmtpEdgeSettings.
func NewStubSmtpEdge(resolver sidecar.SmtpMxResolver, dialer sidecar.SmtpMxDialer, verifier sidecar.SmtpProofVerifier, settings *StubSmtpEdgeSettings) *StubSmtpEdge {
	if settings == nil {
		settings = DefaultStubSmtpEdgeSettings()
	}
	return &StubSmtpEdge{resolver: resolver, dialer: dialer, verifier: verifier, settings: settings, connections: map[string]*stubSmtpConnection{}}
}

// Every preamble read, in order.
func (self *StubSmtpEdge) Preambles() []*protocol.SmtpPreamble {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*protocol.SmtpPreamble(nil), self.preambles...)
}

// Every result answered, in order.
func (self *StubSmtpEdge) Results() []*protocol.SmtpPreambleResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*protocol.SmtpPreambleResult(nil), self.results...)
}

// Serves one stream from a sidecar to its end: the preamble frame, its result, and on OK the splice.
// Closes conn. An error is a reset.
func (self *StubSmtpEdge) Serve(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	preamble, err := sidecar.ReadSmtpPreamble(conn, self.settings.Frame)
	if err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.preambles = append(self.preambles, preamble)
	}()
	answer := func(result *protocol.SmtpPreambleResult) error {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.results = append(self.results, result)
		}()
		return sidecar.WriteSmtpPreambleResult(conn, result, self.settings.Frame)
	}
	refuse := func(code protocol.SmtpPreambleCode) error {
		result := &protocol.SmtpPreambleResult{Code: uint32(code)}
		if code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED || code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA ||
			code == protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER {
			result.RetryAfterMs = uint32(self.settings.RetryAfter.Milliseconds())
		}
		return answer(result)
	}
	if self.settings.Code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		return refuse(self.settings.Code)
	}
	// a key set the verifier does not hold dials no MX
	if !self.verifier.HoldsKeySet(preamble.GetProofKeySet()) {
		return refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)
	}
	mxConn, mxHost, keywords, code := self.connect(ctx, preamble.GetRecipientDomain())
	if code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK {
		return refuse(code)
	}
	chain := self.chain(ctx, preamble.GetRecipientDomain(), mxHost)

	sendId := make([]byte, 12)
	rand.Read(sendId)
	issued := make([]byte, 21)
	rand.Read(issued)
	token := make([]byte, 16)
	rand.Read(token)
	result := &protocol.SmtpPreambleResult{
		Code:         uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK),
		SendId:       sendId,
		XUrRef:       "1." + strings.ToLower(smtpStubBase32.EncodeToString(issued)),
		FeedbackId:   "n:c:" + strings.ToLower(smtpStubBase32.EncodeToString(token)) + ":urnetwork",
		HeloName:     self.settings.HeloName,
		MxHost:       mxHost,
		DnssecChain:  chain,
		EhloKeywords: keywords,
	}
	session, err := self.verifier.NewSmtpProofSession(&sidecar.SmtpProofPreamble{
		RecipientDomain:  preamble.GetRecipientDomain(),
		RecipientCount:   preamble.GetRecipientCount(),
		MessageId:        preamble.GetMessageId(),
		HeaderFromDomain: preamble.GetHeaderFromDomain(),
		DkimSelector:     preamble.GetDkimSelector(),
		MessageByteCount: preamble.GetMessageByteCount(),
		Flags:            preamble.GetFlags(),
		HeloName:         self.settings.HeloName,
		XUrRef:           result.XUrRef,
		FeedbackId:       result.FeedbackId,
		EnvelopeDomain:   self.settings.EnvelopeDomain,
		MxHost:           mxHost,
		ProofKeySet:      preamble.GetProofKeySet(),
	})
	if errors.Is(err, sidecar.ErrSmtpProofKeySet) {
		mxConn.Close()
		return refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)
	}
	if err != nil {
		mxConn.Close()
		return refuse(protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER)
	}
	connection := &stubSmtpConnection{session: session, mxConn: mxConn, sidecar: conn}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.connections[string(sendId)] = connection
	}()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.connections, string(sendId))
	}()
	if err := answer(result); err != nil {
		connection.close()
		return err
	}
	self.splice(connection)
	return nil
}

// Resolves and walks the MXs in preference order, the first that takes STARTTLS winning.
func (self *StubSmtpEdge) connect(ctx context.Context, domain string) (net.Conn, string, []string, protocol.SmtpPreambleCode) {
	answer, err := self.resolver.LookupMx(ctx, domain)
	switch {
	case errors.Is(err, sidecar.ErrSmtpMxNoSuchDomain):
		return nil, "", nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX
	case err != nil:
		return nil, "", nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER
	case answer.NullMx:
		return nil, "", nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX
	}
	hosts := answer.Hosts
	if len(hosts) == 0 {
		hosts = []*sidecar.SmtpMxHost{{Host: domain}}
	}
	// NO_TLS only when an MX answered and offered no STARTTLS; a refusing banner or a dial that
	// failed is worth a later try
	noStartTls := false
	for _, host := range hosts {
		addresses, err := self.resolver.LookupAddresses(ctx, host.Host)
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if !address.Is4() {
				continue
			}
			mxConn, err := self.dialer.DialMx(ctx, self.settings.SendingAddress, address)
			if err != nil {
				continue
			}
			keywords, err := runSmtpPreTls(mxConn, self.settings.HeloName)
			if err != nil {
				noStartTls = noStartTls || errors.Is(err, errSmtpPreTlsNoStartTls)
				mxConn.Close()
				continue
			}
			return mxConn, host.Host, keywords, protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK
		}
	}
	if noStartTls {
		return nil, "", nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS
	}
	return nil, "", nil, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER
}

// The joined chain when the resolver can give one and both answers validated, else none.
func (self *StubSmtpEdge) chain(ctx context.Context, domain string, mxHost string) []byte {
	source, ok := self.resolver.(MxChainSource)
	if !ok {
		return nil
	}
	if answer, err := self.resolver.LookupMx(ctx, domain); err != nil || !answer.Secure {
		return nil
	}
	if answer, err := self.resolver.LookupTlsa(ctx, mxHost); err != nil || !answer.Secure {
		return nil
	}
	chain, err := source.Chain(domain, mxHost)
	if err != nil {
		return nil
	}
	return chain
}

// The edge's own pre-TLS dialog with an MX (§14.4): a 220 banner, EHLO with the sending address's PTR
// name, then STARTTLS, which must answer 220 with nothing after it. Returns the pre-TLS keywords,
// which are hints only, and leaves conn at the point a ClientHello goes next.
func runSmtpPreTls(conn net.Conn, heloName string) ([]string, error) {
	reader := bufio.NewReader(conn)
	banner, err := readFakeSmtpReply(reader)
	if err != nil {
		return nil, err
	}
	if banner.code != "220" {
		return nil, fmt.Errorf("%w: %s", errSmtpPreTlsBanner, banner.code)
	}
	if _, err := conn.Write([]byte("EHLO " + heloName + "\r\n")); err != nil {
		return nil, err
	}
	ehlo, err := readFakeSmtpReply(reader)
	if err != nil {
		return nil, err
	}
	if ehlo.code != "250" {
		return nil, fmt.Errorf("%w: EHLO answered %s", errSmtpPreTlsBanner, ehlo.code)
	}
	keywords := ehlo.lines[1:]
	startTls := false
	for _, keyword := range keywords {
		startTls = startTls || strings.EqualFold(strings.TrimSpace(keyword), "STARTTLS")
	}
	if !startTls {
		return nil, errSmtpPreTlsNoStartTls
	}
	if _, err := conn.Write([]byte("STARTTLS\r\n")); err != nil {
		return nil, err
	}
	ready, err := readFakeSmtpReply(reader)
	if err != nil {
		return nil, err
	}
	if ready.code != "220" {
		return nil, fmt.Errorf("%w: STARTTLS answered %s", errSmtpPreTlsNoStartTls, ready.code)
	}
	// a byte here would reach the session inside TLS (CVE-2011-0411)
	if 0 < reader.Buffered() {
		return nil, errSmtpPreTlsInjected
	}
	return keywords, nil
}

// Reads one whole TLS record, header included, as it travels: at most recordMaxByteCount octets.
func readSmtpTlsRecord(reader io.Reader, recordMaxByteCount int) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if recordMaxByteCount < 5+length {
		return nil, fmt.Errorf("stub smtp edge: a %d-octet record", length)
	}
	record := make([]byte, 5+length)
	copy(record, header)
	if _, err := io.ReadFull(reader, record[5:]); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return record, nil
}

// Both directions until either ends: client records through ClientRecord and only what it clears to
// the MX, server records through ServerRecord and then to the sidecar.
func (self *StubSmtpEdge) splice(connection *stubSmtpConnection) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer connection.close()
		for {
			record, err := readSmtpTlsRecord(connection.mxConn, self.settings.RecordMaxByteCount)
			if err != nil {
				connection.session.ServerClosed()
				return
			}
			if err := connection.session.ServerRecord(record); err != nil {
				return
			}
			if _, err := connection.sidecar.Write(record); err != nil {
				return
			}
		}
	}()
	func() {
		defer connection.close()
		for {
			record, err := readSmtpTlsRecord(connection.sidecar, self.settings.RecordMaxByteCount)
			if err != nil {
				return
			}
			err = func() error {
				connection.writeLock.Lock()
				defer connection.writeLock.Unlock()
				cleared, err := connection.session.ClientRecord(record)
				if err != nil {
					return err
				}
				return connection.writeClearedWithLock(cleared)
			}()
			if err != nil {
				return
			}
		}
	}()
	<-done
}

func (self *StubSmtpEdge) connection(sendId []byte) *stubSmtpConnection {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.connections[string(sendId)]
}

// SMTP_PROOF's handler: the part checked by the connection's session, what it clears written to the
// MX, and the connection cut on a refusal (§14.7).
func (self *StubSmtpEdge) SubmitProof(ctx context.Context, proof *protocol.SmtpProof) *protocol.SmtpProofResult {
	invalid := &protocol.SmtpProofResult{Code: uint32(protocol.SmtpProofCode_SMTP_PROOF_INVALID)}
	connection := self.connection(proof.GetSendId())
	if connection == nil {
		return invalid
	}
	part := &sidecar.SmtpProofPart{
		SendId:            proof.GetSendId(),
		Index:             proof.GetIndex(),
		Mode:              proof.GetMode(),
		FirstRecord:       proof.GetFirstRecord(),
		LastRecord:        proof.GetLastRecord(),
		Proof:             proof.GetProof(),
		Last:              proof.GetLast(),
		ServerRecordCount: proof.GetServerRecordCount(),
		Records:           proof.GetRecords(),
		KeyCommitment:     proof.GetKeyCommitment(),
		ReplyCount:        proof.GetReplyCount(),
		HeaderRecordCount: proof.GetHeaderRecordCount(),
		Carry:             proof.GetCarry(),
	}
	err := func() error {
		connection.writeLock.Lock()
		defer connection.writeLock.Unlock()
		cleared, err := connection.session.VerifyPart(ctx, part)
		if err != nil {
			return err
		}
		return connection.writeClearedWithLock(cleared)
	}()
	if err != nil {
		connection.close()
		return invalid
	}
	return &protocol.SmtpProofResult{Code: uint32(protocol.SmtpProofCode_SMTP_PROOF_OK)}
}

// SMTP_HANDSHAKE's handler: E2 over the disclosed SHTS, which the session uses and forgets.
func (self *StubSmtpEdge) Handshake(ctx context.Context, handshake *protocol.SmtpHandshake) *protocol.SmtpHandshakeResult {
	invalid := &protocol.SmtpHandshakeResult{Code: uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_INVALID)}
	connection := self.connection(handshake.GetSendId())
	if connection == nil {
		return invalid
	}
	err := func() error {
		connection.writeLock.Lock()
		defer connection.writeLock.Unlock()
		cleared, err := connection.session.DiscloseShts(handshake.GetShts())
		if err != nil {
			return err
		}
		return connection.writeClearedWithLock(cleared)
	}()
	if err != nil {
		connection.close()
		return invalid
	}
	return &protocol.SmtpHandshakeResult{Code: uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK)}
}

// A sender's channel for one send, landing as smtpProofChannel's RPCs would on the two handlers.
func (self *StubSmtpEdge) ProofChannel(sendId []byte) sidecar.SmtpProofChannel {
	return &stubSmtpProofChannel{edge: self, sendId: bytes.Clone(sendId)}
}

type stubSmtpProofChannel struct {
	edge   *StubSmtpEdge
	sendId []byte
}

func (self *stubSmtpProofChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	result := self.edge.Handshake(ctx, &protocol.SmtpHandshake{SendId: self.sendId, Shts: shts})
	if result.GetCode() != uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK) {
		return fmt.Errorf("%w: handshake answered %d", errStubSmtpEdgeNoSend, result.GetCode())
	}
	return nil
}

func (self *stubSmtpProofChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	result := self.edge.SubmitProof(ctx, &protocol.SmtpProof{
		SendId:            self.sendId,
		Index:             part.Index,
		Mode:              part.Mode,
		FirstRecord:       part.FirstRecord,
		LastRecord:        part.LastRecord,
		Proof:             part.Proof,
		Last:              part.Last,
		ServerRecordCount: part.ServerRecordCount,
		Records:           part.Records,
		KeyCommitment:     part.KeyCommitment,
		ReplyCount:        part.ReplyCount,
		HeaderRecordCount: part.HeaderRecordCount,
		Carry:             part.Carry,
	})
	if result.GetCode() != uint32(protocol.SmtpProofCode_SMTP_PROOF_OK) {
		return fmt.Errorf("%w: part %d answered %d", errStubSmtpEdgeNoSend, part.Index, result.GetCode())
	}
	return nil
}
