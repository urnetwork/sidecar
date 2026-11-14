package smtpproof

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"sync"

	"golang.org/x/crypto/cryptobyte"

	"github.com/urnetwork/sidecar"
)

// The record gate: E1-E3 of SPEC.md section 6, as one state machine per connection. It runs on the
// edge and holds no key that opens application data; the disclosed SHTS opens only the server's
// handshake flight, and is forgotten once E2 has used it (D-SMTP-10).
//
// All state is under stateLock, so "relayed before it" in E3 has one meaning: the order in which
// clientRecord and serverRecord took the lock. A proof is verified with no lock held, and the gate
// re-reads its state on return, so a part that landed meanwhile cannot be replaced unchecked. Safe for
// concurrent use, one goroutine per direction.

// What an edgeSession may hold. Start from defaultEdgeSettings.
type edgeSettings struct {
	// The proofs' catalog and limits: the shapes a part may take, and how many parts and records.
	proof *ProofSettings
	// Client octets held for a part still proving. An honest sidecar paces records behind its proofs,
	// so this bounds a hostile one. A DATA part can hold a whole 2-minute part, hence 256 KiB.
	maxHeldBytes int
	// Server octets kept for parts to cover. The longest honest run is an EHLO reply and the envelope
	// replies, so 256 KiB is far past any of it.
	maxServerBytes int
	// Handshake octets accepted, as for tlsClientSettings.
	maxHandshakeBytes int
}

func defaultEdgeSettings() *edgeSettings {
	return &edgeSettings{
		proof:             DefaultProofSettings(),
		maxHeldBytes:      256 * 1024,
		maxServerBytes:    256 * 1024,
		maxHandshakeBytes: 256 * 1024,
	}
}

// Checks a part's proof against its statement. Verifier supplies the real one, which refuses any
// part with no circuit behind it.
type partVerifier interface {
	verifyPart(ctx context.Context, statement *partStatement, proof []byte) error
}

// A connection's progress through the handshake.
type edgePhase uint8

const (
	edgePhaseClientHello edgePhase = iota
	edgePhaseServerHello
	// 1.3: the server's flight is relayed and kept, unread, until SHTS arrives.
	edgePhaseFlight13
	// 1.3: E2 has passed, and the client's Finished has yet to arrive. The RPC carrying SHTS and the
	// stream carrying Finished are not ordered against each other, so either may come first.
	edgePhaseClientFinished13
	// 1.2: the server's clear messages, then the client's flight, then the server's Finished.
	edgePhaseFlight12
	edgePhaseClientFlight12
	edgePhaseServerFinished12
	edgePhaseApplication
	edgePhaseEnded
)

// What the gate knows of one opened client record.
type edgeOpenedRecord struct {
	// The ciphertext the part proved.
	raw []byte
	// A message record, which waits for coverage of every server record relayed before it (E3 step 5).
	message bool
	// BDAT's chunk octets this record carries, exact because it is opened.
	chunkOctets uint64
	// The final QUIT, after which nothing is forwarded.
	quit bool
}

// A verified part, as far as the gate needs it.
type edgePart struct {
	part      *sidecar.SmtpProofPart
	statement *partStatement
	// Each opened record by sequence number.
	openedRecords map[uint64]*edgeOpenedRecord
	// The commands it opens, which the MX answers: EHLO, MAIL, RCPT, DATA.
	commands uint32
	// Whether it opens a header or body record, whose carry the gate keeps; and whether that is the
	// header block's last, after which a scan starts again.
	opensScan       bool
	opensLastHeader bool
	// Whether it opens the header block's first record, and so names k.
	namesHeaderCount bool
	// DATA octets declared through the end of this part.
	dataOctets uint64
	// partCommits when its order checks ran.
	commits uint64
}

type edgeSession struct {
	settings *edgeSettings
	preamble *sessionPreamble
	mxHost   string
	verifier partVerifier

	stateLock sync.Mutex
	phase     edgePhase
	version   uint16
	suite     uint16

	// Handshake.
	transcript       []byte
	clientBuffer     tlsHandshakeBuffer
	serverBuffer     tlsHandshakeBuffer
	clientRandom     []byte
	serverRandom     []byte
	helloHash        []byte
	helloRetried     bool
	clientChangeSeen bool
	// 1.3: server records after ServerHello, waiting for SHTS.
	flightRecords [][]byte
	// 1.3: the client's Finished record, held until E2 knows its length.
	clientFinishedRecord []byte
	// 1.3: that length, once E2 has opened the flight.
	clientFlightBytes int
	// 1.2.
	certificateRequested bool
	clientExchangeSeen   bool
	serverCertificate    *x509.Certificate
	preFinishedState     *sha256State
	serverFinishedRecord []byte

	session *sessionStatement
	// The key set the session's preamble named, which every part verifies under (DESIGN-DETAILS 3.2.7).
	keySet []byte
	// C, from the key part once it lands: the commitment every later part's statement takes, and never a
	// value a later part carries (DESIGN-DETAILS 3.2.5).
	keyCommitment []byte
	// The gate over parts (3.2.5): the next client record a part opens; the replies verified parts proved
	// and the commands they opened; the mode part 2 named; k, as the part that opened the header block's
	// first record named it; the carry the next scan opens; DATA's octets so far.
	nextRecord      uint64
	repliesProven   uint32
	commandsCovered uint32
	mode            uint32
	headerRecords   uint32
	carry           []byte
	dataOctets      uint64

	// E3.
	serverRecords     [][]byte
	serverRecordBytes int
	mxClosed          bool
	heldRecords       [][]byte
	heldBytes         int
	nextClientSeq     uint64
	// nextClientSeq as of the last call that handed records to its caller. A call that ends in a cut
	// returns none of the records it cleared before the cut, and those never reach the MX.
	handedClientSeq uint64
	// The first application record's sequence number in each direction: 1.2's Finished takes 0.
	firstSeq uint64
	parts    []*edgePart
	// Parts landed so far. A verification runs with no lock held, so this says whether the checks that
	// came before it still stand.
	partCommits   uint64
	coveredServer uint64
	chunkOctets   uint64
	finished      bool
}

func newEdgeSession(settings *edgeSettings, preamble *sessionPreamble, mxHost string, verifier partVerifier) *edgeSession {
	return &edgeSession{settings: settings, preamble: preamble, mxHost: mxHost, verifier: verifier}
}

// A record the gate refuses without calling it a cut: the connection ends.
func edgeRefuse(check relationCheck, format string, args ...any) error {
	return &relationFailure{check: check, err: fmt.Errorf(format, args...)}
}

// A cut, which counts toward §14.8's halt.
func edgeCut(format string, args ...any) error {
	return &relationFailure{check: checkE3, err: fmt.Errorf("%w: "+format, append([]any{sidecar.ErrSmtpRecordCut}, args...)...)}
}

func (self *edgeSession) addTranscriptWithLock(message []byte) error {
	self.transcript = append(self.transcript, message...)
	if self.settings.maxHandshakeBytes < len(self.transcript) {
		return edgeRefuse(checkE1, "handshake too long")
	}
	return nil
}

func edgeCheckFraming(record []byte) error {
	if len(record) < tlsRecordHeaderBytes {
		return edgeRefuse(checkE1, "short record")
	}
	if len(record) != tlsRecordHeaderBytes+(int(record[3])<<8|int(record[4])) {
		return edgeRefuse(checkE1, "record length does not match its framing")
	}
	if tlsMaxCiphertextBytes < len(record)-tlsRecordHeaderBytes {
		return edgeRefuse(checkE1, "record too long")
	}
	return nil
}

// Ends the gate, so that nothing passes after a refusal. The caller ends the connection on any error,
// and a gate that went on would leave "nothing after a refusal" to the caller alone.
func (self *edgeSession) endWithLock() {
	self.phase = edgePhaseEnded
}

// As endWithLock, from outside the lock.
func (self *edgeSession) end() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.endWithLock()
}

// ClientRecord of sidecar.SmtpProofSession.
func (self *edgeSession) ClientRecord(record []byte) ([][]byte, error) {
	testHookBarrier("edge.client_record.before", "")
	forward, err := func() ([][]byte, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		forward, err := self.clientRecordWithLock(record)
		if err != nil {
			self.endWithLock()
			return nil, err
		}
		self.handedClientSeq = self.nextClientSeq
		return forward, nil
	}()
	testHookBarrier("edge.client_record.after", "")
	return forward, err
}

func (self *edgeSession) clientRecordWithLock(record []byte) ([][]byte, error) {
	if err := edgeCheckFraming(record); err != nil {
		return nil, err
	}
	switch self.phase {
	case edgePhaseClientHello:
		return self.clientHelloWithLock(record)
	case edgePhaseServerHello, edgePhaseFlight12, edgePhaseServerFinished12:
		return nil, edgeRefuse(checkE1, "client record out of turn")
	case edgePhaseFlight13, edgePhaseClientFinished13:
		return self.clientFlight13WithLock(record)
	case edgePhaseClientFlight12:
		return self.clientFlight12WithLock(record)
	case edgePhaseApplication:
		return self.clientApplicationWithLock(record)
	default:
		return nil, errors.New("connection has ended")
	}
}

func (self *edgeSession) clientHelloWithLock(record []byte) ([][]byte, error) {
	if record[0] != tlsRecordHandshake {
		return nil, edgeRefuse(checkE1, "first client record is not a handshake record")
	}
	self.clientBuffer.add(record[tlsRecordHeaderBytes:])
	message := self.clientBuffer.next()
	if message == nil {
		if self.settings.maxHandshakeBytes < len(self.clientBuffer.pending) {
			return nil, edgeRefuse(checkE1, "handshake too long")
		}
		return [][]byte{record}, nil
	}
	if message[0] != tlsHandshakeClientHello || !self.clientBuffer.empty() {
		return nil, edgeRefuse(checkE1, "first client message is not a lone ClientHello")
	}
	hello, err := tlsParseClientHello(message[4:])
	if err != nil {
		return nil, edgeRefuse(checkE1, "%v", err)
	}
	for _, extensionId := range []uint16{tlsExtensionPreSharedKey, tlsExtensionEarlyData, tlsExtensionSessionTicket} {
		if hello.hasExtension(extensionId) {
			return nil, edgeRefuse(checkE1, "ClientHello offers extension %d", extensionId)
		}
	}
	if len(hello.sessionId) != 0 {
		return nil, edgeRefuse(checkE1, "ClientHello carries a session id")
	}
	if hello.serverName != self.mxHost {
		return nil, edgeRefuse(checkE1, "SNI is not the MX host")
	}
	if self.helloRetried {
		if !bytes.Equal(hello.random, self.clientRandom) {
			return nil, edgeRefuse(checkE1, "retried ClientHello changes its random")
		}
	} else {
		self.clientRandom = hello.random
	}
	if err := self.addTranscriptWithLock(message); err != nil {
		return nil, err
	}
	self.phase = edgePhaseServerHello
	return [][]byte{record}, nil
}

// ServerRecord of sidecar.SmtpProofSession.
func (self *edgeSession) ServerRecord(record []byte) error {
	testHookBarrier("edge.server_record.before", "")
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if err := self.serverRecordWithLock(record); err != nil {
			self.endWithLock()
			return err
		}
		return nil
	}()
	testHookBarrier("edge.server_record.after", "")
	return err
}

func (self *edgeSession) serverRecordWithLock(record []byte) error {
	if err := edgeCheckFraming(record); err != nil {
		return err
	}
	switch self.phase {
	case edgePhaseClientHello:
		// a retry's dummy change_cipher_spec comes ahead of the second ClientHello, which the server is
		// still waiting for
		if self.helloRetried && record[0] == tlsRecordChangeCipherSpec && tlsDummyChangeCipherSpec(record) {
			return nil
		}
		return edgeRefuse(checkE1, "server record before ClientHello")
	case edgePhaseServerHello:
		return self.serverHelloWithLock(record)
	case edgePhaseClientFlight12:
		return edgeRefuse(checkE1, "server record out of turn")
	case edgePhaseFlight13:
		if record[0] == tlsRecordChangeCipherSpec && tlsDummyChangeCipherSpec(record) {
			return nil
		}
		if record[0] != tlsRecordApplicationData {
			return edgeRefuse(checkE1, "unexpected record type %d in the flight", record[0])
		}
		self.flightRecords = append(self.flightRecords, record)
		self.serverRecordBytes += len(record)
		if self.settings.maxServerBytes < self.serverRecordBytes {
			return edgeRefuse(checkE1, "server flight too long")
		}
		return nil
	case edgePhaseFlight12:
		return self.serverFlight12WithLock(record)
	case edgePhaseServerFinished12:
		return self.serverFinished12WithLock(record)
	case edgePhaseClientFinished13, edgePhaseApplication:
		return self.serverApplicationWithLock(record)
	default:
		return errors.New("connection has ended")
	}
}

func (self *edgeSession) serverHelloWithLock(record []byte) error {
	// a 1.3 server may send a dummy change_cipher_spec right after a retry
	if record[0] == tlsRecordChangeCipherSpec && self.helloRetried && tlsDummyChangeCipherSpec(record) {
		return nil
	}
	if record[0] != tlsRecordHandshake {
		return edgeRefuse(checkE1, "unexpected record type %d for ServerHello", record[0])
	}
	self.serverBuffer.add(record[tlsRecordHeaderBytes:])
	message := self.serverBuffer.next()
	if message == nil {
		// a ServerHello can declare up to 16 MiB, and an MX is anyone a sidecar mails
		if self.settings.maxHandshakeBytes < len(self.serverBuffer.pending) {
			return edgeRefuse(checkE1, "handshake too long")
		}
		return nil
	}
	if message[0] != tlsHandshakeServerHello {
		return edgeRefuse(checkE1, "expected ServerHello")
	}
	hello, err := tlsParseServerHello(message[4:])
	if err != nil {
		return edgeRefuse(checkE1, "%v", err)
	}
	if hello.retryRequest {
		if self.helloRetried || hello.version != tlsVersion13 {
			return edgeRefuse(checkE1, "bad hello retry request")
		}
		self.helloRetried = true
		firstHash := sha256.Sum256(self.transcript)
		self.transcript = nil
		if err := self.addTranscriptWithLock(tlsHandshakeMessage(tlsHandshakeMessageHash, firstHash[:])); err != nil {
			return err
		}
		if err := self.addTranscriptWithLock(message); err != nil {
			return err
		}
		self.phase = edgePhaseClientHello
		return nil
	}
	if !tlsSuiteCovered(hello.version, hello.suite) {
		return edgeRefuse(checkE1, "version %#x suite %#x is not covered", hello.version, hello.suite)
	}
	if hello.hasExtension(tlsExtensionPreSharedKey) {
		return edgeRefuse(checkE1, "ServerHello selects a psk")
	}
	if err := self.addTranscriptWithLock(message); err != nil {
		return err
	}
	self.version = hello.version
	self.suite = hello.suite
	self.serverRandom = hello.random
	if hello.version == tlsVersion13 {
		if !self.serverBuffer.empty() {
			return edgeRefuse(checkE1, "a handshake message spans the key change")
		}
		sum := sha256.Sum256(self.transcript)
		self.helloHash = sum[:]
		self.phase = edgePhaseFlight13
		return nil
	}
	if hello.hasExtension(tlsExtensionSessionTicket) {
		return edgeRefuse(checkE1, "ServerHello takes a session ticket")
	}
	self.phase = edgePhaseFlight12
	// ServerHello may share its record with what follows
	return self.drainServerFlight12WithLock()
}

func (self *edgeSession) clientFlight13WithLock(record []byte) ([][]byte, error) {
	if record[0] == tlsRecordChangeCipherSpec {
		if self.clientChangeSeen || !tlsDummyChangeCipherSpec(record) {
			return nil, edgeRefuse(checkE1, "more than one client change_cipher_spec")
		}
		self.clientChangeSeen = true
		return [][]byte{record}, nil
	}
	if record[0] != tlsRecordApplicationData || self.clientFinishedRecord != nil {
		return nil, edgeRefuse(checkE1, "the client's flight is one Finished record")
	}
	// held until E2 opens the flight: its length depends on whether a CertificateRequest was in it
	self.clientFinishedRecord = record
	if self.phase == edgePhaseClientFinished13 {
		return self.releaseClientFinishedWithLock()
	}
	return nil, nil
}

// E1 over the client's second flight, once both it and E2 have arrived.
func (self *edgeSession) releaseClientFinishedWithLock() ([][]byte, error) {
	if len(self.clientFinishedRecord) != self.clientFlightBytes {
		return nil, edgeRefuse(checkE1, "the client's flight is not one Finished record")
	}
	self.phase = edgePhaseApplication
	return [][]byte{self.clientFinishedRecord}, nil
}

func (self *edgeSession) serverFlight12WithLock(record []byte) error {
	if record[0] != tlsRecordHandshake {
		return edgeRefuse(checkE1, "unexpected record type %d in the flight", record[0])
	}
	self.serverBuffer.add(record[tlsRecordHeaderBytes:])
	if self.settings.maxHandshakeBytes < len(self.serverBuffer.pending) {
		return edgeRefuse(checkE1, "handshake too long")
	}
	return self.drainServerFlight12WithLock()
}

// Reads whole 1.2 flight messages: Certificate, ServerKeyExchange, optional CertificateRequest,
// ServerHelloDone, in that order and nothing else (E1).
func (self *edgeSession) drainServerFlight12WithLock() error {
	for {
		message := self.serverBuffer.next()
		if message == nil {
			return nil
		}
		switch {
		case self.serverCertificate == nil:
			if message[0] != tlsHandshakeCertificate {
				return edgeRefuse(checkE1, "expected Certificate")
			}
			certificates, err := tlsParseCertificate(tlsVersion12, message[4:])
			if err != nil {
				return edgeRefuse(checkE1, "%v", err)
			}
			if self.serverCertificate, err = x509.ParseCertificate(certificates[0]); err != nil {
				return edgeRefuse(checkE2, "%v", err)
			}
		case self.preFinishedState == nil && message[0] == tlsHandshakeServerKeyExchange:
			_, _, params, scheme, signature, err := tlsParseServerKeyExchange(message[4:])
			if err != nil {
				return edgeRefuse(checkE1, "%v", err)
			}
			signed := make([]byte, 0, 2*tlsRandomBytes+len(params))
			signed = append(signed, self.clientRandom...)
			signed = append(signed, self.serverRandom...)
			signed = append(signed, params...)
			if err := tlsVerifySignature(tlsVersion12, self.serverCertificate.PublicKey, scheme, signed, signature); err != nil {
				return edgeRefuse(checkE2, "%v", err)
			}
			// marks the signature as checked until the real state replaces this
			self.preFinishedState = &sha256State{}
		case self.preFinishedState != nil && message[0] == tlsHandshakeCertificateRequest:
			self.certificateRequested = true
		case self.preFinishedState != nil && message[0] == tlsHandshakeServerHelloDone:
			if err := self.addTranscriptWithLock(message); err != nil {
				return err
			}
			if !self.serverBuffer.empty() {
				return edgeRefuse(checkE1, "a handshake message follows ServerHelloDone")
			}
			self.phase = edgePhaseClientFlight12
			return nil
		default:
			return edgeRefuse(checkE1, "unexpected handshake message %d in the flight", message[0])
		}
		if err := self.addTranscriptWithLock(message); err != nil {
			return err
		}
	}
}

func (self *edgeSession) clientFlight12WithLock(record []byte) ([][]byte, error) {
	switch record[0] {
	case tlsRecordHandshake:
		if self.clientChangeSeen {
			// the record after change_cipher_spec is the client's Finished, encrypted
			if len(record) != tlsRecordHeaderBytes+tlsExplicitNonceBytes+4+tlsVerifyData12Bytes+tlsAeadTagBytes {
				return nil, edgeRefuse(checkE1, "client Finished has the wrong length")
			}
			state, err := newSha256State(self.transcript)
			if err != nil {
				return nil, err
			}
			self.preFinishedState = state
			self.phase = edgePhaseServerFinished12
			return [][]byte{record}, nil
		}
		self.clientBuffer.add(record[tlsRecordHeaderBytes:])
		for {
			message := self.clientBuffer.next()
			if message == nil {
				return [][]byte{record}, nil
			}
			switch message[0] {
			case tlsHandshakeCertificate:
				if !self.certificateRequested || !bytes.Equal(message[4:], []byte{0, 0, 0}) {
					return nil, edgeRefuse(checkE1, "client sent a Certificate other than an empty answer")
				}
			case tlsHandshakeClientKeyExchange:
				if self.clientExchangeSeen {
					return nil, edgeRefuse(checkE1, "a second ClientKeyExchange")
				}
				self.clientExchangeSeen = true
			default:
				return nil, edgeRefuse(checkE1, "unexpected client handshake message %d", message[0])
			}
			if err := self.addTranscriptWithLock(message); err != nil {
				return nil, err
			}
		}
	case tlsRecordChangeCipherSpec:
		if self.clientChangeSeen || !self.clientExchangeSeen || !tlsDummyChangeCipherSpec(record) || !self.clientBuffer.empty() {
			return nil, edgeRefuse(checkE1, "bad client change_cipher_spec")
		}
		self.clientChangeSeen = true
		return [][]byte{record}, nil
	default:
		return nil, edgeRefuse(checkE1, "unexpected record type %d in the client's flight", record[0])
	}
}

func (self *edgeSession) serverFinished12WithLock(record []byte) error {
	if record[0] == tlsRecordChangeCipherSpec && tlsDummyChangeCipherSpec(record) && self.serverFinishedRecord == nil {
		return nil
	}
	if record[0] != tlsRecordHandshake {
		return edgeRefuse(checkE1, "expected the server's Finished")
	}
	if len(record) != tlsRecordHeaderBytes+tlsExplicitNonceBytes+4+tlsVerifyData12Bytes+tlsAeadTagBytes {
		return edgeRefuse(checkE1, "server Finished has the wrong length")
	}
	self.serverFinishedRecord = record
	self.session = &sessionStatement{
		version:              tlsVersion12,
		suite:                self.suite,
		preamble:             self.preamble,
		clientRandom:         self.clientRandom,
		serverRandom:         self.serverRandom,
		preFinishedState:     self.preFinishedState,
		serverFinishedRecord: record,
	}
	// the client's Finished took sequence number 0 in each direction
	self.firstSeq = 1
	self.nextClientSeq = 1
	self.nextRecord = 1
	self.phase = edgePhaseApplication
	return nil
}

// DiscloseShts of sidecar.SmtpProofSession: runs E2 over the flight, then releases the client's
// Finished. shts is never kept: only its hash survives, as Z1's public input.
func (self *edgeSession) DiscloseShts(shts []byte) ([][]byte, error) {
	// HMAC pads a short key with zeros, so any other length of the same secret would open the flight
	if len(shts) != tlsSecretBytes {
		self.end()
		return nil, edgeRefuse(checkE2, "SHTS has the wrong length")
	}
	testHookSecret("edge_shts", shts)
	// the hooks run with no lock held, so the keys are derived first; the suite never changes once set
	suite := func() uint16 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.suite
	}()
	key, iv := tls13TrafficKeys(suite, shts)
	testHookSecret("edge_server_handshake_key", key)
	testHookSecret("edge_server_handshake_iv", iv)

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	forward, err := self.discloseShtsWithLock(shts, key, iv)
	if err != nil {
		self.endWithLock()
		return nil, err
	}
	return forward, nil
}

// E2 over the 1.3 flight under the server handshake key and IV that shts gives.
func (self *edgeSession) discloseShtsWithLock(shts []byte, key []byte, iv []byte) ([][]byte, error) {
	if self.phase != edgePhaseFlight13 {
		return nil, edgeRefuse(checkE2, "SHTS disclosed out of turn")
	}
	cipher, err := newTlsCipher(tlsVersion13, self.suite, key, iv)
	if err != nil {
		return nil, err
	}
	var leaf *x509.Certificate
	certificateRequested := false
	verified := false
	finished := false
	consumed := 0
	for !finished {
		if consumed == len(self.flightRecords) {
			return nil, edgeRefuse(checkE2, "the server's flight ended without Finished")
		}
		recordType, content, err := cipher.open(self.flightRecords[consumed])
		consumed += 1
		if err != nil {
			return nil, edgeRefuse(checkE2, "the disclosed SHTS does not open the server's flight")
		}
		if recordType != tlsRecordHandshake {
			return nil, edgeRefuse(checkE2, "the server's flight holds inner type %d", recordType)
		}
		self.serverBuffer.add(content)
		for {
			message := self.serverBuffer.next()
			if message == nil {
				break
			}
			switch message[0] {
			case tlsHandshakeEncryptedExtension:
			case tlsHandshakeCertificateRequest:
				certificateRequested = true
			case tlsHandshakeCertificate:
				certificates, err := tlsParseCertificate(tlsVersion13, message[4:])
				if err != nil {
					return nil, edgeRefuse(checkE2, "%v", err)
				}
				if leaf, err = x509.ParseCertificate(certificates[0]); err != nil {
					return nil, edgeRefuse(checkE2, "%v", err)
				}
			case tlsHandshakeCertificateVerify:
				if leaf == nil {
					return nil, edgeRefuse(checkE2, "CertificateVerify before Certificate")
				}
				input := cryptobyte.String(message[4:])
				var scheme uint16
				var signature cryptobyte.String
				if !input.ReadUint16(&scheme) || !input.ReadUint16LengthPrefixed(&signature) || !input.Empty() {
					return nil, edgeRefuse(checkE2, "malformed CertificateVerify")
				}
				hash := sha256.Sum256(self.transcript)
				if err := tlsVerifySignature(tlsVersion13, leaf.PublicKey, scheme, tlsCertificateVerifySigned(hash[:]), signature); err != nil {
					return nil, edgeRefuse(checkE2, "%v", err)
				}
				verified = true
			case tlsHandshakeFinished:
				if !verified {
					return nil, edgeRefuse(checkE2, "Finished before CertificateVerify")
				}
				hash := sha256.Sum256(self.transcript)
				if !hmac.Equal(message[4:], tls13FinishedData(shts, hash[:])) {
					return nil, edgeRefuse(checkE2, "the server's Finished does not verify under the disclosed SHTS")
				}
				finished = true
			default:
				return nil, edgeRefuse(checkE2, "unexpected message %d in the server's flight", message[0])
			}
			if err := self.addTranscriptWithLock(message); err != nil {
				return nil, err
			}
		}
	}
	if !self.serverBuffer.empty() {
		return nil, edgeRefuse(checkE2, "a handshake message spans the key change")
	}

	// E1: the client's flight is its Finished, plus an empty Certificate if one was asked for
	contentBytes := 4 + tlsFinished13Bytes
	if certificateRequested {
		contentBytes += 8
	}
	self.clientFlightBytes = tlsRecordHeaderBytes + contentBytes + tlsInnerTypeBytes + tlsAeadTagBytes

	shtsHash := sha256.Sum256(shts)
	finishedHash := sha256.Sum256(self.transcript)
	self.session = &sessionStatement{
		version:      tlsVersion13,
		suite:        self.suite,
		preamble:     self.preamble,
		shtsHash:     shtsHash[:],
		helloHash:    self.helloHash,
		finishedHash: finishedHash[:],
	}
	// whatever followed Finished in the buffer is application traffic
	self.serverRecords = self.flightRecords[consumed:]
	self.flightRecords = nil
	self.phase = edgePhaseClientFinished13
	if self.clientFinishedRecord != nil {
		return self.releaseClientFinishedWithLock()
	}
	return nil, nil
}

func (self *edgeSession) serverApplicationWithLock(record []byte) error {
	if self.version == tlsVersion12 {
		switch record[0] {
		case tlsRecordApplicationData:
		case tlsRecordAlert:
			// the MX is closing; nothing a part could cover is left
			self.mxClosed = true
			return nil
		default:
			return edgeRefuse(checkE1, "server record of type %d after the handshake", record[0])
		}
	} else if record[0] != tlsRecordApplicationData {
		return edgeRefuse(checkE1, "server record of outer type %d after the handshake", record[0])
	}
	self.serverRecordBytes += len(record)
	if self.settings.maxServerBytes < self.serverRecordBytes {
		return edgeRefuse(checkE3, "more server records than any part could cover")
	}
	self.serverRecords = append(self.serverRecords, record)
	return nil
}

// ServerClosed of sidecar.SmtpProofSession.
func (self *edgeSession) ServerClosed() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mxClosed = true
}

func (self *edgeSession) clientApplicationWithLock(record []byte) ([][]byte, error) {
	if self.finished {
		// such as a close_notify: it ends the connection unforwarded, and is no cut (14.7)
		self.phase = edgePhaseEnded
		return nil, errors.New("client record after the final QUIT")
	}
	if record[0] != tlsRecordApplicationData {
		return nil, edgeRefuse(checkE1, "client record of type %d after the handshake", record[0])
	}
	if version := uint16(record[1])<<8 | uint16(record[2]); version != tlsVersion12 {
		return nil, edgeRefuse(checkE1, "client record of version %#x after the handshake", version)
	}
	self.heldRecords = append(self.heldRecords, record)
	self.heldBytes += len(record)
	if self.settings.maxHeldBytes < self.heldBytes {
		return nil, edgeRefuse(checkE3, "more client records held than any part could clear")
	}
	return self.releaseWithLock()
}

// The verified part covering a client sequence number, if any. A part that opens no client record
// covers none.
func (self *edgeSession) coveringPartWithLock(seq uint64) *edgePart {
	for _, part := range self.parts {
		if 0 < len(part.part.Records) && part.part.FirstRecord <= seq && seq <= part.part.LastRecord {
			return part
		}
	}
	return nil
}

// Runs E3 over held records in order, returning those now cleared for the MX (DESIGN-DETAILS 3.2.5 step
// 16): each leaves while a part covers it, equal to the ciphertext that part proved if opened, keeping
// BDAT's chunk within octet n, and, a message record, only when every relayed server record is covered.
func (self *edgeSession) releaseWithLock() ([][]byte, error) {
	var forward [][]byte
	for 0 < len(self.heldRecords) {
		record := self.heldRecords[0]
		seq := self.nextClientSeq
		part := self.coveringPartWithLock(seq)
		if part == nil {
			return forward, nil
		}
		opened, isOpened := part.openedRecords[seq]
		carried := uint64(0)
		if isOpened {
			if !bytes.Equal(opened.raw, record) {
				return nil, edgeCut("record %d is not the ciphertext its part proved", seq)
			}
			carried = opened.chunkOctets
		} else {
			// only BDAT's body is unopened, so this is its count bound (E3 step 4)
			var err error
			if carried, err = self.maxBodyOctets(record); err != nil {
				return nil, err
			}
		}
		if self.preamble.messageByteCount < self.chunkOctets+carried {
			return nil, edgeCut("a chunk record passes octet %d", self.preamble.messageByteCount)
		}
		// held, never cut: a later part, which may open no client record, clears it (E3 step 5)
		if (!isOpened || opened.message) && self.coveredServer < uint64(len(self.serverRecords)) {
			return forward, nil
		}
		self.chunkOctets += carried
		if isOpened && opened.quit {
			if self.mode == partModeBdat && self.chunkOctets != self.preamble.messageByteCount {
				return nil, edgeCut("BDAT's chunk holds %d octets at QUIT, want %d", self.chunkOctets, self.preamble.messageByteCount)
			}
			self.finished = true
		}
		forward = append(forward, record)
		self.heldRecords = self.heldRecords[1:]
		self.heldBytes -= len(record)
		self.nextClientSeq += 1
	}
	return forward, nil
}

// The most chunk octets a body record can carry to the MX (SPEC.md 9.5).
func (self *edgeSession) maxBodyOctets(record []byte) (uint64, error) {
	overhead := tlsRecordHeaderBytes + tlsAeadTagBytes + tlsInnerTypeBytes
	if self.version == tlsVersion12 {
		overhead = tlsRecordHeaderBytes + tlsAeadTagBytes + tlsExplicitNonceBytes
	}
	if len(record) < overhead {
		return 0, edgeCut("a body record too short to carry an octet")
	}
	return uint64(len(record) - overhead), nil
}

// The content length of an opened client record. A 1.3 record has at least its type octet.
func (self *edgeSession) contentBytes(record []byte) (int, error) {
	ciphertext, err := recordCiphertext(self.version, record)
	if err != nil {
		return 0, err
	}
	if self.version == tlsVersion13 {
		if len(ciphertext) == 0 {
			return 0, errors.New("record holds no type octet")
		}
		return len(ciphertext) - tlsInnerTypeBytes, nil
	}
	return len(ciphertext), nil
}

// Whether two parts are the same part, field for field and octet for octet: an exact resend.
func edgePartsEqual(a *sidecar.SmtpProofPart, b *sidecar.SmtpProofPart) bool {
	return bytes.Equal(a.SendId, b.SendId) && a.Index == b.Index && a.Mode == b.Mode &&
		a.FirstRecord == b.FirstRecord && a.LastRecord == b.LastRecord && bytes.Equal(a.Proof, b.Proof) &&
		a.Last == b.Last && a.ServerRecordCount == b.ServerRecordCount &&
		slices.EqualFunc(a.Records, b.Records, bytes.Equal) && bytes.Equal(a.KeyCommitment, b.KeyCommitment) &&
		a.ReplyCount == b.ReplyCount && a.HeaderRecordCount == b.HeaderRecordCount && bytes.Equal(a.Carry, b.Carry)
}

// DESIGN-DETAILS 3.2.5's steps 2 to 12, under stateLock: the part's order, ranges, roles, counts,
// lengths and carry, then its shape and the statement it verifies against, built from the gate's state
// and never from the part. It returns no part and no error for an exact resend of the latest, which is a
// no-op. Any refusal ends the session.
func (self *edgeSession) preparePartWithLock(part *sidecar.SmtpProofPart) (*edgePart, error) {
	proof := self.settings.proof
	// 2: a part may overtake the client's Finished, whose stream it is not ordered against; it can only
	// verify once the session's inputs exist
	if self.session == nil {
		return nil, edgeRefuse(checkE3, "part before the handshake finished")
	}
	// 3: an exact resend of the latest is a no-op, and nothing else replaces a verified part
	switch {
	case part.Index != 0 && int(part.Index) == len(self.parts):
		if edgePartsEqual(part, self.parts[len(self.parts)-1].part) {
			return nil, nil
		}
		return nil, edgeRefuse(checkE3, "part %d changed after it was verified", part.Index)
	case int(part.Index) != len(self.parts)+1:
		return nil, edgeRefuse(checkE3, "part %d after part %d", part.Index, len(self.parts))
	case proof.PartMaxCount < int(part.Index):
		return nil, edgeRefuse(checkE3, "more than %d parts", proof.PartMaxCount)
	}
	finished := 0 < len(self.parts) && self.parts[len(self.parts)-1].part.Last

	// 4: the key part opens EHLO and carries C; no other part carries a key commitment
	if part.Index == 1 {
		if len(part.Records) != 1 || part.FirstRecord != self.firstSeq || part.LastRecord != self.firstSeq ||
			part.Mode != partModeNone || part.ServerRecordCount != 0 || part.ReplyCount != 0 ||
			part.HeaderRecordCount != 0 || len(part.Carry) != 0 || part.Last {
			return nil, edgeRefuse(checkE3, "the key part opens the EHLO record alone, and covers and names nothing else")
		}
		if _, err := decodeCommitment(part.KeyCommitment); err != nil {
			return nil, edgeRefuse(checkE3, "the key part's commitment: %v", err)
		}
	} else if len(part.KeyCommitment) != 0 {
		return nil, edgeRefuse(checkE3, "part %d carries a key commitment", part.Index)
	}

	// 5: the client range, from the next record on, or none
	if part.FirstRecord != self.nextRecord {
		return nil, edgeRefuse(checkE3, "part starts at record %d, want %d", part.FirstRecord, self.nextRecord)
	}
	statement := &partStatement{
		session:                   self.session,
		index:                     part.Index,
		mode:                      part.Mode,
		firstRecord:               part.FirstRecord,
		lastRecord:                part.LastRecord,
		last:                      part.Last,
		previousServerRecordCount: self.coveredServer,
		serverRecordCount:         part.ServerRecordCount,
		replyCount:                part.ReplyCount,
		repliesProven:             self.repliesProven,
		headerRecordCount:         self.headerRecords,
	}
	if len(part.Records) == 0 {
		if part.LastRecord+1 != part.FirstRecord || part.Last {
			return nil, edgeRefuse(checkE3, "a part that opens no record has last_record = first_record - 1, and is not the last")
		}
	} else {
		if finished {
			return nil, edgeRefuse(checkE3, "after the last part, only a part that opens no record")
		}
		if proof.PartRecordMaxCount < len(part.Records) {
			return nil, edgeRefuse(checkE3, "a part opens at most %d records", proof.PartRecordMaxCount)
		}
		for i, record := range part.Records {
			if err := edgeCheckFraming(record); err != nil {
				return nil, err
			}
			// the outer type is public and the circuit sees only ciphertext, so this is the gate's to check
			// before any verification: such a record could never equal one E1 lets through
			if record[0] != tlsRecordApplicationData {
				return nil, edgeRefuse(checkE3, "a part's record %d is not application_data", i)
			}
			seq := part.FirstRecord + uint64(i)
			// BDAT's last part carries QUIT alone at last_record, past the unopened body
			if part.Mode == partModeBdat && part.Last && i == len(part.Records)-1 {
				if part.LastRecord < seq {
					return nil, edgeRefuse(checkE3, "QUIT before the part's other records")
				}
				seq = part.LastRecord
			}
			statement.clientRecords = append(statement.clientRecords, &partRecord{seq: seq, raw: record})
		}
		if statement.clientRecords[len(statement.clientRecords)-1].seq != part.LastRecord {
			return nil, edgeRefuse(checkE3, "part's records do not reach last_record")
		}
	}

	// 6: the server range, from what is covered, at most what was relayed
	if part.ServerRecordCount < self.coveredServer {
		return nil, edgeRefuse(checkE3, "server_record_count fell")
	}
	if uint64(len(self.serverRecords)) < part.ServerRecordCount {
		return nil, edgeRefuse(checkE3, "part covers server records never relayed")
	}
	if len(part.Records) == 0 && part.ServerRecordCount == self.coveredServer {
		return nil, edgeRefuse(checkE3, "a part that opens no record covers at least one more server record")
	}
	for i := self.coveredServer; i < part.ServerRecordCount; i += 1 {
		statement.serverRecords = append(statement.serverRecords, &partRecord{seq: self.firstSeq + i, raw: self.serverRecords[i]})
	}

	// 7: part 2 names the mode, and every later part repeats it
	switch {
	case part.Index == 2 && part.Mode != partModeBdat && part.Mode != partModeData:
		return nil, edgeRefuse(checkE3, "unknown mode %d", part.Mode)
	case 2 < part.Index && part.Mode != self.mode:
		return nil, edgeRefuse(checkE3, "mode changed after part 2")
	}

	// 8: roles by position and the part's kind; k on the part that opens the header block's first record
	recipients := uint64(self.preamble.recipientCount)
	headerFirst := self.firstSeq + 3 + recipients
	opensHeaderFirst := 1 < part.Index && slices.ContainsFunc(statement.clientRecords, func(record *partRecord) bool { return record.seq == headerFirst })
	switch {
	case opensHeaderFirst && (part.HeaderRecordCount < 1 || uint32(proof.HeaderRecordMaxCount) < part.HeaderRecordCount):
		return nil, edgeRefuse(checkE3, "header_record_count %d is outside 1 to %d", part.HeaderRecordCount, proof.HeaderRecordMaxCount)
	case !opensHeaderFirst && part.HeaderRecordCount != 0:
		return nil, edgeRefuse(checkE3, "header_record_count on a part that does not open the header block's first record")
	case opensHeaderFirst:
		statement.headerRecordCount = part.HeaderRecordCount
	}
	roles, err := partRoles(statement)
	if err != nil {
		return nil, edgeRefuse(checkE3, "%v", err)
	}
	kind, err := partKindOf(statement, roles)
	if err != nil {
		return nil, edgeRefuse(checkE3, "%v", err)
	}

	// 9: replies, against the commands opened so far
	gated := &edgePart{
		part:             part,
		statement:        statement,
		openedRecords:    map[uint64]*edgeOpenedRecord{},
		dataOctets:       self.dataOctets,
		commits:          self.partCommits,
		namesHeaderCount: opensHeaderFirst,
	}
	opensFirstMessage := false
	for i, role := range roles {
		switch role {
		case recordRoleEhlo, recordRoleMail, recordRoleRcpt, recordRoleData:
			gated.commands += 1
		case recordRoleBdat:
			opensFirstMessage = true
		case recordRoleHeaderBlock:
			gated.opensScan = true
			ordinal := headerOrdinal(statement, statement.clientRecords[i].seq)
			if ordinal == 1 && part.Mode == partModeData {
				opensFirstMessage = true
			}
			if ordinal == int(statement.headerRecordCount) {
				gated.opensLastHeader = true
			}
		case recordRoleBody:
			gated.opensScan = true
		}
	}
	coversMore := self.coveredServer < part.ServerRecordCount
	switch {
	case part.Index == 1:
	case part.Index == 2:
		if part.ReplyCount != 1 || !coversMore || len(roles) == 0 || roles[0] != recordRoleMail {
			return nil, edgeRefuse(checkE3, "part 2 proves the EHLO reply alone, as one reply, and opens MAIL")
		}
	case self.commandsCovered-self.repliesProven < part.ReplyCount:
		return nil, edgeRefuse(checkE3, "%d replies where %d commands are unanswered", part.ReplyCount, self.commandsCovered-self.repliesProven)
	case !coversMore && part.ReplyCount != 0:
		return nil, edgeRefuse(checkE3, "replies with no server record")
	}
	if opensFirstMessage {
		want := uint64(2) + recipients
		if part.Mode == partModeData {
			want += 1
		}
		if uint64(self.repliesProven)+uint64(part.ReplyCount) != want {
			return nil, edgeRefuse(checkE3, "the first message record before the envelope's %d replies are proven", want)
		}
	}

	// 10: lengths: a template at each command's, the header records' least, and the declared count
	for i, role := range roles {
		record := statement.clientRecords[i]
		contentBytes, err := self.contentBytes(record.raw)
		if err != nil {
			return nil, edgeRefuse(checkE3, "%v", err)
		}
		// no template, no satisfying plaintext: refuse before spending a verification
		if _, err := commandTemplate(role, self.preamble, contentBytes); err != nil {
			return nil, edgeRefuse(checkE3, "%v", err)
		}
		opened := &edgeOpenedRecord{raw: record.raw}
		switch role {
		case recordRoleBdat, recordRoleEndMark:
			opened.message = true
		case recordRoleHeaderBlock, recordRoleBody:
			opened.message = true
			if contentBytes <= 0 {
				return nil, edgeRefuse(checkE3, "an empty message record")
			}
			if role == recordRoleHeaderBlock {
				minimum := proof.HeaderRecordMinByteCount
				if headerOrdinal(statement, record.seq) == int(statement.headerRecordCount) {
					minimum = proof.HeaderLastRecordMinByteCount
				}
				if contentBytes < minimum {
					return nil, edgeRefuse(checkE3, "a header record of %d octets, under %d", contentBytes, minimum)
				}
			}
			if part.Mode == partModeBdat {
				opened.chunkOctets = uint64(contentBytes)
			} else {
				gated.dataOctets += uint64(contentBytes)
			}
		case recordRoleQuit:
			opened.quit = true
		}
		gated.openedRecords[record.seq] = opened
	}
	if self.preamble.messageByteCount < gated.dataOctets {
		return nil, edgeRefuse(checkE3, "DATA octets pass the declared count")
	}
	if part.Mode == partModeData && part.Last && gated.dataOctets != self.preamble.messageByteCount {
		return nil, edgeRefuse(checkE3, "the last DATA part leaves the octet count short")
	}

	// 11: a carry on a part that opens a header or body record, and on no other
	if gated.opensScan {
		if _, err := decodeCommitment(part.Carry); err != nil {
			return nil, edgeRefuse(checkE3, "the part's carry: %v", err)
		}
	} else if len(part.Carry) != 0 {
		return nil, edgeRefuse(checkE3, "a carry on a part that opens no header or body record")
	}

	// 12: the statement, from the gate's state: C, the carry the part opens, and the part's own
	statement.keyCommitment = bytes.Clone(self.keyCommitment)
	if part.Index == 1 {
		statement.keyCommitment = bytes.Clone(part.KeyCommitment)
	}
	if kind == partKindHeader || kind == partKindBody {
		statement.carryIn = bytes.Clone(self.carry)
	}
	statement.carryOut = bytes.Clone(part.Carry)
	if kind == partKindBody && !gated.opensScan {
		// an empty body's last part opens no body record and leaves the state as it was
		statement.carryOut = bytes.Clone(self.carry)
	}
	if _, err := partShapeFor(proof, statement); err != nil {
		return nil, edgeRefuse(checkE3, "no shape holds part %d: %v", part.Index, err)
	}
	return gated, nil
}

// VerifyPart of sidecar.SmtpProofSession: DESIGN-DETAILS 3.2.5's gate, its fences in order. Each refusal
// ends the session; a proof that fails to verify is a cut (14.7), unless the MX has already closed,
// which makes the part moot. The verification runs with no lock held, and a part commits only if no
// other landed meanwhile.
func (self *edgeSession) VerifyPart(ctx context.Context, part *sidecar.SmtpProofPart) ([][]byte, error) {
	var gated *edgePart
	moot := false
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// 1
		if self.phase == edgePhaseEnded {
			return errors.New("connection has ended")
		}
		if self.mxClosed {
			moot = true
			return nil
		}
		var err error
		if gated, err = self.preparePartWithLock(part); err != nil {
			self.endWithLock()
		}
		return err
	}()
	if err != nil {
		return nil, err
	}
	if moot || gated == nil {
		return nil, nil
	}

	// 13: no lock held: this is the slow step, and server records may arrive during it
	testHookBarrier("edge.verify.before", "")
	err = self.verifier.verifyPart(ctx, gated.statement, part.Proof)
	testHookBarrier("edge.verify.after", "")
	if err != nil {
		self.end()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, edgeCut("part %d did not verify: %v", part.Index, err)
	}

	testHookBarrier("edge.commit.before", "")
	forward, err := func() ([][]byte, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		// 14: a refusal elsewhere while this verified ended the gate, and it releases nothing after one;
		// and the checks above stand only if no part landed since
		if self.phase == edgePhaseEnded {
			return nil, errors.New("connection has ended")
		}
		if gated.commits != self.partCommits {
			self.endWithLock()
			return nil, edgeRefuse(checkE3, "part %d verified while another landed", part.Index)
		}
		// 15
		self.parts = append(self.parts, gated)
		self.partCommits += 1
		if part.Index == 1 {
			self.keyCommitment = bytes.Clone(part.KeyCommitment)
		}
		if 0 < len(part.Records) {
			self.nextRecord = part.LastRecord + 1
		}
		self.coveredServer = part.ServerRecordCount
		self.repliesProven += part.ReplyCount
		self.commandsCovered += gated.commands
		if part.Index == 2 {
			self.mode = part.Mode
		}
		if gated.namesHeaderCount {
			self.headerRecords = part.HeaderRecordCount
		}
		if gated.opensScan {
			self.carry = bytes.Clone(part.Carry)
		}
		if gated.opensLastHeader {
			self.carry = scanStartCarry()
		}
		self.dataOctets = gated.dataOctets
		// 16
		forward, err := self.releaseWithLock()
		if err != nil {
			self.endWithLock()
			return nil, err
		}
		self.handedClientSeq = self.nextClientSeq
		return forward, nil
	}()
	testHookBarrier("edge.commit.after", "")
	return forward, err
}

// MailForwarded of sidecar.SmtpProofSession: whether the gate has handed its caller the MAIL record, the
// record at f+1, which is when §14.7 charges the connection a unit.
func (self *edgeSession) MailForwarded() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.firstSeq+1 < self.handedClientSeq
}
