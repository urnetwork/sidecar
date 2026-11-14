package checker

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

// What the edge saw of one connection, and the handshake checks over it: E1's shape and E2's
// signature, from which Z1's public inputs follow (SPEC.md sections 5 and 6).

// The declared values, the issued values and the two the edge derives (SPEC.md section 5).
type Preamble struct {
	RecipientDomain  string
	RecipientCount   uint32
	MessageId        string
	HeaderFromDomain string
	DkimSelector     string
	MessageByteCount uint64
	// 1 BULK, 2 REQUIRETLS, 4 BURNER.
	Flags          uint32
	HeloName       string
	XUrRef         string
	FeedbackId     string
	EnvelopeDomain string
	MxHost         string
}

// A part as the sidecar submitted it (DESIGN.md §14.5's SmtpProof, less its proof).
type Part struct {
	Index             uint32
	Mode              uint32
	FirstRecord       uint64
	LastRecord        uint64
	Last              bool
	ServerRecordCount uint64
	Records           [][]byte
	// Part 1 only: C, 64 octets.
	KeyCommitment []byte
}

// One thing the edge saw, in the order it saw it. Exactly one field is set.
type Event struct {
	ClientRecord []byte
	ServerRecord []byte
	Shts         []byte
	Part         *Part
	ServerClosed bool
}

type Transcript struct {
	Preamble *Preamble
	Events   []*Event
}

// One part's private witness, as the prover claims it (SPEC.md section 7).
type PartWitness struct {
	// 1.3.
	HandshakeSecret []byte
	// 1.2.
	MasterSecret []byte

	ClientKey []byte
	ClientIv  []byte
	ServerKey []byte
	ServerIv  []byte
	// rho, C's blind, big-endian.
	KeyBlind []byte
	// Each opened client record's plaintext, in 1.3 with its inner type octet.
	ClientPlaintexts [][]byte
	// Each covered server record's plaintext, likewise.
	ServerPlaintexts [][]byte
}

// One failed check: E1 to E3, Z1 to Z9, or "preamble" for SPEC.md section 6's forms.
type Failure struct {
	Check string
	// The event at which it failed.
	Event int
	// The part's index, or 0 for a check of the connection.
	Part   uint32
	Reason string
}

func (self *Failure) String() string {
	return fmt.Sprintf("%s at event %d part %d: %s", self.Check, self.Event, self.Part, self.Reason)
}

const (
	recordHeaderBytes = 5

	recordChangeCipherSpec uint8 = 20
	recordAlert            uint8 = 21
	recordHandshake        uint8 = 22
	recordApplicationData  uint8 = 23

	messageClientHello        uint8 = 1
	messageServerHello        uint8 = 2
	messageNewSessionTicket   uint8 = 4
	messageEncryptedExtension uint8 = 8
	messageCertificate        uint8 = 11
	messageServerKeyExchange  uint8 = 12
	messageCertificateRequest uint8 = 13
	messageServerHelloDone    uint8 = 14
	messageCertificateVerify  uint8 = 15
	messageClientKeyExchange  uint8 = 16
	messageFinished           uint8 = 20
	messageHash               uint8 = 254

	extensionServerName          uint16 = 0
	extensionSignatureAlgorithms uint16 = 13
	extensionSessionTicket       uint16 = 35
	extensionPreSharedKey        uint16 = 41
	extensionEarlyData           uint16 = 42
	extensionSupportedVersions   uint16 = 43
)

// SHA-256 of "HelloRetryRequest", a HelloRetryRequest's random (RFC 8446 §4.1.3).
var helloRetryRandom = func() []byte {
	sum := sha256.Sum256([]byte("HelloRetryRequest"))
	return sum[:]
}()

// The handshake's progress.
type handshakePhase uint8

const (
	phaseClientHello handshakePhase = iota
	phaseServerHello
	phaseFlight13
	phaseFlight12
	phaseClientFlight12
	phaseServerFinished12
	phaseApplication
)

// The handshake as the edge relayed it, and the inputs it gives Z1.
type handshake struct {
	preamble *Preamble
	phase    handshakePhase

	clientBuffer []byte
	serverBuffer []byte
	// The handshake messages so far, for Transcript-Hash.
	messages       []byte
	helloRetried   bool
	clientRandom   []byte
	serverRandom   []byte
	offeredSchemes []uint16
	version        uint16
	suite          uint16

	// 1.3.
	helloHash            []byte
	flight               [][]byte
	certificateRequested bool
	clientChange         bool
	clientFinished       []byte
	flightChecked        bool
	shtsHash             []byte
	finishedHash         []byte
	// Server records after the flight, which are the first application records.
	afterFlight [][]byte

	// 1.2.
	leaf             *x509.Certificate
	keyExchangeSeen  bool
	clientExchange   bool
	serverHelloDone  bool
	preFinished      []byte
	serverFinished12 []byte
}

// A record's type, its payload, and whether its framing is true.
func splitRecord(record []byte) (uint8, uint16, []byte, error) {
	if len(record) < recordHeaderBytes || len(record) != recordHeaderBytes+(int(record[3])<<8|int(record[4])) {
		return 0, 0, nil, errors.New("record framing")
	}
	return record[0], uint16(record[1])<<8 | uint16(record[2]), record[recordHeaderBytes:], nil
}

// Takes the next whole handshake message from a buffer, header included.
func nextMessage(buffer *[]byte) []byte {
	if len(*buffer) < 4 {
		return nil
	}
	size := 4 + (int((*buffer)[1])<<16 | int((*buffer)[2])<<8 | int((*buffer)[3]))
	if len(*buffer) < size {
		return nil
	}
	message := (*buffer)[:size:size]
	*buffer = (*buffer)[size:]
	return message
}

// Reads a ClientHello's body for E1.
func (self *handshake) clientHello(body []byte) error {
	input := cryptobyte.String(body)
	var legacyVersion uint16
	var random []byte
	var sessionId, suites, compression, extensions cryptobyte.String
	if !input.ReadUint16(&legacyVersion) || !input.ReadBytes(&random, 32) || !input.ReadUint8LengthPrefixed(&sessionId) ||
		!input.ReadUint16LengthPrefixed(&suites) || !input.ReadUint8LengthPrefixed(&compression) ||
		!input.ReadUint16LengthPrefixed(&extensions) || !input.Empty() {
		return errors.New("malformed ClientHello")
	}
	if len(sessionId) != 0 {
		return errors.New("ClientHello carries a session id")
	}
	seen := map[uint16]bool{}
	serverNames := 0
	serverName := ""
	var schemes []uint16
	for !extensions.Empty() {
		var id uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
			return errors.New("malformed extension")
		}
		if seen[id] {
			return fmt.Errorf("extension %d repeats", id)
		}
		seen[id] = true
		switch id {
		case extensionPreSharedKey, extensionEarlyData, extensionSessionTicket:
			return fmt.Errorf("ClientHello offers extension %d", id)
		case extensionServerName:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
				return errors.New("malformed server_name")
			}
			for !list.Empty() {
				var nameType uint8
				var name cryptobyte.String
				if !list.ReadUint8(&nameType) || !list.ReadUint16LengthPrefixed(&name) {
					return errors.New("malformed server_name")
				}
				serverNames += 1
				if nameType == 0 {
					serverName = string(name)
				}
			}
		case extensionSignatureAlgorithms:
			var list cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&list) || !data.Empty() {
				return errors.New("malformed signature_algorithms")
			}
			for !list.Empty() {
				var scheme uint16
				if !list.ReadUint16(&scheme) {
					return errors.New("malformed signature_algorithms")
				}
				schemes = append(schemes, scheme)
			}
		}
	}
	// exactly one name, the MX host, so no MX can read it as naming another
	if serverNames != 1 || serverName != self.preamble.MxHost {
		return errors.New("server_name is not exactly the MX host")
	}
	if self.helloRetried {
		self.offeredSchemes = slices.DeleteFunc(self.offeredSchemes, func(scheme uint16) bool { return !slices.Contains(schemes, scheme) })
	} else {
		self.offeredSchemes = schemes
		self.clientRandom = random
	}
	return nil
}

// Reads a ServerHello's body for E1, and whether it is a HelloRetryRequest.
func (self *handshake) serverHello(body []byte) (bool, error) {
	input := cryptobyte.String(body)
	var legacyVersion, suite uint16
	var random []byte
	var compression uint8
	var sessionId, extensions cryptobyte.String
	if !input.ReadUint16(&legacyVersion) || !input.ReadBytes(&random, 32) || !input.ReadUint8LengthPrefixed(&sessionId) ||
		!input.ReadUint16(&suite) || !input.ReadUint8(&compression) {
		return false, errors.New("malformed ServerHello")
	}
	version := legacyVersion
	seen := map[uint16]bool{}
	if !input.Empty() {
		if !input.ReadUint16LengthPrefixed(&extensions) || !input.Empty() {
			return false, errors.New("malformed ServerHello")
		}
		for !extensions.Empty() {
			var id uint16
			var data cryptobyte.String
			if !extensions.ReadUint16(&id) || !extensions.ReadUint16LengthPrefixed(&data) {
				return false, errors.New("malformed extension")
			}
			seen[id] = true
			if id == extensionSupportedVersions && (!data.ReadUint16(&version) || !data.Empty()) {
				return false, errors.New("malformed supported_versions")
			}
		}
	}
	if bytes.Equal(random, helloRetryRandom) {
		if self.helloRetried || version != versionTls13 {
			return false, errors.New("a HelloRetryRequest out of place")
		}
		return true, nil
	}
	switch {
	case version == versionTls13 && (suite == suiteAes128GcmSha256 || suite == suiteChacha20Poly1305Sha256):
		if seen[extensionPreSharedKey] {
			return false, errors.New("ServerHello selects a psk")
		}
	case version == versionTls12 && (suite == suiteEcdheRsaAes128GcmSha256 || suite == suiteEcdheEcdsaAes128GcmSha256):
		if seen[extensionSessionTicket] {
			return false, errors.New("ServerHello takes a session ticket")
		}
	default:
		return false, fmt.Errorf("version %#x suite %#x is not covered", version, suite)
	}
	if compression != 0 {
		return false, errors.New("ServerHello selects compression")
	}
	self.version = version
	self.suite = suite
	self.serverRandom = random
	return false, nil
}

// One client record during the handshake: E1's shape.
func (self *handshake) clientRecord(record []byte) error {
	recordType, _, payload, err := splitRecord(record)
	if err != nil {
		return err
	}
	switch self.phase {
	case phaseClientHello:
		if recordType != recordHandshake {
			return errors.New("the client's first record is not a handshake record")
		}
		self.clientBuffer = append(self.clientBuffer, payload...)
		message := nextMessage(&self.clientBuffer)
		if message == nil {
			return nil
		}
		if message[0] != messageClientHello || len(self.clientBuffer) != 0 {
			return errors.New("the client's first message is not a lone ClientHello")
		}
		if err := self.clientHello(message[4:]); err != nil {
			return err
		}
		self.messages = append(self.messages, message...)
		self.phase = phaseServerHello
		return nil
	case phaseFlight13:
		if recordType == recordChangeCipherSpec {
			if self.clientChange || !bytes.Equal(payload, []byte{1}) {
				return errors.New("a second or malformed client change_cipher_spec")
			}
			self.clientChange = true
			return nil
		}
		if recordType != recordApplicationData || self.clientFinished != nil {
			return errors.New("the client's second flight is one Finished record")
		}
		self.clientFinished = record
		return self.finishFlight13()
	case phaseClientFlight12:
		switch recordType {
		case recordChangeCipherSpec:
			if self.clientChange || !self.clientExchange || len(self.clientBuffer) != 0 || !bytes.Equal(payload, []byte{1}) {
				return errors.New("a client change_cipher_spec out of place")
			}
			self.clientChange = true
			return nil
		case recordHandshake:
			if self.clientChange {
				// the client's Finished, encrypted
				if len(record) != recordHeaderBytes+explicitNonceBytes+16+tagBytes {
					return errors.New("the client's Finished has the wrong length")
				}
				self.preFinished = append([]byte{}, self.messages...)
				self.phase = phaseServerFinished12
				return nil
			}
			self.clientBuffer = append(self.clientBuffer, payload...)
			for {
				message := nextMessage(&self.clientBuffer)
				if message == nil {
					return nil
				}
				switch {
				case message[0] == messageCertificate && self.certificateRequested && !self.clientExchange && bytes.Equal(message[4:], []byte{0, 0, 0}):
				case message[0] == messageClientKeyExchange && !self.clientExchange:
					self.clientExchange = true
				default:
					return fmt.Errorf("client message %d out of the flight's shape", message[0])
				}
				self.messages = append(self.messages, message...)
			}
		default:
			return fmt.Errorf("client record of type %d in its flight", recordType)
		}
	default:
		return errors.New("client record out of turn")
	}
}

// One server record during the handshake.
func (self *handshake) serverRecord(record []byte) error {
	recordType, _, payload, err := splitRecord(record)
	if err != nil {
		return err
	}
	dummyChange := recordType == recordChangeCipherSpec && bytes.Equal(payload, []byte{1})
	switch self.phase {
	case phaseClientHello:
		// a retry's dummy change_cipher_spec may come ahead of the second ClientHello
		if self.helloRetried && dummyChange {
			return nil
		}
		return errors.New("server record before the ClientHello")
	case phaseServerHello:
		if self.helloRetried && dummyChange {
			return nil
		}
		if recordType != recordHandshake {
			return errors.New("expected a ServerHello")
		}
		self.serverBuffer = append(self.serverBuffer, payload...)
		message := nextMessage(&self.serverBuffer)
		if message == nil {
			return nil
		}
		if message[0] != messageServerHello {
			return errors.New("expected a ServerHello")
		}
		retry, err := self.serverHello(message[4:])
		if err != nil {
			return err
		}
		if retry {
			// RFC 8446 §4.4.1: the first ClientHello is replaced by its hash
			first := sha256.Sum256(self.messages)
			self.messages = append([]byte{messageHash, 0, 0, 32}, first[:]...)
			self.messages = append(self.messages, message...)
			self.helloRetried = true
			self.phase = phaseClientHello
			return nil
		}
		self.messages = append(self.messages, message...)
		if self.version == versionTls13 {
			if len(self.serverBuffer) != 0 {
				return errors.New("a handshake message spans the key change")
			}
			sum := sha256.Sum256(self.messages)
			self.helloHash = sum[:]
			self.phase = phaseFlight13
			return nil
		}
		self.phase = phaseFlight12
		return self.drainFlight12()
	case phaseFlight13:
		if dummyChange {
			return nil
		}
		if recordType != recordApplicationData {
			return errors.New("the server's encrypted flight holds another record type")
		}
		if self.flightChecked {
			self.afterFlight = append(self.afterFlight, record)
			return nil
		}
		self.flight = append(self.flight, record)
		return nil
	case phaseFlight12:
		if recordType != recordHandshake {
			return errors.New("the server's flight holds another record type")
		}
		self.serverBuffer = append(self.serverBuffer, payload...)
		return self.drainFlight12()
	case phaseServerFinished12:
		if dummyChange && self.serverFinished12 == nil {
			return nil
		}
		if recordType != recordHandshake || len(record) != recordHeaderBytes+explicitNonceBytes+16+tagBytes {
			return errors.New("expected the server's Finished")
		}
		self.serverFinished12 = record
		self.phase = phaseApplication
		return nil
	default:
		return errors.New("server record out of turn")
	}
}

// 1.2's clear flight: Certificate, ServerKeyExchange (E2), optional CertificateRequest,
// ServerHelloDone, and nothing else.
func (self *handshake) drainFlight12() error {
	for {
		message := nextMessage(&self.serverBuffer)
		if message == nil {
			return nil
		}
		switch {
		case self.leaf == nil && message[0] == messageCertificate:
			leaf, err := certificateLeaf(versionTls12, message[4:])
			if err != nil {
				return err
			}
			self.leaf = leaf
		case self.leaf != nil && !self.keyExchangeSeen && message[0] == messageServerKeyExchange:
			if err := self.serverKeyExchange(message[4:]); err != nil {
				return &e2Failure{err: err}
			}
			self.keyExchangeSeen = true
		case self.keyExchangeSeen && !self.certificateRequested && message[0] == messageCertificateRequest:
			self.certificateRequested = true
		case self.keyExchangeSeen && message[0] == messageServerHelloDone:
			if len(message) != 4 || len(self.serverBuffer) != 0 {
				return errors.New("ServerHelloDone is not the flight's end")
			}
			self.messages = append(self.messages, message...)
			self.phase = phaseClientFlight12
			return nil
		default:
			return fmt.Errorf("server message %d out of the flight's shape", message[0])
		}
		self.messages = append(self.messages, message...)
	}
}

// E2 in 1.2: the ServerKeyExchange's signature over r_c ‖ r_s ‖ params, in clear.
func (self *handshake) serverKeyExchange(body []byte) error {
	input := cryptobyte.String(body)
	var curveType uint8
	var group uint16
	var point, signature cryptobyte.String
	var scheme uint16
	if !input.ReadUint8(&curveType) || curveType != 3 || !input.ReadUint16(&group) || !input.ReadUint8LengthPrefixed(&point) {
		return errors.New("malformed ServerKeyExchange")
	}
	params := body[:len(body)-len(input)]
	if !input.ReadUint16(&scheme) || !input.ReadUint16LengthPrefixed(&signature) || !input.Empty() {
		return errors.New("malformed ServerKeyExchange")
	}
	signed := append(append(append([]byte{}, self.clientRandom...), self.serverRandom...), params...)
	return self.verifySignature(scheme, signed, signature)
}

// A failure that belongs to E2 rather than E1.
type e2Failure struct {
	err error
}

func (self *e2Failure) Error() string {
	return self.err.Error()
}

// The leaf of a Certificate message.
func certificateLeaf(version uint16, body []byte) (*x509.Certificate, error) {
	input := cryptobyte.String(body)
	if version == versionTls13 {
		var context cryptobyte.String
		if !input.ReadUint8LengthPrefixed(&context) {
			return nil, errors.New("malformed Certificate")
		}
	}
	var list, leaf cryptobyte.String
	if !input.ReadUint24LengthPrefixed(&list) || !input.Empty() || !list.ReadUint24LengthPrefixed(&leaf) {
		return nil, errors.New("malformed Certificate")
	}
	return x509.ParseCertificate(leaf)
}

// Verifies a signature under the leaf by a scheme the client offered, never with SHA-1 and, in 1.3,
// never PKCS #1 v1.5 (RFC 8446 §4.2.3).
func (self *handshake) verifySignature(scheme uint16, signed []byte, signature []byte) error {
	if !slices.Contains(self.offeredSchemes, scheme) {
		return fmt.Errorf("scheme %#x was not offered", scheme)
	}
	if self.leaf == nil {
		return errors.New("no certificate")
	}
	hashed := func(hash crypto.Hash) []byte {
		switch hash {
		case crypto.SHA384:
			sum := sha512.Sum384(signed)
			return sum[:]
		case crypto.SHA512:
			sum := sha512.Sum512(signed)
			return sum[:]
		default:
			sum := sha256.Sum256(signed)
			return sum[:]
		}
	}
	switch scheme {
	case 0x0807:
		key, ok := self.leaf.PublicKey.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(key, signed, signature) {
			return errors.New("bad ed25519 signature")
		}
		return nil
	case 0x0403, 0x0503, 0x0603:
		hash, curve := crypto.SHA256, elliptic.P256()
		if scheme == 0x0503 {
			hash, curve = crypto.SHA384, elliptic.P384()
		} else if scheme == 0x0603 {
			hash, curve = crypto.SHA512, elliptic.P521()
		}
		key, ok := self.leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || (self.version == versionTls13 && key.Curve != curve) || !ecdsa.VerifyASN1(key, hashed(hash), signature) {
			return errors.New("bad ecdsa signature")
		}
		return nil
	case 0x0804, 0x0805, 0x0806:
		hash := map[uint16]crypto.Hash{0x0804: crypto.SHA256, 0x0805: crypto.SHA384, 0x0806: crypto.SHA512}[scheme]
		key, ok := self.leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("rsa scheme without an rsa key")
		}
		return rsa.VerifyPSS(key, hash, hashed(hash), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case 0x0401, 0x0501, 0x0601:
		if self.version == versionTls13 {
			return errors.New("pkcs1 in 1.3")
		}
		hash := map[uint16]crypto.Hash{0x0401: crypto.SHA256, 0x0501: crypto.SHA384, 0x0601: crypto.SHA512}[scheme]
		key, ok := self.leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("rsa scheme without an rsa key")
		}
		return rsa.VerifyPKCS1v15(key, hash, hashed(hash), signature)
	default:
		return fmt.Errorf("scheme %#x is never accepted", scheme)
	}
}

// An AEAD for the 1.3 flight under the server's handshake key.
func flightAead(suite uint16, key []byte) (cipher.AEAD, error) {
	if suite == suiteChacha20Poly1305Sha256 {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// E2 in 1.3: opens the flight under the disclosed SHTS, checks CertificateVerify and Finished, then
// computes H_shts and H_sf. SHTS is used here and kept nowhere.
func (self *handshake) disclose(shts []byte) error {
	if self.phase != phaseFlight13 || self.flightChecked {
		return errors.New("SHTS out of turn")
	}
	if len(shts) != secretBytes {
		return errors.New("SHTS is not 32 octets")
	}
	key, iv := trafficKeys13(self.suite, shts)
	aead, err := flightAead(self.suite, key)
	if err != nil {
		return err
	}
	var buffer []byte
	finished := false
	consumed := 0
	verified := false
	for !finished {
		if consumed == len(self.flight) {
			return errors.New("the flight ended without Finished")
		}
		record := self.flight[consumed]
		nonce, _ := recordNonce(versionTls13, iv, uint64(consumed), record)
		inner, err := aead.Open(nil, nonce, record[recordHeaderBytes:], record[:recordHeaderBytes])
		consumed += 1
		if err != nil {
			return errors.New("SHTS does not open the flight")
		}
		end := len(inner)
		for 0 < end && inner[end-1] == 0 {
			end -= 1
		}
		if end == 0 || inner[end-1] != recordHandshake {
			return errors.New("the flight holds another inner type")
		}
		buffer = append(buffer, inner[:end-1]...)
		for {
			message := nextMessage(&buffer)
			if message == nil {
				break
			}
			switch message[0] {
			case messageEncryptedExtension:
			case messageCertificateRequest:
				self.certificateRequested = true
			case messageCertificate:
				if self.leaf, err = certificateLeaf(versionTls13, message[4:]); err != nil {
					return err
				}
			case messageCertificateVerify:
				input := cryptobyte.String(message[4:])
				var scheme uint16
				var signature cryptobyte.String
				if !input.ReadUint16(&scheme) || !input.ReadUint16LengthPrefixed(&signature) || !input.Empty() {
					return errors.New("malformed CertificateVerify")
				}
				hash := sha256.Sum256(self.messages)
				signed := append(bytes.Repeat([]byte{0x20}, 64), "TLS 1.3, server CertificateVerify\x00"...)
				if err := self.verifySignature(scheme, append(signed, hash[:]...), signature); err != nil {
					return err
				}
				verified = true
			case messageFinished:
				hash := sha256.Sum256(self.messages)
				if !verified || !bytes.Equal(message[4:], hmacSha256(expandLabel(shts, "finished", nil, secretBytes), hash[:])) {
					return errors.New("the server's Finished does not verify")
				}
				finished = true
			default:
				return fmt.Errorf("message %d in the server's flight", message[0])
			}
			self.messages = append(self.messages, message...)
			if finished {
				break
			}
		}
	}
	if len(buffer) != 0 {
		return errors.New("a handshake message spans the key change")
	}
	shtsHash := sha256.Sum256(shts)
	finishedHash := sha256.Sum256(self.messages)
	self.shtsHash = shtsHash[:]
	self.finishedHash = finishedHash[:]
	self.afterFlight = append(self.afterFlight, self.flight[consumed:]...)
	self.flight = nil
	self.flightChecked = true
	return nil
}

// E1 over the client's second 1.3 flight, once both it and E2 are in: the caller runs it after each.
func (self *handshake) finishFlight13() error {
	if !self.flightChecked || self.clientFinished == nil {
		return nil
	}
	content := 4 + 32
	if self.certificateRequested {
		content += 8
	}
	if len(self.clientFinished) != recordHeaderBytes+content+1+tagBytes {
		return errors.New("the client's second flight is not one Finished record")
	}
	self.phase = phaseApplication
	return nil
}
