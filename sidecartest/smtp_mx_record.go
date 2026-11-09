//go:build !sidecar_http

// RecordMx: an MX whose TLS 1.2 and 1.3 server is written here from RFC 8446, RFC 5246, RFC 5288 and
// RFC 7627, because crypto/tls cannot send a late NewSessionTicket or a KeyUpdate on demand or pad its
// records, and FS-31 needs all three. This module cannot import smtpproof, so it shares no code with
// the provers' tlsClient by construction, which makes it a second implementation of what that client
// talks to. It serves E1's versions and suites only: 1.3 with AES-128-GCM or ChaCha20-Poly1305 over
// X25519 or P-256, and 1.2 with ECDHE and AES-128-GCM, ECDSA or RSA, extended master secret when
// offered. It takes padded 1.3 records from a client and counts them.
//
// The SMTP dialog on either side of STARTTLS is smtp_mx.go's machine, by an MxScript. Record-level
// behavior is keyed by the index of the reply inside TLS, counting from 1 at the EHLO reply, so a test
// places a ticket or a KeyUpdate exactly. Safe for concurrent use across connections.

package sidecartest

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"slices"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

// RFC 8446 and RFC 5246's numbers, format values all.
const (
	rmxRecordChangeCipherSpec = 20
	rmxRecordAlert            = 21
	rmxRecordHandshake        = 22
	rmxRecordApplicationData  = 23

	rmxHandshakeClientHello         = 1
	rmxHandshakeServerHello         = 2
	rmxHandshakeNewSessionTicket    = 4
	rmxHandshakeEncryptedExtensions = 8
	rmxHandshakeCertificate         = 11
	rmxHandshakeServerKeyExchange   = 12
	rmxHandshakeServerHelloDone     = 14
	rmxHandshakeCertificateVerify   = 15
	rmxHandshakeClientKeyExchange   = 16
	rmxHandshakeFinished            = 20
	rmxHandshakeKeyUpdate           = 24

	rmxExtensionSupportedGroups      = 10
	rmxExtensionEcPointFormats       = 11
	rmxExtensionSignatureAlgorithms  = 13
	rmxExtensionExtendedMasterSecret = 23
	rmxExtensionSupportedVersions    = 43
	rmxExtensionKeyShare             = 51
	rmxExtensionRenegotiationInfo    = 0xff01

	rmxGroupSecp256r1 = 23
	rmxGroupX25519    = 29

	rmxSchemeRsaPkcs1Sha256    = 0x0401
	rmxSchemeEcdsaP256Sha256   = 0x0403
	rmxSchemeRsaPssRsaeSha256  = 0x0804
	rmxScsvRenegotiation       = 0x00ff
	rmxRecordMaxPlaintext      = 16 * 1024
	rmxRecordMaxCiphertext     = 16*1024 + 2048
	rmxHandshakeMaxMessageByte = 64 * 1024
)

var errRecordMx = errors.New("record mx")

// What a RecordMx serves and does on the record layer.
type RecordMxSettings struct {
	// tls.VersionTLS13 or tls.VersionTLS12, the only one served.
	Version uint16
	// 1.3: tls.TLS_AES_128_GCM_SHA256 or tls.TLS_CHACHA20_POLY1305_SHA256. 1.2:
	// tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 or tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, whose
	// key the certificate made for the host follows.
	Suite uint16
	// 1.3: a NewSessionTicket ahead of the reply inside TLS with this index, 1 the EHLO reply's. 0 none.
	TicketBeforeReply int
	// 1.3: a KeyUpdate, update_not_requested, ahead of that reply. 0 none.
	KeyUpdateBeforeReply int
	// 1.3: zero octets of padding on every record of a reply.
	PadReplyRecords int
	// Splits each reply into records of at most this many octets. 0 sends each whole.
	SplitRepliesAt int
	// Used as given when set, else one is made for the host.
	Certificate *tls.Certificate
}

func DefaultRecordMxSettings() *RecordMxSettings {
	return &RecordMxSettings{Version: tls.VersionTLS13, Suite: tls.TLS_AES_128_GCM_SHA256}
}

type RecordMx struct {
	mxRecord
	host        string
	script      *MxScript
	settings    *RecordMxSettings
	certificate tls.Certificate

	recordLock          sync.Mutex
	paddedClientRecords int
	handshakeErrors     []error
}

var _ MxServer = (*RecordMx)(nil)

// An MX for host. A nil script is DefaultMxScript's and nil settings DefaultRecordMxSettings'.
func NewRecordMx(host string, script *MxScript, settings *RecordMxSettings) (*RecordMx, error) {
	if script == nil {
		script = DefaultMxScript()
	}
	if settings == nil {
		settings = DefaultRecordMxSettings()
	}
	switch {
	case settings.Version == tls.VersionTLS13 && (settings.Suite == tls.TLS_AES_128_GCM_SHA256 || settings.Suite == tls.TLS_CHACHA20_POLY1305_SHA256):
	case settings.Version == tls.VersionTLS12 && (settings.Suite == tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 || settings.Suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256):
	default:
		return nil, fmt.Errorf("%w: version %#x with suite %#x is not E1's", errRecordMx, settings.Version, settings.Suite)
	}
	mx := &RecordMx{host: host, script: script, settings: settings}
	if settings.Certificate != nil {
		mx.certificate = *settings.Certificate
	} else {
		certificate, err := NewMxCertificate(host, settings.Suite == tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		if err != nil {
			return nil, err
		}
		mx.certificate = certificate
	}
	return mx, nil
}

// The MX's leaf.
func (self *RecordMx) Certificate() *x509.Certificate {
	return self.certificate.Leaf
}

// Client records that carried 1.3 padding, which the server took.
func (self *RecordMx) PaddedClientRecords() int {
	self.recordLock.Lock()
	defer self.recordLock.Unlock()
	return self.paddedClientRecords
}

// Why each refused handshake ended, in order.
func (self *RecordMx) HandshakeErrors() []error {
	self.recordLock.Lock()
	defer self.recordLock.Unlock()
	return append([]error(nil), self.handshakeErrors...)
}

func (self *RecordMx) ServeMx(conn net.Conn) {
	defer conn.Close()
	self.addConnection()
	banner := self.script.Banner
	if banner == "" {
		banner = "220 " + self.host + " ESMTP"
	}
	if _, err := conn.Write([]byte(banner + "\r\n")); err != nil || banner[0] != '2' {
		return
	}
	plain := &mxSmtpSession{host: self.host, script: self.script, record: &self.mxRecord, reader: bufio.NewReader(conn), writer: conn}
	startTls, err := plain.serve()
	if err != nil || !startTls {
		return
	}
	session := &rmxConn{mx: self, conn: conn}
	if err := session.handshake(); err != nil {
		func() {
			self.recordLock.Lock()
			defer self.recordLock.Unlock()
			self.handshakeErrors = append(self.handshakeErrors, err)
		}()
		session.alert(40)
		return
	}
	secure := &mxSmtpSession{host: self.host, script: self.script, record: &self.mxRecord, reader: bufio.NewReader(session), writer: session, secure: true}
	secure.serve()
	session.alert(0)
}

// One direction's record protection. 1.3 forms its nonce from iv and the sequence number; 1.2 from
// a 4-octet salt and an explicit nonce it sends, here the sequence number.
type rmxCipher struct {
	version uint16
	aead    cipher.AEAD
	iv      []byte
	seq     uint64
}

func newRmxCipher(version uint16, suite uint16, key []byte, iv []byte) (*rmxCipher, error) {
	var aead cipher.AEAD
	var err error
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		aead, err = chacha20poly1305.New(key)
	} else {
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		return nil, err
	}
	return &rmxCipher{version: version, aead: aead, iv: iv}, nil
}

// One record, header included.
func (self *rmxCipher) seal(recordType byte, content []byte, padding int) []byte {
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, self.seq)
	self.seq += 1
	if self.version == tls.VersionTLS13 {
		inner := append(append(append([]byte{}, content...), recordType), make([]byte, padding)...)
		nonce := slices.Clone(self.iv)
		for i := range seq {
			nonce[len(nonce)-8+i] ^= seq[i]
		}
		header := []byte{rmxRecordApplicationData, 3, 3, 0, 0}
		binary.BigEndian.PutUint16(header[3:], uint16(len(inner)+self.aead.Overhead()))
		// the header is both the record's start and its additional data, which may not share storage
		return self.aead.Seal(slices.Clone(header), nonce, inner, header)
	}
	nonce := append(slices.Clone(self.iv), seq...)
	additional := append(append(slices.Clone(seq), recordType, 3, 3), byte(len(content)>>8), byte(len(content)))
	header := []byte{recordType, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(8+len(content)+self.aead.Overhead()))
	return self.aead.Seal(append(header, seq...), nonce, content, additional)
}

// One record's content and type. A 1.3 record's padding is stripped, and padded reports it.
func (self *rmxCipher) open(record []byte) (recordType byte, content []byte, padded bool, err error) {
	seq := make([]byte, 8)
	binary.BigEndian.PutUint64(seq, self.seq)
	self.seq += 1
	header, fragment := record[:5], record[5:]
	if self.version == tls.VersionTLS13 {
		nonce := slices.Clone(self.iv)
		for i := range seq {
			nonce[len(nonce)-8+i] ^= seq[i]
		}
		inner, err := self.aead.Open(nil, nonce, fragment, header)
		if err != nil {
			return 0, nil, false, err
		}
		end := len(inner)
		for 0 < end && inner[end-1] == 0 {
			end -= 1
		}
		if end == 0 {
			return 0, nil, false, fmt.Errorf("%w: a record with no type", errRecordMx)
		}
		return inner[end-1], inner[:end-1], end < len(inner), nil
	}
	if len(fragment) < 8+self.aead.Overhead() {
		return 0, nil, false, fmt.Errorf("%w: a short record", errRecordMx)
	}
	nonce := append(slices.Clone(self.iv), fragment[:8]...)
	plainLength := len(fragment) - 8 - self.aead.Overhead()
	additional := append(append(slices.Clone(seq), header[0], header[1], header[2]), byte(plainLength>>8), byte(plainLength))
	content, err = self.aead.Open(nil, nonce, fragment[8:], additional)
	return header[0], content, false, err
}

// RFC 8446 §7.1's HKDF-Expand-Label over SHA-256.
func rmxExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(uint16(length))
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes([]byte("tls13 " + label)) })
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(context) })
	out := make([]byte, length)
	io.ReadFull(hkdf.Expand(sha256.New, secret, builder.BytesOrPanic()), out)
	return out
}

// RFC 5246 §5's PRF over SHA-256.
func rmxPrf(secret []byte, label string, seed []byte, length int) []byte {
	labelSeed := append([]byte(label), seed...)
	out := make([]byte, 0, length+sha256.Size)
	mac := hmac.New(sha256.New, secret)
	a := labelSeed
	for len(out) < length {
		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
		mac.Reset()
		mac.Write(a)
		mac.Write(labelSeed)
		out = mac.Sum(out)
	}
	return out[:length]
}

// What the server read from a ClientHello.
type rmxClientHello struct {
	raw               []byte
	random            []byte
	sessionId         []byte
	suites            []uint16
	supportedVersions []uint16
	groups            []uint16
	keyShares         map[uint16][]byte
	schemes           []uint16
	extendedMaster    bool
	renegotiationInfo bool
	pointFormats      bool
}

func parseRmxClientHello(message []byte) (*rmxClientHello, error) {
	hello := &rmxClientHello{raw: message, keyShares: map[uint16][]byte{}}
	body := cryptobyte.String(message[4:])
	var legacyVersion uint16
	var random, sessionId, compression []byte
	var suites, extensions cryptobyte.String
	if !body.ReadUint16(&legacyVersion) || !body.ReadBytes(&random, 32) || !body.ReadUint8LengthPrefixed((*cryptobyte.String)(&sessionId)) ||
		!body.ReadUint16LengthPrefixed(&suites) || !body.ReadUint8LengthPrefixed((*cryptobyte.String)(&compression)) {
		return nil, fmt.Errorf("%w: a malformed ClientHello", errRecordMx)
	}
	hello.random, hello.sessionId = random, sessionId
	for !suites.Empty() {
		var suite uint16
		if !suites.ReadUint16(&suite) {
			return nil, fmt.Errorf("%w: a malformed suite list", errRecordMx)
		}
		hello.suites = append(hello.suites, suite)
		if suite == rmxScsvRenegotiation {
			hello.renegotiationInfo = true
		}
	}
	if body.Empty() {
		return hello, nil
	}
	if !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return nil, fmt.Errorf("%w: malformed extensions", errRecordMx)
	}
	for !extensions.Empty() {
		var extensionType uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extensionType) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, fmt.Errorf("%w: a malformed extension", errRecordMx)
		}
		switch extensionType {
		case rmxExtensionSupportedVersions:
			var versions cryptobyte.String
			if !data.ReadUint8LengthPrefixed(&versions) {
				return nil, fmt.Errorf("%w: malformed supported_versions", errRecordMx)
			}
			for !versions.Empty() {
				var version uint16
				if !versions.ReadUint16(&version) {
					return nil, fmt.Errorf("%w: malformed supported_versions", errRecordMx)
				}
				hello.supportedVersions = append(hello.supportedVersions, version)
			}
		case rmxExtensionSupportedGroups:
			var groups cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&groups) {
				return nil, fmt.Errorf("%w: malformed supported_groups", errRecordMx)
			}
			for !groups.Empty() {
				var group uint16
				if !groups.ReadUint16(&group) {
					return nil, fmt.Errorf("%w: malformed supported_groups", errRecordMx)
				}
				hello.groups = append(hello.groups, group)
			}
		case rmxExtensionKeyShare:
			var shares cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&shares) {
				return nil, fmt.Errorf("%w: malformed key_share", errRecordMx)
			}
			for !shares.Empty() {
				var group uint16
				var share []byte
				if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed((*cryptobyte.String)(&share)) {
					return nil, fmt.Errorf("%w: malformed key_share", errRecordMx)
				}
				hello.keyShares[group] = share
			}
		case rmxExtensionSignatureAlgorithms:
			var schemes cryptobyte.String
			if !data.ReadUint16LengthPrefixed(&schemes) {
				return nil, fmt.Errorf("%w: malformed signature_algorithms", errRecordMx)
			}
			for !schemes.Empty() {
				var scheme uint16
				if !schemes.ReadUint16(&scheme) {
					return nil, fmt.Errorf("%w: malformed signature_algorithms", errRecordMx)
				}
				hello.schemes = append(hello.schemes, scheme)
			}
		case rmxExtensionExtendedMasterSecret:
			hello.extendedMaster = true
		case rmxExtensionRenegotiationInfo:
			hello.renegotiationInfo = true
		case rmxExtensionEcPointFormats:
			hello.pointFormats = true
		}
	}
	return hello, nil
}

// A handshake message: type, 24-bit length, body.
func rmxHandshakeMessage(messageType byte, body []byte) []byte {
	message := []byte{messageType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(message, body...)
}

func rmxPlainRecord(recordType byte, content []byte) []byte {
	record := []byte{recordType, 3, 3, byte(len(content) >> 8), byte(len(content))}
	return append(record, content...)
}

// One server connection's record layer and handshake.
type rmxConn struct {
	mx   *RecordMx
	conn net.Conn

	version      uint16
	clientCipher *rmxCipher
	serverCipher *rmxCipher
	// 1.3's application secrets, which KeyUpdate advances
	clientSecret []byte
	serverSecret []byte
	transcript   hash.Hash
	// handshake octets read and not yet a whole message
	handshakePending []byte
	// application octets opened and not yet read
	readPending []byte
	readErr     error
	writeLock   sync.Mutex
	replyIndex  int
}

func (self *rmxConn) readRecord() ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(self.conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if rmxRecordMaxCiphertext < length {
		return nil, fmt.Errorf("%w: a %d-octet record", errRecordMx, length)
	}
	record := make([]byte, 5+length)
	copy(record, header)
	if _, err := io.ReadFull(self.conn, record[5:]); err != nil {
		return nil, err
	}
	return record, nil
}

// The next handshake message, from plaintext records, or from protected ones once cipher is set. A
// 1.3 client's one change_cipher_spec is dropped (RFC 8446 §5).
func (self *rmxConn) readHandshake(cipher *rmxCipher) ([]byte, error) {
	for {
		if 4 <= len(self.handshakePending) {
			length := int(self.handshakePending[1])<<16 | int(self.handshakePending[2])<<8 | int(self.handshakePending[3])
			if rmxHandshakeMaxMessageByte < length {
				return nil, fmt.Errorf("%w: a %d-octet handshake message", errRecordMx, length)
			}
			if 4+length <= len(self.handshakePending) {
				message := slices.Clone(self.handshakePending[:4+length])
				self.handshakePending = self.handshakePending[4+length:]
				return message, nil
			}
		}
		record, err := self.readRecord()
		if err != nil {
			return nil, err
		}
		recordType, content := record[0], record[5:]
		if recordType == rmxRecordChangeCipherSpec && self.version == tls.VersionTLS13 && bytes.Equal(content, []byte{1}) {
			continue
		}
		if cipher != nil {
			var padded bool
			if recordType, content, padded, err = cipher.open(record); err != nil {
				return nil, err
			}
			self.notePadded(padded)
		}
		if recordType != rmxRecordHandshake {
			return nil, fmt.Errorf("%w: record type %d during the handshake", errRecordMx, recordType)
		}
		self.handshakePending = append(self.handshakePending, content...)
	}
}

func (self *rmxConn) notePadded(padded bool) {
	if padded {
		self.mx.recordLock.Lock()
		defer self.mx.recordLock.Unlock()
		self.mx.paddedClientRecords += 1
	}
}

func (self *rmxConn) write(data []byte) error {
	_, err := self.conn.Write(data)
	return err
}

// An alert, and the end. 0 is close_notify, anything else fatal.
func (self *rmxConn) alert(description byte) {
	level := byte(2)
	if description == 0 {
		level = 1
	}
	if self.serverCipher != nil {
		self.write(self.serverCipher.seal(rmxRecordAlert, []byte{level, description}, 0))
	} else {
		self.write(rmxPlainRecord(rmxRecordAlert, []byte{level, description}))
	}
}

func (self *rmxConn) handshake() error {
	message, err := self.readHandshake(nil)
	if err != nil {
		return err
	}
	if message[0] != rmxHandshakeClientHello {
		return fmt.Errorf("%w: handshake type %d first", errRecordMx, message[0])
	}
	hello, err := parseRmxClientHello(message)
	if err != nil {
		return err
	}
	suite := self.mx.settings.Suite
	if !slices.Contains(hello.suites, suite) {
		return fmt.Errorf("%w: the client does not offer suite %#x", errRecordMx, suite)
	}
	self.version = self.mx.settings.Version
	self.transcript = sha256.New()
	if self.version == tls.VersionTLS13 {
		if !slices.Contains(hello.supportedVersions, tls.VersionTLS13) {
			return fmt.Errorf("%w: the client does not offer 1.3", errRecordMx)
		}
		return self.handshake13(hello, suite)
	}
	return self.handshake12(hello, suite)
}

// The signature a handshake carries, by the certificate's key: ECDSA P-256, or RSA-PSS (RSA PKCS#1 in
// 1.2 when the client offers no PSS).
func (self *rmxConn) sign(schemes []uint16, signed []byte) (uint16, []byte, error) {
	digest := sha256.Sum256(signed)
	switch key := self.mx.certificate.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
		return rmxSchemeEcdsaP256Sha256, signature, err
	case *rsa.PrivateKey:
		if self.version == tls.VersionTLS12 && !slices.Contains(schemes, rmxSchemeRsaPssRsaeSha256) {
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
			return rmxSchemeRsaPkcs1Sha256, signature, err
		}
		signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		return rmxSchemeRsaPssRsaeSha256, signature, err
	}
	return 0, nil, fmt.Errorf("%w: an unusable key", errRecordMx)
}

// The server's key share and the shared secret, X25519 preferred.
func rmxKeyExchange(group uint16, peer []byte) (public []byte, shared []byte, err error) {
	curve := ecdh.X25519()
	if group == rmxGroupSecp256r1 {
		curve = ecdh.P256()
	}
	peerKey, err := curve.NewPublicKey(peer)
	if err != nil {
		return nil, nil, err
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err = key.ECDH(peerKey)
	return key.PublicKey().Bytes(), shared, err
}

func (self *rmxConn) handshake13(hello *rmxClientHello, suite uint16) error {
	group := uint16(rmxGroupX25519)
	peer, ok := hello.keyShares[group]
	if !ok {
		group = rmxGroupSecp256r1
		if peer, ok = hello.keyShares[group]; !ok {
			return fmt.Errorf("%w: no X25519 or P-256 key share", errRecordMx)
		}
	}
	public, shared, err := rmxKeyExchange(group, peer)
	if err != nil {
		return err
	}
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(tls.VersionTLS12)
	builder.AddBytes(serverRandom)
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(hello.sessionId) })
	builder.AddUint16(suite)
	builder.AddUint8(0)
	builder.AddUint16LengthPrefixed(func(extensions *cryptobyte.Builder) {
		extensions.AddUint16(rmxExtensionSupportedVersions)
		extensions.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddUint16(tls.VersionTLS13) })
		extensions.AddUint16(rmxExtensionKeyShare)
		extensions.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddUint16(group)
			child.AddUint16LengthPrefixed(func(share *cryptobyte.Builder) { share.AddBytes(public) })
		})
	})
	serverHello := rmxHandshakeMessage(rmxHandshakeServerHello, builder.BytesOrPanic())
	self.transcript.Write(hello.raw)
	self.transcript.Write(serverHello)
	flight := rmxPlainRecord(rmxRecordHandshake, serverHello)
	if 0 < len(hello.sessionId) {
		// middlebox compatibility mode, which a client asks for with a session id (RFC 8446 D.4)
		flight = append(flight, rmxPlainRecord(rmxRecordChangeCipherSpec, []byte{1})...)
	}

	zeros := make([]byte, sha256.Size)
	emptyHash := sha256.Sum256(nil)
	earlySecret := hkdf.Extract(sha256.New, zeros, zeros)
	handshakeSecret := hkdf.Extract(sha256.New, shared, rmxExpandLabel(earlySecret, "derived", emptyHash[:], sha256.Size))
	helloHash := self.transcript.Sum(nil)
	clientHandshake := rmxExpandLabel(handshakeSecret, "c hs traffic", helloHash, sha256.Size)
	serverHandshake := rmxExpandLabel(handshakeSecret, "s hs traffic", helloHash, sha256.Size)
	keyLength := 16
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		keyLength = 32
	}
	newCipher := func(secret []byte) (*rmxCipher, error) {
		return newRmxCipher(tls.VersionTLS13, suite, rmxExpandLabel(secret, "key", nil, keyLength), rmxExpandLabel(secret, "iv", nil, 12))
	}
	serverHandshakeCipher, err := newCipher(serverHandshake)
	if err != nil {
		return err
	}
	clientHandshakeCipher, err := newCipher(clientHandshake)
	if err != nil {
		return err
	}

	encryptedExtensions := rmxHandshakeMessage(rmxHandshakeEncryptedExtensions, []byte{0, 0})
	certificateBuilder := cryptobyte.NewBuilder(nil)
	certificateBuilder.AddUint8(0)
	certificateBuilder.AddUint24LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, der := range self.mx.certificate.Certificate {
			list.AddUint24LengthPrefixed(func(entry *cryptobyte.Builder) { entry.AddBytes(der) })
			list.AddUint16(0)
		}
	})
	certificate := rmxHandshakeMessage(rmxHandshakeCertificate, certificateBuilder.BytesOrPanic())
	self.transcript.Write(encryptedExtensions)
	self.transcript.Write(certificate)
	signed := append(bytes.Repeat([]byte{0x20}, 64), []byte("TLS 1.3, server CertificateVerify")...)
	signed = append(append(signed, 0), self.transcript.Sum(nil)...)
	scheme, signature, err := self.sign(hello.schemes, signed)
	if err != nil {
		return err
	}
	verifyBuilder := cryptobyte.NewBuilder(nil)
	verifyBuilder.AddUint16(scheme)
	verifyBuilder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(signature) })
	certificateVerify := rmxHandshakeMessage(rmxHandshakeCertificateVerify, verifyBuilder.BytesOrPanic())
	self.transcript.Write(certificateVerify)
	serverFinishedMac := hmac.New(sha256.New, rmxExpandLabel(serverHandshake, "finished", nil, sha256.Size))
	serverFinishedMac.Write(self.transcript.Sum(nil))
	serverFinished := rmxHandshakeMessage(rmxHandshakeFinished, serverFinishedMac.Sum(nil))
	self.transcript.Write(serverFinished)
	for _, message := range [][]byte{encryptedExtensions, certificate, certificateVerify, serverFinished} {
		flight = append(flight, serverHandshakeCipher.seal(rmxRecordHandshake, message, 0)...)
	}
	if err := self.write(flight); err != nil {
		return err
	}

	finishedHash := self.transcript.Sum(nil)
	masterSecret := hkdf.Extract(sha256.New, zeros, rmxExpandLabel(handshakeSecret, "derived", emptyHash[:], sha256.Size))
	self.clientSecret = rmxExpandLabel(masterSecret, "c ap traffic", finishedHash, sha256.Size)
	self.serverSecret = rmxExpandLabel(masterSecret, "s ap traffic", finishedHash, sha256.Size)

	clientFinished, err := self.readHandshake(clientHandshakeCipher)
	if err != nil {
		return err
	}
	clientFinishedMac := hmac.New(sha256.New, rmxExpandLabel(clientHandshake, "finished", nil, sha256.Size))
	clientFinishedMac.Write(finishedHash)
	if !bytes.Equal(clientFinished, rmxHandshakeMessage(rmxHandshakeFinished, clientFinishedMac.Sum(nil))) {
		return fmt.Errorf("%w: a bad client Finished", errRecordMx)
	}
	if 0 < len(self.handshakePending) {
		return fmt.Errorf("%w: handshake octets past the client Finished", errRecordMx)
	}
	if self.clientCipher, err = newCipher(self.clientSecret); err != nil {
		return err
	}
	self.serverCipher, err = newCipher(self.serverSecret)
	return err
}

func (self *rmxConn) handshake12(hello *rmxClientHello, suite uint16) error {
	group := uint16(rmxGroupX25519)
	if 0 < len(hello.groups) && !slices.Contains(hello.groups, group) {
		group = rmxGroupSecp256r1
		if !slices.Contains(hello.groups, group) {
			return fmt.Errorf("%w: neither X25519 nor P-256 offered", errRecordMx)
		}
	}
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(tls.VersionTLS12)
	builder.AddBytes(serverRandom)
	builder.AddUint8(0)
	builder.AddUint16(suite)
	builder.AddUint8(0)
	builder.AddUint16LengthPrefixed(func(extensions *cryptobyte.Builder) {
		if hello.renegotiationInfo {
			extensions.AddUint16(rmxExtensionRenegotiationInfo)
			extensions.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddUint8(0) })
		}
		if hello.extendedMaster {
			extensions.AddUint16(rmxExtensionExtendedMasterSecret)
			extensions.AddUint16(0)
		}
		if hello.pointFormats {
			extensions.AddUint16(rmxExtensionEcPointFormats)
			extensions.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
				child.AddUint8LengthPrefixed(func(formats *cryptobyte.Builder) { formats.AddUint8(0) })
			})
		}
	})
	serverHello := rmxHandshakeMessage(rmxHandshakeServerHello, builder.BytesOrPanic())
	certificateBuilder := cryptobyte.NewBuilder(nil)
	certificateBuilder.AddUint24LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, der := range self.mx.certificate.Certificate {
			list.AddUint24LengthPrefixed(func(entry *cryptobyte.Builder) { entry.AddBytes(der) })
		}
	})
	certificate := rmxHandshakeMessage(rmxHandshakeCertificate, certificateBuilder.BytesOrPanic())

	curve := ecdh.X25519()
	if group == rmxGroupSecp256r1 {
		curve = ecdh.P256()
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	params := []byte{3, byte(group >> 8), byte(group)}
	params = append(append(params, byte(len(key.PublicKey().Bytes()))), key.PublicKey().Bytes()...)
	signed := append(append(slices.Clone(hello.random), serverRandom...), params...)
	scheme, signature, err := self.sign(hello.schemes, signed)
	if err != nil {
		return err
	}
	exchangeBody := append(slices.Clone(params), byte(scheme>>8), byte(scheme), byte(len(signature)>>8), byte(len(signature)))
	serverKeyExchange := rmxHandshakeMessage(rmxHandshakeServerKeyExchange, append(exchangeBody, signature...))
	serverHelloDone := rmxHandshakeMessage(rmxHandshakeServerHelloDone, nil)
	var flight []byte
	for _, message := range [][]byte{hello.raw, serverHello, certificate, serverKeyExchange, serverHelloDone} {
		self.transcript.Write(message)
		if message[0] != rmxHandshakeClientHello {
			flight = append(flight, rmxPlainRecord(rmxRecordHandshake, message)...)
		}
	}
	if err := self.write(flight); err != nil {
		return err
	}

	clientKeyExchange, err := self.readHandshake(nil)
	if err != nil {
		return err
	}
	if clientKeyExchange[0] != rmxHandshakeClientKeyExchange || len(clientKeyExchange) < 5 || int(clientKeyExchange[4]) != len(clientKeyExchange)-5 {
		return fmt.Errorf("%w: no ClientKeyExchange", errRecordMx)
	}
	peerKey, err := curve.NewPublicKey(clientKeyExchange[5:])
	if err != nil {
		return err
	}
	preMasterSecret, err := key.ECDH(peerKey)
	if err != nil {
		return err
	}
	self.transcript.Write(clientKeyExchange)
	var masterSecret []byte
	if hello.extendedMaster {
		masterSecret = rmxPrf(preMasterSecret, "extended master secret", self.transcript.Sum(nil), 48)
	} else {
		masterSecret = rmxPrf(preMasterSecret, "master secret", append(slices.Clone(hello.random), serverRandom...), 48)
	}
	keyBlock := rmxPrf(masterSecret, "key expansion", append(slices.Clone(serverRandom), hello.random...), 40)
	clientCipher, err := newRmxCipher(tls.VersionTLS12, suite, keyBlock[0:16], keyBlock[32:36])
	if err != nil {
		return err
	}
	serverCipher, err := newRmxCipher(tls.VersionTLS12, suite, keyBlock[16:32], keyBlock[36:40])
	if err != nil {
		return err
	}
	if 0 < len(self.handshakePending) {
		return fmt.Errorf("%w: a handshake message spans the key change", errRecordMx)
	}
	record, err := self.readRecord()
	if err != nil {
		return err
	}
	if record[0] != rmxRecordChangeCipherSpec || !bytes.Equal(record[5:], []byte{1}) {
		return fmt.Errorf("%w: no ChangeCipherSpec", errRecordMx)
	}
	clientFinished, err := self.readHandshake(clientCipher)
	if err != nil {
		return err
	}
	want := rmxHandshakeMessage(rmxHandshakeFinished, rmxPrf(masterSecret, "client finished", self.transcript.Sum(nil), 12))
	if !bytes.Equal(clientFinished, want) {
		return fmt.Errorf("%w: a bad client Finished", errRecordMx)
	}
	self.transcript.Write(clientFinished)
	serverFinished := rmxHandshakeMessage(rmxHandshakeFinished, rmxPrf(masterSecret, "server finished", self.transcript.Sum(nil), 12))
	flight = rmxPlainRecord(rmxRecordChangeCipherSpec, []byte{1})
	flight = append(flight, serverCipher.seal(rmxRecordHandshake, serverFinished, 0)...)
	if err := self.write(flight); err != nil {
		return err
	}
	self.clientCipher, self.serverCipher = clientCipher, serverCipher
	return nil
}

// The application stream's read side: records opened in order, a client's KeyUpdate honored, and an
// alert ending it.
func (self *rmxConn) Read(buffer []byte) (int, error) {
	for len(self.readPending) == 0 {
		if self.readErr != nil {
			return 0, self.readErr
		}
		record, err := self.readRecord()
		if err != nil {
			self.readErr = err
			continue
		}
		recordType, content, padded, err := self.clientCipher.open(record)
		if err != nil {
			self.readErr = err
			continue
		}
		self.notePadded(padded)
		switch recordType {
		case rmxRecordApplicationData:
			self.readPending = content
		case rmxRecordAlert:
			self.readErr = io.EOF
		case rmxRecordHandshake:
			if self.version != tls.VersionTLS13 || len(content) != 5 || content[0] != rmxHandshakeKeyUpdate {
				self.readErr = fmt.Errorf("%w: a handshake message after the handshake", errRecordMx)
				continue
			}
			self.clientSecret = rmxExpandLabel(self.clientSecret, "traffic upd", nil, sha256.Size)
			if self.clientCipher, err = self.newApplicationCipher(self.clientSecret); err != nil {
				self.readErr = err
				continue
			}
			if content[4] == 1 {
				if err := self.sendKeyUpdate(); err != nil {
					self.readErr = err
				}
			}
		default:
			self.readErr = fmt.Errorf("%w: record type %d", errRecordMx, recordType)
		}
	}
	n := copy(buffer, self.readPending)
	self.readPending = self.readPending[n:]
	return n, nil
}

func (self *rmxConn) newApplicationCipher(secret []byte) (*rmxCipher, error) {
	keyLength := 16
	if self.mx.settings.Suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		keyLength = 32
	}
	return newRmxCipher(tls.VersionTLS13, self.mx.settings.Suite, rmxExpandLabel(secret, "key", nil, keyLength), rmxExpandLabel(secret, "iv", nil, 12))
}

// A KeyUpdate with update_not_requested, after which the server's key advances.
func (self *rmxConn) sendKeyUpdate() error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	return self.sendKeyUpdateWithLock()
}

func (self *rmxConn) sendKeyUpdateWithLock() error {
	record := self.serverCipher.seal(rmxRecordHandshake, rmxHandshakeMessage(rmxHandshakeKeyUpdate, []byte{0}), 0)
	if err := self.write(record); err != nil {
		return err
	}
	self.serverSecret = rmxExpandLabel(self.serverSecret, "traffic upd", nil, sha256.Size)
	var err error
	self.serverCipher, err = self.newApplicationCipher(self.serverSecret)
	return err
}

// A NewSessionTicket the client never asked for, for nothing to resume.
func (self *rmxConn) sendTicketWithLock() error {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint32(7200)
	builder.AddUint32(0x01020304)
	builder.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(make([]byte, 8)) })
	builder.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) { child.AddBytes(bytes.Repeat([]byte{0x5a}, 32)) })
	builder.AddUint16(0)
	return self.write(self.serverCipher.seal(rmxRecordHandshake, rmxHandshakeMessage(rmxHandshakeNewSessionTicket, builder.BytesOrPanic()), 0))
}

// One reply, as the machine writes them: the record-level steps the settings place ahead of it, then
// its records.
func (self *rmxConn) Write(reply []byte) (int, error) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	self.replyIndex += 1
	settings := self.mx.settings
	if self.version == tls.VersionTLS13 {
		if settings.TicketBeforeReply == self.replyIndex {
			if err := self.sendTicketWithLock(); err != nil {
				return 0, err
			}
		}
		if settings.KeyUpdateBeforeReply == self.replyIndex {
			if err := self.sendKeyUpdateWithLock(); err != nil {
				return 0, err
			}
		}
	}
	limit := rmxRecordMaxPlaintext
	if 0 < settings.SplitRepliesAt {
		limit = settings.SplitRepliesAt
	}
	padding := 0
	if self.version == tls.VersionTLS13 {
		padding = settings.PadReplyRecords
	}
	var records []byte
	for offset := 0; offset < len(reply); offset += limit {
		end := min(offset+limit, len(reply))
		records = append(records, self.serverCipher.seal(rmxRecordApplicationData, reply[offset:end], padding)...)
	}
	if err := self.write(records); err != nil {
		return 0, err
	}
	return len(reply), nil
}
