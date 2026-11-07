package smtpproof

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// The sidecar's own TLS client, on which the provers run (SPEC.md 4.1). Go's crypto/tls cannot serve:
// its KeyLogWriter never exports TLS 1.3's HS, Z1's witness, and a proof must cover a record's
// ciphertext before the record is sent, so sealing and sending are separate steps here. It also
// fixes what the relation depends on: no padding, no KeyUpdate, no early data, no resumption, and
// only E1's versions and suites.
//
// It holds keys and plaintext, so it runs only on the sending device, and nothing here logs. A
// tlsClient is not safe for concurrent use.

// What a tlsClient needs. Start from defaultTlsClientSettings.
type tlsClientSettings struct {
	// SNI, which E1 requires to be the MX host.
	serverName string
	// Decides TL1-TL3 over the chain the MX sent, leaf first. Nil fails every handshake, so a caller
	// that forgets it can never run unauthenticated.
	verifyPeer func(chain []*x509.Certificate) error
	// Every random value. Nil is crypto/rand.
	rand io.Reader
	// The suites offered, in order.
	suites []uint16
	// Refuses a handshake whose messages exceed this many octets, so a hostile MX cannot grow the
	// transcript without bound. 256 KiB holds any real certificate chain.
	maxHandshakeBytes int
}

func defaultTlsClientSettings() *tlsClientSettings {
	return &tlsClientSettings{
		suites: []uint16{
			tlsSuiteAes128GcmSha256,
			tlsSuiteChacha20Poly1305Sha256,
			tlsSuiteEcdheEcdsaAes128GcmSha256,
			tlsSuiteEcdheRsaAes128GcmSha256,
		},
		maxHandshakeBytes: 256 * 1024,
	}
}

// What a finished handshake leaves behind: the relation's witness, and the values the prover and
// the edge must each arrive at on their own.
type tlsHandshakeResult struct {
	version uint16
	suite   uint16

	// 1.3. HS is what Go never exports; SHTS is the one secret disclosed, to the edge alone (E2).
	handshakeSecret []byte
	shts            []byte
	helloHash       []byte
	finishedHash    []byte

	// 1.2.
	masterSecret         []byte
	clientRandom         []byte
	serverRandom         []byte
	preFinishedMessages  []byte
	serverFinishedRecord []byte

	// Application keys. In 1.2 the IVs are the 4-octet salts.
	clientKey []byte
	clientIv  []byte
	serverKey []byte
	serverIv  []byte
}

// One record read from the MX after the handshake.
type tlsServerRecord struct {
	seq uint64
	// The record as relayed, header included.
	raw []byte
	// 1.3: the inner type. 1.2: the outer type.
	recordType uint8
	content    []byte
}

// A client application record, sealed and not yet sent.
type tlsSealedRecord struct {
	seq uint64
	raw []byte
}

type tlsClient struct {
	conn     net.Conn
	settings *tlsClientSettings

	transcript []byte
	buffer     tlsHandshakeBuffer
	// Set once a HelloRetryRequest has arrived.
	helloRetried bool

	clientCipher *tlsCipher
	serverCipher *tlsCipher

	result *tlsHandshakeResult
}

func newTlsClient(conn net.Conn, settings *tlsClientSettings) *tlsClient {
	return &tlsClient{conn: conn, settings: settings}
}

// Runs the handshake to completion. On success result holds the witness, and records may flow. Any
// failure ends the connection's usefulness: there is no recovery and no retry here.
func (self *tlsClient) handshake(ctx context.Context) (*tlsHandshakeResult, error) {
	if self.settings.verifyPeer == nil {
		return nil, errors.New("tls: no peer verifier")
	}
	if self.settings.serverName == "" {
		return nil, errors.New("tls: no server name")
	}
	// a deadline in the past wakes any blocked read or write
	stop := context.AfterFunc(ctx, func() {
		self.conn.SetDeadline(time.Unix(1, 0))
	})
	defer stop()
	testHookBarrier("tls.handshake.before", "")
	err := self.runHandshake()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("tls: %w", err)
	}
	testHookBarrier("tls.handshake.after", "")
	return self.result, nil
}

func (self *tlsClient) random() io.Reader {
	if self.settings.rand != nil {
		return self.settings.rand
	}
	return rand.Reader
}

func tlsCurve(group uint16) (ecdh.Curve, error) {
	switch group {
	case tlsGroupX25519:
		return ecdh.X25519(), nil
	case tlsGroupSecp256r1:
		return ecdh.P256(), nil
	case tlsGroupSecp384r1:
		return ecdh.P384(), nil
	default:
		return nil, fmt.Errorf("group %d is not supported", group)
	}
}

func (self *tlsClient) newKeyShare(group uint16) (*ecdh.PrivateKey, error) {
	curve, err := tlsCurve(group)
	if err != nil {
		return nil, err
	}
	key, err := curve.GenerateKey(self.random())
	if err != nil {
		return nil, err
	}
	testHookSecret("tls_ecdhe_private", key.Bytes())
	return key, nil
}

func (self *tlsClient) sharedSecret(key *ecdh.PrivateKey, peerShare []byte) ([]byte, error) {
	peer, err := key.Curve().NewPublicKey(peerShare)
	if err != nil {
		return nil, err
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		return nil, err
	}
	testHookSecret("tls_ecdhe_shared", shared)
	return shared, nil
}

// The ClientHello body. It offers neither PSK nor tickets, and in particular omits
// psk_key_exchange_modes, so a compliant MX sends no NewSessionTicket (SPEC.md 4.1).
func (self *tlsClient) clientHelloBody(clientRandom []byte, group uint16, share []byte, cookie []byte) ([]byte, error) {
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(tlsVersion12)
	builder.AddBytes(clientRandom)
	// an empty session id: no compatibility mode, no resumption
	builder.AddUint8(0)
	builder.AddUint16LengthPrefixed(func(suites *cryptobyte.Builder) {
		for _, suite := range self.settings.suites {
			suites.AddUint16(suite)
		}
	})
	builder.AddUint8LengthPrefixed(func(compression *cryptobyte.Builder) {
		compression.AddUint8(0)
	})
	builder.AddUint16LengthPrefixed(func(extensions *cryptobyte.Builder) {
		addExtension := func(extensionId uint16, content func(*cryptobyte.Builder)) {
			extensions.AddUint16(extensionId)
			extensions.AddUint16LengthPrefixed(content)
		}
		addExtension(tlsExtensionServerName, func(names *cryptobyte.Builder) {
			names.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
				list.AddUint8(0)
				list.AddUint16LengthPrefixed(func(name *cryptobyte.Builder) {
					name.AddBytes([]byte(self.settings.serverName))
				})
			})
		})
		addExtension(tlsExtensionSupportedVersions, func(versions *cryptobyte.Builder) {
			versions.AddUint8LengthPrefixed(func(list *cryptobyte.Builder) {
				list.AddUint16(tlsVersion13)
				list.AddUint16(tlsVersion12)
			})
		})
		addExtension(tlsExtensionSupportedGroups, func(groups *cryptobyte.Builder) {
			groups.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
				list.AddUint16(tlsGroupX25519)
				list.AddUint16(tlsGroupSecp256r1)
				list.AddUint16(tlsGroupSecp384r1)
			})
		})
		addExtension(tlsExtensionEcPointFormats, func(formats *cryptobyte.Builder) {
			formats.AddUint8LengthPrefixed(func(list *cryptobyte.Builder) {
				list.AddUint8(tlsPointFormatUncompressed)
			})
		})
		addExtension(tlsExtensionSignatureAlgorithms, func(schemes *cryptobyte.Builder) {
			schemes.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
				for _, scheme := range tlsSignatureSchemes {
					list.AddUint16(scheme)
				}
			})
		})
		addExtension(tlsExtensionExtendedMaster, func(*cryptobyte.Builder) {})
		addExtension(tlsExtensionRenegotiationInfo, func(info *cryptobyte.Builder) {
			info.AddUint8(0)
		})
		if cookie != nil {
			addExtension(tlsExtensionCookie, func(content *cryptobyte.Builder) {
				content.AddUint16LengthPrefixed(func(value *cryptobyte.Builder) {
					value.AddBytes(cookie)
				})
			})
		}
		addExtension(tlsExtensionKeyShare, func(shares *cryptobyte.Builder) {
			shares.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
				list.AddUint16(group)
				list.AddUint16LengthPrefixed(func(value *cryptobyte.Builder) {
					value.AddBytes(share)
				})
			})
		})
	})
	return builder.Bytes()
}

func (self *tlsClient) addTranscript(message []byte) error {
	self.transcript = append(self.transcript, message...)
	if self.settings.maxHandshakeBytes < len(self.transcript) {
		return errors.New("handshake too long")
	}
	return nil
}

func (self *tlsClient) transcriptHash() []byte {
	sum := sha256.Sum256(self.transcript)
	return sum[:]
}

func (self *tlsClient) writeAll(raw []byte) error {
	_, err := self.conn.Write(raw)
	return err
}

// Reads one record as framed on the wire, without opening it.
func (self *tlsClient) readRawRecord() ([]byte, error) {
	header := make([]byte, tlsRecordHeaderBytes)
	if _, err := io.ReadFull(self.conn, header); err != nil {
		return nil, err
	}
	size := int(header[3])<<8 | int(header[4])
	if tlsMaxCiphertextBytes < size {
		return nil, errors.New("record too long")
	}
	record := make([]byte, tlsRecordHeaderBytes+size)
	copy(record, header)
	if _, err := io.ReadFull(self.conn, record[tlsRecordHeaderBytes:]); err != nil {
		return nil, err
	}
	return record, nil
}

// The next handshake message in the clear. A 1.3 server may send a dummy change_cipher_spec any time
// after the first ClientHello, and Go's does right after a HelloRetryRequest. It is dropped (RFC
// 8446 §5). 1.2 has none here, so there it stays an error.
func (self *tlsClient) readPlainMessage() ([]byte, error) {
	for {
		if message := self.buffer.next(); message != nil {
			return message, nil
		}
		record, err := self.readRawRecord()
		if err != nil {
			return nil, err
		}
		switch record[0] {
		case tlsRecordHandshake:
			self.buffer.add(record[tlsRecordHeaderBytes:])
		case tlsRecordAlert:
			return nil, fmt.Errorf("alert %x", record[tlsRecordHeaderBytes:])
		case tlsRecordChangeCipherSpec:
			if !self.helloRetried || !tlsDummyChangeCipherSpec(record) {
				return nil, errors.New("unexpected change_cipher_spec")
			}
		default:
			return nil, fmt.Errorf("unexpected record type %d", record[0])
		}
		if self.settings.maxHandshakeBytes < len(self.buffer.pending) {
			return nil, errors.New("handshake too long")
		}
	}
}

// The next handshake message under the server handshake key. A 1.3 server in compatibility mode may
// put one change_cipher_spec in the flight, which is dropped (RFC 8446 §5).
func (self *tlsClient) readProtectedMessage() ([]byte, error) {
	for {
		if message := self.buffer.next(); message != nil {
			return message, nil
		}
		record, err := self.readRawRecord()
		if err != nil {
			return nil, err
		}
		if record[0] == tlsRecordChangeCipherSpec {
			if !tlsDummyChangeCipherSpec(record) {
				return nil, errors.New("unexpected change_cipher_spec")
			}
			continue
		}
		if record[0] != tlsRecordApplicationData {
			return nil, fmt.Errorf("unexpected record type %d", record[0])
		}
		recordType, content, err := self.serverCipher.open(record)
		if err != nil {
			return nil, err
		}
		if recordType != tlsRecordHandshake {
			return nil, fmt.Errorf("unexpected inner type %d", recordType)
		}
		self.buffer.add(content)
		if self.settings.maxHandshakeBytes < len(self.buffer.pending) {
			return nil, errors.New("handshake too long")
		}
	}
}

// Whether a change_cipher_spec record is the single octet 01 a 1.3 peer may send and drop.
func tlsDummyChangeCipherSpec(record []byte) bool {
	return len(record) == tlsRecordHeaderBytes+1 && record[tlsRecordHeaderBytes] == 1
}

func tlsExpectMessage(message []byte, handshakeType uint8) ([]byte, error) {
	if message[0] != handshakeType {
		return nil, fmt.Errorf("unexpected handshake message %d, expected %d", message[0], handshakeType)
	}
	return message[4:], nil
}

// Checks the chain with the injected TL1-TL3 policy, and returns the leaf.
func (self *tlsClient) verifyChain(certificates [][]byte) (*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(certificates))
	for _, der := range certificates {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		chain = append(chain, certificate)
	}
	if err := self.settings.verifyPeer(chain); err != nil {
		return nil, err
	}
	return chain[0], nil
}

func (self *tlsClient) offered(suite uint16) bool {
	for _, offered := range self.settings.suites {
		if offered == suite {
			return true
		}
	}
	return false
}

func (self *tlsClient) runHandshake() error {
	clientRandom := make([]byte, tlsRandomBytes)
	if _, err := io.ReadFull(self.random(), clientRandom); err != nil {
		return err
	}
	group := tlsGroupX25519
	key, err := self.newKeyShare(group)
	if err != nil {
		return err
	}
	body, err := self.clientHelloBody(clientRandom, group, key.PublicKey().Bytes(), nil)
	if err != nil {
		return err
	}
	clientHello := tlsHandshakeMessage(tlsHandshakeClientHello, body)
	if err := self.addTranscript(clientHello); err != nil {
		return err
	}
	if err := self.writeAll(tlsFrameRecord(tlsRecordHandshake, 0x0301, clientHello)); err != nil {
		return err
	}

	message, err := self.readPlainMessage()
	if err != nil {
		return err
	}
	serverBody, err := tlsExpectMessage(message, tlsHandshakeServerHello)
	if err != nil {
		return err
	}
	serverHello, err := tlsParseServerHello(serverBody)
	if err != nil {
		return err
	}
	if serverHello.retryRequest {
		if serverHello.version != tlsVersion13 || !self.offered(serverHello.suite) {
			return errors.New("bad hello retry request")
		}
		self.helloRetried = true
		// a retry must change something, and may only ask for a group this client supports
		if serverHello.keyShareGroup == group && serverHello.cookie == nil {
			return errors.New("hello retry request changes nothing")
		}
		if serverHello.keyShareGroup != 0 {
			group = serverHello.keyShareGroup
			if key, err = self.newKeyShare(group); err != nil {
				return err
			}
		}
		// the transcript starts over from the first hello's hash (RFC 8446 §4.4.1)
		firstHash := self.transcriptHash()
		self.transcript = nil
		if err := self.addTranscript(tlsHandshakeMessage(tlsHandshakeMessageHash, firstHash)); err != nil {
			return err
		}
		if err := self.addTranscript(message); err != nil {
			return err
		}
		retrySuite := serverHello.suite
		body, err = self.clientHelloBody(clientRandom, group, key.PublicKey().Bytes(), serverHello.cookie)
		if err != nil {
			return err
		}
		clientHello = tlsHandshakeMessage(tlsHandshakeClientHello, body)
		if err := self.addTranscript(clientHello); err != nil {
			return err
		}
		if err := self.writeAll(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, clientHello)); err != nil {
			return err
		}
		if message, err = self.readPlainMessage(); err != nil {
			return err
		}
		if serverBody, err = tlsExpectMessage(message, tlsHandshakeServerHello); err != nil {
			return err
		}
		if serverHello, err = tlsParseServerHello(serverBody); err != nil {
			return err
		}
		if serverHello.retryRequest || serverHello.suite != retrySuite || serverHello.version != tlsVersion13 {
			return errors.New("server hello disagrees with its retry request")
		}
	}
	if len(serverHello.sessionId) != 0 && serverHello.version == tlsVersion13 {
		return errors.New("server echoed a session id never sent")
	}
	if !self.offered(serverHello.suite) || !tlsSuiteCovered(serverHello.version, serverHello.suite) {
		return fmt.Errorf("server selected version %#x suite %#x, which is not covered", serverHello.version, serverHello.suite)
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	self.result = &tlsHandshakeResult{
		version:      serverHello.version,
		suite:        serverHello.suite,
		clientRandom: clientRandom,
		serverRandom: serverHello.random,
	}
	if serverHello.version == tlsVersion13 {
		if serverHello.hasExtension(tlsExtensionPreSharedKey) {
			return errors.New("server selected a psk never offered")
		}
		if serverHello.keyShareGroup != group {
			return errors.New("server key share is for another group")
		}
		return self.runHandshake13(key, serverHello)
	}
	// a 1.3-capable server negotiating 1.2 marks its random; a client must refuse that downgrade
	tail := string(serverHello.random[tlsRandomBytes-len(tlsDowngrade12):])
	if tail == string(tlsDowngrade12) || tail == string(tlsDowngrade11) {
		return errors.New("downgrade detected")
	}
	if serverHello.hasExtension(tlsExtensionSessionTicket) {
		return errors.New("server sent a session ticket extension never offered")
	}
	return self.runHandshake12(serverHello)
}

func (self *tlsClient) runHandshake13(key *ecdh.PrivateKey, serverHello *tlsServerHello) error {
	result := self.result
	shared, err := self.sharedSecret(key, serverHello.keyShare)
	if err != nil {
		return err
	}
	// everything so far went in one record, so nothing may be left buffered across the key change
	if !self.buffer.empty() {
		return errors.New("handshake message spans a key change")
	}
	result.handshakeSecret = tls13HandshakeSecret(shared)
	testHookSecret("tls13_hs", result.handshakeSecret)
	result.helloHash = self.transcriptHash()
	chts := tls13TrafficSecret(result.handshakeSecret, "c hs traffic", result.helloHash)
	testHookSecret("tls13_chts", chts)
	result.shts = tls13TrafficSecret(result.handshakeSecret, "s hs traffic", result.helloHash)
	testHookSecret("tls13_shts", result.shts)
	clientKey, clientIv := tls13TrafficKeys(result.suite, chts)
	testHookSecret("tls13_client_handshake_key", clientKey)
	testHookSecret("tls13_client_handshake_iv", clientIv)
	serverKey, serverIv := tls13TrafficKeys(result.suite, result.shts)
	testHookSecret("tls13_server_handshake_key", serverKey)
	testHookSecret("tls13_server_handshake_iv", serverIv)
	if self.clientCipher, err = newTlsCipher(tlsVersion13, result.suite, clientKey, clientIv); err != nil {
		return err
	}
	if self.serverCipher, err = newTlsCipher(tlsVersion13, result.suite, serverKey, serverIv); err != nil {
		return err
	}

	message, err := self.readProtectedMessage()
	if err != nil {
		return err
	}
	if _, err := tlsExpectMessage(message, tlsHandshakeEncryptedExtension); err != nil {
		return err
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	if message, err = self.readProtectedMessage(); err != nil {
		return err
	}
	certificateRequested := message[0] == tlsHandshakeCertificateRequest
	if certificateRequested {
		if err := self.addTranscript(message); err != nil {
			return err
		}
		if message, err = self.readProtectedMessage(); err != nil {
			return err
		}
	}
	certificateBody, err := tlsExpectMessage(message, tlsHandshakeCertificate)
	if err != nil {
		return err
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	certificates, err := tlsParseCertificate(tlsVersion13, certificateBody)
	if err != nil {
		return err
	}
	leaf, err := self.verifyChain(certificates)
	if err != nil {
		return err
	}
	if message, err = self.readProtectedMessage(); err != nil {
		return err
	}
	verifyBody, err := tlsExpectMessage(message, tlsHandshakeCertificateVerify)
	if err != nil {
		return err
	}
	input := cryptobyte.String(verifyBody)
	var scheme uint16
	var signature cryptobyte.String
	if !input.ReadUint16(&scheme) || !input.ReadUint16LengthPrefixed(&signature) || !input.Empty() {
		return errors.New("malformed certificate verify")
	}
	signed := tlsCertificateVerifySigned(self.transcriptHash())
	if err := tlsVerifySignature(tlsVersion13, leaf.PublicKey, scheme, signed, signature); err != nil {
		return err
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	if message, err = self.readProtectedMessage(); err != nil {
		return err
	}
	finishedBody, err := tlsExpectMessage(message, tlsHandshakeFinished)
	if err != nil {
		return err
	}
	if !hmac.Equal(finishedBody, tls13FinishedData(result.shts, self.transcriptHash())) {
		return errors.New("bad server finished")
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	if !self.buffer.empty() {
		return errors.New("handshake message spans a key change")
	}
	result.finishedHash = self.transcriptHash()

	masterSecret := tls13MasterSecret(result.handshakeSecret)
	testHookSecret("tls13_ms", masterSecret)
	result.masterSecret = masterSecret
	cats := tls13TrafficSecret(masterSecret, "c ap traffic", result.finishedHash)
	testHookSecret("tls13_cats", cats)
	sats := tls13TrafficSecret(masterSecret, "s ap traffic", result.finishedHash)
	testHookSecret("tls13_sats", sats)
	result.clientKey, result.clientIv = tls13TrafficKeys(result.suite, cats)
	testHookSecret("tls13_client_key", result.clientKey)
	testHookSecret("tls13_client_iv", result.clientIv)
	result.serverKey, result.serverIv = tls13TrafficKeys(result.suite, sats)
	testHookSecret("tls13_server_key", result.serverKey)
	testHookSecret("tls13_server_iv", result.serverIv)

	// one record, whose length E1 fixes: an empty Certificate if asked, then Finished
	var flight []byte
	if certificateRequested {
		emptyCertificate := tlsHandshakeMessage(tlsHandshakeCertificate, []byte{0, 0, 0, 0})
		flight = append(flight, emptyCertificate...)
		if err := self.addTranscript(emptyCertificate); err != nil {
			return err
		}
	}
	clientFinished := tlsHandshakeMessage(tlsHandshakeFinished, tls13FinishedData(chts, self.transcriptHash()))
	flight = append(flight, clientFinished...)
	if err := self.addTranscript(clientFinished); err != nil {
		return err
	}
	sealed, err := self.clientCipher.seal(tlsRecordHandshake, flight)
	if err != nil {
		return err
	}
	if err := self.writeAll(sealed); err != nil {
		return err
	}
	if self.clientCipher, err = newTlsCipher(tlsVersion13, result.suite, result.clientKey, result.clientIv); err != nil {
		return err
	}
	if self.serverCipher, err = newTlsCipher(tlsVersion13, result.suite, result.serverKey, result.serverIv); err != nil {
		return err
	}
	return nil
}

// Reads ServerKeyExchange's ECDHE parameters, returning the group, the server's point and the
// octets its signature covers after the two randoms.
func tlsParseServerKeyExchange(body []byte) (group uint16, point []byte, params []byte, scheme uint16, signature []byte, err error) {
	input := cryptobyte.String(body)
	var curveType uint8
	var pointBytes, signatureBytes cryptobyte.String
	if !input.ReadUint8(&curveType) || curveType != tlsCurveTypeNamed ||
		!input.ReadUint16(&group) ||
		!input.ReadUint8LengthPrefixed(&pointBytes) {
		return 0, nil, nil, 0, nil, errors.New("malformed server key exchange")
	}
	params = body[:len(body)-len(input)]
	if !input.ReadUint16(&scheme) || !input.ReadUint16LengthPrefixed(&signatureBytes) || !input.Empty() {
		return 0, nil, nil, 0, nil, errors.New("malformed server key exchange signature")
	}
	return group, []byte(pointBytes), params, scheme, []byte(signatureBytes), nil
}

func (self *tlsClient) runHandshake12(serverHello *tlsServerHello) error {
	result := self.result
	message, err := self.readPlainMessage()
	if err != nil {
		return err
	}
	certificateBody, err := tlsExpectMessage(message, tlsHandshakeCertificate)
	if err != nil {
		return err
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	certificates, err := tlsParseCertificate(tlsVersion12, certificateBody)
	if err != nil {
		return err
	}
	leaf, err := self.verifyChain(certificates)
	if err != nil {
		return err
	}
	if message, err = self.readPlainMessage(); err != nil {
		return err
	}
	exchangeBody, err := tlsExpectMessage(message, tlsHandshakeServerKeyExchange)
	if err != nil {
		return err
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	group, point, params, scheme, signature, err := tlsParseServerKeyExchange(exchangeBody)
	if err != nil {
		return err
	}
	signed := make([]byte, 0, 2*tlsRandomBytes+len(params))
	signed = append(signed, result.clientRandom...)
	signed = append(signed, result.serverRandom...)
	signed = append(signed, params...)
	if err := tlsVerifySignature(tlsVersion12, leaf.PublicKey, scheme, signed, signature); err != nil {
		return err
	}

	if message, err = self.readPlainMessage(); err != nil {
		return err
	}
	certificateRequested := message[0] == tlsHandshakeCertificateRequest
	if certificateRequested {
		if err := self.addTranscript(message); err != nil {
			return err
		}
		if message, err = self.readPlainMessage(); err != nil {
			return err
		}
	}
	if _, err := tlsExpectMessage(message, tlsHandshakeServerHelloDone); err != nil {
		return err
	}
	if err := self.addTranscript(message); err != nil {
		return err
	}
	if !self.buffer.empty() {
		return errors.New("handshake message spans a key change")
	}

	key, err := self.newKeyShare(group)
	if err != nil {
		return err
	}
	preMasterSecret, err := self.sharedSecret(key, point)
	if err != nil {
		return err
	}
	var flight []byte
	if certificateRequested {
		emptyCertificate := tlsHandshakeMessage(tlsHandshakeCertificate, []byte{0, 0, 0})
		flight = append(flight, tlsFrameRecord(tlsRecordHandshake, tlsVersion12, emptyCertificate)...)
		if err := self.addTranscript(emptyCertificate); err != nil {
			return err
		}
	}
	share := key.PublicKey().Bytes()
	exchange := make([]byte, 0, 1+len(share))
	exchange = append(exchange, byte(len(share)))
	exchange = append(exchange, share...)
	clientExchange := tlsHandshakeMessage(tlsHandshakeClientKeyExchange, exchange)
	flight = append(flight, tlsFrameRecord(tlsRecordHandshake, tlsVersion12, clientExchange)...)
	if err := self.addTranscript(clientExchange); err != nil {
		return err
	}
	// every message before the client's Finished: S_ckx is the SHA-256 state after exactly these
	result.preFinishedMessages = append([]byte{}, self.transcript...)

	if serverHello.hasExtension(tlsExtensionExtendedMaster) {
		result.masterSecret = tls12Prf(preMasterSecret, tlsLabelExtendedMasterSecret, self.transcriptHash(), tlsMasterSecretBytes)
	} else {
		seed := make([]byte, 0, 2*tlsRandomBytes)
		seed = append(seed, result.clientRandom...)
		seed = append(seed, result.serverRandom...)
		result.masterSecret = tls12Prf(preMasterSecret, tlsLabelMasterSecret, seed, tlsMasterSecretBytes)
	}
	testHookSecret("tls12_master_secret", result.masterSecret)
	keyBlock := tls12DeriveKeyBlock(result.masterSecret, result.clientRandom, result.serverRandom)
	result.clientKey, result.clientIv = keyBlock.clientKey, keyBlock.clientSalt
	result.serverKey, result.serverIv = keyBlock.serverKey, keyBlock.serverSalt
	testHookSecret("tls12_client_key", result.clientKey)
	testHookSecret("tls12_client_salt", result.clientIv)
	testHookSecret("tls12_server_key", result.serverKey)
	testHookSecret("tls12_server_salt", result.serverIv)
	if self.clientCipher, err = newTlsCipher(tlsVersion12, result.suite, result.clientKey, result.clientIv); err != nil {
		return err
	}
	if self.serverCipher, err = newTlsCipher(tlsVersion12, result.suite, result.serverKey, result.serverIv); err != nil {
		return err
	}

	clientFinished := tls12FinishedMessage(result.masterSecret, tlsLabelClientFinished, self.transcriptHash())
	if err := self.addTranscript(clientFinished); err != nil {
		return err
	}
	sealed, err := self.clientCipher.seal(tlsRecordHandshake, clientFinished)
	if err != nil {
		return err
	}
	flight = append(flight, tlsFrameRecord(tlsRecordChangeCipherSpec, tlsVersion12, []byte{1})...)
	flight = append(flight, sealed...)
	if err := self.writeAll(flight); err != nil {
		return err
	}

	record, err := self.readRawRecord()
	if err != nil {
		return err
	}
	if record[0] != tlsRecordChangeCipherSpec {
		return fmt.Errorf("unexpected record type %d before server finished", record[0])
	}
	if record, err = self.readRawRecord(); err != nil {
		return err
	}
	if record[0] != tlsRecordHandshake {
		return fmt.Errorf("unexpected record type %d for server finished", record[0])
	}
	result.serverFinishedRecord = record
	recordType, content, err := self.serverCipher.open(record)
	if err != nil {
		return err
	}
	want := tls12FinishedMessage(result.masterSecret, tlsLabelServerFinished, self.transcriptHash())
	if recordType != tlsRecordHandshake || !hmac.Equal(content, want) {
		return errors.New("bad server finished")
	}
	return nil
}

// Seals application content into the next client record without sending it, so a proof can cover
// the ciphertext first. 1.3 records are unpadded (Z3). Each call consumes a sequence number, so
// records must go out in the order they were sealed.
func (self *tlsClient) sealApplication(content []byte) (*tlsSealedRecord, error) {
	seq := self.clientCipher.seq
	raw, err := self.clientCipher.seal(tlsRecordApplicationData, content)
	if err != nil {
		return nil, err
	}
	return &tlsSealedRecord{seq: seq, raw: raw}, nil
}

// Sends a sealed record, which holds no state here beyond its bytes.
func (self *tlsClient) writeSealed(record *tlsSealedRecord) error {
	return self.writeAll(record.raw)
}

// Reads and opens the next record from the MX, of any type. Tickets, alerts and KeyUpdates are the
// caller's to judge: a KeyUpdate is returned like any other record, and every record after it fails
// here, because this client never updates keys (Z7).
func (self *tlsClient) readRecord(ctx context.Context) (*tlsServerRecord, error) {
	stop := context.AfterFunc(ctx, func() {
		self.conn.SetDeadline(time.Unix(1, 0))
	})
	defer stop()
	raw, err := self.readRawRecord()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	seq := self.serverCipher.seq
	recordType, content, err := self.serverCipher.open(raw)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	return &tlsServerRecord{seq: seq, raw: raw, recordType: recordType, content: content}, nil
}
