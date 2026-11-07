package smtpproof

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// The TLS wire values the prover's client and the edge's handshake checks share: only what E1's
// covered versions and suites use (SPEC.md 4.1). These are protocol facts, not tunables.

const (
	tlsVersion12 uint16 = 0x0303
	tlsVersion13 uint16 = 0x0304

	tlsSuiteAes128GcmSha256           uint16 = 0x1301
	tlsSuiteChacha20Poly1305Sha256    uint16 = 0x1303
	tlsSuiteEcdheRsaAes128GcmSha256   uint16 = 0xc02f
	tlsSuiteEcdheEcdsaAes128GcmSha256 uint16 = 0xc02b

	tlsRecordChangeCipherSpec uint8 = 20
	tlsRecordAlert            uint8 = 21
	tlsRecordHandshake        uint8 = 22
	tlsRecordApplicationData  uint8 = 23

	tlsHandshakeClientHello        uint8 = 1
	tlsHandshakeServerHello        uint8 = 2
	tlsHandshakeNewSessionTicket   uint8 = 4
	tlsHandshakeEncryptedExtension uint8 = 8
	tlsHandshakeCertificate        uint8 = 11
	tlsHandshakeServerKeyExchange  uint8 = 12
	tlsHandshakeCertificateRequest uint8 = 13
	tlsHandshakeServerHelloDone    uint8 = 14
	tlsHandshakeCertificateVerify  uint8 = 15
	tlsHandshakeClientKeyExchange  uint8 = 16
	tlsHandshakeFinished           uint8 = 20
	tlsHandshakeKeyUpdate          uint8 = 24
	tlsHandshakeMessageHash        uint8 = 254

	tlsExtensionServerName          uint16 = 0
	tlsExtensionSupportedGroups     uint16 = 10
	tlsExtensionEcPointFormats      uint16 = 11
	tlsExtensionSignatureAlgorithms uint16 = 13
	tlsExtensionExtendedMaster      uint16 = 23
	tlsExtensionSessionTicket       uint16 = 35
	tlsExtensionPreSharedKey        uint16 = 41
	tlsExtensionEarlyData           uint16 = 42
	tlsExtensionSupportedVersions   uint16 = 43
	tlsExtensionCookie              uint16 = 44
	tlsExtensionKeyShare            uint16 = 51
	tlsExtensionRenegotiationInfo   uint16 = 0xff01

	tlsGroupX25519    uint16 = 29
	tlsGroupSecp256r1 uint16 = 23
	tlsGroupSecp384r1 uint16 = 24

	tlsSchemeRsaPkcs1Sha256      uint16 = 0x0401
	tlsSchemeRsaPkcs1Sha384      uint16 = 0x0501
	tlsSchemeRsaPkcs1Sha512      uint16 = 0x0601
	tlsSchemeEcdsaSecp256r1      uint16 = 0x0403
	tlsSchemeEcdsaSecp384r1      uint16 = 0x0503
	tlsSchemeEcdsaSecp521r1      uint16 = 0x0603
	tlsSchemeRsaPssRsaeSha256    uint16 = 0x0804
	tlsSchemeRsaPssRsaeSha384    uint16 = 0x0805
	tlsSchemeRsaPssRsaeSha512    uint16 = 0x0806
	tlsSchemeEd25519             uint16 = 0x0807
	tlsAlertCloseNotify          uint8  = 0
	tlsRecordHeaderBytes                = 5
	tlsMaxPlaintextBytes                = 16 * 1024
	tlsMaxCiphertextBytes               = 16*1024 + 256
	tlsAeadTagBytes                     = 16
	tlsExplicitNonceBytes               = 8
	tlsRandomBytes                      = 32
	tlsVerifyData12Bytes                = 12
	tlsFinished13Bytes                  = 32
	tlsCurveTypeNamed            uint8  = 3
	tlsPointFormatUncompressed   uint8  = 0
	tlsCertificateVerifyContext         = "TLS 1.3, server CertificateVerify"
	tlsCertificateVerifyPadBytes        = 64
)

// The ServerHello.random of a HelloRetryRequest, SHA-256("HelloRetryRequest") (RFC 8446 §4.1.3).
var tlsHelloRetryRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

// The last octets of ServerHello.random when a 1.3 server negotiates lower (RFC 8446 §4.1.3).
var (
	tlsDowngrade12 = []byte("DOWNGRD\x01")
	tlsDowngrade11 = []byte("DOWNGRD\x00")
)

// Every scheme the client offers and either role accepts. No SHA-1 scheme is here, so none passes.
var tlsSignatureSchemes = []uint16{
	tlsSchemeEd25519,
	tlsSchemeEcdsaSecp256r1,
	tlsSchemeEcdsaSecp384r1,
	tlsSchemeEcdsaSecp521r1,
	tlsSchemeRsaPssRsaeSha256,
	tlsSchemeRsaPssRsaeSha384,
	tlsSchemeRsaPssRsaeSha512,
	tlsSchemeRsaPkcs1Sha256,
	tlsSchemeRsaPkcs1Sha384,
	tlsSchemeRsaPkcs1Sha512,
}

// Whether a negotiated version and suite are E1's.
func tlsSuiteCovered(version uint16, suite uint16) bool {
	switch version {
	case tlsVersion13:
		return suite == tlsSuiteAes128GcmSha256 || suite == tlsSuiteChacha20Poly1305Sha256
	case tlsVersion12:
		return suite == tlsSuiteEcdheRsaAes128GcmSha256 || suite == tlsSuiteEcdheEcdsaAes128GcmSha256
	default:
		return false
	}
}

// Appends a handshake message's four-octet header and body.
func tlsHandshakeMessage(handshakeType uint8, body []byte) []byte {
	message := make([]byte, 0, 4+len(body))
	message = append(message, handshakeType, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(message, body...)
}

// One record as framed on the wire, header included.
func tlsFrameRecord(recordType uint8, version uint16, payload []byte) []byte {
	record := make([]byte, 0, tlsRecordHeaderBytes+len(payload))
	record = append(record, recordType, byte(version>>8), byte(version), byte(len(payload)>>8), byte(len(payload)))
	return append(record, payload...)
}

// A parsed ClientHello, as far as E1 reads one. tlsParseClientHello is the only constructor.
type tlsClientHello struct {
	random       []byte
	sessionId    []byte
	suites       []uint16
	serverName   string
	extensionIds []uint16
}

func (self *tlsClientHello) hasExtension(extensionId uint16) bool {
	for _, id := range self.extensionIds {
		if id == extensionId {
			return true
		}
	}
	return false
}

// The body of a ClientHello, without its handshake header.
func tlsParseClientHello(body []byte) (*tlsClientHello, error) {
	input := cryptobyte.String(body)
	var legacyVersion uint16
	hello := &tlsClientHello{}
	var sessionId, suites, compression, extensions cryptobyte.String
	if !input.ReadUint16(&legacyVersion) ||
		!input.ReadBytes(&hello.random, tlsRandomBytes) ||
		!input.ReadUint8LengthPrefixed(&sessionId) ||
		!input.ReadUint16LengthPrefixed(&suites) ||
		!input.ReadUint8LengthPrefixed(&compression) ||
		!input.ReadUint16LengthPrefixed(&extensions) ||
		!input.Empty() {
		return nil, errors.New("malformed client hello")
	}
	hello.sessionId = []byte(sessionId)
	for !suites.Empty() {
		var suite uint16
		if !suites.ReadUint16(&suite) {
			return nil, errors.New("malformed client hello suites")
		}
		hello.suites = append(hello.suites, suite)
	}
	// E1 compares one server name, so a hello an MX could read as naming another is refused here: RFC
	// 8446 §4.2 forbids a repeated extension, and this client sends one name
	seen := map[uint16]bool{}
	for !extensions.Empty() {
		var extensionId uint16
		var extension cryptobyte.String
		if !extensions.ReadUint16(&extensionId) || !extensions.ReadUint16LengthPrefixed(&extension) {
			return nil, errors.New("malformed client hello extension")
		}
		if seen[extensionId] {
			return nil, errors.New("client hello repeats an extension")
		}
		seen[extensionId] = true
		hello.extensionIds = append(hello.extensionIds, extensionId)
		if extensionId == tlsExtensionServerName {
			var names, name cryptobyte.String
			var nameType uint8
			if !extension.ReadUint16LengthPrefixed(&names) ||
				!names.ReadUint8(&nameType) ||
				!names.ReadUint16LengthPrefixed(&name) ||
				nameType != 0 ||
				!names.Empty() ||
				!extension.Empty() {
				return nil, errors.New("malformed server name")
			}
			hello.serverName = string(name)
		}
	}
	return hello, nil
}

// A parsed ServerHello. tlsParseServerHello is the only constructor.
type tlsServerHello struct {
	random        []byte
	sessionId     []byte
	suite         uint16
	version       uint16
	keyShareGroup uint16
	keyShare      []byte
	cookie        []byte
	extensionIds  []uint16
	retryRequest  bool
}

func (self *tlsServerHello) hasExtension(extensionId uint16) bool {
	for _, id := range self.extensionIds {
		if id == extensionId {
			return true
		}
	}
	return false
}

// The body of a ServerHello, without its handshake header. version is the negotiated version, from
// supported_versions when present.
func tlsParseServerHello(body []byte) (*tlsServerHello, error) {
	input := cryptobyte.String(body)
	hello := &tlsServerHello{}
	var legacyVersion uint16
	var compression uint8
	var sessionId, extensions cryptobyte.String
	if !input.ReadUint16(&legacyVersion) ||
		!input.ReadBytes(&hello.random, tlsRandomBytes) ||
		!input.ReadUint8LengthPrefixed(&sessionId) ||
		!input.ReadUint16(&hello.suite) ||
		!input.ReadUint8(&compression) {
		return nil, errors.New("malformed server hello")
	}
	if compression != 0 {
		return nil, errors.New("server hello selected compression")
	}
	hello.sessionId = []byte(sessionId)
	hello.version = legacyVersion
	hello.retryRequest = string(hello.random) == string(tlsHelloRetryRandom)
	if input.Empty() {
		return hello, nil
	}
	if !input.ReadUint16LengthPrefixed(&extensions) || !input.Empty() {
		return nil, errors.New("malformed server hello extensions")
	}
	for !extensions.Empty() {
		var extensionId uint16
		var extension cryptobyte.String
		if !extensions.ReadUint16(&extensionId) || !extensions.ReadUint16LengthPrefixed(&extension) {
			return nil, errors.New("malformed server hello extension")
		}
		hello.extensionIds = append(hello.extensionIds, extensionId)
		switch extensionId {
		case tlsExtensionSupportedVersions:
			if !extension.ReadUint16(&hello.version) || !extension.Empty() {
				return nil, errors.New("malformed supported_versions")
			}
		case tlsExtensionKeyShare:
			if !extension.ReadUint16(&hello.keyShareGroup) {
				return nil, errors.New("malformed key_share")
			}
			// a HelloRetryRequest names only the group
			if !hello.retryRequest {
				var share cryptobyte.String
				if !extension.ReadUint16LengthPrefixed(&share) || !extension.Empty() {
					return nil, errors.New("malformed key_share")
				}
				hello.keyShare = []byte(share)
			}
		case tlsExtensionCookie:
			var cookie cryptobyte.String
			if !extension.ReadUint16LengthPrefixed(&cookie) || !extension.Empty() {
				return nil, errors.New("malformed cookie")
			}
			hello.cookie = []byte(cookie)
		}
	}
	return hello, nil
}

// The certificates of a Certificate message, leaf first, in DER. 1.3 wraps each in an entry with
// extensions and prefixes a request context.
func tlsParseCertificate(version uint16, body []byte) ([][]byte, error) {
	input := cryptobyte.String(body)
	if version == tlsVersion13 {
		var requestContext cryptobyte.String
		if !input.ReadUint8LengthPrefixed(&requestContext) {
			return nil, errors.New("malformed certificate context")
		}
	}
	var list cryptobyte.String
	if !input.ReadUint24LengthPrefixed(&list) || !input.Empty() {
		return nil, errors.New("malformed certificate list")
	}
	var certificates [][]byte
	for !list.Empty() {
		var certificate cryptobyte.String
		if !list.ReadUint24LengthPrefixed(&certificate) {
			return nil, errors.New("malformed certificate entry")
		}
		certificates = append(certificates, []byte(certificate))
		if version == tlsVersion13 {
			var extensions cryptobyte.String
			if !list.ReadUint16LengthPrefixed(&extensions) {
				return nil, errors.New("malformed certificate entry extensions")
			}
		}
	}
	if len(certificates) == 0 {
		return nil, errors.New("server sent no certificate")
	}
	return certificates, nil
}

// The content a 1.3 CertificateVerify signs (RFC 8446 §4.4.3).
func tlsCertificateVerifySigned(transcriptHash []byte) []byte {
	signed := make([]byte, 0, tlsCertificateVerifyPadBytes+len(tlsCertificateVerifyContext)+1+len(transcriptHash))
	for range tlsCertificateVerifyPadBytes {
		signed = append(signed, 0x20)
	}
	signed = append(signed, tlsCertificateVerifyContext...)
	signed = append(signed, 0)
	return append(signed, transcriptHash...)
}

// Checks a TLS signature under a certificate's public key, for the given version's rules: 1.3 ties
// each ECDSA scheme to its curve and allows no PKCS #1 v1.5. Used by both the client and E2.
func tlsVerifySignature(version uint16, publicKey crypto.PublicKey, scheme uint16, signed []byte, signature []byte) error {
	allowed := false
	for _, offered := range tlsSignatureSchemes {
		allowed = allowed || offered == scheme
	}
	if !allowed {
		return fmt.Errorf("signature scheme %#x is not accepted", scheme)
	}
	digest := func(hash crypto.Hash) []byte {
		switch hash {
		case crypto.SHA256:
			sum := sha256.Sum256(signed)
			return sum[:]
		case crypto.SHA384:
			sum := sha512.Sum384(signed)
			return sum[:]
		default:
			sum := sha512.Sum512(signed)
			return sum[:]
		}
	}
	switch scheme {
	case tlsSchemeEd25519:
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("ed25519 scheme with another key type")
		}
		if !ed25519.Verify(key, signed, signature) {
			return errors.New("bad ed25519 signature")
		}
		return nil
	case tlsSchemeEcdsaSecp256r1, tlsSchemeEcdsaSecp384r1, tlsSchemeEcdsaSecp521r1:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("ecdsa scheme with another key type")
		}
		hash := crypto.SHA256
		curve := elliptic.P256()
		if scheme == tlsSchemeEcdsaSecp384r1 {
			hash, curve = crypto.SHA384, elliptic.P384()
		} else if scheme == tlsSchemeEcdsaSecp521r1 {
			hash, curve = crypto.SHA512, elliptic.P521()
		}
		if version == tlsVersion13 && key.Curve != curve {
			return errors.New("ecdsa scheme does not match the key's curve")
		}
		if !ecdsa.VerifyASN1(key, digest(hash), signature) {
			return errors.New("bad ecdsa signature")
		}
		return nil
	case tlsSchemeRsaPssRsaeSha256, tlsSchemeRsaPssRsaeSha384, tlsSchemeRsaPssRsaeSha512:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("rsa scheme with another key type")
		}
		hash := crypto.SHA256
		if scheme == tlsSchemeRsaPssRsaeSha384 {
			hash = crypto.SHA384
		} else if scheme == tlsSchemeRsaPssRsaeSha512 {
			hash = crypto.SHA512
		}
		return rsa.VerifyPSS(key, hash, digest(hash), signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		if version == tlsVersion13 {
			return errors.New("pkcs1 signature in tls 1.3")
		}
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("rsa scheme with another key type")
		}
		hash := crypto.SHA256
		if scheme == tlsSchemeRsaPkcs1Sha384 {
			hash = crypto.SHA384
		} else if scheme == tlsSchemeRsaPkcs1Sha512 {
			hash = crypto.SHA512
		}
		return rsa.VerifyPKCS1v15(key, hash, digest(hash), signature)
	}
}

// Splits a stream of handshake messages, which records may fragment or pack. It holds what is not
// yet a whole message.
type tlsHandshakeBuffer struct {
	pending []byte
}

func (self *tlsHandshakeBuffer) add(fragment []byte) {
	self.pending = append(self.pending, fragment...)
}

// The next whole message, header included, or nil if more is needed.
func (self *tlsHandshakeBuffer) next() []byte {
	if len(self.pending) < 4 {
		return nil
	}
	size := int(self.pending[1])<<16 | int(self.pending[2])<<8 | int(self.pending[3])
	if len(self.pending) < 4+size {
		return nil
	}
	message := self.pending[: 4+size : 4+size]
	self.pending = self.pending[4+size:]
	return message
}

// Whether no partial message is buffered.
func (self *tlsHandshakeBuffer) empty() bool {
	return len(self.pending) == 0
}
