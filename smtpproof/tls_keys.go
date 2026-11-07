package smtpproof

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// TLS key derivation and record protection, for the prover's client, the edge's E2 checks and the
// reference relation. Every covered suite hashes with SHA-256 (E1), so nothing here is generic over
// the hash. Every function is pure; tlsCipher alone carries state, its sequence number.

const (
	tlsSecretBytes       = 32
	tlsIv13Bytes         = 12
	tlsSalt12Bytes       = 4
	tlsAes128KeyBytes    = 16
	tlsChachaKeyBytes    = 32
	tlsMasterSecretBytes = 48

	// The TLS 1.2 PRF labels (RFC 5246, RFC 7627).
	tlsLabelMasterSecret         = "master secret"
	tlsLabelExtendedMasterSecret = "extended master secret"
	tlsLabelKeyExpansion         = "key expansion"
	tlsLabelClientFinished       = "client finished"
	tlsLabelServerFinished       = "server finished"
)

// The fixed prefix of each 1.3 label (RFC 8446 §7.1).
const tlsLabelPrefix = "tls13 "

// HKDF-Expand-Label (RFC 8446 §7.1), for a SHA-256 suite.
func tlsExpandLabel(secret []byte, label string, context []byte, size int) []byte {
	info := tlsExpandLabelInfo(label, context, size)
	out, err := hkdf.Expand(sha256.New, secret, string(info), size)
	if err != nil {
		// only a size past 255 hash lengths fails, and none here is
		panic(err)
	}
	return out
}

// The HkdfLabel structure, which the circuit hashes as HMAC input.
func tlsExpandLabelInfo(label string, context []byte, size int) []byte {
	info := make([]byte, 0, 4+len(tlsLabelPrefix)+len(label)+len(context))
	info = append(info, byte(size>>8), byte(size), byte(len(tlsLabelPrefix)+len(label)))
	info = append(info, tlsLabelPrefix...)
	info = append(info, label...)
	info = append(info, byte(len(context)))
	return append(info, context...)
}

// HKDF-Extract with SHA-256.
func tlsExtract(salt []byte, keying []byte) []byte {
	out, err := hkdf.Extract(sha256.New, keying, salt)
	if err != nil {
		panic(err)
	}
	return out
}

// The SHA-256 of the empty string, Derive-Secret's context for "derived".
func tlsEmptyHash() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

// The 1.3 key schedule from the ECDHE secret up to HS.
func tls13HandshakeSecret(sharedSecret []byte) []byte {
	zeros := make([]byte, tlsSecretBytes)
	earlySecret := tlsExtract(nil, zeros)
	derived := tlsExpandLabel(earlySecret, "derived", tlsEmptyHash(), tlsSecretBytes)
	return tlsExtract(derived, sharedSecret)
}

// MS from HS. This and the two traffic secrets below are exactly what Z1 proves.
func tls13MasterSecret(handshakeSecret []byte) []byte {
	derived := tlsExpandLabel(handshakeSecret, "derived", tlsEmptyHash(), tlsSecretBytes)
	return tlsExtract(derived, make([]byte, tlsSecretBytes))
}

// A direction's handshake or application traffic secret; label is RFC 8446 §7.1's.
func tls13TrafficSecret(secret []byte, label string, transcriptHash []byte) []byte {
	return tlsExpandLabel(secret, label, transcriptHash, tlsSecretBytes)
}

// The AEAD key length of a suite.
func tlsKeyBytes(suite uint16) int {
	if suite == tlsSuiteChacha20Poly1305Sha256 {
		return tlsChachaKeyBytes
	}
	return tlsAes128KeyBytes
}

// A traffic secret's key and IV (RFC 8446 §7.3).
func tls13TrafficKeys(suite uint16, trafficSecret []byte) (key []byte, iv []byte) {
	key = tlsExpandLabel(trafficSecret, "key", nil, tlsKeyBytes(suite))
	iv = tlsExpandLabel(trafficSecret, "iv", nil, tlsIv13Bytes)
	return key, iv
}

// A Finished's verify_data under a traffic secret (RFC 8446 §4.4.4).
func tls13FinishedData(trafficSecret []byte, transcriptHash []byte) []byte {
	finishedKey := tlsExpandLabel(trafficSecret, "finished", nil, tlsSecretBytes)
	mac := hmac.New(sha256.New, finishedKey)
	mac.Write(transcriptHash)
	return mac.Sum(nil)
}

// The TLS 1.2 PRF with SHA-256 (RFC 5246 §5).
func tls12Prf(secret []byte, label string, seed []byte, size int) []byte {
	labelSeed := make([]byte, 0, len(label)+len(seed))
	labelSeed = append(labelSeed, label...)
	labelSeed = append(labelSeed, seed...)
	out := make([]byte, 0, size+sha256.Size)
	a := labelSeed
	for len(out) < size {
		mac := hmac.New(sha256.New, secret)
		mac.Write(a)
		a = mac.Sum(nil)
		mac.Reset()
		mac.Write(a)
		mac.Write(labelSeed)
		out = mac.Sum(out)
	}
	return out[:size]
}

// The four keying values a 1.2 AES-128-GCM connection uses, from its key block.
type tls12KeyBlock struct {
	clientKey  []byte
	serverKey  []byte
	clientSalt []byte
	serverSalt []byte
}

func tls12DeriveKeyBlock(masterSecret []byte, clientRandom []byte, serverRandom []byte) *tls12KeyBlock {
	seed := make([]byte, 0, 2*tlsRandomBytes)
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)
	block := tls12Prf(masterSecret, tlsLabelKeyExpansion, seed, 2*tlsAes128KeyBytes+2*tlsSalt12Bytes)
	return &tls12KeyBlock{
		clientKey:  block[:tlsAes128KeyBytes],
		serverKey:  block[tlsAes128KeyBytes : 2*tlsAes128KeyBytes],
		clientSalt: block[2*tlsAes128KeyBytes : 2*tlsAes128KeyBytes+tlsSalt12Bytes],
		serverSalt: block[2*tlsAes128KeyBytes+tlsSalt12Bytes:],
	}
}

// A 1.2 Finished's plaintext, handshake header included.
func tls12FinishedMessage(masterSecret []byte, label string, transcriptHash []byte) []byte {
	return tlsHandshakeMessage(tlsHandshakeFinished, tls12Prf(masterSecret, label, transcriptHash, tlsVerifyData12Bytes))
}

// One direction of record protection under one key. Not safe for concurrent use.
type tlsCipher struct {
	version uint16
	aead    cipher.AEAD
	// 1.3: the 12-octet IV. 1.2: the 4-octet salt.
	iv []byte
	// The next record's TLS sequence number.
	seq uint64
}

func newTlsCipher(version uint16, suite uint16, key []byte, iv []byte) (*tlsCipher, error) {
	var aead cipher.AEAD
	switch suite {
	case tlsSuiteChacha20Poly1305Sha256:
		var err error
		aead, err = chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
	case tlsSuiteAes128GcmSha256, tlsSuiteEcdheRsaAes128GcmSha256, tlsSuiteEcdheEcdsaAes128GcmSha256:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("suite %#x is not covered", suite)
	}
	return &tlsCipher{version: version, aead: aead, iv: iv}, nil
}

// The 1.3 nonce at a sequence number: the IV with the sequence number XORed into its low octets.
func tls13Nonce(iv []byte, seq uint64) []byte {
	nonce := make([]byte, len(iv))
	copy(nonce, iv)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(seq >> (8 * i))
	}
	return nonce
}

// Seals content into a whole record at the next sequence number. In 1.3 the inner type is appended
// with no padding, and the outer type is application_data; in 1.2 recordType is the outer type and
// the explicit nonce is the sequence number.
func (self *tlsCipher) seal(recordType uint8, content []byte) ([]byte, error) {
	if tlsMaxPlaintextBytes < len(content) {
		return nil, errors.New("record content too long")
	}
	seq := self.seq
	self.seq += 1
	if self.version == tlsVersion13 {
		inner := make([]byte, 0, len(content)+1)
		inner = append(inner, content...)
		inner = append(inner, recordType)
		size := len(inner) + tlsAeadTagBytes
		header := []byte{tlsRecordApplicationData, 0x03, 0x03, byte(size >> 8), byte(size)}
		return self.aead.Seal(header, tls13Nonce(self.iv, seq), inner, header[:tlsRecordHeaderBytes]), nil
	}
	explicitNonce := make([]byte, tlsExplicitNonceBytes)
	for i := range explicitNonce {
		explicitNonce[len(explicitNonce)-1-i] = byte(seq >> (8 * i))
	}
	nonce := make([]byte, 0, tlsSalt12Bytes+tlsExplicitNonceBytes)
	nonce = append(nonce, self.iv...)
	nonce = append(nonce, explicitNonce...)
	size := tlsExplicitNonceBytes + len(content) + tlsAeadTagBytes
	record := []byte{recordType, 0x03, 0x03, byte(size >> 8), byte(size)}
	record = append(record, explicitNonce...)
	return self.aead.Seal(record, nonce, content, tls12AdditionalData(seq, recordType, len(content))), nil
}

// The 1.2 AEAD additional data (RFC 5246 §6.2.3.3).
func tls12AdditionalData(seq uint64, recordType uint8, contentBytes int) []byte {
	return []byte{
		byte(seq >> 56), byte(seq >> 48), byte(seq >> 40), byte(seq >> 32),
		byte(seq >> 24), byte(seq >> 16), byte(seq >> 8), byte(seq),
		recordType, 0x03, 0x03, byte(contentBytes >> 8), byte(contentBytes),
	}
}

// Opens a whole record at the next sequence number. It returns the content and, in 1.3, the inner
// type with any padding removed. A record that fails its tag advances nothing.
func (self *tlsCipher) open(record []byte) (recordType uint8, content []byte, err error) {
	if len(record) < tlsRecordHeaderBytes+tlsAeadTagBytes {
		return 0, nil, errors.New("record too short")
	}
	header := record[:tlsRecordHeaderBytes]
	payload := record[tlsRecordHeaderBytes:]
	if self.version == tlsVersion13 {
		inner, err := self.aead.Open(nil, tls13Nonce(self.iv, self.seq), payload, header)
		if err != nil {
			return 0, nil, errors.New("record failed authentication")
		}
		end := len(inner)
		for 0 < end && inner[end-1] == 0 {
			end -= 1
		}
		if end == 0 {
			return 0, nil, errors.New("record holds no inner type")
		}
		self.seq += 1
		return inner[end-1], inner[:end-1], nil
	}
	if len(payload) < tlsExplicitNonceBytes+tlsAeadTagBytes {
		return 0, nil, errors.New("record too short")
	}
	nonce := make([]byte, 0, tlsSalt12Bytes+tlsExplicitNonceBytes)
	nonce = append(nonce, self.iv...)
	nonce = append(nonce, payload[:tlsExplicitNonceBytes]...)
	sealed := payload[tlsExplicitNonceBytes:]
	additional := tls12AdditionalData(self.seq, header[0], len(sealed)-tlsAeadTagBytes)
	content, err = self.aead.Open(nil, nonce, sealed, additional)
	if err != nil {
		return 0, nil, errors.New("record failed authentication")
	}
	self.seq += 1
	return header[0], content, nil
}
