// The visitor's first flight, §13.5's step 1: the TLS records up to the end of the ClientHello, and
// the values routing takes from it, which are SNI, ALPN and ECH presence (D-TLS-3). tlsedge reads
// nothing else of a visitor's bytes, and §2.8's tls-1 row is what it may see of them.
//
// The input is a stranger's, so every length is checked before it is used, and nothing here holds a
// goroutine or a clock: the caller sets deadlines. connect/ip_sni.go's field walk is where this
// started, but that one reads one record, reads no ALPN and keeps going past a bad extension, because
// it only labels traffic. tlsedge routes on the answer, so this one reassembles and refuses.
//
// Where crypto/tls refuses a field read here, this refuses too, because the listener's crypto/tls
// reads the same hello after tlsedge has routed it, and the two must not disagree on where a hello
// goes (FuzzClientHelloRecords holds that). Extensions other than server_name and ALPN are walked and
// not parsed: their bodies route nothing, and a bad one fails at the listener. Three places differ
// from crypto/tls on purpose. A trailing-dot name passes here for NormalizeSni, as §13.5 says. Any
// record but a handshake record is refused, where crypto/tls skips a warning alert. And ECH's body is
// not read, because a GREASE one means nothing (D-TLS-10), so a malformed one fails at the listener.
//
// Package-level functions are safe for concurrent use.

package tlsedgeservice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// Wire values: RFC 8446 §4, §4.2 and §5.1, RFC 6066 §3, RFC 7301 §3.1 and RFC 9849.
const (
	tlsRecordHeaderByteCount = 5
	tlsRecordTypeHandshake   = 22
	// RFC 8446 §5.1's limit on a plaintext fragment
	tlsRecordMaxByteCount = 16 * 1024
	// a record version from here on is no TLS client, the line crypto/tls draws before reading a body
	tlsRecordVersionRefused = 0x1000

	tlsHandshakeHeaderByteCount = 4
	tlsHandshakeTypeClientHello = 1
	// legacy_version and random
	tlsClientHelloFixedByteCount = 2 + 32

	tlsExtensionServerName           = 0
	tlsExtensionAlpn                 = 16
	tlsExtensionEncryptedClientHello = 0xfe0d
	tlsServerNameTypeHostName        = 0
)

// More extensions than browsers and TLS libraries send, GREASE included. Only a working size: a hello
// with more parses all the same, on the heap.
const tlsExtensionUsualCount = 64

// The ALPN id of §13.4's route probes, which offer it first and http/1.1 second. A hello offering it
// is answered unrecognized_name at once, whatever its SNI, so the id must stay one no listener
// registers. A wire value, so probes and this file must change together.
const tlsAlpnRouteProbe = "ur-route-probe"

// Wraps every refusal of a hello's bytes, which a caller answers with decode_error. Any other error
// from ReadClientHello is the connection's, such as a deadline passing or the visitor leaving.
var ErrClientHelloRefused = errors.New("client hello refused")

// Why, each built once so that a scanner's refusal costs no allocation. No text holds a byte of the
// hello: these may reach a log, and SNI may not (I-13).
var (
	errClientHelloNotHandshake = fmt.Errorf("%w: not a handshake record", ErrClientHelloRefused)
	errClientHelloRecordLength = fmt.Errorf("%w: record length out of range", ErrClientHelloRefused)
	errClientHelloMessageType  = fmt.Errorf("%w: handshake message is not a ClientHello", ErrClientHelloRefused)
	errClientHelloTooLong      = fmt.Errorf("%w: past max bytes", ErrClientHelloRefused)
	errClientHelloMalformed    = fmt.Errorf("%w: malformed", ErrClientHelloRefused)
	errClientHelloExtension    = fmt.Errorf("%w: repeated extension", ErrClientHelloRefused)
	errClientHelloServerName   = fmt.Errorf("%w: malformed server_name", ErrClientHelloRefused)
	errClientHelloAlpn         = fmt.Errorf("%w: malformed ALPN", ErrClientHelloRefused)
)

// What a ClientHello offers and the bytes it arrived in. Edge memory only: nothing here is stored
// (§2.8 tls-1), and neither name nor list reaches a log or a metric label (I-13).
type TlsClientHello struct {
	// server_name's host_name as sent, empty when there is none. NormalizeSni makes it a routing key.
	// This is the outer name when ECH is present, which is what tlsedge routes on (D-TLS-10).
	ServerName string
	// Offered ids in the visitor's order, empty with no ALPN extension. Every id is at least one byte.
	AlpnIds []string
	// True when encrypted_client_hello is present, GREASE included. It changes nothing here.
	EchPresent bool
	// Every byte ReadClientHello read, verbatim: the records that carried the hello, record headers
	// included, and nothing past the last of them. Empty from ParseClientHello.
	RawBytes []byte
}

// True when the hello is one of §13.4's route probes.
func (self *TlsClientHello) OffersRouteProbe() bool {
	return slices.Contains(self.AlpnIds, tlsAlpnRouteProbe)
}

// Reads TLS records from conn until the first ClientHello is complete, whether it arrives in one read
// or many and in one record or many, and parses it. maxBytes bounds what is read, record headers
// included, so a hello that could not fit is refused as soon as a length says so and before its
// bytes are waited for. Nothing past the record that ends the hello is read: those bytes stay in conn
// for the splice, and the bytes that were read come back in RawBytes for the same reason.
//
// A refusal wraps ErrClientHelloRefused. Any other error is conn's own. The caller sets any deadline.
func ReadClientHello(conn io.Reader, maxBytes int) (*TlsClientHello, error) {
	var recordHeader [tlsRecordHeaderByteCount]byte
	rawBytes := []byte{}
	message := []byte{}
	for {
		if maxBytes < len(rawBytes)+len(recordHeader) {
			return nil, errClientHelloTooLong
		}
		if _, err := io.ReadFull(conn, recordHeader[:]); err != nil {
			return nil, err
		}
		// SSLv2 lands here too: its first byte has the high bit set, so it is no handshake record
		if recordHeader[0] != tlsRecordTypeHandshake || tlsRecordVersionRefused <= binary.BigEndian.Uint16(recordHeader[1:]) {
			return nil, errClientHelloNotHandshake
		}
		recordByteCount := int(binary.BigEndian.Uint16(recordHeader[3:]))
		if recordByteCount == 0 || tlsRecordMaxByteCount < recordByteCount {
			return nil, errClientHelloRecordLength
		}
		if maxBytes < len(rawBytes)+len(recordHeader)+recordByteCount {
			return nil, errClientHelloTooLong
		}

		rawBytes = append(slices.Grow(rawBytes, len(recordHeader)+recordByteCount), recordHeader[:]...)
		bodyStart := len(rawBytes)
		rawBytes = rawBytes[:bodyStart+recordByteCount]
		if _, err := io.ReadFull(conn, rawBytes[bodyStart:]); err != nil {
			return nil, err
		}
		if len(message) == 0 {
			// nearly every hello is one record, which parses where it lies. The capacity is cut so
			// that a second record copies the message out rather than writing into rawBytes.
			message = rawBytes[bodyStart:len(rawBytes):len(rawBytes)]
		} else {
			message = append(message, rawBytes[bodyStart:]...)
		}

		if message[0] != tlsHandshakeTypeClientHello {
			return nil, errClientHelloMessageType
		}
		if len(message) < tlsHandshakeHeaderByteCount {
			continue
		}
		messageByteCount := tlsHandshakeHeaderByteCount + int(message[1])<<16 + int(message[2])<<8 + int(message[3])
		if messageByteCount <= len(message) {
			hello, err := ParseClientHello(message[:messageByteCount])
			if err != nil {
				return nil, err
			}
			hello.RawBytes = rawBytes
			return hello, nil
		}
		// the rest needs at least one more record
		if maxBytes < len(rawBytes)+len(recordHeader)+messageByteCount-len(message) {
			return nil, errClientHelloTooLong
		}
	}
}

// Parses one ClientHello handshake message, its type and length included and with nothing after it,
// such as a caller with its own record layer holds. §4.4 keeps mxedge from importing this package, so
// its host passes this in (reading 15). A refusal wraps ErrClientHelloRefused.
func ParseClientHello(message []byte) (*TlsClientHello, error) {
	reader := cryptobyte.String(message)
	var messageType uint8
	if !reader.ReadUint8(&messageType) {
		return nil, errClientHelloMalformed
	}
	if messageType != tlsHandshakeTypeClientHello {
		return nil, errClientHelloMessageType
	}
	var body cryptobyte.String
	if !reader.ReadUint24LengthPrefixed(&body) || !reader.Empty() {
		return nil, errClientHelloMalformed
	}

	var sessionId, cipherSuites, compressionMethods cryptobyte.String
	if !body.Skip(tlsClientHelloFixedByteCount) ||
		!body.ReadUint8LengthPrefixed(&sessionId) ||
		!body.ReadUint16LengthPrefixed(&cipherSuites) || len(cipherSuites)%2 != 0 ||
		!body.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil, errClientHelloMalformed
	}

	hello := &TlsClientHello{}
	if body.Empty() {
		// extensions are optional, and with none there is nothing to route on, which is the caller's
		// answer to give
		return hello, nil
	}
	var extensions cryptobyte.String
	if !body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return nil, errClientHelloMalformed
	}

	// a hello can carry thousands of extensions, and neither a map nor a scan of those seen is what a
	// hostile one should get, so repeats are found by sorting once at the end. A usual hello's types
	// fit this array, which stays on the stack.
	var extensionTypeArray [tlsExtensionUsualCount]uint16
	extensionTypes := extensionTypeArray[:0]
	for !extensions.Empty() {
		var extension uint16
		var data cryptobyte.String
		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&data) {
			return nil, errClientHelloMalformed
		}
		extensionTypes = append(extensionTypes, extension)

		var ok bool
		switch extension {
		case tlsExtensionServerName:
			if hello.ServerName, ok = parseServerNameExtension(data); !ok {
				return nil, errClientHelloServerName
			}
		case tlsExtensionAlpn:
			if hello.AlpnIds, ok = parseAlpnExtension(data); !ok {
				return nil, errClientHelloAlpn
			}
		case tlsExtensionEncryptedClientHello:
			hello.EchPresent = true
		}
	}
	slices.Sort(extensionTypes)
	if len(slices.Compact(extensionTypes)) != len(extensionTypes) {
		return nil, errClientHelloExtension
	}
	return hello, nil
}

// The one host_name of a server_name extension, as RFC 6066 §3 and crypto/tls read it: an entry of
// another type is skipped, a second host_name refuses the hello, and no entry may be empty. A list
// holding no host_name gives the empty name.
func parseServerNameExtension(data cryptobyte.String) (string, bool) {
	var nameList cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() || !data.Empty() {
		return "", false
	}
	var hostName cryptobyte.String
	for !nameList.Empty() {
		var nameType uint8
		var name cryptobyte.String
		if !nameList.ReadUint8(&nameType) || !nameList.ReadUint16LengthPrefixed(&name) || name.Empty() {
			return "", false
		}
		if nameType != tlsServerNameTypeHostName {
			continue
		}
		if len(hostName) != 0 {
			return "", false
		}
		hostName = name
	}
	return string(hostName), true
}

// The ids of an ALPN extension in order, as RFC 7301 §3.1 and crypto/tls read it: an empty list or an
// empty id refuses the hello. Every id is a slice of one string, so a list of thousands of one-byte
// ids costs a few allocations and not one each.
func parseAlpnExtension(data cryptobyte.String) ([]string, bool) {
	var idList cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&idList) || idList.Empty() || !data.Empty() {
		return nil, false
	}
	idBytes := string(idList)
	alpnIds := []string{}
	for 0 < len(idBytes) {
		idByteCount := int(idBytes[0])
		if idByteCount == 0 || len(idBytes)-1 < idByteCount {
			return nil, false
		}
		alpnIds = append(alpnIds, idBytes[1:1+idByteCount])
		idBytes = idBytes[1+idByteCount:]
	}
	return alpnIds, true
}
