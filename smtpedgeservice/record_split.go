// smtpRecordSplitter (SMTP-M9-13): cuts one direction's byte stream into whole TLS records, each with its
// 5-octet header (RFC 8446 §5.1, RFC 5246 §6.2), since SmtpProofSession takes whole records. It reads one
// record a call and keeps nothing between calls, so a caller that stops calling stops reading the stream:
// back-pressure, never a buffer. It judges no content type or version, which is the session's (E1).
//
// Nothing of a raw TLS stream is dropped or skipped (connect/CODESTYLE.md's raw byte-stream rule): a record
// past RecordMaxByteCount or a stream that ends inside a record is an error, and the connection ends.
//
// Not safe for concurrent use: one per direction, on that direction's goroutine.

package smtpedgeservice

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TLS's identifiers this file reads (RFC 8446 §5.1, §4, §4.2): the record header's octets (content type,
// version, length), the handshake content type, the ServerHello message type and the supported_versions
// extension.
const (
	smtpTlsRecordHeaderByteCount      = 5
	smtpTlsContentHandshake           = 22
	smtpTlsHandshakeServerHello       = 2
	smtpTlsExtensionSupportedVersions = 43
)

// A record whose length passes RecordMaxByteCount.
var errSmtpRecordTooLong = errors.New("smtp record: past the record bound")

type smtpRecordSplitter struct {
	reader             io.Reader
	recordMaxByteCount int
}

// A splitter of reader's records, each at most recordMaxByteCount octets, header included.
func newSmtpRecordSplitter(reader io.Reader, recordMaxByteCount int) *smtpRecordSplitter {
	return &smtpRecordSplitter{reader: reader, recordMaxByteCount: recordMaxByteCount}
}

// The next whole record, header included, in a slice of its own. io.EOF when the stream ended at a record
// boundary; io.ErrUnexpectedEOF when it ended inside one.
func (self *smtpRecordSplitter) next() ([]byte, error) {
	header := make([]byte, smtpTlsRecordHeaderByteCount)
	if _, err := io.ReadFull(self.reader, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if self.recordMaxByteCount < smtpTlsRecordHeaderByteCount+length {
		return nil, fmt.Errorf("%w: a %d-octet record", errSmtpRecordTooLong, length)
	}
	record := make([]byte, smtpTlsRecordHeaderByteCount+length)
	copy(record, header)
	if _, err := io.ReadFull(self.reader, record[smtpTlsRecordHeaderByteCount:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return record, nil
}

// The TLS version a ServerHello record names, read in the clear before any key: 1.3's from its
// supported_versions extension (RFC 8446 §4.1.3, §4.2.1), else the legacy version. 0 for a record that is no
// ServerHello, or one cut short. Bounds-checked at every step, since the MX writes it.
func smtpServerHelloVersion(record []byte) uint16 {
	// handshake record, ServerHello message
	if len(record) < smtpTlsRecordHeaderByteCount+4 || record[0] != smtpTlsContentHandshake || record[smtpTlsRecordHeaderByteCount] != smtpTlsHandshakeServerHello {
		return 0
	}
	body := record[smtpTlsRecordHeaderByteCount+4:]
	// legacy_version 2, random 32
	if len(body) < 2+32+1 {
		return 0
	}
	version := binary.BigEndian.Uint16(body[0:2])
	rest := body[2+32:]
	sessionIdLength := int(rest[0])
	if len(rest) < 1+sessionIdLength+2+1+2 {
		return version
	}
	// session id, cipher suite 2, compression 1
	rest = rest[1+sessionIdLength+2+1:]
	extensionsLength := int(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if len(rest) < extensionsLength {
		return version
	}
	rest = rest[:extensionsLength]
	for 4 <= len(rest) {
		extensionType := binary.BigEndian.Uint16(rest[0:2])
		extensionLength := int(binary.BigEndian.Uint16(rest[2:4]))
		if len(rest) < 4+extensionLength {
			return version
		}
		// supported_versions, which a ServerHello carries as one version
		if extensionType == smtpTlsExtensionSupportedVersions && extensionLength == 2 {
			return binary.BigEndian.Uint16(rest[4:6])
		}
		rest = rest[4+extensionLength:]
	}
	return version
}
