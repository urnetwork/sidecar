// What tlsedge says to a visitor it will not route, §13.5's step 7: one plaintext alert before any
// ServerHello, then the caller closes. It is all tlsedge ever writes on its own account, and it holds
// no key, so nothing here can present a certificate (D-TLS-1). Which alert a failure gets is the
// connection path's to choose: unknown, unpublished and denied names must read the same on the wire.

package tlsedgeservice

import (
	"errors"
	"io"
)

// An AlertDescription of RFC 8446 §6, limited to the three tlsedge sends.
type TlsAlertCode uint8

const (
	// a hello that does not parse
	TlsAlertDecodeError TlsAlertCode = 50
	// no listener, busy, quota, overload or a closed gate
	TlsAlertInternalError TlsAlertCode = 80
	// an unknown, unpublished, denied or killed name, and every route probe
	TlsAlertUnrecognizedName TlsAlertCode = 112
)

// Wire values, from RFC 8446 §5.1 and §6.
const (
	tlsRecordTypeAlert = 21
	// legacy_record_version, 0x0303 on every TLS 1.3 record but a first ClientHello
	tlsRecordVersionMajor = 3
	tlsRecordVersionMinor = 3
	tlsAlertByteCount     = 2
	tlsAlertLevelFatal    = 2
)

var errTlsAlertCode = errors.New("not an alert tlsedge sends")

// Writes one fatal alert record to conn in a single write, and writes nothing for any other code. The
// caller sets any deadline and closes afterward.
func WriteTlsAlert(conn io.Writer, code TlsAlertCode) error {
	switch code {
	case TlsAlertDecodeError, TlsAlertInternalError, TlsAlertUnrecognizedName:
	default:
		return errTlsAlertCode
	}
	_, err := conn.Write([]byte{
		tlsRecordTypeAlert, tlsRecordVersionMajor, tlsRecordVersionMinor, 0, tlsAlertByteCount,
		tlsAlertLevelFatal, byte(code),
	})
	return err
}
