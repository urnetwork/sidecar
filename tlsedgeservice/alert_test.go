// T1 for §13.5's step 7: the bytes on the wire, by RFC 8446 §5.1 and §6, and what a real client makes
// of them.

package tlsedgeservice

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestWriteTlsAlertBytesMatchRfc8446(t *testing.T) {
	cases := []struct {
		code TlsAlertCode
		want []byte
	}{
		// ContentType alert(21), legacy_record_version 0x0303, length 2, AlertLevel fatal(2), and the
		// description from §6's enum, written out here so that a wrong constant cannot pass itself
		{code: TlsAlertDecodeError, want: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50}},
		{code: TlsAlertInternalError, want: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 80}},
		{code: TlsAlertUnrecognizedName, want: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 112}},
	}
	for _, c := range cases {
		written := &bytes.Buffer{}
		if err := WriteTlsAlert(written, c.code); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(written.Bytes(), c.want) {
			t.Errorf("%d: %x", c.code, written.Bytes())
		}
	}
}

func TestWriteTlsAlertWritesNothingForAnotherCode(t *testing.T) {
	for _, code := range []TlsAlertCode{0, 40, 70, 113, 255} {
		written := &bytes.Buffer{}
		if err := WriteTlsAlert(written, code); err == nil {
			t.Errorf("%d: no error", code)
		}
		if written.Len() != 0 {
			t.Errorf("%d: wrote %x", code, written.Bytes())
		}
	}
}

// Counts writes, so one alert is shown to be one record in one write.
type testCountingWriter struct {
	writeCount int
	err        error
}

func (self *testCountingWriter) Write(b []byte) (int, error) {
	self.writeCount += 1
	if self.err != nil {
		return 0, self.err
	}
	return len(b), nil
}

func TestWriteTlsAlertIsOneWrite(t *testing.T) {
	writer := &testCountingWriter{}
	if err := WriteTlsAlert(writer, TlsAlertUnrecognizedName); err != nil {
		t.Fatal(err)
	}
	if writer.writeCount != 1 {
		t.Errorf("%d writes", writer.writeCount)
	}
}

func TestWriteTlsAlertReturnsTheConnsError(t *testing.T) {
	writer := &testCountingWriter{err: io.ErrClosedPipe}
	if err := WriteTlsAlert(writer, TlsAlertInternalError); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("%v", err)
	}
}

// What a visitor's own TLS library reports, before any ServerHello, on both sides of a real pipe.
func TestCryptoTlsClientReadsEachAlert(t *testing.T) {
	cases := []struct {
		code TlsAlertCode
		want string
	}{
		{code: TlsAlertDecodeError, want: "error decoding message"},
		{code: TlsAlertInternalError, want: "internal error"},
		{code: TlsAlertUnrecognizedName, want: "unrecognized name"},
	}
	for _, c := range cases {
		clientConn, edgeConn := net.Pipe()
		handshakeResult := make(chan error, 1)
		go func() {
			handshakeResult <- tls.Client(clientConn, &tls.Config{ServerName: testServerName}).Handshake()
		}()
		hello, err := ReadClientHello(edgeConn, testMaxBytes)
		if err != nil {
			t.Fatal(err)
		}
		if hello.ServerName != testServerName {
			t.Errorf("server name %q", hello.ServerName)
		}
		if err := WriteTlsAlert(edgeConn, c.code); err != nil {
			t.Fatal(err)
		}
		err = <-handshakeResult
		if err == nil || !strings.Contains(err.Error(), "remote error: tls: "+c.want) {
			t.Errorf("%d: %v", c.code, err)
		}
		clientConn.Close()
		edgeConn.Close()
	}
}
