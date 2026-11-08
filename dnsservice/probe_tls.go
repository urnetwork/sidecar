// What one interface probe sends and what passes it (§12.6, §13.4). A probe sends a ClientHello for the
// reserved probe.edge.<root> and passes only on tlsedge's answer to it: one plaintext alert record,
// fatal, unrecognized_name, before any ServerHello (D-TLS-3). A ServerHello or a certificate fails,
// since that is the lb's http branch answering, which is what a broken SNI split looks like.
//
// The hello is crypto/tls's own, made once for each probe name over an in-memory pipe and reused, so
// it is a hello crypto/tls reads on the far side; a probe never finishes a handshake, so a reused
// random and key share cost nothing.

package dnsservice

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// Wire values, from RFC 8446 §5.1 and §6: a record's header, the alert record type, a fatal alert's
// level, unrecognized_name, and the handshake record type a ServerHello opens with.
const (
	dnsTlsRecordHeaderByteCount = 5
	dnsTlsRecordTypeAlert       = 21
	dnsTlsRecordTypeHandshake   = 22
	dnsTlsRecordVersionMajor    = 3
	dnsTlsAlertByteCount        = 2
	dnsTlsAlertLevelFatal       = 2
	dnsTlsAlertUnrecognizedName = 112
)

// The label every root reserves for probes (§12.5's reserved list).
const dnsProbeEdgeLabel = "probe.edge"

// The name a probe of root asks for: probe.edge.<root>, without the final dot SNI leaves off.
func dnsProbeServerName(root string) string {
	return dnsProbeEdgeLabel + "." + root[:len(root)-1]
}

// The first record crypto/tls writes as a client for serverName: its ClientHello, whole.
func dnsProbeClientHello(serverName string) ([]byte, error) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	handshakeDone := make(chan struct{})
	go func() {
		defer close(handshakeDone)
		// the far side closes after one record, so this always fails, and only the hello matters
		tls.Client(clientConn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	header := make([]byte, dnsTlsRecordHeaderByteCount)
	if _, err := io.ReadFull(serverConn, header); err != nil {
		return nil, err
	}
	if header[0] != dnsTlsRecordTypeHandshake {
		return nil, errors.New("crypto/tls opened with no handshake record")
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(serverConn, body); err != nil {
		return nil, err
	}
	serverConn.Close()
	<-handshakeDone
	return append(header, body...), nil
}

// Whether the first record conn sends back is tlsedge's: a plaintext fatal unrecognized_name alert.
// Reads at most that record, so a ServerHello fails at its header.
func dnsProbeAnswerPasses(conn io.Reader) bool {
	header := make([]byte, dnsTlsRecordHeaderByteCount)
	if _, err := io.ReadFull(conn, header); err != nil {
		return false
	}
	if header[0] != dnsTlsRecordTypeAlert || header[1] != dnsTlsRecordVersionMajor ||
		binary.BigEndian.Uint16(header[3:5]) != dnsTlsAlertByteCount {
		return false
	}
	alert := make([]byte, dnsTlsAlertByteCount)
	if _, err := io.ReadFull(conn, alert); err != nil {
		return false
	}
	return alert[0] == dnsTlsAlertLevelFatal && alert[1] == dnsTlsAlertUnrecognizedName
}

// How a probe reaches an lb interface: TCP, as a visitor's does. A fake in tests; NewDnsNetProbeDialer
// on a host. Safe for concurrent use.
type DnsProbeDialer interface {
	// A connection to address. ctx bounds the dial and ends with the probe.
	DialProbe(ctx context.Context, address netip.AddrPort) (net.Conn, error)
}

// Dials over the host's own network.
type dnsNetProbeDialer struct {
	dialer net.Dialer
}

// The dialer a host probes with: TCP from this host's own addresses, bounded by the probe's context.
// DNS-M5-18 may give the edge hosts' transparent interfaces a dialer of their own.
func NewDnsNetProbeDialer() DnsProbeDialer {
	return &dnsNetProbeDialer{}
}

func (self *dnsNetProbeDialer) DialProbe(ctx context.Context, address netip.AddrPort) (net.Conn, error) {
	return self.dialer.DialContext(ctx, "tcp", address.String())
}

// One probe of address with hello, passing only on tlsedge's alert within timeout on clock. Every
// fault is a failure, and none is logged, since a connection's error names its addresses. The timeout
// and ctx's end each cut the connection short, so a silent far side holds a probe no longer.
func dnsProbeOnce(ctx context.Context, clock sidecar.Clock, timeout time.Duration, dialer DnsProbeDialer, address netip.AddrPort, hello []byte) bool {
	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var connLock sync.Mutex
	var conn net.Conn
	cut := false
	context.AfterFunc(probeCtx, func() {
		connLock.Lock()
		defer connLock.Unlock()
		cut = true
		if conn != nil {
			conn.SetDeadline(dnsPastDeadline)
		}
	})
	stop := clock.AfterFunc(timeout, cancel)
	defer stop()
	dialed, err := dialer.DialProbe(probeCtx, address)
	if err != nil {
		return false
	}
	defer dialed.Close()
	if func() bool {
		connLock.Lock()
		defer connLock.Unlock()
		conn = dialed
		return cut
	}() {
		return false
	}
	if _, err := dialed.Write(hello); err != nil {
		return false
	}
	return dnsProbeAnswerPasses(dialed)
}
