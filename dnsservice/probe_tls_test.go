package dnsservice_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// The probe's hello is crypto/tls's own, and crypto/tls on the far side reads probe.edge.<root> from
// it, as tlsedge's parser does from any real visitor's.
func TestProbeHelloParsesWithCryptoTls(t *testing.T) {
	hello, err := dnsservice.ProbeClientHelloForTest("probe.edge.zone.example")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	serverNames := make(chan string, 1)
	go func() {
		defer server.Close()
		tls.Server(server, &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNames <- info.ServerName
			return nil, errors.New("seen")
		}}).Handshake()
	}()
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case serverName := <-serverNames:
		if serverName != "probe.edge.zone.example" {
			t.Errorf("server name %q", serverName)
		}
	case <-t.Context().Done():
		t.Fatal("crypto/tls read no hello")
	}
}

// tlsedge's own alert, written by its own code, passes; nothing else does.
func TestProbePassesOnlyOnTlsedgesAlert(t *testing.T) {
	alert := func(code tlsedgeservice.TlsAlertCode) []byte {
		var buffer bytes.Buffer
		if err := tlsedgeservice.WriteTlsAlert(&buffer, code); err != nil {
			t.Fatal(err)
		}
		return buffer.Bytes()
	}
	if !dnsservice.ProbeAnswerPassesForTest(bytes.NewReader(alert(tlsedgeservice.TlsAlertUnrecognizedName))) {
		t.Error("tlsedge's unrecognized_name failed")
	}
	refused := map[string][]byte{
		"internal_error":    alert(tlsedgeservice.TlsAlertInternalError),
		"decode_error":      alert(tlsedgeservice.TlsAlertDecodeError),
		"a warning":         {21, 3, 3, 0, 2, 1, 112},
		"a long alert":      {21, 3, 3, 0, 3, 2, 112, 0},
		"an SSLv2 version":  {21, 2, 0, 0, 2, 2, 112},
		"a handshake":       {22, 3, 3, 0, 2, 2, 112},
		"a header alone":    {21, 3, 3, 0, 2},
		"nothing":           {},
		"application bytes": []byte("HTTP/1.1 400 Bad Request\r\n"),
	}
	for name, answer := range refused {
		if dnsservice.ProbeAnswerPassesForTest(bytes.NewReader(answer)) {
			t.Errorf("%s passed", name)
		}
	}
}

// A self-signed certificate on a fixed key, as the lb's http branch presents a platform one.
func probeTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key := edgeTestKey(t, edgeTestOtherHex)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "platform.example"},
		DNSNames:     []string{"platform.example"},
		NotBefore:    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: (*ecdsa.PrivateKey)(key)}
}

// The http branch's answer, a ServerHello on the way to a certificate, fails, which is how a broken
// split shows.
func TestProbeFailsOnAServerHello(t *testing.T) {
	hello, err := dnsservice.ProbeClientHelloForTest("probe.edge.zone.example")
	if err != nil {
		t.Fatal(err)
	}
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		tls.Server(server, &tls.Config{Certificates: []tls.Certificate{probeTestCertificate(t)}}).Handshake()
	}()
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	if dnsservice.ProbeAnswerPassesForTest(client) {
		t.Error("a ServerHello passed")
	}
}

// A prober over the host's network, through NewDnsNetProbeDialer: a loopback listener answering as
// tlsedge passes on one port, and one answering as the http branch fails on the other, so after three
// rounds the interface's gauge says it failed while never-all keeps its address.
func TestProberDialsOverTheNetwork(t *testing.T) {
	listen := func(answer func(conn net.Conn)) int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(edgeTcpTestHang))
					header := make([]byte, 5)
					if _, err := io.ReadFull(conn, header); err != nil {
						return
					}
					if _, err := io.ReadFull(conn, make([]byte, int(header[3])<<8|int(header[4]))); err != nil {
						return
					}
					answer(conn)
				}()
			}
		}()
		return listener.Addr().(*net.TCPAddr).Port
	}
	tlsedgePort := listen(func(conn net.Conn) {
		tlsedgeservice.WriteTlsAlert(conn, tlsedgeservice.TlsAlertUnrecognizedName)
	})
	httpPort := listen(func(conn net.Conn) {
		conn.Write([]byte{22, 3, 3, 0, 4, 2, 0, 0, 0})
	})
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	settings := probeTestSettings(t)
	settings.Probe.Ports = []int{tlsedgePort, httpPort}
	prober, err := dnsservice.NewProber(t.Context(), host.ServiceHost(), settings,
		&dnsservice.ProberDeps{Dialer: dnsservice.NewDnsNetProbeDialer()}, func(set *dnsservice.HealthySet) {})
	if err != nil {
		t.Fatal(err)
	}
	defer prober.Close()
	awaitRounds := func(count int) {
		for {
			current, changed := prober.Rounds()
			if count <= current {
				return
			}
			select {
			case <-changed:
			case <-t.Context().Done():
				t.Fatalf("rounds %d", current)
			}
		}
	}
	awaitRounds(1)
	prober.SetInterfaces([]dnsservice.DnsLbInterface{{Name: "lb-1", Ipv4: netip.MustParseAddr("127.0.0.1")}})
	healthy := func() float64 {
		return host.Metrics.Value("urnetwork_dnsedge_interface_healthy", "lb-1", "ipv4")
	}
	for round := 2; round <= 4; round += 1 {
		clock.Advance(time.Duration(settings.Probe.IntervalSeconds) * time.Second)
		awaitRounds(round)
		if want := float64(map[bool]int{true: 1, false: 0}[round < 4]); healthy() != want {
			t.Errorf("round %d: healthy %v", round, healthy())
		}
	}
	if held := host.Metrics.Value("urnetwork_dnsedge_healthy_held", "edge", "ipv4"); held != 1 {
		t.Errorf("held %v", held)
	}
}
