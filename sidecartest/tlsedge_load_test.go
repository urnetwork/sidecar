package sidecartest_test

// The tlsedge load harness scaled down (TLS-M5-26; §22.8): RunTlsEdgeLoad against an engine in process, behind its
// PROXY listener on loopback 443, with sidecartest's store, host and clock and a dialer whose listener writes one byte
// at once, holds every connection open at once, every scan refused with an alert and nothing reached, and a p95 it
// measured. The 50,000 connections and the p95 evidence are a T5 host's.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// A stream whose listener writes one byte at once and then drains what the engine sends.
type tlsEdgeLoadTestStream struct {
	toListener   *io.PipeReader
	engineWrites *io.PipeWriter
	fromListener *io.PipeReader
	closeOnce    sync.Once
}

func newTlsEdgeLoadTestStream() *tlsEdgeLoadTestStream {
	toListener, engineWrites := io.Pipe()
	fromListener, listener := io.Pipe()
	go func() {
		listener.Write([]byte{0x16})
		io.Copy(io.Discard, toListener)
		listener.Close()
	}()
	return &tlsEdgeLoadTestStream{toListener: toListener, engineWrites: engineWrites, fromListener: fromListener}
}

func (self *tlsEdgeLoadTestStream) Read(b []byte) (int, error)  { return self.fromListener.Read(b) }
func (self *tlsEdgeLoadTestStream) Write(b []byte) (int, error) { return self.engineWrites.Write(b) }
func (self *tlsEdgeLoadTestStream) CloseWrite() error           { return self.engineWrites.Close() }
func (self *tlsEdgeLoadTestStream) Close() error {
	self.closeOnce.Do(func() {
		self.engineWrites.Close()
		self.fromListener.Close()
	})
	return nil
}
func (self *tlsEdgeLoadTestStream) Reset(code protocol.StreamResetCode) error { return self.Close() }
func (self *tlsEdgeLoadTestStream) SetReadDeadline(t time.Time) error         { return nil }
func (self *tlsEdgeLoadTestStream) SetWriteDeadline(t time.Time) error        { return nil }

// A dialer that opens every dial.
type tlsEdgeLoadTestDialer struct {
	clientIds []sidecar.Id
}

func (self *tlsEdgeLoadTestDialer) ClientIds() []sidecar.Id { return slices.Clone(self.clientIds) }

func (self *tlsEdgeLoadTestDialer) Dial(ctx context.Context, request *tlsedgeservice.TlsEdgeDialRequest) (tlsedgeservice.TlsEdgeStream, error) {
	if _, err := request.Metadata(0); err != nil {
		return nil, err
	}
	return newTlsEdgeLoadTestStream(), nil
}

// A listener whose address names 443, the port the engine serves.
type tlsEdgeLoadTestListener struct {
	net.Listener
}

func (self *tlsEdgeLoadTestListener) Addr() net.Addr {
	address := *self.Listener.Addr().(*net.TCPAddr)
	address.Port = 443
	return &address
}

func TestTlsEdgeLoadScaledDown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	store := sidecartest.NewFakeTlsEdgeStore(nil)
	root := "load.example"
	networkId := sidecar.NewId()
	label, err := store.AddLabel(root, networkId)
	if err != nil {
		t.Fatal(err)
	}
	// one network takes every connection here, so §13.9's caps are lifted; they are the engine's own tests'
	none := int64(-1)
	host.Quota.SetLimits(connect.Id(networkId), &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{
		"tls_endpoint_concurrent": none, "tls_endpoint_new_per_s": none, "tls_endpoint_mbit_per_s": none,
		"tls_visitor_concurrent": none, "tls_visitor_new_per_s": none, "tls_visitor_aggregate_multiple": none,
	}})
	host.Quota.SetBalance(connect.Id(networkId), 1<<40)
	host.Gates.OpenService(sidecar.ServiceGateTlsedge, connect.Id(networkId))
	settings := tlsedgeservice.DefaultTlsEdgeSettings()
	settings.Root = root
	settings.Blocks = 1
	settings.ColdLimits = &tlsedgeservice.TlsEndpointLimits{
		EndpointConcurrent: none, EndpointNewPerS: none, EndpointMbitPerS: none,
		VisitorConcurrent: none, VisitorNewPerS: none, VisitorAggregateMultiple: none,
	}
	dialer := &tlsEdgeLoadTestDialer{}
	for range settings.Clients {
		dialer.clientIds = append(dialer.clientIds, sidecar.NewId())
	}
	service, err := tlsedgeservice.NewTlsEdgeService(ctx, host.ServiceHost(), store, dialer, settings)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	for _, loads := range []func() (uint64, chan struct{}){service.NameLoads, service.KillLoads} {
		for {
			count, changed := loads()
			if 0 < count {
				break
			}
			select {
			case <-changed:
			case <-time.After(30 * time.Second):
				t.Fatal("the engine never loaded")
			}
		}
	}
	if !service.Ready() {
		t.Fatal("the engine is not ready")
	}
	bound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxySettings := tlsedgeservice.DefaultProxyHeaderSettings()
	proxySettings.Clock = clock
	listener, err := tlsedgeservice.NewProxyHeaderListener(ctx, &tlsEdgeLoadTestListener{Listener: bound}, proxySettings)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- service.Serve(listener)
	}()
	defer func() {
		listener.Close()
		<-served
	}()

	loadSettings := sidecartest.DefaultTlsEdgeLoadSettings()
	loadSettings.ConnectionCount = 300
	loadSettings.OpenConcurrency = 16
	loadSettings.ScanCount = 60
	loadSettings.HoldDuration = 0
	report, err := sidecartest.RunTlsEdgeLoad(ctx, &sidecartest.TlsEdgeLoadArgs{
		Address:     bound.Addr().String(),
		ServerNames: []string{"blog." + label + "." + root, "shop." + label + "." + root, label + "." + root},
		ScanName: func(index int) string {
			return fmt.Sprintf("scan%d.zzzzzzzzzz.%s", index, root)
		},
		Visitor: func(index int) (netip.AddrPort, int) {
			return netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + index%250)}), uint16(40000+index)), 443
		},
		Settings: loadSettings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", report)
	if report.Opened != loadSettings.ConnectionCount || report.Failed != 0 || report.PeakOpen != loadSettings.ConnectionCount {
		t.Fatalf("the load: %s, %v", report, report.Errors)
	}
	if report.ScansRefused != loadSettings.ScanCount || report.ScansReached != 0 {
		t.Fatalf("the scans: %s", report)
	}
	if report.SetupP95 <= 0 || report.SetupP95 < report.SetupP50 || report.SetupMax < report.SetupP95 {
		t.Fatalf("the setups: %s", report)
	}
}

// A load with no address, no name, scans with no names or a count past its bounds is the harness's own error.
func TestTlsEdgeLoadRefusesWhatItCannotRun(t *testing.T) {
	for _, args := range []*sidecartest.TlsEdgeLoadArgs{
		nil,
		{ServerNames: []string{"blog.example"}},
		{Address: "127.0.0.1:1"},
		{Address: "127.0.0.1:1", ServerNames: []string{"blog.example"}, Settings: &sidecartest.TlsEdgeLoadSettings{ConnectionCount: 1, OpenConcurrency: 1, ScanCount: 1, SetupTimeout: time.Second}},
		{Address: "127.0.0.1:1", ServerNames: []string{"blog.example"}, Settings: &sidecartest.TlsEdgeLoadSettings{ConnectionCount: 1, OpenConcurrency: 0, SetupTimeout: time.Second}},
	} {
		if _, err := sidecartest.RunTlsEdgeLoad(context.Background(), args); err == nil {
			t.Errorf("%+v ran", args)
		}
	}
}
