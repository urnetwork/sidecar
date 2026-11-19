// §22.8's tlsedge load harness (TLS-M5-26; §13.5's p95 setup targets, §13.9's 50,000 connections a process, X11): a
// driver that opens ConnectionCount visitor connections against one tlsedge process's PROXY listener and holds them
// all open at once, each a PROXY v1 header naming its visitor and a ClientHello for one of the published names, timed
// from the TCP connect to the first byte the listener sends back through the splice; and beside them ScanCount name
// scans, hellos for names no map holds, each of which must end on tlsedge's alert with nothing reached. The report
// carries every count and the setup's p50, p95 and maximum.
//
// It is built to run on a T5 host against a block behind its lb or its PROXY port directly, at
// DefaultTlsEdgeLoadSettings' 50,000 connections, with the listener a device that answers TLS (its ServerHello is the
// first byte back), so its p95 is §13.5's setup with the contract round trip and the end-to-end handshake included; that
// evidence run is external. sidecartest's own test runs it scaled down against an engine in process. It measures the
// wall clock by nature, so nothing here waits on a fake one; a run's waits all end on a connection's own bytes, and the
// hold after the last open is HoldDuration's, zero for none.
//
// The driver holds no address but the ones its Visitor function names and writes nothing but connections' bytes.

package sidecartest

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
)

// What a load run drives.
type TlsEdgeLoadSettings struct {
	// Connections held open at once: §13.9's 50,000 a process.
	ConnectionCount int
	// Connections opening at once while the run ramps up, so the run measures setup and not the driver's own queue.
	OpenConcurrency int
	// Hellos for names no map holds, each refused with an alert: a scan's shape (§13.5's negative cache).
	ScanCount int
	// The ALPN ids each visitor offers.
	Alpn []string
	// How long one connection's setup, or one scan's answer, may take before it reads as failed.
	SetupTimeout time.Duration
	// How long every connection stays open once the last has opened, before the run closes them. Zero closes them at
	// once.
	HoldDuration time.Duration
	// How many failures' errors a report keeps, to say why.
	ErrorKeepCount int
}

// §13.9's process cap, ramping 256 at a time, with 10,000 scans, each setup held to client_hello's 10 s.
func DefaultTlsEdgeLoadSettings() *TlsEdgeLoadSettings {
	return &TlsEdgeLoadSettings{
		ConnectionCount: 50000,
		OpenConcurrency: 256,
		ScanCount:       10000,
		Alpn:            []string{"h2", "http/1.1"},
		SetupTimeout:    10 * time.Second,
		HoldDuration:    60 * time.Second,
		ErrorKeepCount:  8,
	}
}

// One run's target.
type TlsEdgeLoadArgs struct {
	// The tlsedge listener a visitor's connection reaches, host:port, which takes the lb's PROXY header.
	Address string
	// The published names the connections reach, one after another.
	ServerNames []string
	// Scan index's name: one no map holds.
	ScanName func(index int) string
	// Connection index's visitor as the PROXY header names it, and the port it came in on. Nil names 192.0.2.1:443.
	Visitor func(index int) (netip.AddrPort, int)
	// Nil takes DefaultTlsEdgeLoadSettings.
	Settings *TlsEdgeLoadSettings
}

// What a run saw.
type TlsEdgeLoadReport struct {
	// Connections whose setup ended on the listener's first byte, and those that did not.
	Opened int
	Failed int
	// The most held open at one moment.
	PeakOpen int
	// Scans answered with an alert and closed, and scans that got anything else, each a failure.
	ScansRefused int
	ScansReached int
	// The opened connections' setups.
	SetupP50 time.Duration
	SetupP95 time.Duration
	SetupMax time.Duration
	// The first few failures, to say why.
	Errors []error
}

func (self *TlsEdgeLoadReport) String() string {
	return fmt.Sprintf(
		"%d opened, %d failed, %d held at once, %d scans refused, %d reached; setup p50 %v, p95 %v, max %v",
		self.Opened, self.Failed, self.PeakOpen, self.ScansRefused, self.ScansReached, self.SetupP50, self.SetupP95, self.SetupMax,
	)
}

// A TLS record's content type for an alert (RFC 8446 §5.1), the first byte of what tlsedge answers a refused hello.
const tlsEdgeLoadAlertType = 21

// A ClientHello for serverName offering alpnIds, the bytes crypto/tls writes first, as a browser's would begin.
func TlsEdgeLoadHello(serverName string, alpnIds []string) ([]byte, error) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	go tls.Client(client, &tls.Config{ServerName: serverName, NextProtos: alpnIds, InsecureSkipVerify: true}).Handshake()
	header := make([]byte, 5)
	if _, err := io.ReadFull(peer, header); err != nil {
		return nil, err
	}
	body := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(peer, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

// The lb's PROXY v1 header for visitor reaching port.
func tlsEdgeLoadProxyHeader(visitor netip.AddrPort, port int) []byte {
	family, destination := "TCP4", "198.51.100.1"
	if visitor.Addr().Is6() && !visitor.Addr().Is4In6() {
		family, destination = "TCP6", "2001:db8::1"
	}
	return fmt.Appendf(nil, "PROXY %s %s %s %d %d\r\n", family, visitor.Addr().Unmap(), destination, visitor.Port(), port)
}

// The run's state across its connections.
type tlsEdgeLoadRun struct {
	args     *TlsEdgeLoadArgs
	settings *TlsEdgeLoadSettings
	hellos   map[string][]byte

	stateLock sync.Mutex
	report    *TlsEdgeLoadReport
	setups    []time.Duration
	open      []net.Conn
}

func (self *tlsEdgeLoadRun) failed(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.report.Failed += 1
	if len(self.report.Errors) < self.settings.ErrorKeepCount {
		self.report.Errors = append(self.report.Errors, err)
	}
}

// Opens connection index and holds it once its setup ends on the listener's first byte.
func (self *tlsEdgeLoadRun) openOne(ctx context.Context, index int) {
	serverName := self.args.ServerNames[index%len(self.args.ServerNames)]
	visitor, port := netip.MustParseAddrPort("192.0.2.1:50000"), 443
	if self.args.Visitor != nil {
		visitor, port = self.args.Visitor(index)
	}
	start := time.Now()
	dialer := &net.Dialer{Timeout: self.settings.SetupTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", self.args.Address)
	if err != nil {
		self.failed(err)
		return
	}
	conn.SetDeadline(start.Add(self.settings.SetupTimeout))
	visit := append(tlsEdgeLoadProxyHeader(visitor, port), self.hellos[serverName]...)
	if _, err := conn.Write(visit); err != nil {
		conn.Close()
		self.failed(err)
		return
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(conn, first); err != nil {
		conn.Close()
		self.failed(err)
		return
	}
	if first[0] == tlsEdgeLoadAlertType {
		conn.Close()
		self.failed(errors.New("a published name was answered with an alert"))
		return
	}
	setup := time.Since(start)
	conn.SetDeadline(time.Time{})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.report.Opened += 1
	self.setups = append(self.setups, setup)
	self.open = append(self.open, conn)
	self.report.PeakOpen = max(self.report.PeakOpen, len(self.open))
}

// Sends scan index's hello and reads its answer to the close, which must be an alert alone.
func (self *tlsEdgeLoadRun) scanOne(ctx context.Context, index int) {
	reached := func() bool {
		dialer := &net.Dialer{Timeout: self.settings.SetupTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", self.args.Address)
		if err != nil {
			return true
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(self.settings.SetupTimeout))
		hello, err := TlsEdgeLoadHello(self.args.ScanName(index), self.settings.Alpn)
		if err != nil {
			return true
		}
		visitor := netip.MustParseAddrPort("192.0.2.2:50000")
		if _, err := conn.Write(append(tlsEdgeLoadProxyHeader(visitor, 443), hello...)); err != nil {
			return true
		}
		answer, err := io.ReadAll(conn)
		return err != nil || len(answer) == 0 || answer[0] != tlsEdgeLoadAlertType
	}()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if reached {
		self.report.ScansReached += 1
	} else {
		self.report.ScansRefused += 1
	}
}

// The quantile q of durations, sorted.
func tlsEdgeLoadQuantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(q*float64(len(sorted))))]
}

// Runs one load against args.Address: every connection opened and held, the scans between them, then every
// connection closed. An error is the run's own (no names, a hello that could not be built); what the target does is
// in the report.
func RunTlsEdgeLoad(ctx context.Context, args *TlsEdgeLoadArgs) (*TlsEdgeLoadReport, error) {
	if args == nil || args.Address == "" || len(args.ServerNames) == 0 {
		return nil, errors.New("a load needs an address and a published name")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultTlsEdgeLoadSettings()
	}
	if settings.ConnectionCount < 0 || settings.OpenConcurrency <= 0 || settings.ScanCount < 0 || settings.SetupTimeout <= 0 || settings.HoldDuration < 0 ||
		settings.ErrorKeepCount < 0 {
		return nil, errors.New("a load's counts and times are positive")
	}
	if 0 < settings.ScanCount && args.ScanName == nil {
		return nil, errors.New("a load with scans needs their names")
	}
	run := &tlsEdgeLoadRun{args: args, settings: settings, hellos: map[string][]byte{}, report: &TlsEdgeLoadReport{}}
	for _, serverName := range args.ServerNames {
		hello, err := TlsEdgeLoadHello(serverName, settings.Alpn)
		if err != nil {
			return nil, err
		}
		run.hellos[serverName] = hello
	}
	defer func() {
		for _, conn := range run.open {
			conn.Close()
		}
	}()

	// the connections and the scans interleaved, OpenConcurrency at a time
	work := make(chan int)
	var workers sync.WaitGroup
	for range settings.OpenConcurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for item := range work {
				if item < settings.ConnectionCount {
					run.openOne(ctx, item)
				} else {
					run.scanOne(ctx, item-settings.ConnectionCount)
				}
			}
		}()
	}
	scanEvery := 0
	if 0 < settings.ScanCount {
		scanEvery = max(1, settings.ConnectionCount/settings.ScanCount)
	}
	scanned := 0
	for index := 0; index < settings.ConnectionCount; index += 1 {
		if ctx.Err() != nil {
			break
		}
		work <- index
		if 0 < scanEvery && index%scanEvery == 0 && scanned < settings.ScanCount {
			work <- settings.ConnectionCount + scanned
			scanned += 1
		}
	}
	for ; scanned < settings.ScanCount && ctx.Err() == nil; scanned += 1 {
		work <- settings.ConnectionCount + scanned
	}
	close(work)
	workers.Wait()

	if 0 < settings.HoldDuration {
		select {
		case <-ctx.Done():
		case <-time.After(settings.HoldDuration):
		}
	}
	run.stateLock.Lock()
	defer run.stateLock.Unlock()
	setups := slices.Clone(run.setups)
	sort.Slice(setups, func(i int, j int) bool { return setups[i] < setups[j] })
	run.report.SetupP50 = tlsEdgeLoadQuantile(setups, 0.5)
	run.report.SetupP95 = tlsEdgeLoadQuantile(setups, 0.95)
	if 0 < len(setups) {
		run.report.SetupMax = setups[len(setups)-1]
	}
	return run.report, ctx.Err()
}
