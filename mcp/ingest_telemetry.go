//go:build !js && !ios && !android && !sdk_mobile_bind

// The daemon's telemetry listener (§16.18's harness OpenTelemetry; I-17; QD-822): IngestTelemetry's handler
// (ingest_model.go) on 127.0.0.1 at the port of the telemetry pair `ur install-harness` sealed (harness_telemetry.go),
// taking that pair's token, while Ingest.ModelCalls is on (M6's capture, off by default).
//
//	start      at the daemon's start, from the pair as it stands. With no pair, one that does not read, capture off,
//	           or a port the loopback interface will not give, it serves nothing and Status says why, the closed
//	           direction
//	reload     ur install-harness asks again once it seals a pair (the daemon's telemetry.reload): another pair stops
//	           the old server and serves the new one, and the same pair, already serving, changes nothing
//	loopback   it binds 127.0.0.1 alone, whatever the daemon's --listen names, and refuses 401 a request whose Host
//	           names anything but that address, as git's http front refuses a misdirected one, so a page a browser
//	           rebinds to loopback cannot reach it under another name; the token is what admits a caller
//	limits     Ingest.TelemetryRequestTimeout bounds a request from its first byte to its answer, and an idle
//	           connection; Ingest.TelemetryHeaderByteCount its header; the receiver its body and its rate
//	close      the daemon's end, or a reload, waits Ingest.TelemetryShutdownTimeout for requests in flight, closes
//	           their connections, and joins the server's goroutine
//
// Status names the port and whether it serves, never the token. Safe for concurrent use: reloadLock orders reloads and
// the close, taken before stateLock, which guards what Status reads.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// What the listener serves from.
type IngestTelemetryListenerArgs struct {
	Ingest *Ingest
	// The instance's <state>, whose harness/telemetry.json holds the pair.
	StateDirectory string
	// How it binds: net.Listen, unless a test stands one in.
	Listen func(network string, address string) (net.Listener, error)
}

// The listener: see the file header.
type IngestTelemetryListener struct {
	ingest         *Ingest
	settings       *sidecar.SidecarIngestSettings
	log            sidecar.Logger
	stateDirectory string
	listen         func(network string, address string) (net.Listener, error)

	reloadLock sync.Mutex

	stateLock sync.Mutex
	// the pair read last, nil for none that reads
	pair      *HarnessTelemetry
	telemetry *IngestTelemetry
	server    *http.Server
	// closed once the server's goroutine returns
	served chan struct{}
	// why it serves nothing, "" while it serves
	reason string
	closed bool
}

// What `ur status` reads of the listener: the port and whether it serves, never the token.
type IngestTelemetryStatus struct {
	// Whether model calls are captured at all (Ingest.ModelCalls).
	ModelCalls bool `json:"model_calls,omitempty"`
	// The sealed pair's port, 0 where none reads.
	Port int `json:"port,omitempty"`
	// The address it serves on, while it serves.
	Address string `json:"address,omitempty"`
	Serving bool   `json:"serving,omitempty"`
	// Why it serves nothing.
	Reason string                `json:"reason,omitempty"`
	Counts IngestTelemetryCounts `json:"counts"`
}

// The listener over args, serving the sealed pair at once where it can.
func NewIngestTelemetryListener(args *IngestTelemetryListenerArgs) *IngestTelemetryListener {
	listen := args.Listen
	if listen == nil {
		listen = net.Listen
	}
	self := &IngestTelemetryListener{
		ingest:         args.Ingest,
		settings:       args.Ingest.settings,
		log:            args.Ingest.log,
		stateDirectory: args.StateDirectory,
		listen:         listen,
	}
	self.Reload()
	return self
}

// The pair under <state> and why it is not served, "" where it can be.
func (self *IngestTelemetryListener) readPair() (*HarnessTelemetry, string) {
	pair, err := ReadHarnessTelemetry(self.stateDirectory, self.settings.HarnessConfigByteCount)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, "no harness's exporter settings are installed: ur install-harness writes them"
	case err != nil:
		// the error names no path or token, and neither does the reason
		return nil, "the telemetry pair does not read: run ur install-harness again"
	case !self.settings.ModelCalls:
		return pair, "model calls are off: M6's capture, off by default"
	}
	return pair, ""
}

// Reads the pair again and serves it, the server of another pair stopped first: see the file header. The answer is
// the status after.
func (self *IngestTelemetryListener) Reload() IngestTelemetryStatus {
	self.reloadLock.Lock()
	defer self.reloadLock.Unlock()
	pair, reason := self.readPair()
	var stopping *http.Server
	var stoppingServed chan struct{}
	keep := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return true
		}
		if reason == "" && self.server != nil && self.pair.equal(pair) {
			return true
		}
		stopping, stoppingServed = self.server, self.served
		self.server, self.served, self.telemetry = nil, nil, nil
		self.pair, self.reason = pair, reason
		return false
	}()
	if keep {
		return self.Status()
	}
	self.stop(stopping, stoppingServed)
	if reason != "" {
		return self.Status()
	}
	listener, err := self.listen("tcp", pair.Address())
	if err != nil {
		// the bind's error names the loopback address and port, and no path or token
		reason = fmt.Sprintf("port %d did not bind on loopback: %s", pair.Port, err)
		self.log.Warningf("[telemetry]the listener serves nothing: %s", reason)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.reason = reason
		}()
		return self.Status()
	}
	telemetry := NewIngestTelemetry(self.ingest, []byte(pair.Token))
	server := &http.Server{
		Handler:        self.handler(telemetry, pair),
		ReadTimeout:    self.settings.TelemetryRequestTimeout,
		WriteTimeout:   self.settings.TelemetryRequestTimeout,
		IdleTimeout:    self.settings.TelemetryRequestTimeout,
		MaxHeaderBytes: self.settings.TelemetryHeaderByteCount,
	}
	served := make(chan struct{})
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.server, self.served, self.telemetry, self.reason = server, served, telemetry, ""
		return true
	}()
	if !started {
		listener.Close()
		return self.Status()
	}
	go func() {
		defer close(served)
		server.Serve(listener)
	}()
	if self.log.V(1).Enabled() {
		self.log.Infof("[telemetry]serving on %s", pair.Address())
	}
	return self.Status()
}

// The receiver's handler behind the loopback Host check.
func (self *IngestTelemetryListener) handler(telemetry *IngestTelemetry, pair *HarnessTelemetry) http.Handler {
	port := strconv.Itoa(pair.Port)
	allowed := map[string]bool{
		pair.Address():                      true,
		net.JoinHostPort("localhost", port): true,
	}
	receive := telemetry.Handler()
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !allowed[strings.ToLower(request.Host)] {
			telemetry.refuse(writer)
			return
		}
		receive.ServeHTTP(writer, request)
	})
}

// Stops a server: requests in flight get Ingest.TelemetryShutdownTimeout, then their connections close, and its
// goroutine is joined.
func (self *IngestTelemetryListener) stop(server *http.Server, served chan struct{}) {
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), self.settings.TelemetryShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		server.Close()
	}
	<-served
}

// The listener's port, whether it serves, why not, and the receiver's counts.
func (self *IngestTelemetryListener) Status() IngestTelemetryStatus {
	status := IngestTelemetryStatus{ModelCalls: self.settings.ModelCalls}
	telemetry := func() *IngestTelemetry {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		status.Reason = self.reason
		if self.pair != nil {
			status.Port = self.pair.Port
		}
		if self.server != nil {
			status.Serving = true
			status.Address = self.pair.Address()
		}
		if self.closed && status.Reason == "" {
			status.Reason = "the daemon is ending"
		}
		return self.telemetry
	}()
	if telemetry != nil {
		status.Counts = telemetry.Counts()
	}
	return status
}

// Stops serving for good: see the file header.
func (self *IngestTelemetryListener) Close() {
	self.reloadLock.Lock()
	defer self.reloadLock.Unlock()
	server, served := func() (*http.Server, chan struct{}) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		server, served := self.server, self.served
		self.server, self.served, self.telemetry = nil, nil, nil
		return server, served
	}()
	self.stop(server, served)
}
