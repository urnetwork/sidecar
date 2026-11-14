//go:build !ios_extension && !js

// §13.10 step 3's probe: the daemon's own ports and both named agent UIs refused and recorded, and everything else
// passed, a target that answers nothing included. Targets are loopback listeners on ports the kernel picks.

package sidecar

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

// A local service answering GET / with body.
func newTlsProbeTestTarget(t *testing.T, body string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

// The agent UIs' pages as the fixture table knows them, in the case each serves.
var tlsProbeTestAgentUis = map[string]string{
	"mcp-inspector": "<!doctype html><html><head><title>MCP Inspector</title></head><body><div id=\"root\"></div></body></html>",
	"openclaw":      "<!doctype html><html><head><TITLE>OpenClaw Control</TITLE></head><body></body></html>",
}

func TestTlsProbeRefusesAndRecordsAnAgentUi(t *testing.T) {
	if len(tlsProbeFingerprints) != len(tlsProbeTestAgentUis) || tlsProbeFingerprintVersion != 1 {
		t.Fatalf("the fingerprint table changed without its fixtures: version %d", tlsProbeFingerprintVersion)
	}
	for name, page := range tlsProbeTestAgentUis {
		recorded := []TlsProbeRefusal{}
		_, err := tlsProbeTarget(t.Context(), &tlsProbeArgs{
			LocalAddress: newTlsProbeTestTarget(t, page),
			Record: func(refusal TlsProbeRefusal) {
				recorded = append(recorded, refusal)
			},
		})
		if !errors.Is(err, ErrTlsProbeRefused) {
			t.Errorf("%s: %v", name, err)
		}
		if len(recorded) != 1 || recorded[0] != TlsProbeRefusalAgentUi {
			t.Errorf("%s: recorded %v", name, recorded)
		}
	}
}

func TestTlsProbeRefusesTheDaemonsPortsWithoutDialing(t *testing.T) {
	recorded := []TlsProbeRefusal{}
	dialed := false
	_, err := tlsProbeTarget(t.Context(), &tlsProbeArgs{
		LocalAddress: "127.0.0.1:50123",
		DaemonPorts:  []int{50122, 50123},
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("not dialed")
		},
		Record: func(refusal TlsProbeRefusal) {
			recorded = append(recorded, refusal)
		},
	})
	if !errors.Is(err, ErrTlsProbeRefused) || dialed {
		t.Errorf("the daemon's port: %v, dialed %t", err, dialed)
	}
	if len(recorded) != 1 || recorded[0] != TlsProbeRefusalDaemonPort {
		t.Errorf("recorded %v", recorded)
	}
	// on any local address
	if _, err := tlsProbeTarget(t.Context(), &tlsProbeArgs{LocalAddress: "[::1]:50122", DaemonPorts: []int{50122}}); !errors.Is(err, ErrTlsProbeRefused) {
		t.Errorf("the daemon's port on another address: %v", err)
	}
}

func TestTlsProbePassesAnOrdinaryTarget(t *testing.T) {
	recorded := 0
	record := func(refusal TlsProbeRefusal) {
		recorded += 1
	}
	result, err := tlsProbeTarget(t.Context(), &tlsProbeArgs{
		LocalAddress: newTlsProbeTestTarget(t, "<html><head><title>A blog</title></head><body>MCP Inspector is a tool I wrote about</body></html>"),
		Record:       record,
	})
	if err != nil || !result.Reachable {
		t.Errorf("an ordinary page: %+v, %v", result, err)
	}

	// a target that speaks no HTTP answers nothing the table knows
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Write([]byte{0x20, 0x02, 0x00, 0x00})
		conn.Close()
	}()
	result, err = tlsProbeTarget(t.Context(), &tlsProbeArgs{LocalAddress: listener.Addr().String(), Record: record})
	if err != nil || !result.Reachable {
		t.Errorf("a target that speaks no HTTP: %+v, %v", result, err)
	}
	<-served

	// a port nothing listens on is no refusal: the front holds the endpoint not serving
	closed := listener.Addr().String()
	listener.Close()
	result, err = tlsProbeTarget(t.Context(), &tlsProbeArgs{LocalAddress: closed, Record: record})
	if err != nil || result.Reachable {
		t.Errorf("a closed port: %+v, %v", result, err)
	}
	if recorded != 0 {
		t.Errorf("%d refusals recorded for targets that passed", recorded)
	}
}

func TestTlsProbeWaitsNoLongerThanItsTimeout(t *testing.T) {
	settings := DefaultSidecarTlsSettings()
	if settings.ProbeTimeout != 3*time.Second || settings.ProbeResponseMaxByteCount != 64*1024 {
		t.Fatalf("probe defaults %s, %d", settings.ProbeTimeout, settings.ProbeResponseMaxByteCount)
	}
	settings.ProbeTimeout = 20 * time.Millisecond
	// a target that takes the connection and never answers
	near, far := net.Pipe()
	defer far.Close()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buffer := make([]byte, 1024)
		for {
			if _, err := far.Read(buffer); err != nil {
				return
			}
		}
	}()
	result, err := tlsProbeTarget(t.Context(), &tlsProbeArgs{
		LocalAddress: "127.0.0.1:50124",
		Settings:     settings,
		Dial: func(ctx context.Context, address string) (net.Conn, error) {
			return near, nil
		},
	})
	if err != nil || !result.Reachable {
		t.Errorf("a silent target: %+v, %v", result, err)
	}
	far.Close()
	<-drained
}

func TestTlsProbeRefusesArgsThatAreNoTarget(t *testing.T) {
	for _, address := range []string{"", "localhost:8080", "127.0.0.1", "127.0.0.1:0"} {
		if _, err := tlsProbeTarget(t.Context(), &tlsProbeArgs{LocalAddress: address}); !errors.Is(err, errInvalidSettings) {
			t.Errorf("%q: %v", address, err)
		}
	}
	if _, err := tlsProbeTarget(t.Context(), nil); !errors.Is(err, errInvalidSettings) {
		t.Errorf("no args: %v", err)
	}
	if _, err := netip.ParseAddrPort("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
}
