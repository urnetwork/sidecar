package tlsedgeservice

import (
	"errors"
	"testing"
	"time"
)

// §13.5's sketch of tlsedge.yml, with blocks (reading 12) and root.
const testTlsEdgeYaml = `
root: root.example
clients: 4
max_connections: 50000
blocks: 4
proxy_header: {timeout_s: 2, max_bytes: 2048}
client_hello: {timeout_s: 10, max_bytes: 16384}
find: {timeout_s: 2, max_finds: 3}
accept: {ticket_timeout_s: 5, setup_timeout_s: 15}
idle_timeout_s: 900
drain_s: 600
`

// The design's file loads to the design's numbers.
func TestLoadTlsEdgeSettingsDesignFile(t *testing.T) {
	settings, err := LoadTlsEdgeSettings([]byte(testTlsEdgeYaml))
	if err != nil {
		t.Fatal(err)
	}
	if settings.Root != "root.example" || settings.Clients != 4 || settings.MaxConnectionCount != 50000 || settings.Blocks != 4 {
		t.Fatalf("settings %+v", settings)
	}
	if settings.ProxyHeader.Timeout != 2*time.Second || settings.ProxyHeader.MaxByteCount != 2048 {
		t.Fatalf("proxy_header %+v", settings.ProxyHeader)
	}
	if settings.ClientHelloTimeout != 10*time.Second || settings.ClientHelloMaxByteCount != 16384 {
		t.Fatalf("client_hello %v, %d", settings.ClientHelloTimeout, settings.ClientHelloMaxByteCount)
	}
	if settings.FindTimeout != 2*time.Second || settings.FindMaxCount != 3 {
		t.Fatalf("find %v, %d", settings.FindTimeout, settings.FindMaxCount)
	}
	if settings.AcceptTicketTimeout != 5*time.Second || settings.AcceptSetupTimeout != 15*time.Second {
		t.Fatalf("accept %v, %v", settings.AcceptTicketTimeout, settings.AcceptSetupTimeout)
	}
	if settings.IdleTimeout != 900*time.Second || settings.DrainTimeout != 600*time.Second {
		t.Fatalf("idle %v, drain %v", settings.IdleTimeout, settings.DrainTimeout)
	}
}

// tlsedge refuses to start without blocks or root, on a zero, and on a key it does not know.
func TestLoadTlsEdgeSettingsRefusals(t *testing.T) {
	for _, data := range []string{
		"root: root.example\n",
		"blocks: 4\n",
		"root: root.example\nblocks: 0\n",
		"root: Root.Example\nblocks: 4\n",
		"root: example\nblocks: 4\n",
		"root: root.example.\nblocks: 4\n",
		"root: root.example\nblocks: 4\nclients: 0\n",
		"root: root.example\nblocks: 4\nmax_conections: 10\n",
		"root: root.example\nblocks: 4\nfind: {timeout_s: 2, max_find: 3}\n",
		"root: root.example\nblocks: 4\nproxy_header: {timeout_s: 0}\n",
		"root: root.example\nblocks: 4\n---\nroot: root.example\n",
	} {
		if _, err := LoadTlsEdgeSettings([]byte(data)); !errors.Is(err, ErrTlsEdgeSettingsRefused) {
			t.Errorf("%q: %v", data, err)
		}
	}
}
