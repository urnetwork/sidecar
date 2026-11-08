package localstack

import (
	"net"
	"testing"
)

// A listener on loopback above the floor. An ephemeral port can land below it, and that one stays open
// until the test ends so the next bind gets another.
func listenOnStackPort(t *testing.T) net.Listener {
	t.Helper()
	for {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		if CheckStackAddress(listener.Addr().String()) == nil {
			return listener
		}
	}
}

func TestStackAddresses(t *testing.T) {
	for _, c := range []struct {
		address string
		ok      bool
	}{
		{address: "127.0.0.1:56401", ok: true},
		{address: "[::1]:59000", ok: true},
		{address: "127.0.0.1:50001", ok: true},
		// server/test-env.sh: these can be production tunnels
		{address: "127.0.0.1:5432", ok: false},
		{address: "127.0.0.1:6379", ok: false},
		{address: "127.0.0.1:6427", ok: false},
		{address: "127.0.0.1:50000", ok: false},
		// off the machine, and a name that could resolve there
		{address: "203.0.113.7:56401", ok: false},
		{address: "localhost:56401", ok: false},
		{address: "store.example:56401", ok: false},
		{address: "127.0.0.1", ok: false},
		{address: "127.0.0.1:port", ok: false},
	} {
		if err := CheckStackAddress(c.address); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.address, err)
		}
	}
}
