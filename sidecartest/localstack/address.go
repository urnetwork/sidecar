// Where these clients may dial.

package localstack

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// The lowest port the private stack binds. Below it, a loopback port can be a production data tunnel
// (server/test-env.sh).
const stackPortFloor = 50000

// Refuses anything but a loopback address on a port above the floor: where local/ binds, and where no
// production tunnel sits. A redirect goes through this as a seed does, so a store cannot send a client
// off the machine.
func CheckStackAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("address %q is no ip: %w", address, err)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("address %q is not loopback", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return fmt.Errorf("address %q: %w", address, err)
	}
	if port <= stackPortFloor {
		return fmt.Errorf("address %q is at or below port %d", address, stackPortFloor)
	}
	return nil
}
