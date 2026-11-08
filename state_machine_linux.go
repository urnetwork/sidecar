//go:build linux && !android

// The machine id on a Linux desktop or server, for sidecar.json's hash (§5.9).

package sidecar

import (
	"bytes"
	"os"
)

// systemd's id, else D-Bus's older home for it. Empty if neither reads, on a host that has neither,
// and sidecar.json then keeps no hash.
func SidecarMachineId() []byte {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		machineId, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if machineId = bytes.TrimSpace(machineId); 0 < len(machineId) {
			return machineId
		}
	}
	return nil
}
