//go:build windows

// The machine id on Windows, for sidecar.json's hash (§5.9).

package sidecar

import (
	"golang.org/x/sys/windows/registry"
)

// MachineGuid, or empty if the registry does not give it.
func SidecarMachineId() []byte {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return nil
	}
	defer key.Close()
	machineId, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return nil
	}
	return []byte(machineId)
}
