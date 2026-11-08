//go:build darwin && !ios && !sdk_mobile_bind

// The machine id on a Mac, for sidecar.json's hash (§5.9). IOKit needs cgo, which §4.7 refuses, so this
// asks ioreg, and a sandbox that forbids that simply has no machine id.

package sidecar

import (
	"bytes"
	"os/exec"
)

// What ioreg's output names the hardware UUID by.
const machineIdIoregKey = `"IOPlatformUUID" = "`

// The hardware UUID, or empty if ioreg gives none.
func SidecarMachineId() []byte {
	output, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return nil
	}
	_, rest, found := bytes.Cut(output, []byte(machineIdIoregKey))
	if !found {
		return nil
	}
	machineId, _, found := bytes.Cut(rest, []byte(`"`))
	if !found {
		return nil
	}
	return machineId
}
