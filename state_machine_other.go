//go:build !(linux && !android) && !(darwin && !ios && !sdk_mobile_bind) && !windows

// Where no machine id can be read: phones, whose ids are not this code's to read, and the page Worker.
// sidecar.json keeps no hash there, and a copy of the state cannot be told.

package sidecar

// Empty.
func SidecarMachineId() []byte {
	return nil
}
