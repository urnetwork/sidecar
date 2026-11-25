//go:build ((!darwin && !linux && !windows) || ios || android) && !ios_extension && !sidecar_http

// The platforms ur-engine does not run on (DESIGN-COMPUTE §6.5): the phones, whose apps embed LiteRT-LM behind the
// sdk's host seam (INFER-M11-06), the browser, whose engine is Later, and any other. A desktop engine here has no
// device to read.

package sidecar

import (
	"errors"
	"runtime"
)

// Refuses: no desktop engine runs on this platform.
func inferEngineDeviceCapabilities() (*InferDeviceCapabilities, error) {
	return nil, errors.New("no desktop engine runs on " + runtime.GOOS + "/" + runtime.GOARCH)
}
