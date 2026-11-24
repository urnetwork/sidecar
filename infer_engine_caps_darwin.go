//go:build darwin && !ios && !ios_extension && !sidecar_http

// What a Mac can run a local model on (DESIGN-COMPUTE §6.5): its memory from sysctl's hw.memsize, unified on Apple
// silicon, whose GPU the engine reaches through Metal; an Intel Mac has no engine build and gets remote models only,
// which the catalog says from its platform. A Mac is a desktop to §6.5's defaults: macOS tells a laptop from a desktop
// by no identifier the engine can read without cgo, and each default serves the larger classes, so a laptop with the
// memory of a desktop is offered what a desktop is.

package sidecar

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// This device's capabilities, as its OS reports them.
func inferEngineDeviceCapabilities() (*InferDeviceCapabilities, error) {
	memory, err := unix.SysctlUint64("hw.memsize")
	if err != nil {
		return nil, err
	}
	capabilities := &InferDeviceCapabilities{
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Class:           InferDeviceClassDesktop,
		MemoryByteCount: int64(memory),
		Accelerators:    []InferAccelerator{InferAcceleratorCpu},
	}
	if runtime.GOARCH == "arm64" {
		capabilities.UnifiedMemory = true
		capabilities.Accelerators = append(capabilities.Accelerators, InferAcceleratorGpu)
	}
	return capabilities, nil
}
