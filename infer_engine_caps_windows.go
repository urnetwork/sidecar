//go:build windows && !ios_extension && !sidecar_http

// What a Windows desktop can run a local model on (DESIGN-COMPUTE §6.5): its memory from GlobalMemoryStatusEx, and a
// GPU where Direct3D 12 is present, d3d12.dll in the system directory, which the engine's GPU backend runs on. Windows
// on arm64 has no engine build and gets remote models only, which the catalog says from its platform.

package sidecar

import (
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MEMORYSTATUSEX, as kernel32 fills it.
type inferEngineMemoryStatus struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

// This device's capabilities, as its OS reports them.
func inferEngineDeviceCapabilities() (*InferDeviceCapabilities, error) {
	status := &inferEngineMemoryStatus{}
	status.length = uint32(unsafe.Sizeof(*status))
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	if ok, _, err := proc.Call(uintptr(unsafe.Pointer(status))); ok == 0 {
		return nil, err
	}
	capabilities := &InferDeviceCapabilities{
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Class:           InferDeviceClassDesktop,
		MemoryByteCount: int64(status.totalPhys),
		Accelerators:    []InferAccelerator{InferAcceleratorCpu},
	}
	if system, err := windows.GetSystemDirectory(); err == nil {
		if _, err := os.Stat(filepath.Join(system, "d3d12.dll")); err == nil {
			capabilities.Accelerators = append(capabilities.Accelerators, InferAcceleratorGpu)
		}
	}
	return capabilities, nil
}
