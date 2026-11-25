//go:build linux && !android && !ios_extension && !sidecar_http

// What a Linux desktop or server can run a local model on (DESIGN-COMPUTE §6.5): its memory from /proc/meminfo's
// MemTotal, and a GPU where the kernel offers a render node, /dev/dri/renderD*, which the engine's WebGPU backend
// reaches through Vulkan. Its memory is never unified to §6.5's largest default, which asks for Apple's. An enclave's
// Debian runs here too, on its CPU (§6.5).

package sidecar

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// This device's capabilities, as its OS reports them.
func inferEngineDeviceCapabilities() (*InferDeviceCapabilities, error) {
	meminfo, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer meminfo.Close()
	memory := int64(0)
	scanner := bufio.NewScanner(meminfo)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			kibibytes, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return nil, err
			}
			memory = kibibytes * 1024
			break
		}
	}
	if memory <= 0 {
		return nil, errors.New("/proc/meminfo gives no MemTotal")
	}
	capabilities := &InferDeviceCapabilities{
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		Class:           InferDeviceClassDesktop,
		MemoryByteCount: memory,
		Accelerators:    []InferAccelerator{InferAcceleratorCpu},
	}
	if nodes, _ := filepath.Glob("/dev/dri/renderD*"); 0 < len(nodes) {
		capabilities.Accelerators = append(capabilities.Accelerators, InferAcceleratorGpu)
	}
	return capabilities, nil
}
