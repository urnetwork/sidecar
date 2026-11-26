//go:build !darwin && !linux && !windows && !ios_extension && !sidecar_http

// The room a model download checks for (DESIGN-COMPUTE §6.5) where no OS reading is built, as on js, whose model
// downloads are the browser's own (INFER-M13-02): unknown, so a download here refuses to start unless its host gives
// InferModelDownloadArgs.FreeByteCount.

package sidecar

import (
	"errors"
	"runtime"
)

// Refuses: this platform reports no room.
func inferDownloadFreeByteCount(directory string) (int64, error) {
	return 0, errors.New("no free space is read on " + runtime.GOOS)
}
