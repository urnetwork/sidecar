//go:build ((!darwin && !linux && !windows) || ios || android) && !ios_extension && !sidecar_http

// The helper's confinement where nothing confines one (DESIGN-COMPUTE §6.5; infer_engine_confine.go): a phone, whose
// app embeds the engine and implements the host seam instead (infer_host.go), and any OS §6.5 builds no helper for.
// No helper runs here: the daemon lists local inference unavailable, and a helper refuses to start.

package sidecar

import (
	"fmt"
	"path/filepath"
	"runtime"
)

// See infer_engine_confine.go: never.
func inferEngineConfineAvailable() error {
	return fmt.Errorf("%w: no engine helper is confined on %s", ErrInferEngineUnconfined, runtime.GOOS)
}

// See infer_engine_confine.go: beside ur, though none runs here.
func inferEngineDefaultHelperPath(executable string) string {
	return filepath.Join(filepath.Dir(executable), inferEngineHelperName())
}

// See infer_engine_confine.go: refused, since nothing would confine it.
func inferEngineStartChild(spec *inferEngineChildSpec) (*inferEngineChild, error) {
	return nil, inferEngineConfineAvailable()
}

// See infer_engine_confine.go: refused.
func inferEngineConfine(confinement *inferEngineConfinement, settings *InferSettings, argv []string, env []string) error {
	return inferEngineConfineAvailable()
}
