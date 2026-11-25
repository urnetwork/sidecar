//go:build ur_engine && !windows && !ios_extension && !sidecar_http

// Opening LiteRT-LM's libraries on macOS and Linux (DESIGN-COMPUTE §6.5): dlopen through purego, read only, by the path
// the helper checked against its pin.

package sidecar

import (
	"github.com/ebitengine/purego"
)

// The library at path, loaded now, its symbols global so the engine's own loads of it by name find it.
func inferEngineLiteRtOpen(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
}

// The address of symbol in library, or an error where it exports none.
func inferEngineLiteRtSymbol(library uintptr, symbol string) (uintptr, error) {
	return purego.Dlsym(library, symbol)
}
