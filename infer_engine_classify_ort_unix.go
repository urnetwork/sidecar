//go:build ur_engine && !windows && !ios_extension && !sidecar_http

// Opening ONNX Runtime's library on macOS and Linux (DESIGN-COMPUTE §27.5; SAFE-M13-03): dlopen through purego, by the
// path the helper checked against its pin, its symbols kept local so they meet no other library's, and the model's
// path as a C string.

package sidecar

import (
	"github.com/ebitengine/purego"
)

// The library at path, loaded now.
func ortOpen(path string) (uintptr, error) {
	return purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_LOCAL)
}

// The address of symbol in library, or an error where it exports none.
func ortSymbol(library uintptr, symbol string) (uintptr, error) {
	return purego.Dlsym(library, symbol)
}

// CreateSession at address, its ORTCHAR_T path a char string here.
func ortRegisterCreateSession(address uintptr) func(env uintptr, modelPath string, options uintptr, session *uintptr) uintptr {
	if address == 0 {
		return nil
	}
	var createSession func(env uintptr, modelPath string, options uintptr, session *uintptr) uintptr
	purego.RegisterFunc(&createSession, address)
	return createSession
}
