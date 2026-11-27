//go:build ur_engine && windows && !ios_extension && !sidecar_http

// Opening ONNX Runtime's library on Windows (DESIGN-COMPUTE §27.5; SAFE-M13-03): LoadLibraryEx by the path the helper
// checked against its pin, its dependencies searched in its own directory and the system's, never the working
// directory, and the model's path as ORTCHAR_T's wide string.

package sidecar

import (
	"runtime"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/windows"
)

// The library at path, loaded now.
func ortOpen(path string) (uintptr, error) {
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	return uintptr(handle), err
}

// The address of symbol in library, or an error where it exports none.
func ortSymbol(library uintptr, symbol string) (uintptr, error) {
	return windows.GetProcAddress(windows.Handle(library), symbol)
}

// CreateSession at address, its ORTCHAR_T path UTF-16 here. A path no UTF-16 string holds, one with a NUL, which the
// pin's check never passes, goes as an empty one, which the runtime refuses.
func ortRegisterCreateSession(address uintptr) func(env uintptr, modelPath string, options uintptr, session *uintptr) uintptr {
	if address == 0 {
		return nil
	}
	var createSession func(env uintptr, modelPath *uint16, options uintptr, session *uintptr) uintptr
	purego.RegisterFunc(&createSession, address)
	return func(env uintptr, modelPath string, options uintptr, session *uintptr) uintptr {
		path, err := windows.UTF16PtrFromString(modelPath)
		if err != nil {
			path = &[]uint16{0}[0]
		}
		status := createSession(env, path, options, session)
		runtime.KeepAlive(path)
		return status
	}
}
