//go:build ur_engine && windows && !ios_extension && !sidecar_http

// Opening LiteRT-LM's libraries on Windows (DESIGN-COMPUTE §6.5): LoadLibraryEx by the path the helper checked against
// its pin, its dependencies searched in its own directory and the system's, never the working directory.

package sidecar

import (
	"golang.org/x/sys/windows"
)

// The library at path, loaded now.
func inferEngineLiteRtOpen(path string) (uintptr, error) {
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	return uintptr(handle), err
}

// The address of symbol in library, or an error where it exports none.
func inferEngineLiteRtSymbol(library uintptr, symbol string) (uintptr, error) {
	return windows.GetProcAddress(windows.Handle(library), symbol)
}
