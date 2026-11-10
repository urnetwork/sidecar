//go:build js

// The page Worker's leg has no files, so it has no sink, and a follow job is refused there (ErrRecordExportNoSink).

package sidecar

import "io"

// No sink.
func recordExportFileSink() func(path string) (io.WriteCloser, error) {
	return nil
}
