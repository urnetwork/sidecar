//go:build !js

// Where a follow job's lines go on a leg that has files (RECORD.md section 9's target row): a file on this device,
// appended to, readable by its owner alone. Never a network address: a customer's own forwarder ships the file.

package sidecar

import (
	"io"
	"os"
)

// The file sink: opens the file at path to append to, creating it for its owner alone.
func recordExportFileSink() func(path string) (io.WriteCloser, error) {
	return func(path string) (io.WriteCloser, error) {
		return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	}
}
