//go:build sidecar_http

// The sidecar_http leg's directory client: the console's page Worker is read_only (§16.11's console row), so its
// client reads and refuses every write, whatever its args say.

package sidecar

// Whether this leg's directory client refuses every write: yes, the page Worker's.
const directoryLegReadOnly = true
