//go:build !sidecar_http && !js

// What the sweep's external cases (clock_select_ctx_sweep_external_test.go) reach of the config writer: the channel
// that closes once its fold loop has returned, so a case knows the loop ended rather than waiting on nothing. Tests
// only.

package sidecar

// writer's runDone: closed once its fold loop has returned.
func ConfigWriterRunDone(writer *ConfigWriter) <-chan struct{} {
	return writer.runDone
}
