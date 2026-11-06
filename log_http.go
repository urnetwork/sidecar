//go:build sidecar_http

// The sidecar_http leg's default: no glog here, so an unset settings.Log logs nowhere (§5.4).

package sidecar

// settings.Log, or nothing when it is nil.
func loggerOrDefault(log Logger) Logger {
	if log == nil {
		return NewNoopLogger()
	}
	return log
}
