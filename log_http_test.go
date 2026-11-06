//go:build sidecar_http

package sidecar

import (
	"testing"
)

func TestLoggerOrDefaultLogsNowhereOnThisLeg(t *testing.T) {
	if _, ok := loggerOrDefault(nil).(noopLogger); !ok {
		t.Errorf("nil settings.Log gave %T", loggerOrDefault(nil))
	}
}
