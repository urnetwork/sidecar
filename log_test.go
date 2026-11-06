package sidecar

import (
	"testing"
)

func TestNoopLoggerDisablesEveryLevel(t *testing.T) {
	log := NewNoopLogger()
	log.Info("synthetic")
	log.Infof("synthetic %d", 1)
	log.Warningf("synthetic %d", 1)
	log.Errorf("synthetic %d", 1)
	for _, level := range []int32{0, 1, 2} {
		verbose := log.V(level)
		if verbose.Enabled() {
			t.Errorf("level %d enabled", level)
		}
		verbose.Info("synthetic")
		verbose.Infof("synthetic %d", 1)
	}
}

func TestLoggerOrDefaultKeepsASetLogger(t *testing.T) {
	log := NewNoopLogger()
	if loggerOrDefault(log) != log {
		t.Error("a set logger was replaced")
	}
}

func TestLoggerOrDefaultAlwaysAnswers(t *testing.T) {
	if loggerOrDefault(nil) == nil {
		t.Error("nil settings.Log gave no logger")
	}
}
