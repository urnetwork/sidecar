//go:build !sidecar_http

package sidecar

import (
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/connect"
)

// Records every call, for both directions of the boundary. It implements connect.Logger.
type recordingConnectLogger struct {
	lines *[]string
}

func (self recordingConnectLogger) Info(args ...any) {
	*self.lines = append(*self.lines, fmt.Sprint(append([]any{"info "}, args...)...))
}

func (self recordingConnectLogger) Infof(format string, args ...any) {
	*self.lines = append(*self.lines, "infof "+fmt.Sprintf(format, args...))
}

func (self recordingConnectLogger) Warningf(format string, args ...any) {
	*self.lines = append(*self.lines, "warningf "+fmt.Sprintf(format, args...))
}

func (self recordingConnectLogger) Errorf(format string, args ...any) {
	*self.lines = append(*self.lines, "errorf "+fmt.Sprintf(format, args...))
}

func (self recordingConnectLogger) V(level int32) connect.Verbose {
	return recordingVerbose{lines: self.lines, level: level}
}

// connect.Verbose and the root's Verbose are one method set.
type recordingVerbose struct {
	lines *[]string
	level int32
}

func (self recordingVerbose) Enabled() bool {
	return self.level <= 1
}

func (self recordingVerbose) Info(args ...any) {
	*self.lines = append(*self.lines, fmt.Sprintf("v%d info ", self.level)+fmt.Sprint(args...))
}

func (self recordingVerbose) Infof(format string, args ...any) {
	*self.lines = append(*self.lines, fmt.Sprintf("v%d infof ", self.level)+fmt.Sprintf(format, args...))
}

// The same recorder as a root Logger, the one case a connect.Logger is not.
type recordingLogger struct {
	recordingConnectLogger
}

func (self recordingLogger) V(level int32) Verbose {
	return recordingVerbose{lines: self.lines, level: level}
}

func exerciseConnectLogger(log connect.Logger) {
	log.Info("a")
	log.Infof("b %d", 1)
	log.Warningf("c %d", 2)
	log.Errorf("d %d", 3)
	log.V(2).Info("e")
	log.V(2).Infof("f %d", 4)
}

func exerciseLogger(log Logger) {
	log.Info("a")
	log.Infof("b %d", 1)
	log.Warningf("c %d", 2)
	log.Errorf("d %d", 3)
	log.V(2).Info("e")
	log.V(2).Infof("f %d", 4)
}

var wantLogLines = []string{"info a", "infof b 1", "warningf c 2", "errorf d 3", "v2 info e", "v2 infof f 4"}

func TestLoggerFromConnectPassesEveryCall(t *testing.T) {
	lines := []string{}
	exerciseLogger(loggerFromConnect(recordingConnectLogger{lines: &lines}))
	if !slices.Equal(lines, wantLogLines) {
		t.Errorf("lines %q", lines)
	}
}

func TestConnectLoggerPassesEveryCall(t *testing.T) {
	lines := []string{}
	exerciseConnectLogger(connectLogger(recordingLogger{recordingConnectLogger: recordingConnectLogger{lines: &lines}}))
	if !slices.Equal(lines, wantLogLines) {
		t.Errorf("lines %q", lines)
	}
}

func TestVerboseLevelsPassThroughTheAdapter(t *testing.T) {
	lines := []string{}
	log := loggerFromConnect(recordingConnectLogger{lines: &lines})
	if !log.V(1).Enabled() {
		t.Error("level 1 disabled")
	}
	if log.V(2).Enabled() {
		t.Error("level 2 enabled")
	}
}

func TestConnectLoggerUnwrapsAnAdaptedLogger(t *testing.T) {
	lines := []string{}
	original := recordingConnectLogger{lines: &lines}
	// a round trip adds no layer, so nothing logs through two adapters
	if backed, ok := connectLogger(loggerFromConnect(original)).(recordingConnectLogger); !ok || backed.lines != &lines {
		t.Errorf("round trip gave %T", connectLogger(loggerFromConnect(original)))
	}
}

// settings.Log's default is nil, and connect's Log fields resolve nil to connect's default, so nil has
// to arrive there as nil. An adapter around it would be a logger that panics at its first line.
func TestConnectLoggerLeavesTheUnsetLoggerUnset(t *testing.T) {
	if log := connectLogger(DefaultSidecarSettings().Log); log != nil {
		t.Errorf("settings.Log's default gave %T", log)
	}
	if log := loggerFromConnect(nil); log != nil {
		t.Errorf("a nil connect logger gave %T", log)
	}
}

func TestLoggerOrDefaultUsesConnectsDefault(t *testing.T) {
	lines := []string{}
	var set connect.Logger = recordingConnectLogger{lines: &lines}
	connect.SetDefaultLogger(set)
	t.Cleanup(func() { connect.SetDefaultLogger(nil) })

	exerciseLogger(loggerOrDefault(nil))
	if !slices.Equal(lines, wantLogLines) {
		t.Errorf("lines %q", lines)
	}
}
