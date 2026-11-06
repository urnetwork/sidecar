// Logging on every leg. Components log through a Logger, never a global, and §5.4's settings.Log
// names the one a Sidecar uses. These carry connect.Logger's and connect.Verbose's methods
// (connect/log.go:41), declared here because naming connect's links gVisor into the page Worker
// (§4.4). Logger.V returns this package's Verbose, so a connect.Logger is not a Logger as it stands:
// log_connect.go adapts it in both directions, and log_http.go is the sidecar_http leg.
//
// Logs carry opaque ids only, never a secret, content or a peer address (I-13, §5.10).

package sidecar

type Logger interface {
	Info(args ...any)
	Infof(format string, args ...any)
	Warningf(format string, args ...any)
	Errorf(format string, args ...any)
	V(level int32) Verbose
}

// Level-guarded logging, so a disabled level skips its arguments. Guard every call that formats:
// if self.log.V(2).Enabled() { self.log.Infof("[tag]...", a, b) }. The boxing into []any happens at
// the call site, before the level is checked.
type Verbose interface {
	Enabled() bool
	Info(args ...any)
	Infof(format string, args ...any)
}

// Discards everything: what a host that wants silence sets, and what the sidecar_http leg logs to
// unless settings.Log says otherwise.
func NewNoopLogger() Logger {
	return noopLogger{}
}

type noopLogger struct{}

func (self noopLogger) Info(args ...any) {
}

func (self noopLogger) Infof(format string, args ...any) {
}

func (self noopLogger) Warningf(format string, args ...any) {
}

func (self noopLogger) Errorf(format string, args ...any) {
}

func (self noopLogger) V(level int32) Verbose {
	return noopVerbose{}
}

type noopVerbose struct{}

func (self noopVerbose) Enabled() bool {
	return false
}

func (self noopVerbose) Info(args ...any) {
}

func (self noopVerbose) Infof(format string, args ...any) {
}
