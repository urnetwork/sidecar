// Logging on every leg. Components log through a Logger, never a global, and §5.4's settings.Log
// names the one a Sidecar uses. These carry connect.Logger's and connect.Verbose's methods
// (connect/log.go:41), declared here because naming connect's links gVisor into the page Worker
// (§4.4). Logger.V returns this package's Verbose, so a connect.Logger is not a Logger as it stands:
// log_connect.go adapts it in both directions, and log_http.go is the sidecar_http leg.
//
// Logs carry opaque ids only, never a secret, content or a peer address (I-13, §5.10).

package sidecar

// What a component logs through, with connect's meaning for each level (connect/log.go): Info for
// what is abnormal or worth a trace, Warningf for a recovered crash, Errorf for an unexpected one.
// Safe for concurrent use.
type Logger interface {
	// Always emits, in fmt.Print's form.
	Info(args ...any)
	// Always emits, in fmt.Printf's form.
	Infof(format string, args ...any)
	// Always emits, as a warning.
	Warningf(format string, args ...any)
	// Always emits, as an error.
	Errorf(format string, args ...any)
	// The guarded logger for a verbosity level.
	V(level int32) Verbose
}

// Level-guarded logging, so a disabled level skips its arguments. Guard every call that formats:
// if self.log.V(2).Enabled() { self.log.Infof("[tag]...", a, b) }. The boxing into []any happens at
// the call site, before the level is checked.
type Verbose interface {
	// Whether this level logs.
	Enabled() bool
	// Emits only while enabled.
	Info(args ...any)
	// Emits only while enabled, with the boxing above already paid.
	Infof(format string, args ...any)
}

// Discards everything: what a host that wants silence sets, and what the sidecar_http leg logs to
// unless settings.Log says otherwise.
func NewNoopLogger() Logger {
	return noopLogger{}
}

// A Logger with nothing behind it.
type noopLogger struct{}

// Drops args.
func (self noopLogger) Info(args ...any) {
}

// Drops the line.
func (self noopLogger) Infof(format string, args ...any) {
}

// Drops the line.
func (self noopLogger) Warningf(format string, args ...any) {
}

// Drops the line.
func (self noopLogger) Errorf(format string, args ...any) {
}

// Every level is off.
func (self noopLogger) V(level int32) Verbose {
	return noopVerbose{}
}

// A Verbose that is never enabled.
type noopVerbose struct{}

// Always false, so a guarded call formats nothing.
func (self noopVerbose) Enabled() bool {
	return false
}

// Drops args.
func (self noopVerbose) Info(args ...any) {
}

// Drops the line.
func (self noopVerbose) Infof(format string, args ...any) {
}
