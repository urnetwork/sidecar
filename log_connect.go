//go:build !sidecar_http

// The boundary between the root's Logger and connect's. Their method sets match but for V's result
// type, so each direction is one small adapter. glog's file:line for a line logged through an
// adapter names this file, since connect's logger skips one frame and an adapter adds one.

package sidecar

import (
	"github.com/urnetwork/connect"
)

// settings.Log, or connect's default logger (glog) when it is nil (§5.4).
func loggerOrDefault(log Logger) Logger {
	if log == nil {
		return loggerFromConnect(connect.DefaultLogger())
	}
	return log
}

// A connect logger as a root one. Nil stays nil, the unset logger on both sides, never an adapter
// around nothing.
func loggerFromConnect(log connect.Logger) Logger {
	if log == nil {
		return nil
	}
	return connectBackedLogger{log: log}
}

// What a connect settings struct's Log field takes. Nil stays nil, so settings.Log's default passes
// down as connect's own rule has it: a nil Log resolves to connect's default at construction
// (connect/log.go), which an adapter around nothing would panic in place of.
func connectLogger(log Logger) connect.Logger {
	if log == nil {
		return nil
	}
	if backed, ok := log.(connectBackedLogger); ok {
		return backed.log
	}
	return rootBackedLogger{log: log}
}

// A connect.Logger as a root Logger.
type connectBackedLogger struct {
	log connect.Logger
}

// Passes through.
func (self connectBackedLogger) Info(args ...any) {
	self.log.Info(args...)
}

// Passes through.
func (self connectBackedLogger) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

// Passes through.
func (self connectBackedLogger) Warningf(format string, args ...any) {
	self.log.Warningf(format, args...)
}

// Passes through.
func (self connectBackedLogger) Errorf(format string, args ...any) {
	self.log.Errorf(format, args...)
}

// connect's Verbose as it stands, the two interfaces being one method set.
func (self connectBackedLogger) V(level int32) Verbose {
	return self.log.V(level)
}

// A root Logger as a connect.Logger.
type rootBackedLogger struct {
	log Logger
}

// Passes through.
func (self rootBackedLogger) Info(args ...any) {
	self.log.Info(args...)
}

// Passes through.
func (self rootBackedLogger) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

// Passes through.
func (self rootBackedLogger) Warningf(format string, args ...any) {
	self.log.Warningf(format, args...)
}

// Passes through.
func (self rootBackedLogger) Errorf(format string, args ...any) {
	self.log.Errorf(format, args...)
}

// The root's Verbose as it stands, the two interfaces being one method set.
func (self rootBackedLogger) V(level int32) connect.Verbose {
	return self.log.V(level)
}
