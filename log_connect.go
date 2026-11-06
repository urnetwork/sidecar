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

func loggerFromConnect(log connect.Logger) Logger {
	return connectBackedLogger{log: log}
}

// What a connect settings struct's Log field takes.
func connectLogger(log Logger) connect.Logger {
	if backed, ok := log.(connectBackedLogger); ok {
		return backed.log
	}
	return rootBackedLogger{log: log}
}

type connectBackedLogger struct {
	log connect.Logger
}

func (self connectBackedLogger) Info(args ...any) {
	self.log.Info(args...)
}

func (self connectBackedLogger) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

func (self connectBackedLogger) Warningf(format string, args ...any) {
	self.log.Warningf(format, args...)
}

func (self connectBackedLogger) Errorf(format string, args ...any) {
	self.log.Errorf(format, args...)
}

func (self connectBackedLogger) V(level int32) Verbose {
	return self.log.V(level)
}

type rootBackedLogger struct {
	log Logger
}

func (self rootBackedLogger) Info(args ...any) {
	self.log.Info(args...)
}

func (self rootBackedLogger) Infof(format string, args ...any) {
	self.log.Infof(format, args...)
}

func (self rootBackedLogger) Warningf(format string, args ...any) {
	self.log.Warningf(format, args...)
}

func (self rootBackedLogger) Errorf(format string, args ...any) {
	self.log.Errorf(format, args...)
}

func (self rootBackedLogger) V(level int32) connect.Verbose {
	return self.log.V(level)
}
