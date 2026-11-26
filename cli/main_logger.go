// The daemon's stderr logger, which every build of the package links (main.go's and main_ur_engine.go's).

package main

import (
	"fmt"
	"io"
	"sync"

	"github.com/urnetwork/sidecar"
)

// A daemon's logger: stderr, never stdout, which an MCP relay owns. An auto-spawned daemon has no stderr, so its
// lines go nowhere until §5.9's size-bounded log/ is built. Verbose levels are off.
type urStderrLogger struct {
	stateLock sync.Mutex
	out       io.Writer
}

// A logger on out.
func newUrStderrLogger(out io.Writer) sidecar.Logger {
	return &urStderrLogger{out: out}
}

func (self *urStderrLogger) line(prefix string, text string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// a key must never reach a log line (I-7)
	fmt.Fprintf(self.out, "%s%s\n", prefix, sidecar.RedactAuthKey(text))
}

func (self *urStderrLogger) Info(args ...any) {
	self.line("I ", fmt.Sprint(args...))
}

func (self *urStderrLogger) Infof(format string, args ...any) {
	self.line("I ", fmt.Sprintf(format, args...))
}

func (self *urStderrLogger) Warningf(format string, args ...any) {
	self.line("W ", fmt.Sprintf(format, args...))
}

func (self *urStderrLogger) Errorf(format string, args ...any) {
	self.line("E ", fmt.Sprintf(format, args...))
}

func (self *urStderrLogger) V(level int32) sidecar.Verbose {
	return urQuietVerbose{}
}

// Verbose levels, off.
type urQuietVerbose struct{}

func (self urQuietVerbose) Enabled() bool {
	return false
}

func (self urQuietVerbose) Info(args ...any) {}

func (self urQuietVerbose) Infof(format string, args ...any) {}
