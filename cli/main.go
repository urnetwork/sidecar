// The ur binary (§4.10, §5.8): the person's commands, the relay a harness spawns for MCP, and the per-instance
// daemon they reach over a peer-uid socket or pipe. It also runs as git-remote-ur. commands.go dispatches, and each
// command is its own cmd_<name>.go.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/urnetwork/sidecar"
)

// A context that ends at an interrupt or a terminate, so a daemon closes its Sidecar and releases its lock.
func urSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func main() {
	ctx, cancel := urSignalContext()
	exitCode := newUrCli().main(ctx, os.Args)
	cancel()
	os.Exit(exitCode)
}

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
