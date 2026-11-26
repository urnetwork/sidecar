//go:build !ur_engine

// The ur binary (§4.10, §5.8): the person's commands, the relay a harness spawns for MCP, and the per-instance
// daemon they reach over a peer-uid socket or pipe. It also runs as git-remote-ur. commands.go dispatches, and each
// command is its own cmd_<name>.go. Built with the ur_engine tag, this package is the ur-engine helper instead, whose
// main is main_ur_engine.go's (QD-1401).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
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
