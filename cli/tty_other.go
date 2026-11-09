//go:build !darwin && !linux && !windows

// No terminal on a system ur is not released for: every pass and confirmation is refused, never read elsewhere.

package main

import (
	"os"
)

func openOsTty() (urTty, error) {
	return nil, errUrNoTty
}

func isTerminal(file *os.File) bool {
	return false
}
