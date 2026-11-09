//go:build darwin

package main

import (
	"golang.org/x/sys/unix"
)

// termios's ioctls on the BSDs.
const (
	ttyGetTermios = unix.TIOCGETA
	ttySetTermios = unix.TIOCSETA
)
