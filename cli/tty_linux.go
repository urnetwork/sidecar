//go:build linux

package main

import (
	"golang.org/x/sys/unix"
)

// termios's ioctls on Linux.
const (
	ttyGetTermios = unix.TCGETS
	ttySetTermios = unix.TCSETS
)
