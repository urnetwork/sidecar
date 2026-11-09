//go:build windows

// The terminal on Windows: the console, CONIN$ and CONOUT$, with echo turned off through the console mode while a
// pass is typed.

package main

import (
	"bufio"
	"os"

	"golang.org/x/sys/windows"
)

// The console, read through one buffer.
type osTty struct {
	in     *os.File
	out    *os.File
	reader *bufio.Reader
}

// Opens the console, which fails with none attached: never a fallback to stdin.
func openOsTty() (urTty, error) {
	in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	out, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		in.Close()
		return nil, err
	}
	return &osTty{in: in, out: out, reader: bufio.NewReader(in)}, nil
}

func (self *osTty) Write(p []byte) (int, error) {
	return self.out.Write(p)
}

// A line typed with echo off, the console's mode put back after.
func (self *osTty) readSecretLine() ([]byte, error) {
	handle := windows.Handle(self.in.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return nil, err
	}
	quiet := (mode &^ windows.ENABLE_ECHO_INPUT) | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(handle, quiet); err != nil {
		return nil, err
	}
	defer windows.SetConsoleMode(handle, mode)
	return readTtyLine(self.reader)
}

func (self *osTty) readLine() (string, error) {
	line, err := readTtyLine(self.reader)
	return string(line), err
}

func (self *osTty) Close() error {
	self.out.Close()
	return self.in.Close()
}

// Whether file is a console: only a console has a mode.
func isTerminal(file *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil
}
