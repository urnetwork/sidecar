//go:build darwin || linux

// The terminal on Unix: /dev/tty, with echo turned off through termios while a pass is typed.

package main

import (
	"bufio"
	"os"

	"golang.org/x/sys/unix"
)

// /dev/tty, read through one buffer.
type osTty struct {
	file   *os.File
	reader *bufio.Reader
}

// Opens /dev/tty, which fails with no controlling terminal: never a fallback to stdin.
func openOsTty() (urTty, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &osTty{file: file, reader: bufio.NewReader(file)}, nil
}

func (self *osTty) Write(p []byte) (int, error) {
	return self.file.Write(p)
}

// A line typed with ECHO off, the terminal's settings put back after.
func (self *osTty) readSecretLine() ([]byte, error) {
	fd := int(self.file.Fd())
	termios, err := unix.IoctlGetTermios(fd, ttyGetTermios)
	if err != nil {
		return nil, err
	}
	quiet := *termios
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	quiet.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, ttySetTermios, &quiet); err != nil {
		return nil, err
	}
	defer unix.IoctlSetTermios(fd, ttySetTermios, termios)
	return readTtyLine(self.reader)
}

func (self *osTty) readLine() (string, error) {
	line, err := readTtyLine(self.reader)
	return string(line), err
}

func (self *osTty) Close() error {
	return self.file.Close()
}

// Whether file is a terminal: termios answers only for one.
func isTerminal(file *os.File) bool {
	_, err := unix.IoctlGetTermios(int(file.Fd()), ttyGetTermios)
	return err == nil
}
