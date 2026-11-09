// The controlling terminal, where a person types a pass or confirms (§5.9's Pass, D-CORE-13): /dev/tty on Unix and
// the console on Windows, never stdin, argv or the environment, which an agent driving ur could fill. A pass is read
// with echo off and approves nothing: it only opens U (owner decisions 47, 75). A confirmation is what a Confirm
// method's call carries as ur_confirmed, which any same-uid process can forge (owner decision 47's residual).

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The longest line read from the terminal: far past any pass a person types, so a stuck input cannot hold memory.
const urTtyMaxLineByteCount = 4 * 1024

// No terminal to ask: ur will not read a pass or a confirmation anywhere else.
var errUrNoTty = errors.New("this needs a terminal: ur reads a pass or a confirmation only from /dev/tty")

// The controlling terminal, opened for one question.
type urTty interface {
	io.Writer
	// One line without its newline, typed with echo off. The caller zeroes it.
	readSecretLine() ([]byte, error)
	// One line without its newline, echoed.
	readLine() (string, error)
	Close() error
}

// A pass from the terminal, prompt first, echo off. Never stdin: with no terminal this fails (errUrNoTty). An empty
// pass is refused. The caller zeroes what it answers.
func readPassFromTty(cli *urCli, prompt string) ([]byte, error) {
	tty, err := cli.openTty()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	pass, err := tty.readSecretLine()
	fmt.Fprint(tty, "\n")
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, errors.New("no pass was typed")
	}
	return pass, nil
}

// A yes or no from the terminal, for a Confirm method (D-CORE-13): true only for y or yes.
func confirmOnTty(cli *urCli, question string) (bool, error) {
	tty, err := cli.openTty()
	if err != nil {
		return false, fmt.Errorf("%w: %w", errUrNoTty, err)
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s [y/N] ", question)
	answer, err := tty.readLine()
	if err != nil {
		return false, err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// One line from reader, at most urTtyMaxLineByteCount bytes, without its line ending.
func readTtyLine(reader *bufio.Reader) ([]byte, error) {
	line := []byte{}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && 0 < len(line) {
				return line, nil
			}
			clear(line)
			return nil, err
		}
		if b == '\n' {
			return bytes.TrimSuffix(line, []byte{'\r'}), nil
		}
		if urTtyMaxLineByteCount <= len(line) {
			clear(line)
			return nil, errors.New("the line is too long")
		}
		line = append(line, b)
	}
}
