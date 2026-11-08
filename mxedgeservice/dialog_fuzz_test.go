// FuzzMxDialog (§22.6): over any bytes split into any reads, §15.4 holds, nothing is ready for TLS
// before STARTTLS's 220, and memory stays bounded. What §15.4 says is written a second time here as
// regular expressions over whole lines, apart from dialog.go's byte walk, so a mistake has to be made
// twice in two forms to pass.
//
// Seeds live in the module's testdata/fuzz/FuzzMxDialog, where §22.6 keeps them, which go test does not
// read for a package in a directory of its own, so this loads them. They are in go test's corpus form,
// and a crasher go test writes under this package's testdata moves there as a seed.

package mxedgeservice_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/mxedgeservice"
)

const testFuzzSeedDirectory = "../testdata/fuzz/FuzzMxDialog"

// A command name for a regular expression, ASCII case only: (?i) would fold Unicode, the very mistake
// a model here must not share.
func modelName(name string) string {
	var builder strings.Builder
	for _, c := range name {
		builder.WriteString("[" + string(c) + strings.ToLower(string(c)) + "]")
	}
	return builder.String()
}

var (
	modelLineEnd   = regexp.MustCompile(`\r\n`)
	modelBadEnd    = regexp.MustCompile(`^[^\r\n]*(\n|\r[^\n])`)
	modelHello     = regexp.MustCompile(`(?s)^(` + modelName("EHLO") + `|` + modelName("HELO") + `)([ \t].*)?$`)
	modelEhlo      = regexp.MustCompile(`^` + modelName("EHLO"))
	modelHelloName = regexp.MustCompile(`(?s)^[^ \t]+[ \t]+[\x21-\x7e]{1,255}([ \t].*)?$`)
	modelStartTls  = regexp.MustCompile(`^` + modelName("STARTTLS") + `[ \t]*$`)
	modelStartArg  = regexp.MustCompile(`(?s)^` + modelName("STARTTLS") + `[ \t].*$`)
	modelQuit      = regexp.MustCompile(`^` + modelName("QUIT") + `[ \t]*$`)
	modelQuitArg   = regexp.MustCompile(`(?s)^` + modelName("QUIT") + `[ \t].*$`)
	modelTransact  = regexp.MustCompile(`(?s)^(` + modelName("MAIL") + `|` + modelName("RCPT") + `|` +
		modelName("DATA") + `|` + modelName("BDAT") + `)([ \t].*)?$`)
)

// §15.4's dialog over whole reads: what goes out, and how it ends.
func modelDialog(reads [][]byte, recent bool, refused bool) (written string, finalStep mxedgeservice.DialogStep) {
	stream := []byte{}
	position := 0
	for _, read := range reads {
		stream = append(stream, read...)
		overLimit := mxedgeservice.DialogMaxByteCount < len(stream)
		visible := stream[:min(len(stream), mxedgeservice.DialogMaxByteCount)]
		pending := ""
		for {
			rest := visible[position:]
			lineByteCount := 0
			for lineByteCount < len(rest) && rest[lineByteCount] != '\r' && rest[lineByteCount] != '\n' {
				lineByteCount += 1
			}
			if modelBadEnd.Match(rest) || mxedgeservice.DialogMaxLineByteCount < lineByteCount {
				return written + pending, mxedgeservice.DialogStepClose
			}
			end := modelLineEnd.FindIndex(rest)
			if end == nil {
				if overLimit {
					return written + pending, mxedgeservice.DialogStepClose
				}
				break
			}
			line := rest[:end[0]]
			position += end[1]
			switch {
			case modelQuit.Match(line):
				return written + pending + "221 2.0.0 Bye\r\n", mxedgeservice.DialogStepQuit
			case refused:
				pending += "503 5.5.1 Bad sequence of commands\r\n"
			case modelStartTls.Match(line):
				if position != len(stream) {
					return written, mxedgeservice.DialogStepReset
				}
				return written + pending + testReply220, mxedgeservice.DialogStepTls
			case modelStartArg.Match(line), modelQuitArg.Match(line):
				pending += "501 5.5.4 Syntax error\r\n"
			case modelHello.Match(line):
				switch {
				case !modelHelloName.Match(line):
					pending += "501 5.5.4 Syntax error\r\n"
				case modelEhlo.Match(line):
					pending += testReplyEhlo
				default:
					pending += "250 " + testBannerHostName + "\r\n"
				}
			case modelTransact.Match(line):
				if recent {
					pending += testReply451
				} else {
					pending += testReply530
				}
			default:
				pending += "502 5.5.1 Command not implemented\r\n"
			}
		}
		written += pending
	}
	return written, mxedgeservice.DialogStepRead
}

func FuzzMxDialog(f *testing.F) {
	seeds, err := filepath.Glob(filepath.Join(testFuzzSeedDirectory, "*"))
	if err != nil {
		f.Fatal(err)
	}
	if len(seeds) < 10 {
		f.Fatalf("%d seeds in %s", len(seeds), testFuzzSeedDirectory)
	}
	// one seed in go test's corpus form: its header, then a []byte per line
	readSeed := func(path string) ([][]byte, error) {
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		values := [][]byte{}
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		for _, line := range lines[1:] {
			value, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")"))
			if err != nil {
				return nil, err
			}
			values = append(values, []byte(value))
		}
		return values, nil
	}
	for _, path := range seeds {
		values, err := readSeed(path)
		if err != nil {
			f.Fatalf("%s: %v", path, err)
		}
		if len(values) != 2 {
			f.Fatalf("%s holds %d values", path, len(values))
		}
		f.Add(values[0], values[1])
	}
	settings := testSettings()
	f.Fuzz(func(t *testing.T, data []byte, shape []byte) {
		// shape's first byte holds the flags, and each later one a read's size, cycling, where 0 is as
		// much as a read can hold, so every read fits service.go's buffer
		recent := 0 < len(shape) && shape[0]&1 != 0
		refused := 0 < len(shape) && shape[0]&2 != 0
		sizes := []byte{0}
		if 1 < len(shape) {
			sizes = shape[1:]
		}
		reads := [][]byte{}
		for index, rest := 0, data; 0 < len(rest); index += 1 {
			size := int(sizes[index%len(sizes)])
			if size == 0 {
				size = mxedgeservice.DialogMaxByteCount + 1
			}
			size = min(size, len(rest))
			reads = append(reads, rest[:size])
			rest = rest[size:]
		}
		dialog := mxedgeservice.NewDialog(settings, func() bool { return recent }, refused)

		written := []byte{}
		step := mxedgeservice.DialogStepRead
		fedReads := [][]byte{}
		for _, read := range reads {
			var reply []byte
			reply, step = dialog.Receive(read)
			fedReads = append(fedReads, read)
			written = append(written, reply...)
			if step == mxedgeservice.DialogStepReset && 0 < len(reply) {
				t.Fatalf("a reset wrote %q", reply)
			}
			if step != mxedgeservice.DialogStepRead {
				break
			}
		}

		// §15.4 holds: what went out, and how it ended, is what the model says of the reads it saw
		wantWritten, wantStep := modelDialog(fedReads, recent, refused)
		if string(written) != wantWritten || step != wantStep {
			t.Fatalf("reads %q: wrote %q and step %d, want %q and step %d", fedReads, written, step, wantWritten, wantStep)
		}

		// nothing is ready for TLS before STARTTLS's 220, the last thing written
		if step == mxedgeservice.DialogStepTls {
			if !bytes.HasSuffix(written, []byte(testReply220)) {
				t.Fatalf("ready for TLS on %q", written)
			}
			if refused {
				t.Fatal("a refused session reached TLS")
			}
			// the last line of what was read was the STARTTLS, with nothing behind it
			fed := bytes.Join(fedReads, nil)
			if !bytes.HasSuffix(bytes.ToUpper(fed), []byte("\r\n")) || mxedgeservice.DialogMaxByteCount < len(fed) {
				t.Fatalf("ready for TLS after %q", fed)
			}
			lastLine := fed[:len(fed)-2]
			if index := bytes.LastIndex(lastLine, []byte("\r\n")); 0 <= index {
				lastLine = lastLine[index+2:]
			}
			if !modelStartTls.Match(lastLine) {
				t.Fatalf("ready for TLS on the line %q", lastLine)
			}
		} else if bytes.Contains(written, []byte(testReply220)) {
			t.Fatalf("a 220 went out with step %d", step)
		}
		if bytes.Contains(bytes.ToUpper(written), []byte("PIPELINING")) {
			t.Fatalf("offered pipelining: %q", written)
		}

		// bounded memory: a dialog's one buffer is the same size whatever came in
		if dialog.BufferByteCount() != mxedgeservice.DialogMaxByteCount {
			t.Fatalf("buffer of %d", dialog.BufferByteCount())
		}

		// once over, nothing more is read, and no later call can reach TLS
		if step != mxedgeservice.DialogStepRead {
			if reply, nextStep := dialog.Receive([]byte("STARTTLS\r\n")); 0 < len(reply) || nextStep != mxedgeservice.DialogStepReset {
				t.Fatalf("after the end: %q and step %d", reply, nextStep)
			}
		}
	})
}
