//go:build !js

// FuzzMailParse (MAIL-M7-11, §22.6's go-message target): MailParseMessage over any bytes never panics and never
// errs on a reader that cannot fail, keeps every value valid UTF-8 within its cap and every single-line value on one
// line, expands nothing past its bounds and allocates within a fixed multiple of its input, and what it gives builds
// an IndexEntry that encodes and ingest headers that never split (checkMailParse). Off the js leg, whose Worker has
// no file system for go test's corpus reader; mail_parse_test.go runs the seeds there through embed.

package sidecar

import (
	"testing"
)

func FuzzMailParse(f *testing.F) {
	f.Add([]byte("From: ada@sender.example\r\nSubject: hi\r\n\r\nbody\r\n"))
	f.Fuzz(func(t *testing.T, message []byte) {
		if failure := checkMailParse(message); failure != "" {
			t.Fatalf("%q: %s", message[:min(len(message), 200)], failure)
		}
	})
}
