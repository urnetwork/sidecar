//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

import (
	"bytes"
	"strings"
	"testing"
)

// §22.6: no hello line panics the parser, every refusal names a code and repeats nothing of the line, and an
// accepted hello names a mode the daemon knows.
func FuzzDaemonHello(f *testing.F) {
	f.Add([]byte(`{"ur_local":1,"mode":"control","version":"synthetic-version"}`))
	f.Add([]byte(`{"ur_local":1,"mode":"git","version":"synthetic-version","repo":"k7q2m9/repo","service":"git-upload-pack"}`))
	f.Add([]byte(`{"ur_local":1,"mode":"mcp","version":"synthetic-version","cwd":"synthetic-canary-cwd"}`))
	f.Add([]byte(`{"ur_local":1}`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, line []byte) {
		hello, code, err := parseDaemonHello(line, "synthetic-version")
		if err != nil {
			if hello != nil || code == "" {
				t.Fatal("a refusal with a hello or without a code")
			}
			if 8 <= len(line) && strings.Contains(err.Error(), string(line)) {
				t.Fatal("the refusal repeats the line")
			}
			if bytes.Contains(line, []byte("synthetic-canary")) && strings.Contains(err.Error(), "synthetic-canary") {
				t.Fatal("the refusal repeats the canary")
			}
			return
		}
		switch hello.Mode {
		case DaemonModeMcp, DaemonModeControl, DaemonModeHook, DaemonModeGit:
		default:
			t.Fatalf("accepted mode %q", hello.Mode)
		}
		if hello.Version != "synthetic-version" {
			t.Fatal("accepted another version")
		}
	})
}
