//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// Whether text holds anything a terminal reads as a control: a C0 control but a newline, DEL, a C1 control, a bidi
// control, or a byte that is not UTF-8.
func testHarnessHoldsControl(text string) bool {
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		i += size
		switch {
		case r == utf8.RuneError && size == 1:
			return true
		case r < 0x20 && r != '\n', r == 0x7f, 0x80 <= r && r <= 0x9f:
			return true
		case r == 0x200e || r == 0x200f || (0x202a <= r && r <= 0x202e) || (0x2066 <= r && r <= 0x2069) || r == 0x061c:
			return true
		}
	}
	return false
}

// Every escape a hostile text could carry leaves no ESC, C0 or C1 control: OSC 52's clipboard write, OSC 8's link, CSI's
// screen clear and cursor move, CSI's 8-bit form 0x9b as U+009B and as a raw byte, a C1 OSC, the image protocols'
// APC and DCS, a bell and a backspace, a lone carriage return and the bidi controls; a newline stays and a tab is a
// space, and HarnessSanitizeLine drops the newline too.
func TestHarnessSanitizeStripsEscC0C1(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "osc 52", input: "copy \x1b]52;c;ZXZpbA==\x07 done", want: "copy ]52;c;ZXZpbA== done"},
		{name: "osc 8", input: "\x1b]8;;https://evil.example\x1b\\click\x1b]8;;\x1b\\", want: "]8;;https://evil.example\\click]8;;\\"},
		{name: "csi", input: "\x1b[2J\x1b[1;1Hhello", want: "[2J[1;1Hhello"},
		{name: "8-bit csi as a code point", input: "a\u009b2Jb", want: "a2Jb"},
		{name: "8-bit csi as a byte", input: "a\x9b2Jb", want: "a�2Jb"},
		{name: "c1 osc and st", input: "x\u009d52;c;Zm9v\u009cy", want: "x52;c;Zm9vy"},
		{name: "kitty image", input: "\x1b_Ga=T,f=100;iVBORw0K\x1b\\", want: "_Ga=T,f=100;iVBORw0K\\"},
		{name: "sixel", input: "\x1bPq#0;2;0;0;0#0!10~\x1b\\", want: "Pq#0;2;0;0;0#0!10~\\"},
		{name: "iterm image", input: "\x1b]1337;File=inline=1:AAAA\x07", want: "]1337;File=inline=1:AAAA"},
		{name: "bell and backspace", input: "ab\x07\x08c", want: "abc"},
		{name: "carriage return", input: "safe\rEVIL", want: "safeEVIL"},
		{name: "bidi", input: "abc‮def⁦g⁩", want: "abcdefg"},
		{name: "del", input: "a\x7fb", want: "ab"},
		{name: "tab and newline", input: "a\tb\nc", want: "a b\nc"},
		{name: "plain", input: "nothing to do here: 1 < 2", want: "nothing to do here: 1 < 2"},
	}
	for _, c := range cases {
		got := HarnessSanitize(c.input)
		if got != c.want {
			t.Errorf("%s: HarnessSanitize(%q) = %q, want %q", c.name, c.input, got, c.want)
		}
		if testHarnessHoldsControl(got) {
			t.Errorf("%s: %q still holds a control", c.name, got)
		}
		line := HarnessSanitizeLine(c.input)
		if strings.ContainsAny(line, "\n") || testHarnessHoldsControl(line) {
			t.Errorf("%s: HarnessSanitizeLine(%q) = %q holds a newline or a control", c.name, c.input, line)
		}
	}
}

// A raw JSON line keeps its value while every DEL, C1 and bidi control in it becomes an escape, a byte that is not
// UTF-8 the replacement character JSON's own decoder reads it as, and a line with none of them stays as it was.
func TestHarnessJsonTerminalSafeKeepsTheValue(t *testing.T) {
	raw := []byte("{\"type\":\"message_end\",\"text\":\"a\u009b2J\x7f‮b\xffc\",\"n\":1}")
	safe := HarnessJsonTerminalSafe(raw)
	if testHarnessHoldsControl(string(safe)) {
		t.Fatalf("%q still holds a control", safe)
	}
	before, after := map[string]any{}, map[string]any{}
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(safe, &after); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("the value changed: %v, then %v", before, after)
	}
	plain := []byte(`{"type":"turn_start","agent":"x","seq":1}`)
	if got := HarnessJsonTerminalSafe(plain); string(got) != string(plain) {
		t.Fatalf("a clean line changed: %s", got)
	}
}

// Only an absolute https URL with a host, no credentials and nothing but printable ASCII passes, within the bound.
func TestHarnessCheckedUrl(t *testing.T) {
	passing := []string{"https://docs.example/guide", "https://docs.example:8443/a?b=c#d", "HTTPS://upper.example/"}
	for _, raw := range passing {
		if _, ok := HarnessCheckedUrl(raw, 2048); !ok {
			t.Errorf("%q was refused", raw)
		}
	}
	refused := []string{
		"", "http://plain.example/", "https://user:pass@creds.example/", "https://user@creds.example/",
		"javascript:alert(1)", "https:opaque", "https:///nohost", "https://spaced.example/a b",
		"https://esc.example/\x1b\\", "https://bell.example/\x07", "https://unicode.example/é",
		"https://back.example\\@evil.example/", "/relative/path", "mailto:someone@mail.example",
	}
	for _, raw := range refused {
		if _, ok := HarnessCheckedUrl(raw, 2048); ok {
			t.Errorf("%q passed", raw)
		}
	}
	if _, ok := HarnessCheckedUrl("https://long.example/"+strings.Repeat("a", 64), 32); ok {
		t.Error("a URL past the bound passed")
	}
}
