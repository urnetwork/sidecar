//go:build !ios_extension

package sidecar

import (
	"strings"
	"testing"
)

// The policy is RFC 8461 §3.2's text for the mail host, CRLF a line, and its id is 32 lowercase hex digits
// that move with any change of the text and stay with none.
func TestMtaStsPolicyAndItsId(t *testing.T) {
	policy := MtaStsPolicy("mx.abcdefghij.zone.example.", nil)
	want := "version: STSv1\r\nmode: enforce\r\nmx: mx.abcdefghij.zone.example\r\nmax_age: 604800\r\n"
	if policy != want {
		t.Fatalf("policy %q", policy)
	}
	id := MtaStsPolicyId(policy, nil)
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("id %q", id)
	}
	if again := MtaStsPolicyId(MtaStsPolicy("MX.abcdefghij.zone.example", nil), nil); again != id {
		t.Errorf("the same host spelt another way moved the id: %s", again)
	}
	settings := DefaultMtaStsSettings()
	settings.MaxAgeSeconds = 86400
	if moved := MtaStsPolicyId(MtaStsPolicy("mx.abcdefghij.zone.example", settings), settings); moved == id {
		t.Error("a new max_age kept the id")
	}
	if moved := MtaStsPolicyId(MtaStsPolicy("mx.other.zone.example", nil), nil); moved == id {
		t.Error("another mail host kept the id")
	}
}
