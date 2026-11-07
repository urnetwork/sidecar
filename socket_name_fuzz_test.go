//go:build !sidecar_http

// FuzzParseSocketAddress, with its seeds in testdata/fuzz/FuzzParseSocketAddress. It stays off the
// sidecar_http leg with ParseSocketAddress itself, and because go test reads those seeds from a file
// system the page Worker does not have. socket_name_test.go tables the same grammar on that leg.

package sidecar

import (
	"reflect"
	"strings"
	"testing"
)

// Nothing panics, and whatever parses is canonical: its text reads back to the same address, its
// name reads back to the same name and namespace, and it stays within §9.4's bounds and bytes.
func FuzzParseSocketAddress(f *testing.F) {
	f.Fuzz(func(t *testing.T, text string) {
		address, err := ParseSocketAddress(text)
		if err != nil {
			if address != nil {
				t.Fatalf("%q: a refusal came back with an address", text)
			}
			return
		}
		output := address.String()
		again, err := ParseSocketAddress(output)
		if err != nil {
			t.Fatalf("%q printed %q, which is refused: %v", text, output, err)
		}
		if !reflect.DeepEqual(again, address) {
			t.Fatalf("%q printed %q, which reads as %+v", text, output, *again)
		}
		if againOutput := again.String(); againOutput != output {
			t.Fatalf("%q printed %q, then %q", text, output, againOutput)
		}

		name, namespace, err := ParseSocketName(address.Name)
		if err != nil || name != address.Name || namespace == 0 {
			t.Fatalf("%q: the name %q reads as %q %d %v", text, address.Name, name, namespace, err)
		}
		if socketNameMaxByteCount < len(name) {
			t.Fatalf("%q: a %d-byte name", text, len(name))
		}
		segments := strings.Split(name, "/")
		if socketNameMaxSegmentCount < len(segments) {
			t.Fatalf("%q: %d segments", text, len(segments))
		}
		for _, segment := range segments {
			if segment == "" || segment == "." || segment == ".." || socketSegmentMaxByteCount < len(segment) {
				t.Fatalf("%q: the segment %q", text, segment)
			}
			if strings.Contains(segment, "@") && segment != "@" {
				t.Fatalf("%q: the segment %q", text, segment)
			}
		}
		for index := range len(output) {
			c := output[index]
			if 'A' <= c && c <= 'Z' || 0x7f <= c || c <= ' ' || c == '%' {
				t.Fatalf("%q printed %q, with the byte %#x", text, output, c)
			}
		}
		// a reserved word never reads as an application name, however it came in
		if first := segments[0]; namespace == SocketNamespaceApplication &&
			(first == "tls" || first == "smtp" || first == "ur" || first == "share" || first == "sys" || first == "c" || len(first) == 1 || first[0] == '_') {
			t.Fatalf("%q: the reserved %q read as an application name", text, first)
		}
	})
}
