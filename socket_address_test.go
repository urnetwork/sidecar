//go:build !sidecar_http

// §9.9's SocketAddress over the grammar. socket_name_test.go tables the grammar itself on every leg,
// so this holds what the type adds: nothing resolved yet, and text that reads back to itself.

package sidecar

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseSocketAddress(t *testing.T) {
	cases := []struct {
		text    string
		address SocketAddress
		output  string
	}{
		{text: "db", address: SocketAddress{Name: "db"}, output: "db"},
		{text: "db/primary", address: SocketAddress{Name: "db/primary"}, output: "db/primary"},
		{text: "acme:db/primary", address: SocketAddress{NetworkLabel: "acme", Name: "db/primary"}, output: "acme:db/primary"},
		{text: "Acme:DB/Primary", address: SocketAddress{NetworkLabel: "acme", Name: "db/primary"}, output: "acme:db/primary"},
		{text: "acme:tls/443/blog", address: SocketAddress{NetworkLabel: "acme", Name: "tls/443/blog"}, output: "acme:tls/443/blog"},
		{text: "acme:smtp/25/mx", address: SocketAddress{NetworkLabel: "acme", Name: "smtp/25/mx"}, output: "acme:smtp/25/mx"},
		{text: "ur/smtpedge", address: SocketAddress{Name: "ur/smtpedge"}, output: "ur/smtpedge"},
		{text: "acme:share/" + testSocketShareToken, address: SocketAddress{NetworkLabel: "acme", Name: "share/" + testSocketShareToken}, output: "acme:share/" + testSocketShareToken},
		// a reserved name parses, so that Listen and Dial can say why it stops
		{text: "sys/x", address: SocketAddress{Name: "sys/x"}, output: "sys/x"},
	}
	for _, c := range cases {
		address, err := ParseSocketAddress(c.text)
		if err != nil {
			t.Errorf("%q: %v", c.text, err)
			continue
		}
		if !reflect.DeepEqual(*address, c.address) {
			t.Errorf("%q: %+v", c.text, *address)
		}
		if address.NetworkId != nil {
			t.Errorf("%q: resolved by parsing", c.text)
		}
		if output := address.String(); output != c.output {
			t.Errorf("%q: printed %q", c.text, output)
		}
		again, err := ParseSocketAddress(c.output)
		if err != nil || !reflect.DeepEqual(again, address) {
			t.Errorf("%q: %q read back as %+v %v", c.text, c.output, again, err)
		}
	}
}

func TestParseSocketAddressRefuses(t *testing.T) {
	for _, text := range []string{
		"", ":", ":db", "acme:", "a:b:c", "-acme:db", "acme-:db", "ac_me:db", "acme:db/", "acme:db/..", "acme:%2e%2e", "acme:tls/443", "tls/80/blog",
		strings.Repeat("a", 64) + ":db", "acme:" + testSocketLongName(113), "acme:share/" + testSocketShareToken + "#k",
	} {
		if address, err := ParseSocketAddress(text); err == nil {
			t.Errorf("%q parsed: %+v", text, *address)
		} else if address != nil {
			t.Errorf("%q: a refusal came back with an address", text)
		}
	}
}
