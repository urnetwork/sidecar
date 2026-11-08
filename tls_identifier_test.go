// §13.8's identifier sets: each shape the table names, every refusal of a name a visitor could not reach, and a hash
// that depends on the set alone. Names are synthetic, under .example.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
)

// A root and a network label for these tests.
const (
	testTlsRoot  = "ur.example"
	testTlsLabel = "k7m2q9xa"
)

func TestTlsIdentifierSetShapes(t *testing.T) {
	cases := []struct {
		scope   string
		aliases []string
		want    []string
	}{
		{
			want: []string{"*.k7m2q9xa.ur.example", "k7m2q9xa.ur.example"},
		},
		{
			// each live alias's pair beside the network's, sorted bytewise, so every wildcard comes first
			aliases: []string{"blog", "acme"},
			want: []string{
				"*.acme.ur.example", "*.blog.ur.example", "*.k7m2q9xa.ur.example",
				"acme.ur.example", "blog.ur.example", "k7m2q9xa.ur.example",
			},
		},
		{
			// a scope's devices hold its pair alone, whatever the network's aliases are
			scope:   "eng",
			aliases: []string{"acme"},
			want:    []string{"*.eng.k7m2q9xa.ur.example", "eng.k7m2q9xa.ur.example"},
		},
		{
			// an alias named twice, or named as the label, adds nothing
			aliases: []string{"acme", "acme", testTlsLabel},
			want: []string{
				"*.acme.ur.example", "*.k7m2q9xa.ur.example", "acme.ur.example", "k7m2q9xa.ur.example",
			},
		},
	}
	for _, c := range cases {
		identifierSet, err := TlsIdentifierSet(testTlsRoot, testTlsLabel, c.scope, c.aliases)
		if err != nil {
			t.Errorf("scope %q aliases %q: %v", c.scope, c.aliases, err)
			continue
		}
		if !slices.Equal(identifierSet, c.want) {
			t.Errorf("scope %q aliases %q: %q", c.scope, c.aliases, identifierSet)
		}
	}
}

func TestTlsIdentifierSetRefusesWhatNoVisitorReaches(t *testing.T) {
	// a 249-byte root: abc.<root> is 253 bytes and passes as a name, and its wildcard, 2 bytes more, does not
	longRoot := strings.Repeat("r", 63) + "." + strings.Repeat("o", 63) + "." + strings.Repeat("o", 63) + "." +
		strings.Repeat("t", 57)
	cases := []struct {
		root    string
		label   string
		scope   string
		aliases []string
	}{
		{root: testTlsRoot, label: ""},
		{root: testTlsRoot, label: "K7m2q9xa"},
		{root: testTlsRoot, label: "k7_m2q9xa"},
		{root: testTlsRoot, label: "-k7m2q9xa"},
		{root: testTlsRoot, label: "k7m2q9xa-"},
		{root: testTlsRoot, label: "k7.m2q9xa"},
		{root: testTlsRoot, label: "*"},
		{root: testTlsRoot, label: strings.Repeat("a", 64)},
		{root: testTlsRoot, label: "k7m2q9xá"},
		{root: "", label: testTlsLabel},
		{root: "ur.example.", label: testTlsLabel},
		{root: "UR.example", label: testTlsLabel},
		{root: "ur..example", label: testTlsLabel},
		{root: testTlsRoot, label: testTlsLabel, scope: "Eng"},
		{root: testTlsRoot, label: testTlsLabel, scope: "eng.ops"},
		{root: testTlsRoot, label: testTlsLabel, aliases: []string{"acme", ""}},
		{root: testTlsRoot, label: testTlsLabel, aliases: []string{"ac me"}},
		{root: testTlsRoot, label: testTlsLabel, aliases: []string{"acme.blog"}},
		{root: longRoot, label: "abc"},
	}
	for _, c := range cases {
		identifierSet, err := TlsIdentifierSet(c.root, c.label, c.scope, c.aliases)
		if !errors.Is(err, ErrTlsIdentifierSet) || identifierSet != nil {
			t.Errorf("root %q label %q scope %q aliases %q: %q %v", c.root, c.label, c.scope, c.aliases, identifierSet, err)
		}
	}
	// the same root under a one-byte label, its wildcard at 253 bytes exactly
	identifierSet, err := TlsIdentifierSet(longRoot, "a", "", nil)
	if err != nil || len(identifierSet[0]) != 253 {
		t.Errorf("a 253-byte wildcard: %q %v", identifierSet, err)
	}
}

// SHA-256 over the names, sorted bytewise, each followed by one 0x00, written out here apart from the code.
func testTlsIdentifierSetHash(names []string) [sha256.Size]byte {
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	joined := []byte{}
	for _, name := range sorted {
		joined = append(joined, name...)
		joined = append(joined, 0x00)
	}
	return sha256.Sum256(joined)
}

func TestTlsIdentifierSetHashIsReadingTwosBytes(t *testing.T) {
	identifierSet, err := TlsIdentifierSet(testTlsRoot, testTlsLabel, "", []string{"acme"})
	if err != nil {
		t.Fatal(err)
	}
	hash, err := TlsIdentifierSetHash(identifierSet)
	if err != nil {
		t.Fatal(err)
	}
	if hash != testTlsIdentifierSetHash(identifierSet) {
		t.Errorf("hash %x", hash)
	}
}

func TestTlsIdentifierSetHashIgnoresOrder(t *testing.T) {
	names := []string{"*.acme.ur.example", "acme.ur.example", "*.k7m2q9xa.ur.example", "k7m2q9xa.ur.example"}
	want, err := TlsIdentifierSetHash(names)
	if err != nil {
		t.Fatal(err)
	}
	orders := [][]string{
		{"k7m2q9xa.ur.example", "*.k7m2q9xa.ur.example", "acme.ur.example", "*.acme.ur.example"},
		{"acme.ur.example", "k7m2q9xa.ur.example", "*.acme.ur.example", "*.k7m2q9xa.ur.example"},
		// a CSR that lists a name twice covers the same names
		{"acme.ur.example", "acme.ur.example", "*.acme.ur.example", "k7m2q9xa.ur.example", "*.k7m2q9xa.ur.example"},
	}
	for _, order := range orders {
		hash, err := TlsIdentifierSetHash(order)
		if err != nil || hash != want {
			t.Errorf("%q: %x %v", order, hash, err)
		}
	}
	// another set hashes apart, including one whose bytes run together the same without the 0x00s
	for _, other := range [][]string{
		{"*.k7m2q9xa.ur.example", "k7m2q9xa.ur.example"},
		{"a.example", "b.example"},
	} {
		hash, err := TlsIdentifierSetHash(other)
		if err != nil || hash == want {
			t.Errorf("%q: %x %v", other, hash, err)
		}
	}
	joined, err := TlsIdentifierSetHash([]string{"a.exampleb.example"})
	if err != nil {
		t.Fatal(err)
	}
	split, err := TlsIdentifierSetHash([]string{"a.example", "b.example"})
	if err != nil || joined == split {
		t.Errorf("two names hash as their concatenation: %v", err)
	}
}

// A name off a CSR or a certificate is hashed only in the one form a set holds, so a name in another case, with a
// trailing dot or a 0x00 inside cannot hash as a name it is not. A caller reads a refusal as no match.
func TestTlsIdentifierSetHashRefusesWhatASetCannotHold(t *testing.T) {
	for _, names := range [][]string{
		nil,
		{},
		{""},
		{"K7m2q9xa.ur.example"},
		{"k7m2q9xa.ur.example."},
		{"k7m2q9xa.ur.example\x00*.k7m2q9xa.ur.example"},
		{"*."},
		{"*"},
		{"*.*.ur.example"},
		{"k7m2q9xa.*.example"},
		{"k7m2q9xa..ur.example"},
		{"k7m2q9xa.ur.example", "xn--bcher-kva.example", "bücher.example"},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62)},
	} {
		if _, err := TlsIdentifierSetHash(names); !errors.Is(err, ErrTlsIdentifierSet) {
			t.Errorf("%q: %v", names, err)
		}
	}
}
