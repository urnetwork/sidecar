//go:build !js

// FuzzValidateDnsName (DNS-M0-01, §22.6): ValidateDnsName never panics, and a name it accepts is
// lowercase LDH, 5 to 50 bytes, with no dash at either end or as its third and fourth characters, not
// reserved and not confusable with a brand. Off the js leg, whose Worker has no file system for go
// test's corpus reader; dns_label_test.go runs the seeds there through embed.

package sidecar

import (
	"strings"
	"testing"
)

func FuzzValidateDnsName(f *testing.F) {
	for _, seed := range []string{"quiet-river-lab", "xn--abcde", "urnetw0rk", "main-api", "-edge", "a"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if failure := checkValidateDnsName(name); failure != "" {
			t.Fatalf("%q: %s", name, failure)
		}
		// the predicates answer anything, folding ASCII case alike
		upper := strings.Map(func(character rune) rune {
			if 'a' <= character && character <= 'z' {
				return character - ('a' - 'A')
			}
			return character
		}, name)
		if IsReservedDnsLabel(name) != IsReservedDnsLabel(upper) || IsBrandConfusableDnsName(name) != IsBrandConfusableDnsName(upper) {
			t.Fatalf("%q: case changed a predicate's answer", name)
		}
		IsWordNumberDnsLabel(name)
	})
}
