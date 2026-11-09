// FuzzValidateDnsName (DNS-M0-01, §22.6): ValidateDnsName never panics, and a name it accepts is
// lowercase LDH, 5 to 50 bytes, with no dash at either end or as its third and fourth characters, not
// reserved and not confusable with a brand.

package sidecar

import (
	"strings"
	"testing"
)

// What an accepted name breaks, or empty when it breaks nothing or was refused.
func checkValidateDnsName(name string) string {
	if ValidateDnsName(name) != nil {
		return ""
	}
	if len(name) < 5 || 50 < len(name) {
		return "accepted a name of the wrong length"
	}
	for index := range len(name) {
		character := name[index]
		if !('a' <= character && character <= 'z') && !('0' <= character && character <= '9') && character != '-' {
			return "accepted a byte outside lowercase LDH"
		}
	}
	if strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
		return "accepted a dash at an end"
	}
	if name[2:4] == "--" {
		return "accepted dashes as the third and fourth characters"
	}
	if IsReservedDnsLabel(name) {
		return "accepted a reserved name"
	}
	if IsBrandConfusableDnsName(name) {
		return "accepted a name confusable with a brand"
	}
	return ""
}

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
