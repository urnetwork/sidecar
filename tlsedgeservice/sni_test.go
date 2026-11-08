// T1 for §13.5's step 2: what a server name may be, on the lengths and characters a name can reach.

package tlsedgeservice

import (
	"strings"
	"testing"
)

func TestNormalizeSni(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	cases := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "blog.a1b2c3d4e5.ur.example", want: "blog.a1b2c3d4e5.ur.example", ok: true},
		{name: "BLOG.A1B2c3d4e5.UR.Example", want: "blog.a1b2c3d4e5.ur.example", ok: true},
		{name: "blog.a1b2c3d4e5.ur.example.", want: "blog.a1b2c3d4e5.ur.example", ok: true},
		{name: "a-b.example", want: "a-b.example", ok: true},
		{name: "xn--bcher-kva.example", want: "xn--bcher-kva.example", ok: true},
		{name: "1.2.3.4", want: "1.2.3.4", ok: true},
		{name: "localhost", want: "localhost", ok: true},
		{name: "A", want: "a", ok: true},
		{name: "a.", want: "a", ok: true},
		{name: label63 + ".example", want: label63 + ".example", ok: true},
		{name: name253, want: name253, ok: true},
		{name: name253 + ".", want: name253, ok: true},

		{name: ""},
		{name: "."},
		{name: ".."},
		{name: "example.."},
		{name: ".example"},
		{name: "a..example"},
		{name: "a" + label63 + ".example"},
		{name: name253 + "b"},
		{name: name253 + ".."},
		{name: "-a.example"},
		{name: "a-.example"},
		{name: "a.-b.example"},
		{name: "a.b-"},
		{name: "-"},
		{name: "under_score.example"},
		{name: "sp ace.example"},
		{name: "star.*.example"},
		{name: "*.example"},
		{name: "bücher.example"},
		{name: "a\x00.example"},
		{name: "a\nb.example"},
		{name: "a.example\x00"},
		{name: "a\xff.example"},
		{name: "a:443"},
		{name: "a/b"},
	}
	for _, c := range cases {
		got, ok := NormalizeSni(c.name)
		if ok != c.ok || got != c.want {
			t.Errorf("%q: %q, %t", c.name, got, ok)
		}
	}
}

func TestNormalizeSniIsIdempotent(t *testing.T) {
	for _, name := range []string{"a.example", "A.EXAMPLE", "a.example.", "A-1.B-2.example."} {
		once, ok := NormalizeSni(name)
		if !ok {
			t.Fatalf("%q refused", name)
		}
		twice, ok := NormalizeSni(once)
		if !ok || twice != once {
			t.Errorf("%q: %q then %q, %t", name, once, twice, ok)
		}
	}
}

func TestNormalizeSniDoesNotAllocateForALowercaseName(t *testing.T) {
	allocationCount := testing.AllocsPerRun(100, func() {
		if _, ok := NormalizeSni(testServerName + "."); !ok {
			t.Fatal("refused")
		}
	})
	if allocationCount != 0 {
		t.Errorf("%.0f allocations", allocationCount)
	}
}
