package pushservice_test

import (
	"math"
	"math/big"
	mathrand "math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/pushservice"
)

// A canonical decimal of length digits, its first digit not 0, drawn so that neighbors and shared
// prefixes come up often: the cases where a double would round two versions to one.
func testCanonicalDecimal(random *mathrand.Rand, length int) string {
	var builder strings.Builder
	builder.WriteByte(byte('1' + random.IntN(9)))
	for builder.Len() < length {
		builder.WriteByte(byte('0' + random.IntN(10)))
	}
	return builder.String()
}

// CompareVersion against math/big over random canonical decimals of every length, neighbors around
// 2^53 and 1.8e18, and shared prefixes past 10 digits, where the comparison splits.
func TestCompareVersionMatchesBigInt(t *testing.T) {
	random := mathrand.New(mathrand.NewPCG(1, 2))
	pairs := [][2]string{}
	for range 20000 {
		a := testCanonicalDecimal(random, 1+random.IntN(20))
		b := testCanonicalDecimal(random, 1+random.IntN(20))
		pairs = append(pairs, [2]string{a, b})
		// the same length, sharing all but the last few digits
		if 3 < len(a) {
			shared := a[:len(a)-1-random.IntN(3)]
			c := shared + testCanonicalDecimal(random, len(a)-len(shared))[0:len(a)-len(shared)]
			pairs = append(pairs, [2]string{a, c})
		}
	}
	for _, center := range []uint64{1 << 53, 1_800_000_000_000_000_000, math.MaxUint64 - 2, 10_000_000_000} {
		for delta := uint64(0); delta <= 2; delta += 1 {
			pairs = append(pairs, [2]string{strconv.FormatUint(center, 10), strconv.FormatUint(center+delta, 10)})
			pairs = append(pairs, [2]string{strconv.FormatUint(center+delta, 10), strconv.FormatUint(center, 10)})
		}
	}
	for _, pair := range pairs {
		got, err := pushservice.CompareVersion(pair[0], pair[1])
		if err != nil {
			t.Fatalf("%s vs %s: %v", pair[0], pair[1], err)
		}
		aBig, _ := new(big.Int).SetString(pair[0], 10)
		bBig, _ := new(big.Int).SetString(pair[1], 10)
		if want := aBig.Cmp(bBig); got != want {
			t.Fatalf("%s vs %s: %d, want %d", pair[0], pair[1], got, want)
		}
	}
}

func TestCanonicalVersion(t *testing.T) {
	for _, c := range []struct {
		text      string
		canonical bool
	}{
		{text: "1", canonical: true},
		{text: "9007199254740993", canonical: true},
		{text: "18446744073709551615", canonical: true},
		// canonical for the comparison, past uint64 for ParseVersion
		{text: "99999999999999999999", canonical: true},
		{text: "0", canonical: false},
		{text: "", canonical: false},
		{text: "01", canonical: false},
		{text: "123456789012345678901", canonical: false},
		{text: "-1", canonical: false},
		{text: "+1", canonical: false},
		{text: "1e3", canonical: false},
		{text: " 1", canonical: false},
		{text: "1.0", canonical: false},
	} {
		if got := pushservice.CanonicalVersion(c.text); got != c.canonical {
			t.Errorf("%q: %t", c.text, got)
		}
	}
	if _, err := pushservice.ParseVersion("99999999999999999999"); err == nil {
		t.Errorf("a version past uint64 parsed")
	}
	for _, version := range []uint64{1, 1 << 53, 1<<53 + 1, 1_800_000_000_000_000_001, math.MaxUint64} {
		parsed, err := pushservice.ParseVersion(pushservice.FormatVersion(version))
		if err != nil || parsed != version {
			t.Errorf("%d round-trips as %d, %v", version, parsed, err)
		}
	}
	if _, err := pushservice.CompareVersion("01", "1"); err == nil {
		t.Errorf("a non-canonical version compared")
	}
}

func TestCompareStreamId(t *testing.T) {
	for _, c := range []struct {
		a    string
		b    string
		want int
	}{
		{a: "1700000000000-0", b: "1700000000000-0", want: 0},
		{a: "1700000000000-1", b: "1700000000000-0", want: 1},
		{a: "1700000000000-9", b: "1700000000000-10", want: -1},
		{a: "1699999999999-99", b: "1700000000000-0", want: -1},
		{a: "17000000000000-0", b: "1700000000000-99", want: 1},
		{a: "0-1", b: "0-0", want: 1},
		{a: "18446744073709551615-18446744073709551615", b: "18446744073709551615-18446744073709551614", want: 1},
	} {
		got, err := pushservice.CompareStreamId(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("%s vs %s: %d, %v", c.a, c.b, got, err)
		}
	}
	for _, malformed := range []string{"", "5", "-5", "5-", "05-1", "5-01", "a-1", "5-1-2", "18446744073709551616-0"} {
		if _, err := pushservice.CompareStreamId(malformed, "1-0"); err == nil {
			t.Errorf("%q compared", malformed)
		}
	}
}
