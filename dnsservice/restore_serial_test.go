package dnsservice

import (
	"testing"
)

// An SOA's 32 bits stand for the serial nearest the restored one by RFC 1982: ahead of it across the
// 32-bit wrap counts in full, behind it counts as behind, and nothing lifts below zero.
func TestDnsSoaSerialNear(t *testing.T) {
	const wrap = uint64(1) << 32
	cases := []struct {
		base      uint64
		soaSerial uint32
		want      uint64
	}{
		{base: 10, soaSerial: 10, want: 10},
		{base: 10, soaSerial: 25, want: 25},
		{base: 10, soaSerial: 4, want: 4},
		{base: wrap - 2, soaSerial: 3, want: wrap + 3},
		{base: wrap + 3, soaSerial: uint32(wrap - 2), want: wrap - 2},
		{base: 3*wrap + 5, soaSerial: 9, want: 3*wrap + 9},
		{base: 5, soaSerial: uint32(wrap - 1), want: 0},
	}
	for _, c := range cases {
		if got := dnsSoaSerialNear(c.base, c.soaSerial); got != c.want {
			t.Errorf("near %d, %d: %d, want %d", c.base, c.soaSerial, got, c.want)
		}
	}
}
