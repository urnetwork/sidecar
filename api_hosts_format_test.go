//go:build !ios_extension

package sidecar

// §18.9's host names held to the format's bounds (QD-702): RFC 1035's 63-byte label and 253-byte name under the
// defaults, and whatever a settings instance names when one is given, so no bound is a constant of the code.

import (
	"errors"
	"strings"
	"testing"
)

// A host of a 63-byte label and one of a 253-byte name parse, and one byte past either refuses the list.
func TestHostListHoldsHostNamesToRfc1035sBounds(t *testing.T) {
	withHost := func(host string) string {
		return strings.Replace(testSidecarHostListJson(), `"ct.hosttest.example"`, `"`+host+`"`, 1)
	}
	longest := func(labelByteCount int) string {
		// 63 + 1 + 63 + 1 + 63 + 1 + labelByteCount + len(".hosttest.example")
		return strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
			strings.Repeat("d", labelByteCount) + ".hosttest.example"
	}
	if len(longest(44)) != 253 {
		t.Fatalf("the fixture's name is %d bytes", len(longest(44)))
	}
	for _, host := range []string{strings.Repeat("a", 63) + ".hosttest.example", longest(44)} {
		if _, err := ParseSidecarHostList([]byte(withHost(host))); err != nil {
			t.Errorf("a host of %d bytes: %v", len(host), err)
		}
	}
	for _, host := range []string{strings.Repeat("a", 64) + ".hosttest.example", longest(45)} {
		if _, err := ParseSidecarHostList([]byte(withHost(host))); !errors.Is(err, ErrSidecarHostList) {
			t.Errorf("a host of %d bytes: %v", len(host), err)
		}
	}
}

// validate reads its bounds from the instance it is given: the fixture's longest name is 24 bytes and its longest
// label 8, so bounds at those pass and a bound one below either refuses. The defaults are a fresh value each call.
func TestHostListBoundsAreTheSettings(t *testing.T) {
	list, err := ParseSidecarHostList([]byte(testSidecarHostListJson()))
	if err != nil {
		t.Fatal(err)
	}
	if err := list.validate(&SidecarHostListFormatSettings{HostNameMaxByteCount: 24, HostLabelMaxByteCount: 8}); err != nil {
		t.Fatalf("bounds at the fixture's longest: %v", err)
	}
	if err := list.validate(&SidecarHostListFormatSettings{HostNameMaxByteCount: 23, HostLabelMaxByteCount: 8}); !errors.Is(err, ErrSidecarHostList) {
		t.Errorf("a name bound below the longest name: %v", err)
	}
	if err := list.validate(&SidecarHostListFormatSettings{HostNameMaxByteCount: 24, HostLabelMaxByteCount: 7}); !errors.Is(err, ErrSidecarHostList) {
		t.Errorf("a label bound below the longest label: %v", err)
	}

	changed := DefaultSidecarHostListFormatSettings()
	changed.HostNameMaxByteCount = 1
	changed.HostLabelMaxByteCount = 1
	if defaults := DefaultSidecarHostListFormatSettings(); defaults.HostNameMaxByteCount != 253 || defaults.HostLabelMaxByteCount != 63 {
		t.Fatalf("the defaults after a change to another value: %+v", defaults)
	}
}
