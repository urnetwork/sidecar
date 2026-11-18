//go:build !sidecar_http

// §5.9's file class of the index cache (state_class.go) is a name no component may take, on every leg that runs
// components, the ios_extension legs among them, which link no cache (QD-988).

package sidecar

import (
	"errors"
	"testing"
)

// The index cache's file class names a seal class and is reserved from components, wherever the cache links.
func TestSearchFileClassIsReservedFromComponents(t *testing.T) {
	if !isSealClass(SidecarSearchFileClass) {
		t.Fatalf("%q is no seal class", SidecarSearchFileClass)
	}
	if err := checkSidecarComponentName(SidecarSearchFileClass); !errors.Is(err, errInvalidSettings) {
		t.Errorf("a component named %q: %v", SidecarSearchFileClass, err)
	}
	if err := checkSidecarComponentName("evs"); err != nil {
		t.Errorf("CONTROL FAILED: a component named evs is refused: %v", err)
	}
}
