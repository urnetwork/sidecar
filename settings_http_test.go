//go:build sidecar_http

package sidecar

import (
	"reflect"
	"testing"
)

// The page Worker has no platform client, so a url it never dials does not hold it back.
func TestPlatformUrlGoesUnreadOnThisLeg(t *testing.T) {
	settings := validSidecarSettings()
	settings.PlatformUrl = ""
	if err := settings.validate(); err != nil {
		t.Error(err)
	}
}

func TestConnectSettingsAreEmptyOnThisLeg(t *testing.T) {
	if fieldCount := reflect.TypeOf(SidecarConnectSettings{}).NumField(); fieldCount != 0 {
		t.Errorf("%d fields", fieldCount)
	}
	if DefaultSidecarSettings().Connect == nil {
		t.Error("nil, where a host may read the field on every leg")
	}
}

// §5.9's wasm cost: OWASP's 19 MiB, t=2, p=1.
const (
	testLegPassMemoryByteCount = 19 * 1024 * 1024
	testLegPassIterationCount  = 2
	testLegPassThreadCount     = 1
)

// The page Worker's pass costs §5.9's wasm Argon2id, so a keychain open on one thread stays short.
func TestPassCostOnThisLeg(t *testing.T) {
	settings := DefaultSidecarSettings().KeychainSettings
	if settings.PassMemoryByteCount != 19*1024*1024 || settings.PassIterationCount != 2 || settings.PassThreadCount != 1 {
		t.Errorf("Argon2id at %d B, t=%d, p=%d", settings.PassMemoryByteCount, settings.PassIterationCount, settings.PassThreadCount)
	}
}
