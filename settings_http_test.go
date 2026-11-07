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
