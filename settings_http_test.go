//go:build sidecar_http

package sidecar

import (
	"reflect"
	"testing"
)

func TestConnectSettingsAreEmptyOnThisLeg(t *testing.T) {
	if fieldCount := reflect.TypeOf(SidecarConnectSettings{}).NumField(); fieldCount != 0 {
		t.Errorf("%d fields", fieldCount)
	}
	if DefaultSidecarSettings().Connect == nil {
		t.Error("nil, where a host may read the field on every leg")
	}
}
