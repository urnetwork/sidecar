//go:build sidecar_testhooks && !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// FS-73's twin on T2 (evsgit/fs73_testhooks.go): the pruned clause with the pushing device's tip check switched off
// must fail at the force push that goes through.

package sidecartest_test

import (
	"testing"

	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

func TestEvsGitFs73TipCheckOffTwinIsCaught(t *testing.T) {
	evsgit.Fs73TipCheckOffTwin(t, newEvsGitFs73World(t))
}
