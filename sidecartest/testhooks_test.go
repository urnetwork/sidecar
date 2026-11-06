//go:build !sidecar_testhooks

package sidecartest

import (
	"errors"
	"testing"
)

func TestInstallFailsLoudlyWithoutTheTag(t *testing.T) {
	if HooksLinked {
		t.Error("the untagged build claims hooks")
	}
	if _, err := InstallTestHooks(nil, nil); !errors.Is(err, ErrHooksNotLinked) {
		t.Errorf("err %v", err)
	}
}
