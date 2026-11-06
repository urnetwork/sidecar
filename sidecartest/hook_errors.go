package sidecartest

import (
	"errors"
)

var (
	// This build has no call site for a hook to reach: build the test with sidecar_testhooks.
	ErrHooksNotLinked = errors.New("this build has no test hooks: build with -tags sidecar_testhooks")
	// Another test's hooks are installed. Hooks are process-wide, so a test using them is not parallel.
	ErrHooksInstalled = errors.New("test hooks are already installed")
)
