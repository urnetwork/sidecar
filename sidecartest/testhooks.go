//go:build !sidecar_testhooks

// The untagged build: no call site in this module reaches anything here, so a schedule that names a
// barrier has to be built with sidecar_testhooks. What a test passes straight to BarrierDriver.Hit
// still holds, which is how the driver's own tests run on both builds.

package sidecartest

// Whether this build links the hooks.
const HooksLinked = false

// Fails rather than do nothing: a test that installs hooks on a build without them would otherwise
// wait out its timeout at a site nothing can reach.
func InstallTestHooks(secret func(kind string, secret []byte), barrier func(name string, key string)) (remove func(), err error) {
	return nil, ErrHooksNotLinked
}
