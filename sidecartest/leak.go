//go:build !sidecar_leaktest

// The untagged build: no leak is linked, and none can be registered. §22.7's self-test runs in a
// sidecar_leaktest build (leak_enabled.go), which check/ keeps off every release leg.

package sidecartest

// Whether this build links the leaks.
const LeaksLinked = false

// No leak: this build leaks nothing.
func LeakClasses() map[PrivacyClass]*Leak {
	return nil
}

// Panics: a leak registered outside the tag would link leak code into an untagged build.
func RegisterLeak(leak *Leak) *Leak {
	panic("a leak registers only in a sidecar_leaktest file")
}
