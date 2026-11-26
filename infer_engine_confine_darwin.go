//go:build darwin && !ios && !ios_extension && !sidecar_http

// The helper's confinement on macOS (DESIGN-COMPUTE §6.5; infer_engine_confine.go): its own signed executable inside
// ur.app, at Contents/Helpers/ur-engine.app/Contents/MacOS/ur-engine, with its own identifier, the hardened runtime and
// the App Sandbox, whose entitlements (build/all/ur/macos/ur-engine.entitlements) give it a read-only exception for
// <ur>/_local, the folder that holds every instance's engine and model files and nothing else
// (InferDesktopLocalDirectory), and turn library validation off for it alone, so it loads LiteRT-LM's libraries, which
// another team signs, while ur's own daemon keeps library validation. It has no network entitlement, no app group and
// no keychain access. The kernel applies the sandbox at the helper's exec, before any of its code runs, so at run time
// there is only the proof: a helper that can list the instance's state directory is not sandboxed, a build signed
// without its entitlements or one run from outside its bundle, and runs nothing.
//
// The exception is a literal path, home-relative, so it names that one folder for every instance; no instance's state
// is under it (question infer-m11-05-macos-instance-directories, option 1).

package sidecar

import (
	"fmt"
	"path/filepath"
)

// Where the helper sits inside ur.app, from the directory ur's executable is in (Contents/MacOS).
const inferEngineBundleHelperPath = "../Helpers/ur-engine.app/Contents/MacOS/ur-engine"

// See infer_engine_confine.go: the kernel sandboxes a signed helper at its exec, so nothing here can be missing
// beforehand; a helper not sandboxed refuses at its proof.
func inferEngineConfineAvailable() error {
	return nil
}

// See infer_engine_confine.go: the helper inside ur.app where ur runs from its bundle, its links resolved, else the one
// beside ur, as a build from source places it.
func inferEngineDefaultHelperPath(executable string) string {
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}
	directory := filepath.Dir(executable)
	if filepath.Base(directory) == "MacOS" && filepath.Base(filepath.Dir(directory)) == "Contents" {
		return filepath.Join(directory, filepath.FromSlash(inferEngineBundleHelperPath))
	}
	return filepath.Join(directory, inferEngineHelperName())
}

// See infer_engine_confine.go: an exec of the helper, which the sandbox confines at its start.
func inferEngineStartChild(spec *inferEngineChildSpec) (*inferEngineChild, error) {
	return inferEngineStartExecChild(spec)
}

// See infer_engine_confine.go: the sandbox holds already, so only the proof.
func inferEngineConfine(confinement *inferEngineConfinement, settings *InferSettings, argv []string, env []string) error {
	if err := confinement.validate(); err != nil {
		return err
	}
	if err := inferEngineConfineProbe(confinement.DeniedDirectory); err != nil {
		return fmt.Errorf("%w (is this ur-engine the one signed inside ur.app?)", err)
	}
	return nil
}
