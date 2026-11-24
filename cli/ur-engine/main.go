//go:build ur_engine

// ur-engine, the local engine's helper (DESIGN-COMPUTE §6.5, D-INFER-2): a second executable beside ur, built from this
// directory with the ur_engine tag, which loads LiteRT-LM's C library through purego and speaks JSON lines on its stdio
// to the daemon that starts it. Its code is the sidecar root's infer_engine_*.go, so ur, built without the tag, links
// neither the binding nor this main. It holds none of ur's keys, keychain access or app groups, and its operating
// system confines it to its engine and model files with no network (INFER-M11-05).
package main

import (
	"os"

	"github.com/urnetwork/sidecar"
)

func main() {
	os.Exit(sidecar.InferEngineHelperMain())
}
