//go:build ur_engine

// The ur-engine helper (DESIGN-COMPUTE §6.5, D-INFER-2; QD-1401): this package built with the ur_engine tag, `go build
// -tags ur_engine -o ur-engine .`, whose main runs only the helper's loop. It links ur's code but none of it runs: no
// command, no daemon and no key, only the helper, which confines itself before it loads anything and serves LiteRT-LM
// over its stdio (the root's InferEngineHelperMain, infer_engine_litert.go). Every release target with an engine build
// ships it beside ur (build/all/build-ur.sh).
package main

import (
	"os"

	"github.com/urnetwork/sidecar"
)

func main() {
	os.Exit(sidecar.InferEngineHelperMain())
}
