//go:build sidecar_testhooks && !ios_extension && !sidecar_http

// The sidecar_testhooks seam for sidecartest's compute fakes (CTEST-M11-01's computetest.ScriptedModel, DESIGN-COMPUTE
// §18): INFER's own router, the one a Sidecar builds (infer_router.go), over a release manifest and a local engine a
// test gives in place of this build's, so a scripted model is a local model the catalog lists, and the Harness, the
// gateway, the skill and the classifier's callers reach it through the router's own resolution, checks and stream,
// unchanged. Only the sidecar_testhooks build has it (§22.4), and make check fails a release leg built with that tag,
// so no shipped build runs a model its signed release manifest does not pin.

package sidecar

import (
	"errors"
)

// What NewInferRouterForTest builds on.
type InferRouterForTestArgs struct {
	// Nil takes DefaultInferSettings.
	Settings *InferSettings
	// Nil logs nothing.
	Log Logger
	// The background grants' clock (infer_background.go); nil for real time.
	Clock Clock
	// Required: the manifest the local view is judged from, in place of the release's (infer_manifest.go).
	Manifest *InferManifest
	// The engine every local call runs on; nil for none, which lists no local entry.
	Engine InferLocalEngine
	// The checks' facts (infer_check.go); nil wires none, which refuses every remote call and passes a local one on the
	// person's allow as the defaults read it.
	Sources *InferCheckSources
}

// INFER's router over args, with no remote path and no remote catalog, so a remote name answers model_refused.
func NewInferRouterForTest(args *InferRouterForTestArgs) (InferRouter, error) {
	if args == nil || args.Manifest == nil {
		return nil, errors.New("inference router for a test: a manifest")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultInferSettings()
	}
	sources := args.Sources
	if sources == nil {
		sources = &InferCheckSources{}
	}
	router, err := newInferRouter(&inferRouterArgs{
		Settings: settings,
		Log:      args.Log,
		Manifest: args.Manifest,
		Checker:  newInferSourceChecker(settings, sources, nil),
		Clock:    args.Clock,
	})
	if err != nil {
		return nil, err
	}
	router.setLocalEngine(args.Engine)
	return router, nil
}
