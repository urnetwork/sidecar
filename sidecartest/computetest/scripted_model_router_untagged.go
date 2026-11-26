//go:build !sidecar_testhooks

// The untagged build's half of scripted_model_router.go: no seam into INFER's router is linked, so Router fails with a
// named error rather than hand a caller a router that never reaches the model, as sidecartest.InstallTestHooks fails
// without the tag.

package computetest

import (
	"github.com/urnetwork/sidecar"
)

// ErrScriptedRouterUnlinked: this build links no seam into INFER's router.
func (self *ScriptedModel) Router(sources *sidecar.InferCheckSources) (sidecar.InferRouter, error) {
	return nil, ErrScriptedRouterUnlinked
}
