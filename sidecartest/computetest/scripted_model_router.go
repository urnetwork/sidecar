//go:build sidecar_testhooks

// The model behind INFER's own router (DESIGN-COMPUTE §6.4, §18): sidecar.NewInferRouterForTest, which only the
// sidecar_testhooks build has (infer_router_testhooks.go), builds the router a Sidecar builds over the model's manifest,
// with the model as its local engine, so a call resolves, passes the router's checks and streams through its relay as
// any local call does. scripted_model_router_untagged.go is the untagged build's half.

package computetest

import (
	"github.com/urnetwork/sidecar"
)

// INFER's router with this model as its local engine and its manifest as the release's, the checks reading sources:
// nil wires none, which refuses every remote name and passes this model's on the person's allow as the defaults read
// it. A Harness, a gateway or any other caller takes the router as it takes a Sidecar's (sidecar.HarnessArgs.Router).
func (self *ScriptedModel) Router(sources *sidecar.InferCheckSources) (sidecar.InferRouter, error) {
	return sidecar.NewInferRouterForTest(&sidecar.InferRouterForTestArgs{
		Settings: self.settings.Infer,
		Clock:    self.clock,
		Manifest: self.Manifest(),
		Engine:   self,
		Sources:  sources,
	})
}
