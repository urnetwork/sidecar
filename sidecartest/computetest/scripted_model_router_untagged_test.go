//go:build !sidecar_testhooks

package computetest

import (
	"errors"
	"testing"
)

// Without sidecar_testhooks no seam into INFER's router is linked, and Router says so by name rather than hand back a
// router that never reaches the model.
func TestScriptedModelRouterNeedsTestHooks(t *testing.T) {
	model, err := NewScriptedModel(nil)
	if err != nil {
		t.Fatal(err)
	}
	router, err := model.Router(nil)
	if router != nil || !errors.Is(err, ErrScriptedRouterUnlinked) {
		t.Fatalf("the untagged build's router: %v, %v", router, err)
	}
}
