//go:build !sidecar_http && !js

// §16.6's turn-on row for a new network (CACL-M11-02): its first head turns on every authorization feature its creating
// release implements, since no device of the network is older than it, and a reader of that release follows base 1.

package sidecar_test

import (
	"testing"

	"github.com/urnetwork/sidecar"
)

func TestAuthFeatureFirstHeadSetsImplemented(t *testing.T) {
	implemented := sidecar.AuthFeatureAgentRepos | sidecar.AuthFeatureListeners
	sidecar.WithAuthFeaturesImplementedForTest(t, implemented, nil)
	world := newTestWriterWorld(t)
	seams := &testBootstrapSeams{t: t, world: world}
	result, err := sidecar.BootstrapNetwork(world.ctx, seams.args(world.owner, world.publisher()))
	if err != nil || !result.Won {
		t.Fatalf("bootstrap: %v", err)
	}
	if features := result.State.AuthFeatures(); features != implemented || !result.State.AuthFeatureOn(sidecar.AuthFeatureListeners) {
		t.Fatalf("base 1 turns on %s", features)
	}
	world.genesis = result
	client := world.client()
	if err := client.CatchUp(world.ctx); err != nil || client.Pin().GetVersion() != 1 || client.State().AuthFeatures() != implemented {
		t.Fatalf("a reader of the same release at base 1: %v", err)
	}

	// a release that implements none turns none on, and adds no settings record of its own
	sidecar.WithAuthFeaturesImplementedForTest(t, 0, nil)
	plain := newTestWriterWorld(t)
	plainSeams := &testBootstrapSeams{t: t, world: plain}
	result, err = sidecar.BootstrapNetwork(plain.ctx, plainSeams.args(plain.owner, plain.publisher()))
	if err != nil || !result.Won || result.State.AuthFeatures() != 0 {
		t.Fatalf("a release implementing none: %v, %v", err, result)
	}
	if settings, known := result.State.HeadSettings(); !known || settings != nil {
		t.Fatalf("a release implementing none wrote settings %v", settings)
	}
}
