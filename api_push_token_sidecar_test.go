//go:build !sidecar_http && !js

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// A Sidecar posts its wake token on its current generation's token and on no other, and refuses with no enrolled
// client, sending nothing (sdk's Sidecar.SetPushToken).
func TestSidecarSetPushTokenPostsOnTheGenerationToken(t *testing.T) {
	world := newTestEnrollWorld(t)
	if err := world.sidecar.SetPushToken(context.Background(), PushTokenPlatformApns, testPushToken); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Fatalf("before enrollment: %v", err)
	}
	for _, path := range world.api.requestedPaths() {
		if path == "/sidecar/push-token" {
			t.Fatal("a push token was posted with no enrolled client")
		}
	}
	if err := world.enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOffline, 1))
	// the fake api has no such route, so the post answers its 404, after it was sent
	world.sidecar.SetPushToken(context.Background(), PushTokenPlatformApns, testPushToken)
	byJwt, err := loadSidecarByJwt(world.instance.secrets(world.api.networkId, sidecarCoreSecretsNamespace))
	if err != nil {
		t.Fatal(err)
	}
	world.api.stateLock.Lock()
	defer world.api.stateLock.Unlock()
	posted := -1
	for i, path := range world.api.paths {
		if path == "/sidecar/push-token" {
			posted = i
		}
	}
	if posted < 0 {
		t.Fatalf("no push token was posted: %v", world.api.paths)
	}
	if world.api.bearers[posted] != byJwt {
		t.Fatal("the push token was not posted on the generation's token")
	}
	body := &SidecarPushTokenArgs{}
	if err := json.Unmarshal(world.api.bodies[posted], body); err != nil || body.Platform != PushTokenPlatformApns || body.Token != testPushToken {
		t.Fatalf("the body: %v %v", body, err)
	}
}
