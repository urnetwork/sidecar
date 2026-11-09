//go:build !sidecar_http && !js

package sidecar

import (
	"bytes"
	"testing"
)

// Identity answers the enrolled sidecar's ids and public keys as a copy a caller may change, and nil before an
// identity exists.
func TestIdentityIsACopyOfTheEnrolledIdentity(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOffline, 1))

	identity := sidecar.Identity()
	if identity == nil || identity.SidecarId != enrollment.sidecarId || identity.NetworkId != enrollment.networkId {
		t.Fatalf("identity %+v", identity)
	}
	if !bytes.Equal(identity.IdentityPublicKey, enrollment.keys.identityPublicKey()) {
		t.Error("the identity's public key is not the keychain's")
	}
	identity.IdentityPublicKey[0] ^= 0xff
	identity.SidecarId = NewId()
	if again := sidecar.Identity(); again.SidecarId != enrollment.sidecarId || !bytes.Equal(again.IdentityPublicKey, enrollment.keys.identityPublicKey()) {
		t.Error("an edit to one copy reached the sidecar")
	}

	unenrolled := newTestRunningSidecar(t, newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore()), nil, testSidecarSettings(newTestSidecarPlatform()))
	if identity := unenrolled.Identity(); identity != nil {
		t.Errorf("an unenrolled sidecar's identity %+v", identity)
	}
}
