//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// Several networks per daemon (CORE-M6-01, R-CORE-15, D-CORE-14): one instance, one U, and per network its own
// sidecar_id, identity key, ClientKey, R_n and InstanceId; one network failing or logging out leaves the others.

// Two Sidecars on one unlocked instance, each enrolled through its own network's api.
type testTwoNetworks struct {
	backend  SidecarStoreBackend
	instance *SidecarInstance
	worlds   [2]*testEnrollWorld
}

func newTestTwoNetworks(t *testing.T) *testTwoNetworks {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	networks := &testTwoNetworks{backend: backend, instance: instance}
	for i := range networks.worlds {
		world := &testEnrollWorld{
			instance: instance,
			backend:  backend,
			api:      newTestEnrollApi(t),
			platform: newTestSidecarPlatform(),
			log:      &testLineLogger{},
		}
		settings := testSidecarSettings(world.platform)
		settings.Log = world.log
		world.sidecar = newTestRunningSidecar(t, instance, nil, settings)
		world.sidecar.sidecarApi.setTransport(world.api)
		world.sidecar.hostStores = func() []SidecarHostCredentialStore { return nil }
		awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, 0))
		if err := world.enroll(context.Background()); err != nil {
			t.Fatal(err)
		}
		world.platform.connected.Set(true)
		awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
		networks.worlds[i] = world
	}
	return networks
}

// The networks share U and nothing else: no sidecar_id, identity key, ClientKey, client, R_n or connect InstanceId,
// and neither network's keychain names the other's secrets.
func TestTwoNetworksShareNoKey(t *testing.T) {
	networks := newTestTwoNetworks(t)
	first, second := networks.worlds[0].sidecar.currentIdentity(), networks.worlds[1].sidecar.currentIdentity()
	if first.NetworkId == second.NetworkId || first.SidecarId == second.SidecarId || first.ClientId == second.ClientId ||
		bytes.Equal(first.IdentityPublicKey, second.IdentityPublicKey) || bytes.Equal(first.ClientPublicKey, second.ClientPublicKey) {
		t.Fatalf("the networks share an identity: %+v %+v", first, second)
	}
	records := networks.instance.Networks()
	if len(records) != 2 || records[0].ConnectInstanceId == records[1].ConnectInstanceId {
		t.Fatalf("records %+v", records)
	}
	roots := [2][]byte{}
	for i, identity := range []*SidecarIdentity{first, second} {
		opened, err := networks.instance.keychainFor(identity.NetworkId)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			opened.stateLock.Lock()
			defer opened.stateLock.Unlock()
			roots[i] = bytes.Clone(opened.generationRoots[opened.currentGeneration])
		}()
	}
	if bytes.Equal(roots[0], roots[1]) {
		t.Fatal("the networks share a root key")
	}
	firstSecrets := networks.instance.secrets(first.NetworkId, sidecarCoreSecretsNamespace)
	if err := firstSecrets.Put("synthetic-only-in-the-first", []byte("synthetic value")); err != nil {
		t.Fatal(err)
	}
	if _, err := networks.instance.secrets(second.NetworkId, sidecarCoreSecretsNamespace).Get("synthetic-only-in-the-first"); !errors.Is(err, ErrSidecarStoreAbsent) {
		t.Fatalf("the second network reads the first's secret: %v", err)
	}
}

// One unlock of U opens every network: a locked instance holds both Sidecars Locked, and one pass opens both.
func TestOneUnlockOpensAll(t *testing.T) {
	networks := newTestTwoNetworks(t)
	networks.instance.Lock()
	for _, world := range networks.worlds {
		awaitSidecarStatus(t, world.sidecar, func(status SidecarStatus) bool { return status.State == SidecarStateLocked })
	}
	if err := networks.worlds[0].sidecar.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	for _, world := range networks.worlds {
		awaitSidecarStatus(t, world.sidecar, func(status SidecarStatus) bool { return status.State != SidecarStateLocked })
	}
}

// A network whose keychain fails is Locked alone, with its alarm, and the other runs on.
func TestOneFailedNetworkLeavesOthers(t *testing.T) {
	networks := newTestTwoNetworks(t)
	failing := networks.worlds[1].sidecar.currentIdentity()
	networks.instance.Lock()
	putBackendFile(t, networks.backend, keychainWrapPath(failing.NetworkId), []byte("not a keychain wrap"))
	if err := networks.instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	networks.worlds[0].sidecar.wake()
	networks.worlds[1].sidecar.wake()
	awaitSidecarStatus(t, networks.worlds[0].sidecar, func(status SidecarStatus) bool {
		return status.State == SidecarStateOffline || status.State == SidecarStateOnline
	})
	awaitSidecarStatus(t, networks.worlds[1].sidecar, func(status SidecarStatus) bool { return status.State == SidecarStateLocked })
	if networks.worlds[0].sidecar.currentIdentity() == nil {
		t.Error("the healthy network lost its identity")
	}
}

// A network's logout wipes that network alone: the other keeps its files, record and generation.
func TestLogoutOneNetworkKeepsOther(t *testing.T) {
	networks := newTestTwoNetworks(t)
	staying, leaving := networks.worlds[0], networks.worlds[1]
	stayingIdentity, leavingIdentity := staying.sidecar.currentIdentity(), leaving.sidecar.currentIdentity()
	leaving.installAuthority(t, nil)
	stayingFiles := len(networkFiles(t, networks.backend, stayingIdentity.NetworkId))
	if err := leaving.sidecar.Logout(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(networkFiles(t, networks.backend, leavingIdentity.NetworkId)) != 0 {
		t.Error("the leaving network's files stayed")
	}
	if len(networkFiles(t, networks.backend, stayingIdentity.NetworkId)) != stayingFiles {
		t.Error("the staying network's files changed")
	}
	records := networks.instance.Networks()
	if len(records) != 1 || records[0].NetworkId != stayingIdentity.NetworkId {
		t.Fatalf("records %+v", records)
	}
	if status := staying.sidecar.Status(); status.State != SidecarStateOnline || status.Generation != 1 {
		t.Errorf("the staying network: %+v", status)
	}
}

// A Sidecar enrolling a further network is refused where its key turns out to be for a network the instance holds,
// and the held network's identity stands.
func TestFurtherEnrollmentRefusesAHostedNetwork(t *testing.T) {
	networks := newTestTwoNetworks(t)
	held := networks.worlds[0]
	heldIdentity := held.sidecar.currentIdentity()
	settings := testSidecarSettings(newTestSidecarPlatform())
	further := newTestRunningSidecar(t, networks.instance, nil, settings)
	further.sidecarApi.setTransport(held.api)
	further.hostStores = func() []SidecarHostCredentialStore { return nil }
	awaitSidecarStatus(t, further, atStatus(SidecarStateUnenrolled, 0))
	removedBefore := len(held.api.removed)
	err := further.Enroll(context.Background(), &SidecarEnrollCredential{AuthKey: testAuthKeyBearer()})
	if !errors.Is(err, ErrSidecarEnrolled) {
		t.Fatalf("a further enrollment into a held network: %v", err)
	}
	if len(held.api.removed) != removedBefore+1 {
		t.Error("the refused enrollment's client was not removed")
	}
	record, err := loadSidecarIdentity(networks.instance.secrets(heldIdentity.NetworkId, sidecarCoreSecretsNamespace))
	if err != nil || record.identity.SidecarId != heldIdentity.SidecarId || record.identity.ClientId != heldIdentity.ClientId {
		t.Fatalf("the held network's identity moved: %v", err)
	}
}
