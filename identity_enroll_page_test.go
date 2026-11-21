//go:build !sidecar_http && !js

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func testPageMint(networkId, clientId Id) *SidecarAuthClientResult {
	return &SidecarAuthClientResult{
		ByClientJwt: testPairChildTokenMarked(networkId, clientId, `"strict_exp":true,"admin_refused":true,"declares_no_egress":true`),
		ClientId:    clientId, StrictExp: true, AdminRefused: true, DeclaresNoEgress: true,
	}
}

func TestPageClientRequiresMarkedTopLevelMintForOpenedNetwork(t *testing.T) {
	world := newTestEnrollWorld(t)
	client := NewId()
	result := testPageMint(world.api.networkId, client)
	mint := func(context.Context) (*SidecarAuthClientResult, error) { return result, nil }
	if err := world.sidecar.EnrollPageClient(t.Context(), NewId(), false, mint); !errors.Is(err, ErrSidecarApiReply) {
		t.Fatalf("another network's mint: %v", err)
	}
	result.DeclaresNoEgress = false
	if err := world.sidecar.EnrollPageClient(t.Context(), world.api.networkId, false, mint); !errors.Is(err, ErrSidecarEnrollNotAdminRefused) {
		t.Fatalf("unmarked mint: %v", err)
	}
	if len(world.instance.Networks()) != 0 || len(world.api.generationsBy) != 0 {
		t.Fatal("a refused mint bound or persisted an identity")
	}
	result.DeclaresNoEgress = true
	markedToken := result.ByClientJwt
	result.ByClientJwt = testClientTokenOf(world.api.networkId, client)
	if err := world.sidecar.EnrollPageClient(t.Context(), world.api.networkId, false, mint); !errors.Is(err, ErrSidecarEnrollNotAdminRefused) {
		t.Fatal("accepted a page credential whose claims lacked the confirmed marks")
	}
	result.ByClientJwt = markedToken
	if err := world.sidecar.EnrollPageClient(t.Context(), world.api.networkId, false, mint); err != nil {
		t.Fatal(err)
	}
	records := world.instance.Networks()
	if len(records) != 1 || records[0].Child || records[0].ClientId != client || world.sidecar.Admitted() {
		t.Fatal("the bound page must be a top-level client awaiting a verified admission")
	}
}

func TestPageRemintRestartsWithTheSameTopLevelBinding(t *testing.T) {
	world := newTestEnrollWorld(t)
	ctx := t.Context()
	networkId := world.api.networkId
	mints := 0
	mint := func(context.Context) (*SidecarAuthClientResult, error) {
		mints++
		return testPageMint(networkId, NewId()), nil
	}
	if err := world.sidecar.EnrollPageClient(ctx, networkId, false, mint); err != nil {
		t.Fatal(err)
	}
	world.platform.connected.Set(true)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
	original := world.sidecar.Identity()
	world.sidecar.runningGeneration().tokenManager.Load().end(SidecarReasonRefused)
	awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateUnenrolled, 1))
	world.api.stateLock.Lock()
	world.api.loseBindReply = true
	world.api.stateLock.Unlock()
	if err := world.sidecar.EnrollPageClient(ctx, networkId, false, mint); !errors.Is(err, ErrSidecarBindingPending) {
		t.Fatalf("a lost reply left no pending binding: %v", err)
	}
	if err := world.sidecar.EnrollPageClient(ctx, NewId(), false, mint); !errors.Is(err, ErrSidecarEnrolled) {
		t.Fatalf("a different opened network accepted the pending binding: %v", err)
	}
	if err := world.sidecar.CloseAndWait(ctx); err != nil {
		t.Fatal(err)
	}
	world.instance.Close()
	instance := newInstanceOn(t, world.backend, newFakeKeyStore())
	running := newTestRunningSidecar(t, instance, &networkId, testSidecarSettings(newTestSidecarPlatform()))
	running.sidecarApi.setTransport(world.api)
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	awaitSidecarStatus(t, running, atStatus(SidecarStateOffline, 2))
	replayed := running.Identity()
	if mints != 2 || replayed.SidecarId != original.SidecarId || !bytes.Equal(replayed.IdentityPublicKey, original.IdentityPublicKey) ||
		replayed.ClientId == original.ClientId || running.Paired() || instance.Networks()[0].Child {
		t.Fatal("the browser lost its top-level identity or minted a third client on replay")
	}
}

func TestPendingPageBindingMatchesOnlyItsOperation(t *testing.T) {
	pending := &sidecarPendingBinding{Operation: bindingPage}
	if !pending.matches(bindingPage, nil) || pending.matches(bindingAuthKey, nil) || pending.matches(bindingChild, nil) || pending.matches(bindingBurner, nil) {
		t.Fatal("an explicit retry adopted a different enrollment's pending operation")
	}
	legacy := &sidecarPendingBinding{}
	if !legacy.matches(bindingAuthKey, nil) || legacy.matches(bindingPage, nil) {
		t.Fatal("a legacy top-level enrollment became a page enrollment")
	}
}
