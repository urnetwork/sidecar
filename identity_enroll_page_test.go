//go:build !sidecar_http && !js

package sidecar

import (
	"context"
	"errors"
	"testing"
)

func TestPageClientRequiresMarkedTopLevelMintForOpenedNetwork(t *testing.T) {
	world := newTestEnrollWorld(t)
	client := NewId()
	result := &SidecarAuthClientResult{
		ByClientJwt: testClientTokenOf(world.api.networkId, client), ClientId: client,
		StrictExp: true, AdminRefused: true, DeclaresNoEgress: true,
	}
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
	if err := world.sidecar.EnrollPageClient(t.Context(), world.api.networkId, false, mint); err != nil {
		t.Fatal(err)
	}
	records := world.instance.Networks()
	if len(records) != 1 || records[0].Child || records[0].ClientId != client || world.sidecar.Admitted() {
		t.Fatal("the bound page must be a top-level client awaiting a verified admission")
	}
}
