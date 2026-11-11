package sidecartest

// §6.10.1's share rules on T2 (PROTO-M6-01; C18, D-PROTO-15, X11), through real Sidecars on the Net's exchange: a
// sidecar provides FriendsAndFamily only while an inbound share holds it, the mode reaching its client's provide
// modes and leaving with the last hold; and a share's contract carries no 21842, so a Hello over a FriendsAndFamily
// contract is dropped at the receiver's mode check, counted, its handler never reached (a pair's Network contracts
// carry it, as subprotocol_test.go shows). Which contracts are FriendsAndFamily, their escrow on the dialer's
// network and their seals are CreateContract's (server/controller/connect_controller_share_test.go).

import (
	"context"
	"testing"
	"time"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
)

func TestShareModeHeldOnlyWhileAShareLives(t *testing.T) {
	_, _, b, _, _ := newTestSubprotocolPair(t)
	manager := b.Client().Client.ContractManager()
	if manager.GetProvideModes()[connectprotocol.ProvideMode_FriendsAndFamily] {
		t.Fatal("FriendsAndFamily provided with no share")
	}
	release, err := b.Subprotocol().HoldProvideMode(connectprotocol.ProvideMode_FriendsAndFamily)
	if err != nil {
		t.Fatal(err)
	}
	if modes := manager.GetProvideModes(); !modes[connectprotocol.ProvideMode_FriendsAndFamily] || !modes[connectprotocol.ProvideMode_Network] {
		t.Errorf("a share held: %v", modes)
	}
	release()
	if modes := manager.GetProvideModes(); modes[connectprotocol.ProvideMode_FriendsAndFamily] || !modes[connectprotocol.ProvideMode_Network] {
		t.Errorf("the share released: %v", modes)
	}
}

func TestShareContractCarriesNoHelloOrRpc(t *testing.T) {
	net, a, b, _, runs := newTestSubprotocolPair(t)
	release, err := b.Subprotocol().HoldProvideMode(connectprotocol.ProvideMode_FriendsAndFamily)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	net.SetContractProvideMode(a.ClientId(), b.ClientId(), connectprotocol.ProvideMode_FriendsAndFamily)
	droppedBefore := b.Sidecar().Stats().Subprotocol.ProvideModeDroppedCount

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := a.Subprotocol().EnsureHello(ctx, sidecar.Id(b.ClientId())); err == nil {
		t.Fatal("a Hello over a share's contract was answered")
	}
	if dropped := b.Sidecar().Stats().Subprotocol.ProvideModeDroppedCount; dropped <= droppedBefore {
		t.Errorf("the receiver counted no mode drop: %d, before %d", dropped, droppedBefore)
	}
	if _, ok := b.Subprotocol().PeerIdentity(sidecar.Id(a.ClientId())); ok {
		t.Error("the receiver holds a Hello that came over a share's contract")
	}
	select {
	case <-runs:
		t.Error("a handler ran for a share's contract")
	default:
	}
}
